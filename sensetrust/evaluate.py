"""
Measured evaluation. Every number quoted in the application comes from here.

    python -m sensetrust.evaluate            # full run, ~10 min
    python -m sensetrust.evaluate --quick    # smaller sample, ~1 min

Writes results/metrics.json, results/EVALUATION.md and results/calibration.pkl.

What is measured
  1. Fault-vs-attack detector: calibrated on normal operation only, then tested on
     unseen normal episodes (false alarms) and on randomised injected faults and attacks
     on every sensor (detection, isolation, verdict, time to detect).
  2. Biometric operator login (synthetic data): genuine/impostor match scores under harsh
     recapture, and the screen-replay detector on live vs recaptured images.
  3. Gateway decision latency per request type.
"""

import argparse
import json
import os
import pickle
import random
import statistics
import tempfile
import time
from collections import Counter, defaultdict

import numpy as np

from .anomaly import calibrate
from .biometric import MATCH_ALGORITHM, MATCH_THRESHOLD, match_templates, detect_screen_replay
from .plant import SENSORS
from .simulation import ATTACKS, FAULTS, make_injection, normal_training_runs, run_episode
from .synthetic import make_template, recapture, ridge_image, screen_recapture_image

DETECT_WINDOW_S = 400


def eval_detector(cal, n_normal, n_per_cell, duration=900, seed=0):
    out = {"normal": {}, "cells": [], "summary": {}}
    fa_eps, fa_total = 0, 0
    for i in range(n_normal):
        r = run_episode(50_000 + i, duration=duration, calibration=cal)
        if r.diagnoses:
            fa_eps += 1
            fa_total += len(r.diagnoses)
    hours = n_normal * duration / 3600
    out["normal"] = {"episodes": n_normal, "hours": round(hours, 2),
                     "episodes_with_false_alarm": fa_eps, "false_alarms": fa_total,
                     "false_alarms_per_hour": round(fa_total / hours, 3)}

    rng = random.Random(seed)
    agg = defaultdict(Counter)
    ttd = defaultdict(list)
    ep = 0
    for kind in FAULTS + ATTACKS:
        truth = "fault" if kind in FAULTS else "attack"
        for s in SENSORS:
            cell = Counter()
            times = []
            for _ in range(n_per_cell):
                ep += 1
                inj = make_injection(kind, s, rng.randint(350, 450), rng)
                r = run_episode(80_000 + ep, duration=duration, injection=inj, calibration=cal)
                hits = [d for d in r.diagnoses if d.t >= inj.start]
                early = [d for d in r.diagnoses if d.t < inj.start]
                if early:
                    cell["false_alarm_before_onset"] += 1
                d = hits[0] if hits else None
                if d is None or d.t - inj.start > DETECT_WINDOW_S:
                    cell["missed"] += 1
                    agg[truth]["missed"] += 1
                    continue
                cell["detected"] += 1
                cell["isolated_correctly"] += int(d.sensor == s)
                cell["verdict_" + d.verdict] += 1
                agg[truth]["detected"] += 1
                agg[truth]["verdict_" + d.verdict] += 1
                agg[truth]["isolated_correctly"] += int(d.sensor == s)
                times.append(d.t - inj.start)
                ttd[truth].append(d.t - inj.start)
            out["cells"].append({"kind": kind, "truth": truth, "sensor": s, "n": n_per_cell,
                                 **dict(cell),
                                 "median_time_to_detect_s": statistics.median(times) if times else None})
    for truth in ("fault", "attack"):
        a = agg[truth]
        n = a["detected"] + a["missed"]
        out["summary"][truth] = {
            "episodes": n,
            "detection_rate": round(a["detected"] / n, 3),
            "isolation_accuracy": round(a["isolated_correctly"] / max(1, a["detected"]), 3),
            "verdict_fault": a["verdict_fault"], "verdict_attack": a["verdict_attack"],
            "verdict_ambiguous": a["verdict_ambiguous"], "missed": a["missed"],
            "median_time_to_detect_s": statistics.median(ttd[truth]) if ttd[truth] else None}
    # The two errors that matter operationally.
    f, a = agg["fault"], agg["attack"]
    out["summary"]["fault_wrongly_called_attack_rate"] = round(f["verdict_attack"] / max(1, f["detected"]), 3)
    out["summary"]["attack_wrongly_called_fault_rate"] = round(a["verdict_fault"] / max(1, a["detected"]), 3)
    # Excluding the deliberately indistinguishable pair (drift vs stealth ramp):
    for truth, excluded in (("fault", "drift"), ("attack", "stealth_ramp")):
        cells = [c for c in out["cells"] if c["truth"] == truth and c["kind"] != excluded]
        det = sum(c.get("detected", 0) for c in cells)
        right = sum(c.get("verdict_" + truth, 0) for c in cells)
        out["summary"]["%s_correct_verdict_excl_%s" % (truth, excluded)] = round(right / max(1, det), 3)
    return out


def eval_biometric(n_ids=30, n_captures=3, seed=0):
    gallery = [make_template(seed=5000 + i) for i in range(n_ids)]
    gen, imp = [], []
    rng = random.Random(seed)
    for i, g in enumerate(gallery):
        for k in range(n_captures):
            probe = recapture(g, drop=0.3, spurious=0.2, rotation=rng.uniform(-40, 40), seed=100 * i + k)
            gen.append(match_templates(g, probe, algorithm=MATCH_ALGORITHM))
            j = (i + 1 + rng.randrange(n_ids - 1)) % n_ids
            imp.append(match_templates(gallery[j], probe, algorithm=MATCH_ALGORITHM))
    gen, imp = np.array(gen), np.array(imp)
    ths = np.linspace(0, 1, 401)
    far = np.array([(imp >= t).mean() for t in ths])
    frr = np.array([(gen < t).mean() for t in ths])
    i = int(np.argmin(np.abs(far - frr)))
    live, spoof = [], []
    for k in range(30):
        ang = rng.uniform(0, np.pi)
        noise = (0, 6, 15)[k % 3]
        live.append((noise, detect_screen_replay(ridge_image(angle=ang, noise=noise, seed=k))["is_screen"]))
        grid = (6.0, 8.0, 10.0)[k % 3]
        spoof.append(detect_screen_replay(screen_recapture_image(angle=ang, grid_period=grid))["is_screen"])
    by_noise = {n: [f for (nn, f) in live if nn == n] for n in (0, 6, 15)}
    return {
        "algorithm": MATCH_ALGORITHM, "identities": n_ids, "genuine_pairs": len(gen),
        "impostor_pairs": len(imp),
        "threshold": MATCH_THRESHOLD,
        "FAR_at_threshold": round(float((imp >= MATCH_THRESHOLD).mean()), 4),
        "FRR_at_threshold": round(float((gen < MATCH_THRESHOLD).mean()), 4),
        "EER": round(float((far[i] + frr[i]) / 2), 4),
        "genuine_score_min_median": [round(float(gen.min()), 3), round(float(np.median(gen)), 3)],
        "impostor_score_median_max": [round(float(np.median(imp)), 3), round(float(imp.max()), 3)],
        "spoof_detection_rate": round(float(np.mean(spoof)), 3),
        "live_false_reject_rate": round(float(np.mean([f for _, f in live])), 3),
        "live_false_reject_by_noise": {str(n): round(float(np.mean(v)), 3) for n, v in by_noise.items()},
        "caveat": "Synthetic minutiae and synthetic images. Real contactless captures in the "
                  "UIDAI PoC measured EER ~43% on a 31-identity gallery with the production "
                  "matcher; real-capture accuracy is the open item this funding addresses.",
    }


def eval_latency():
    from .site import Site
    site = Site(tempfile.mkdtemp(prefix="sensetrust-lat-"))
    site.gw.latency_us.clear()
    site.run(300)
    tel = list(site.gw.latency_us)
    site.gw.latency_us.clear()
    for _ in range(20):
        site.login("ravi")
    login = list(site.gw.latency_us)
    tok = site.login("ravi")["token"]
    site.gw.latency_us.clear()
    for _ in range(200):
        site.send_command(tok, "valve.set", "XV-101", position=0.5)
    cmd = list(site.gw.latency_us)
    t0 = time.perf_counter()
    for _ in range(100):
        site.gw.process_tick(site.plant.pump, site.plant.valve)
    tick = (time.perf_counter() - t0) / 100 * 1e6

    def st(xs):
        return {"median_ms": round(statistics.median(xs) / 1000, 3),
                "p99_ms": round(float(np.percentile(xs, 99)) / 1000, 3), "n": len(xs)}
    return {"telemetry_and_m2m_request": st(tel), "operator_login_biometric": st(login),
            "operator_command": st(cmd), "physics_check_per_second_ms": round(tick / 1000, 3)}


def write_markdown(m, path):
    d, b, l = m["detector"], m["biometric"], m["latency"]
    lines = ["# SenseTrust — measured results", "",
             "Generated by `python -m sensetrust.evaluate` on %s. Simulation and synthetic data "
             "only — see caveats." % m["generated"], "",
             "## 1. Fault-vs-attack detection", "",
             "Calibrated on %d normal episodes (%d samples); tested on unseen episodes."
             % (m["calibration"]["normal_episodes"], m["calibration"]["samples"]), "",
             "**Normal operation:** %d false alarms in %.1f h (%d of %d episodes)." % (
                 d["normal"]["false_alarms"], d["normal"]["hours"],
                 d["normal"]["episodes_with_false_alarm"], d["normal"]["episodes"]), "",
             "| Ground truth | Episodes | Detected | Correct sensor | Called fault | Called attack | Ambiguous | Median time to detect |",
             "|---|---|---|---|---|---|---|---|"]
    for t in ("fault", "attack"):
        s = d["summary"][t]
        lines.append("| %s | %d | %.0f%% | %.0f%% | %d | %d | %d | %s s |" % (
            t, s["episodes"], 100 * s["detection_rate"], 100 * s["isolation_accuracy"],
            s["verdict_fault"], s["verdict_attack"], s["verdict_ambiguous"], s["median_time_to_detect_s"]))
    sm = d["summary"]
    lines += ["",
              "- Faults wrongly called attacks (would trigger a needless revocation): **%.1f%%**"
              % (100 * sm["fault_wrongly_called_attack_rate"]),
              "- Attacks wrongly called faults (attacker gets a maintenance ticket instead of revocation): **%.1f%%**"
              % (100 * sm["attack_wrongly_called_fault_rate"]),
              "- Correct verdict excluding the drift / stealth-ramp pair: faults **%.1f%%**, attacks **%.1f%%**"
              % (100 * sm["fault_correct_verdict_excl_drift"], 100 * sm["attack_correct_verdict_excl_stealth_ramp"]),
              "", "Per injection type and sensor:", "",
              "| Type | Truth | Sensor | n | Detected | Correct sensor | Fault | Attack | Ambiguous | Median TTD (s) |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for c in d["cells"]:
        lines.append("| %s | %s | %s | %d | %d | %d | %d | %d | %d | %s |" % (
            c["kind"], c["truth"], c["sensor"], c["n"], c.get("detected", 0), c.get("isolated_correctly", 0),
            c.get("verdict_fault", 0), c.get("verdict_attack", 0), c.get("verdict_ambiguous", 0),
            c["median_time_to_detect_s"]))
    lines += ["", "## 2. Biometric operator login (synthetic)", "",
              "| Metric | Value |", "|---|---|",
              "| Matcher | `%s` (from the UIDAI SDK) |" % b["algorithm"],
              "| Genuine / impostor comparisons | %d / %d |" % (b["genuine_pairs"], b["impostor_pairs"]),
              "| EER | %.1f%% |" % (100 * b["EER"]),
              "| FAR / FRR at threshold %.2f | %.1f%% / %.1f%% |" % (b["threshold"], 100 * b["FAR_at_threshold"], 100 * b["FRR_at_threshold"]),
              "| Screen-replay detected | %.0f%% |" % (100 * b["spoof_detection_rate"]),
              "| Live captures wrongly rejected as replay | %.0f%% (by noise level: %s) |" % (
                  100 * b["live_false_reject_rate"], b["live_false_reject_by_noise"]),
              "", "> " + b["caveat"], "",
              "## 3. Gateway latency (single process, laptop-class CPU)", "",
              "| Request | Median | p99 |", "|---|---|---|"]
    for k in ("telemetry_and_m2m_request", "operator_command", "operator_login_biometric"):
        lines.append("| %s | %.2f ms | %.2f ms |" % (k, l[k]["median_ms"], l[k]["p99_ms"]))
    lines += ["| physics check (per plant-second) | %.2f ms | |" % l["physics_check_per_second_ms"], "",
              "## Caveats", "",
              "- The plant is simulated. Real plants have more instruments, actuator lag, and "
              "process disturbances; thresholds must be recalibrated on site data.",
              "- `drift` and `stealth_ramp` are generated identically on purpose: they are not "
              "separable from process data alone, and the detector reports them as *ambiguous*.",
              "- A frozen flow meter is hard to see in this plant: the outflow barely changes "
              "within the controller's level band, so there is little physics to contradict it.",
              "- Biometric numbers are synthetic. They show the zero-trust wiring works; they are "
              "not a claim about real-capture accuracy.", ""]
    with open(path, "w") as f:
        f.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    n_train, n_normal, n_cell = (15, 10, 3) if a.quick else (40, 60, 12)
    os.makedirs("results", exist_ok=True)
    t0 = time.time()
    runs = normal_training_runs(n=n_train)
    cal = calibrate(runs)
    with open("results/calibration.pkl", "wb") as f:
        pickle.dump(cal, f)
    print("calibrated in %.0fs: %s" % (time.time() - t0, {k: round(v, 2) for k, v in cal["thresholds"].items()}))
    det = eval_detector(cal, n_normal, n_cell)
    print("detector done in %.0fs" % (time.time() - t0))
    bio = eval_biometric()
    lat = eval_latency()
    m = {"generated": time.strftime("%Y-%m-%d %H:%M"), "quick": a.quick,
         "calibration": {"normal_episodes": n_train, "samples": cal["calibration_samples"],
                         "thresholds_sigma": {k: round(v, 2) for k, v in cal["thresholds"].items()}},
         "detector": det, "biometric": bio, "latency": lat}
    with open("results/metrics.json", "w") as f:
        json.dump(m, f, indent=2)
    write_markdown(m, "results/EVALUATION.md")
    print(json.dumps(det["summary"], indent=2))
    print(json.dumps({k: v for k, v in bio.items() if k != "caveat"}, indent=2))
    print(json.dumps(lat, indent=2))


if __name__ == "__main__":
    main()
