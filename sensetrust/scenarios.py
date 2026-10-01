"""
Scripted attack/fault scenarios — the live demo, and an end-to-end regression suite.

    python -m sensetrust.scenarios            # run all, print a summary, write results/scenarios.json

Every scenario states what should happen, runs the real gateway against the simulated
plant, and reports what did happen. `passed` is computed, not asserted by hand.
"""

import copy
import json
import os
import sys
import tempfile

from .ca import CertificateAuthority
from .crypto import sign_envelope
from .devices import DeviceIdentity
from .plant import OVERFLOW
from .site import Site
from .synthetic import make_template, recapture, ridge_image, screen_recapture_image


def s1_rogue_device(base):
    """A device that was never enrolled tries to publish as LT-101."""
    site = Site(os.path.join(base, "s1"))
    site.run(5)
    rogue_ca = CertificateAuthority(os.path.join(base, "s1-rogue-ca"), name="Attacker CA")
    rogue_ca.issue("LT-101", "sensor")
    rogue = DeviceIdentity.load(rogue_ca, "LT-101", site.clock)
    d1 = site.gw.telemetry(rogue.cert, rogue.envelope(value=0.5))
    d2 = site.gw.telemetry(None, {"body": {"device_id": "LT-101", "value": 0.5}, "sig": ""})
    ok = d1["effect"] == "deny" and d2["effect"] == "deny"
    return {"observed": {"cloned_identity_cert": d1, "no_certificate": d2}, "passed": ok}


def s2_stolen_key_false_data(base, calibration=None):
    """
    Attacker extracts LT-101's real key and reports the tank 1.2 m lower than it is, so the
    pump controller keeps filling. Run twice: a conventional setup where the controller
    believes any correctly-keyed device, and with the zero-trust response.
    """
    def tamper(t, s, v):
        return v - 1.2 if (s == "LT-101" and t >= 120) else v

    out = {}
    for zt in (False, True):
        site = Site(os.path.join(base, "s2-" + ("zt" if zt else "baseline")),
                    calibration=calibration, zero_trust=zt, level=1.2)
        site.tamper = tamper
        site.run(600)
        attack = next((e for e in site.gw.events if e["kind"] == "attack_detected"), None)
        post = site.gw.telemetry(site.dev["LT-101"].cert, site.dev["LT-101"].envelope(value=1.0))
        r = {"overflow_seconds": site.plant.overflow_seconds,
             "max_true_level_m": round(max(x["true_level"] for x in site.log), 3)}
        if zt:
            r.update({
                "attack_detected_after_s": None if attack is None else int(attack["ts"] - site.t0) - 120,
                "diagnosis": None if attack is None else attack["diagnosis"],
                "LT101_revoked": site.gw.ca.is_revoked(site.dev["LT-101"].cert),
                "LT101_next_message": post,
                "control_source_at_end": site.log[-1]["control_source"]})
        out["zero_trust" if zt else "baseline"] = r
        if zt:
            out["log"] = site.log
            out["events"] = site.gw.events
    zt, base_ = out["zero_trust"], out["baseline"]
    ok = (base_["overflow_seconds"] > 0 and zt["overflow_seconds"] == 0
          and zt["LT101_revoked"] and zt["LT101_next_message"]["effect"] == "deny"
          and zt["diagnosis"] is not None and zt["diagnosis"]["verdict"] == "attack")
    return {"observed": {k: v for k, v in out.items() if k not in ("log", "events")},
            "passed": ok, "_log": out.get("log"), "_events": out.get("events")}


def s3_fingerprint_spoof(base):
    """Critical command: someone holds up a photo of the supervisor's finger on a phone."""
    site = Site(os.path.join(base, "s3"))
    site.run(5)
    spoof = site.login("asha", image=screen_recapture_image())
    impostor = site.login("asha", minutiae=recapture(make_template(seed=4242), seed=3))
    genuine = site.login("asha", minutiae=recapture(site.finger("asha"), seed=5, rotation=25))
    cmd = None
    if genuine["ok"]:
        _, cmd = site.send_command(genuine["token"], "pump.force_on", "P-101")
    ok = (not spoof["ok"] and not impostor["ok"] and genuine["ok"]
          and cmd is not None and cmd["effect"] == "allow")
    strip = lambda d: {k: v for k, v in d.items() if k != "token"}
    return {"observed": {"screen_replay_login": strip(spoof), "impostor_finger_login": strip(impostor),
                         "genuine_live_login": strip(genuine), "critical_command_after_login": cmd},
            "passed": ok}


def s4_api_replay(base):
    """A captured, validly signed command and telemetry message are sent a second time."""
    site = Site(os.path.join(base, "s4"))
    site.run(5)
    login = site.login("ravi")
    env, first = site.send_command(login["token"], "valve.set", "XV-101", position=0.5)
    again = site.gw.command(site.dev["console-01"].cert, login["token"], copy.deepcopy(env))
    tel = site.dev["PT-101"].envelope(value=12.0)
    t1 = site.gw.telemetry(site.dev["PT-101"].cert, tel)
    t2 = site.gw.telemetry(site.dev["PT-101"].cert, copy.deepcopy(tel))
    site.now += 120                                 # a message held back and sent later
    late = site.dev["PT-101"].envelope(value=12.0)
    late["body"]["ts"] -= 120
    late = sign_envelope(site.dev["PT-101"].key, late["body"])
    t3 = site.gw.telemetry(site.dev["PT-101"].cert, late)
    ok = (first["effect"] == "allow" and again["effect"] == "deny" and t1["effect"] == "allow"
          and t2["effect"] == "deny" and t3["effect"] == "deny")
    return {"observed": {"command_first": first, "command_replayed": again,
                         "telemetry_first": t1, "telemetry_replayed": t2,
                         "telemetry_stale": t3}, "passed": ok}


def s5_genuine_fault(base, calibration=None):
    """
    LT-101's transmitter freezes — a real hardware fault, no attacker. The right response
    is a maintenance ticket and taking the value out of the control loop, *not* revoking
    the device's identity.
    """
    site = Site(os.path.join(base, "s5"), calibration=calibration, level=1.3)
    frozen = {}

    def tamper(t, s, v):
        if s == "LT-101" and t >= 100:
            return frozen.setdefault("v", v)
        return v
    site.tamper = tamper
    site.run(600)
    diag = [e for e in site.gw.events if e["kind"] in ("fault_detected", "attack_detected",
                                                     "ambiguous_anomaly")]
    first = diag[0] if diag else None
    ok = (first is not None and first["kind"] == "fault_detected" and first["subject"] == "LT-101"
          and not site.gw.ca.is_revoked(site.dev["LT-101"].cert)
          and not site.gw.trust.is_quarantined("LT-101")
          and site.log[-1]["control_source"] == "gateway-consensus"
          and site.plant.overflow_seconds == 0)
    return {"observed": {"first_diagnosis": first,
                         "detected_after_s": None if first is None else int(first["ts"] - site.t0) - 100,
                         "LT101_revoked": site.gw.ca.is_revoked(site.dev["LT-101"].cert),
                         "LT101_trust": site.gw.trust.score("LT-101"),
                         "control_source_at_end": site.log[-1]["control_source"],
                         "overflow_seconds": site.plant.overflow_seconds,
                         "tickets": site.gw.tickets}, "passed": ok}


def s6_stolen_token(base):
    """Ravi's session token is lifted from console-01 and replayed from console-02."""
    site = Site(os.path.join(base, "s6"))
    site.run(5)
    login = site.login("ravi", console="console-01")
    _, d = site.send_command(login["token"], "pump.force_off", "P-101", console="console-02")
    _, esc = site.send_command(login["token"], "interlock.bypass", "P-101", console="console-01")
    ok = d["effect"] == "deny" and esc["effect"] == "deny"
    return {"observed": {"token_from_other_console": d, "privilege_escalation": esc}, "passed": ok}


def s7_m2m_forgery(base):
    """A forged 'tank is low' message to the pump controller, signed with a key the CA never saw."""
    site = Site(os.path.join(base, "s7"))
    site.run(5)
    from cryptography.hazmat.primitives.asymmetric import ec
    forged = sign_envelope(ec.generate_private_key(ec.SECP256R1()),
                           {"device_id": "LT-101", "nonce": "x" * 32, "ts": site.now, "seq": 10**6,
                            "value": 0.2, "kind": "level"})
    d_forged = site.gw.authorize_m2m(site.dev["LT-101"].cert, forged, "level")
    d_actuator = site.gw.authorize_m2m(site.dev["XV-101"].cert,
                                       site.dev["XV-101"].envelope(value=0.2, kind="level"), "level")
    d_genuine = site.gw.authorize_m2m(site.dev["LT-101"].cert,
                                      site.dev["LT-101"].envelope(value=1.4, kind="level"), "level")
    ok = d_forged["effect"] == "deny" and d_actuator["effect"] == "deny" and d_genuine["effect"] == "allow"
    return {"observed": {"forged_signature": d_forged, "actuator_posing_as_sensor": d_actuator,
                         "genuine_peer": d_genuine}, "passed": ok}


SCENARIOS = [
    ("S1", "Rogue / cloned device", "Device identity, mTLS", s1_rogue_device),
    ("S2", "Stolen key + false data injection", "Anomaly detection, M2M trust, revocation", s2_stolen_key_false_data),
    ("S3", "Fingerprint photo replay on critical command", "Authentication (biometric + liveness)", s3_fingerprint_spoof),
    ("S4", "API request replay", "Secure APIs", s4_api_replay),
    ("S5", "Genuine sensor fault", "Fault vs attack separation", s5_genuine_fault),
    ("S6", "Stolen session token", "Secure access (sender-constrained tokens, least privilege)", s6_stolen_token),
    ("S7", "Forged M2M interlock", "Machine-to-machine trust", s7_m2m_forgery),
]


def load_calibration(path="results/calibration.pkl"):
    if os.path.exists(path):
        import pickle
        with open(path, "rb") as f:
            return pickle.load(f)
    return None


def run_all(base=None, calibration=None):
    base = base or tempfile.mkdtemp(prefix="sensetrust-")
    results = []
    for sid, name, keywords, fn in SCENARIOS:
        kw = {"calibration": calibration} if fn in (s2_stolen_key_false_data, s5_genuine_fault) else {}
        r = fn(base, **kw)
        results.append({"id": sid, "name": name, "ps13": keywords, **r})
    return results


def main():
    cal = load_calibration()
    results = run_all(calibration=cal)
    os.makedirs("results", exist_ok=True)
    with open("results/scenarios.json", "w") as f:
        json.dump([{k: v for k, v in r.items() if not k.startswith("_")} for r in results],
                  f, indent=2, default=str)
    width = max(len(r["name"]) for r in results)
    for r in results:
        print("%s  %-*s  %s   [%s]" % (r["id"], width, r["name"], "PASS" if r["passed"] else "FAIL", r["ps13"]))
    s2 = next(r for r in results if r["id"] == "S2")["observed"]
    print("\nS2 physical impact: baseline overflow %ds (peak %.2f m, rim at %.1f m)  vs  zero-trust %ds (peak %.2f m)"
          % (s2["baseline"]["overflow_seconds"], s2["baseline"]["max_true_level_m"], OVERFLOW,
             s2["zero_trust"]["overflow_seconds"], s2["zero_trust"]["max_true_level_m"]))
    sys.exit(0 if all(r["passed"] for r in results) else 1)


if __name__ == "__main__":
    main()
