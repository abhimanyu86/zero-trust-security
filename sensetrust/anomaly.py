"""
Anomaly detection that separates a *physical fault* from a *cyber-attack*.

Most industrial anomaly detectors answer one question: "is something wrong?" The
operator then has to decide whether to send a technician or an incident responder. This
detector answers the second question too, because the response is completely different:
a stuck transmitter needs maintenance; a transmitter lying on purpose needs its identity
revoked *now*.

How it works
------------
1. Analytical redundancy. The plant's three instruments measure physically linked
   quantities, so each one can be predicted from the others:

       L1 = LT-101 level
       L2 = PT-101 pressure / (rho*g)          hydrostatics
       L3 = observer integrating pump inflow - FT-101 outflow (mass balance),
            re-anchored to L1/L2 only while those two agree

   Each sensor gets a residual — its reading minus what the other instruments imply —
   expressed in units of its own noise sigma. Thresholds are calibrated from normal
   operation (see `calibrate`), not hand-tuned.

2. Isolation. When residuals persist above threshold, the sensor with the largest
   normalised residual is the suspect (structured-residual isolation: an error in one
   instrument shows up fully in its own residual and only half as much in the others').

3. Fault vs attack. The suspect's own signal is then examined:
      - missing samples, out-of-range values, a frozen value, or a noise burst are the
        signatures of failing hardware                                 -> FAULT
      - security evidence on the device's channel (bad signature, replay,
        rate abuse) around the same time                                -> ATTACK
      - a signal that still *looks* healthy (in range, normal noise) but
        disagrees with the physics — by a sudden step, or by diverging
        faster than hardware drifts                                     -> ATTACK
      - a slow, smooth divergence                                       -> AMBIGUOUS
   The last case is reported honestly as ambiguous: calibration drift and a patient,
   stealthy ramp attack are indistinguishable from the data alone. The response for it
   is maintenance plus heightened monitoring, not automatic revocation.

4. An IsolationForest trained on normal residual vectors runs alongside as a
   model-free backstop for anomaly patterns the residual rules were not written for.
"""

import math
from collections import deque
from dataclasses import dataclass, field

import numpy as np

from .plant import AREA, CV, KPA_PER_M, NOISE, Q_PUMP, SENSORS

WINDOW = 5            # smoothing window for residuals, samples
PERSIST = 3           # consecutive over-threshold samples before an alarm
OBSERVER_GAIN = 0.02  # L3 re-anchoring rate while L1 and L2 agree
AGREE_SIGMA = 4.0     # L1/L2 "agree" if within this many level-sigmas
STEP_SIGMA = 15.0     # a single-sample residual jump this large is a step, not noise
RAMP_SIGMA_PER_S = 0.3  # divergence slower than this is drift-like
MISSING_PERSIST = 3
RANGE = {"LT-101": (-0.05, 3.5), "PT-101": (-0.5, 34.0), "FT-101": (-0.002, 0.05)}
CHANNEL_MEMORY_S = 60
IFOREST_EVERY = 10      # the forest is a backstop; scoring it every second is not needed

DEFAULT_THRESHOLDS = {"LT-101": 6.0, "PT-101": 6.0, "FT-101": 6.0}


@dataclass
class Diagnosis:
    t: int
    sensor: str
    verdict: str            # "fault" | "attack" | "ambiguous"
    kind: str
    detected_by: str        # "residual" | "isolation_forest" | "range" | "missing"
    evidence: dict = field(default_factory=dict)

    def as_dict(self):
        return {"t": self.t, "sensor": self.sensor, "verdict": self.verdict,
                "kind": self.kind, "detected_by": self.detected_by, "evidence": self.evidence}


def _level_sigma():
    return NOISE["LT-101"]


class FaultAttackDetector:

    def __init__(self, calibration=None):
        calibration = calibration or {}
        self.thr = dict(DEFAULT_THRESHOLDS, **calibration.get("thresholds", {}))
        self._iforest = calibration.get("iforest")
        self._if_thr = calibration.get("iforest_threshold")
        self.L3 = None
        self._last_q = None
        self.t = 0
        self.raw = {s: deque(maxlen=40) for s in SENSORS}
        self.dev = {s: deque(maxlen=40) for s in SENSORS}
        self.smooth = {s: deque(maxlen=WINDOW) for s in SENSORS}
        self.over = {s: 0 for s in SENSORS}
        self.missing = {s: 0 for s in SENSORS}
        self.out_of_range = {s: 0 for s in SENSORS}
        self.if_over = 0
        self.channel_events = deque()
        self.alarmed = {}           # sensor -> Diagnosis (latched)
        self.history = []           # per-step residual record, for plots

    # ── inputs ───────────────────────────────────────────────────────────────

    def note_channel_event(self, device, reason):
        """Security evidence from the gateway: bad signature, replay, rate abuse..."""
        self.channel_events.append((self.t, device, reason))

    def update(self, readings, pump, valve):
        """Feed one second of data. Returns a list of *new* Diagnosis objects."""
        self.t += 1
        new = []
        while self.channel_events and self.channel_events[0][0] < self.t - CHANNEL_MEMORY_S:
            self.channel_events.popleft()

        for s in SENSORS:
            v = readings.get(s)
            ok = v is not None and not (isinstance(v, float) and math.isnan(v))
            self.missing[s] = 0 if ok else self.missing[s] + 1
            if ok:
                lo, hi = RANGE[s]
                self.out_of_range[s] = self.out_of_range[s] + 1 if not (lo <= v <= hi) else 0
            self.raw[s].append(v if ok else None)
            if s not in self.alarmed:
                if self.missing[s] >= MISSING_PERSIST:
                    new.append(self._raise(s, "fault", "dropout", "missing",
                                           {"missing_samples": self.missing[s]}))
                elif self.out_of_range[s] >= 2:
                    new.append(self._raise(s, "fault", "out_of_range", "range",
                                           {"value": v, "range": RANGE[s]}))

        L1 = self._usable(readings, "LT-101")
        P = self._usable(readings, "PT-101")
        Q = self._usable(readings, "FT-101")
        L2 = P / KPA_PER_M if P is not None else None

        # Mass-balance observer.
        if self.L3 is None:
            anchors = [x for x in (L1, L2) if x is not None]
            self.L3 = float(np.mean(anchors)) if anchors else 1.5
        # `pump` is the state that drove the last second; pair it with last second's flow.
        if self._last_q is not None:
            self.L3 += (pump * Q_PUMP - self._last_q) / AREA
        self._last_q = Q if Q is not None else valve * CV * math.sqrt(max(self.L3, 0.0))
        if L1 is not None and L2 is not None and abs(L1 - L2) < AGREE_SIGMA * _level_sigma():
            self.L3 += OBSERVER_GAIN * ((L1 + L2) / 2 - self.L3)

        levels = [x for x in (L1, L2, self.L3) if x is not None]
        Lc = float(np.median(levels))
        dev = {
            "LT-101": None if L1 is None or L2 is None else
            (L1 - (L2 + self.L3) / 2) / NOISE["LT-101"],
            "PT-101": None if L1 is None or P is None else
            (P - KPA_PER_M * (L1 + self.L3) / 2) / NOISE["PT-101"],
            "FT-101": None if Q is None else
            (Q - valve * CV * math.sqrt(max(Lc, 0.0))) / NOISE["FT-101"],
        }
        score = {}
        for s in SENSORS:
            self.dev[s].append(dev[s])
            if dev[s] is not None:
                self.smooth[s].append(dev[s])
            sm = float(np.mean(self.smooth[s])) if self.smooth[s] else 0.0
            score[s] = abs(sm) / self.thr[s]
            self.over[s] = self.over[s] + 1 if score[s] > 1.0 else 0

        self.history.append({"t": self.t, "L1": L1, "L2": L2, "L3": self.L3,
                             **{"z_" + s: dev[s] for s in SENSORS},
                             **{"score_" + s: score[s] for s in SENSORS}})

        persistent = [s for s in SENSORS if self.over[s] >= PERSIST and s not in self.alarmed]
        if persistent:
            suspect = max(persistent, key=lambda s: score[s])
            new.append(self._classify(suspect, "residual", score))
        elif (self._iforest is not None and self.t % IFOREST_EVERY == 0
              and all(d is not None for d in dev.values())):
            feats = np.array([[float(np.mean(self.smooth[s])) for s in SENSORS]])
            if_score = float(self._iforest.score_samples(feats)[0])
            self.if_over = self.if_over + 1 if if_score < self._if_thr else 0
            if self.if_over >= 2:
                suspect = max(SENSORS, key=lambda s: score[s])
                if suspect not in self.alarmed:
                    new.append(self._classify(suspect, "isolation_forest", score))
        return [d for d in new if d is not None]

    # ── classification ───────────────────────────────────────────────────────

    @staticmethod
    def _usable(readings, s):
        v = readings.get(s)
        if v is None or (isinstance(v, float) and math.isnan(v)):
            return None
        lo, hi = RANGE[s]
        return v if lo <= v <= hi else None

    def _raise(self, sensor, verdict, kind, detected_by, evidence):
        d = Diagnosis(self.t, sensor, verdict, kind, detected_by, evidence)
        self.alarmed[sensor] = d
        return d

    def _classify(self, s, detected_by, score):
        sigma = NOISE[s]
        recent = [v for v in list(self.raw[s])[-10:] if v is not None]
        last5 = [v for v in list(self.raw[s])[-5:] if v is not None]
        ev = {"residual_score": round(score[s], 2)}
        channel = [r for (_, dev, r) in self.channel_events if dev == s]
        if len(recent) >= 5:
            std = float(np.std(recent))
            # Robust (MAD-based) spread of sample-to-sample changes: one big step — the
            # signature of injected data — barely moves it, sustained noise does.
            d = np.diff(recent)
            diff_std = 1.4826 * float(np.median(np.abs(d - np.median(d)))) / math.sqrt(2)
            ev.update(signal_std_sigma=round(std / sigma, 2), diff_std_sigma=round(diff_std / sigma, 2))
            if len(last5) == 5 and float(np.std(last5)) < 0.3 * sigma:
                return self._raise(s, "fault", "stuck_value", detected_by, ev)
            if diff_std > 3.0 * sigma:
                return self._raise(s, "fault", "noise_burst", detected_by, ev)
        if channel:
            ev["channel_evidence"] = sorted(set(channel))
            return self._raise(s, "attack", "compromised_channel", detected_by, ev)

        devs = [d for d in list(self.dev[s])[-30:] if d is not None]
        if len(devs) >= 2:
            jump = float(np.max(np.abs(np.diff(devs))))
            ev["max_step_sigma"] = round(jump, 1)
            if jump > STEP_SIGMA:
                return self._raise(s, "attack", "false_data_injection_step", detected_by, ev)
        if len(devs) >= 10:
            slope = float(np.polyfit(np.arange(len(devs)), devs, 1)[0])
            ev["divergence_sigma_per_s"] = round(slope, 3)
            if abs(slope) >= RAMP_SIGMA_PER_S:
                return self._raise(s, "attack", "false_data_injection_divergence", detected_by, ev)
        return self._raise(s, "ambiguous", "slow_drift_or_stealth_ramp", detected_by, ev)


# ── calibration ──────────────────────────────────────────────────────────────

def calibrate(normal_runs, margin=1.25, floor_sigma=6.0, seed=0):
    """
    Thresholds from normal operation only.

    `normal_runs` is a list of episodes; each episode is a list of (readings, pump,
    valve) tuples. Per sensor, the threshold is the larger of `floor_sigma` and
    `margin` x the worst smoothed residual seen in normal operation — i.e. zero false
    alarms on the calibration data by construction; the false-alarm rate on *unseen*
    normal data is what evaluate.py measures.
    """
    from sklearn.ensemble import IsolationForest

    worst = {s: 0.0 for s in SENSORS}
    feats = []
    for run in normal_runs:
        det = FaultAttackDetector()
        for readings, pump, valve in run:
            det.update(readings, pump, valve)
            row = []
            for s in SENSORS:
                sm = float(np.mean(det.smooth[s])) if det.smooth[s] else 0.0
                worst[s] = max(worst[s], abs(sm))
                row.append(sm)
            if det.t > 10:
                feats.append(row)
    thresholds = {s: max(floor_sigma, margin * worst[s]) for s in SENSORS}
    X = np.array(feats)
    forest = IsolationForest(n_estimators=100, contamination="auto", random_state=seed).fit(X)
    scores = forest.score_samples(X)
    return {"thresholds": thresholds, "iforest": forest,
            "iforest_threshold": float(scores.min()) - 0.02,
            "calibration_samples": int(len(X))}
