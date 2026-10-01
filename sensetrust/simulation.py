"""
Episode runner: the plant, its instruments, an optional injected fault or attack, and
the detector watching it — shared by calibration, evaluation, the scripted demo and the
dashboard so they all exercise exactly the same code.

Injections
----------
Faults (failing hardware):
    stuck          value freezes at its last reading
    dropout        transmitter stops reporting
    noise_burst    loose connector / EMI: noise jumps to ~8 sigma
    out_of_range   4-20 mA loop break: reading pinned outside the physical range
    drift          calibration drift: slow, smooth bias growth

Attacks (a compromised device, or an attacker holding a stolen device key):
    fdi_offset     false data injection: plausible values with a fixed bias
    fdi_replay     replays the device's own recorded readings from earlier
    fdi_freeze     reports a steady, realistically noisy value while the process moves
    stealth_ramp   bias grown slowly to stay under the radar

`drift` and `stealth_ramp` are intentionally generated the same way. They are
indistinguishable from the data alone, and the evaluation reports how the detector
handles that rather than pretending the problem does not exist.
"""

import random
from dataclasses import dataclass, field

from .anomaly import RANGE, FaultAttackDetector
from .plant import NOISE, SENSORS, KPA_PER_M, LevelController, WaterPlant

FAULTS = ("stuck", "dropout", "noise_burst", "out_of_range", "drift")
ATTACKS = ("fdi_offset", "fdi_replay", "fdi_freeze", "stealth_ramp")
OFFSET_SIGMA = {"LT-101": (20, 100), "PT-101": (20, 100), "FT-101": (8, 15)}


@dataclass
class Injection:
    sensor: str
    kind: str
    start: int
    params: dict = field(default_factory=dict)

    @property
    def truth(self):
        return "fault" if self.kind in FAULTS else "attack"


def make_injection(kind, sensor, start, rng):
    s = NOISE[sensor]
    sign = rng.choice((-1, 1))
    if sensor == "LT-101" and kind in ("fdi_offset", "stealth_ramp"):
        sign = -1          # the attack that matters: hide a rising tank
    params = {}
    if kind in ("drift", "stealth_ramp"):
        params["rate"] = sign * rng.uniform(0.05, 0.15) * s
    elif kind == "fdi_offset":
        # Plausible, in-range lies: an attacker who reports impossible values is caught
        # by a range check and gains nothing.
        lo, hi = OFFSET_SIGMA[sensor]
        params["offset"] = sign * rng.uniform(lo, hi) * s
    elif kind == "noise_burst":
        params["sigma"] = 8 * s
    return Injection(sensor, kind, start, params)


def apply_injection(inj, t, true_value, frozen, recorded, rng):
    if t < inj.start:
        return true_value
    k, s = inj.kind, NOISE[inj.sensor]
    dt = t - inj.start
    if k == "stuck":
        return frozen
    if k == "dropout":
        return None
    if k == "noise_burst":
        return true_value + rng.gauss(0, inj.params["sigma"])
    if k == "out_of_range":
        return RANGE[inj.sensor][0] - 1.0
    if k in ("drift", "stealth_ramp"):
        return true_value + inj.params["rate"] * dt
    if k == "fdi_offset":
        return true_value + inj.params["offset"]
    if k == "fdi_replay":
        return recorded[dt % len(recorded)]
    if k == "fdi_freeze":
        return frozen + rng.gauss(0, s)
    raise ValueError(k)


@dataclass
class EpisodeResult:
    seed: int
    injection: Injection | None
    records: list
    diagnoses: list
    overflow_seconds: int
    detector: FaultAttackDetector

    def first_diagnosis(self):
        return self.diagnoses[0] if self.diagnoses else None


def run_episode(seed, duration=900, injection=None, calibration=None, respond=True,
                on_step=None):
    """
    Simulate one episode. With `respond`, a confirmed attack on LT-101 switches the level
    controller to the detector's consensus level (the zero-trust response: stop trusting
    the compromised identity, keep the plant safe on the remaining evidence).
    """
    rng = random.Random(seed)
    plant = WaterPlant(level=rng.uniform(1.1, 1.9), valve=rng.uniform(0.4, 0.8), seed=seed)
    ctrl = LevelController()
    det = FaultAttackDetector(calibration)
    next_valve_change = rng.randint(100, 250)
    history = {s: [] for s in SENSORS}
    frozen = {}
    records, diagnoses = [], []
    quarantined_level = False

    for t in range(1, duration + 1):
        if t == next_valve_change:
            plant.valve = round(rng.uniform(0.35, 0.8), 2)
            next_valve_change = t + rng.randint(100, 250)
        true = plant.true_readings()
        reported = dict(true)
        if injection and injection.sensor in true:
            s = injection.sensor
            if t == injection.start:
                frozen[s] = history[s][-1] if history[s] else true[s]
            recorded = history[s][-300:] if len(history[s]) >= 30 else [true[s]]
            if t >= injection.start and "rec" not in frozen:
                frozen["rec"] = list(recorded)
            reported[s] = apply_injection(injection, t, true[s], frozen.get(s),
                                          frozen.get("rec", recorded), rng)
        for s in SENSORS:
            history[s].append(true[s])

        new = det.update(reported, plant.pump, plant.valve)
        for d in new:
            diagnoses.append(d)
            if d.sensor == "LT-101" and d.verdict == "attack":
                quarantined_level = True

        if quarantined_level and respond:
            safe = [x for x in (det.L3, None if reported["PT-101"] is None else reported["PT-101"] / KPA_PER_M)
                    if x is not None]
            level_for_control = sum(safe) / len(safe)
        else:
            level_for_control = reported["LT-101"]
        plant.pump = ctrl.update(level_for_control)

        rec = {"t": t, "true_level": plant.h, "pump": plant.pump, "valve": plant.valve,
               **{"rep_" + s: reported[s] for s in SENSORS}}
        records.append(rec)
        if on_step:
            on_step(t, rec, new)
        plant.step()

    return EpisodeResult(seed, injection, records, diagnoses, plant.overflow_seconds, det)


def normal_training_runs(n=40, duration=900, seed0=10_000):
    """Normal-operation episodes as (readings, pump, valve) sequences, for calibrate()."""
    runs = []
    for i in range(n):
        res = run_episode(seed0 + i, duration=duration, injection=None, calibration=None)
        runs.append([({s: r["rep_" + s] for s in SENSORS}, r["pump"], r["valve"]) for r in res.records])
    return runs
