"""
A small water-treatment plant, simulated with real (if simple) physics.

One storage tank fed by a pump and drained through a valve:

    A * dh/dt = pump * Q_PUMP  -  valve * CV * sqrt(h)

Instrumented the way a real skid is:

    LT-101  level transmitter      h + noise                         [m]
    PT-101  pressure transmitter   rho*g*h (hydrostatic) + noise     [kPa]
    FT-101  outlet flow meter      valve * CV * sqrt(h) + noise      [m3/s]
    P-101   feed pump              on/off, commanded by the level controller
    XV-101  outlet valve           position 0..1, commanded by operators

The level controller runs the pump on hysteresis (on below LOW, off above HIGH) using
the level it is *told* by LT-101 — exactly the dependency a false-data-injection attack
exploits: convince the controller the tank is low and it overfills it.

The three instruments measure physically related quantities, which is the analytical
redundancy the anomaly detector uses: level and pressure must agree through hydrostatics,
and level must change the way pump inflow minus metered outflow says it should.
"""

import math
import random

AREA = 2.0            # tank cross-section, m2
Q_PUMP = 0.03         # pump delivery, m3/s
CV = 0.01             # valve coefficient, m3/s per sqrt(m)
KPA_PER_M = 9.81      # hydrostatic pressure per metre of water (rho*g/1000)
H_MAX = 3.2           # tank rim; above OVERFLOW the tank is spilling
OVERFLOW = 3.0
LOW, HIGH = 1.0, 2.0  # level controller hysteresis band

NOISE = {"LT-101": 0.005, "PT-101": 0.05, "FT-101": 0.0003}
SENSORS = ("LT-101", "PT-101", "FT-101")
UNITS = {"LT-101": "m", "PT-101": "kPa", "FT-101": "m3/s"}


class WaterPlant:
    """Ground-truth process. `step` advances one second."""

    def __init__(self, level=1.5, valve=0.6, seed=0):
        self.h = level
        self.valve = valve
        self.pump = 0
        self.t = 0
        self.rng = random.Random(seed)
        self.overflow_seconds = 0

    def outflow(self):
        return self.valve * CV * math.sqrt(max(self.h, 0.0))

    def step(self, dt=1.0):
        inflow = self.pump * Q_PUMP
        self.h += (inflow - self.outflow()) * dt / AREA
        self.h = min(max(self.h, 0.0), H_MAX)
        if self.h >= OVERFLOW:
            self.overflow_seconds += 1
        self.t += 1

    def true_readings(self):
        """What perfectly honest, healthy instruments would report (with noise)."""
        g = self.rng.gauss
        return {
            "LT-101": self.h + g(0, NOISE["LT-101"]),
            "PT-101": KPA_PER_M * self.h + g(0, NOISE["PT-101"]),
            "FT-101": self.outflow() + g(0, NOISE["FT-101"]),
        }


class LevelController:
    """P-101's controller: hysteresis on the level it receives over M2M messages."""

    def __init__(self):
        self.pump = 0

    def update(self, reported_level):
        if reported_level is None:
            return self.pump          # hold last state on missing data
        if reported_level < LOW:
            self.pump = 1
        elif reported_level > HIGH:
            self.pump = 0
        return self.pump
