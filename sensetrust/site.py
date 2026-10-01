"""
A complete simulated site: plant + instruments + level controller + gateway + consoles.

Each simulated second:
  1. every sensor signs its reading and sends it to the gateway (telemetry)
  2. LT-101 also sends its level straight to the pump controller P-101 (M2M); P-101
     asks the gateway's trust service whether to believe it, and falls back to the
     gateway's physics-consistent level if not
  3. the gateway runs the fault-vs-attack check over the second's accepted telemetry
  4. the plant advances one second

`tamper` lets a scenario play attacker: it receives (t, sensor, true_value) and returns
the value the compromised device should report instead (or the true value).
"""

import os
import time

from .devices import DeviceIdentity
from .gateway import Gateway
from .plant import SENSORS, LevelController, WaterPlant
from .synthetic import make_template, ridge_image

DEVICES = {"LT-101": "sensor", "PT-101": "sensor", "FT-101": "sensor",
           "P-101": "actuator", "XV-101": "actuator",
           "console-01": "console", "console-02": "console"}

OPERATORS = {
    "asha": {"role": "shift_supervisor", "scopes": ["actuate", "override", "admin"], "seed": 7},
    "ravi": {"role": "operator", "scopes": ["actuate"], "seed": 11},
}


class Site:

    def __init__(self, data_dir, calibration=None, seed=1, level=1.4, valve=0.6, zero_trust=True):
        self.now = self.t0 = 1_760_000_000.0
        self.clock = lambda: self.now
        self.gw = Gateway(data_dir, calibration=calibration, clock=self.clock)
        for ident, role in DEVICES.items():
            self.gw.ca.issue(ident, role)
        self.gw.ca.issue("gateway", "gateway", hostnames=("localhost", "127.0.0.1"))
        self.dev = {i: DeviceIdentity.load(self.gw.ca, i, self.clock) for i in DEVICES}
        for op, spec in OPERATORS.items():
            self.gw.operators.enroll(op, spec["role"], self.finger(op), ridge_image(noise=0),
                                     spec["scopes"])
        self.plant = WaterPlant(level=level, valve=valve, seed=seed)
        self.ctrl = LevelController()
        self.zero_trust = zero_trust
        self.tamper = None
        self.log = []

    @staticmethod
    def finger(operator):
        """The operator's enrolled minutiae (synthetic)."""
        return make_template(seed=1000 + OPERATORS[operator]["seed"])

    def step(self):
        self.now += 1
        t = self.plant.t + 1
        true = self.plant.true_readings()
        reported = dict(true)
        if self.tamper:
            for s in SENSORS:
                reported[s] = self.tamper(t, s, true[s])

        decisions = {}
        for s in SENSORS:
            if reported[s] is None:
                continue
            decisions[s] = self.gw.telemetry(self.dev[s].cert, self.dev[s].envelope(value=reported[s]))

        # M2M: LT-101 -> P-101 level feed, vetted by the trust service.
        level_msg = self.dev["LT-101"].envelope(value=reported["LT-101"], kind="level")
        m2m = self.gw.authorize_m2m(self.dev["LT-101"].cert, level_msg, "level")
        if not self.zero_trust or m2m["effect"] == "allow":
            level_for_control = reported["LT-101"]
            source = "LT-101"
        else:
            level_for_control = self.gw.safe_level()
            source = "gateway-consensus"

        diagnoses = self.gw.process_tick(self.plant.pump, self.plant.valve)
        self.ctrl.update(level_for_control)
        self.plant.pump = self.ctrl.pump
        self.log.append({"t": t, "true_level": self.plant.h, "reported_level": reported["LT-101"],
                         "control_level": level_for_control, "control_source": source,
                         "pump": self.plant.pump, "valve": self.plant.valve,
                         "trust_LT": self.gw.trust.score("LT-101"),
                         "trust_PT": self.gw.trust.score("PT-101"),
                         "trust_FT": self.gw.trust.score("FT-101"),
                         "denied": [s for s, d in decisions.items() if d["effect"] != "allow"]})
        self.plant.step()
        return diagnoses

    def run(self, seconds):
        for _ in range(seconds):
            self.step()

    def login(self, operator, console="console-01", minutiae=None, image=None):
        minutiae = minutiae if minutiae is not None else self.finger(operator)
        image = image if image is not None else ridge_image(noise=0)
        return self.gw.operator_login(self.dev[console].cert, operator, minutiae, image)

    def send_command(self, token, action, target, console="console-01", **params):
        env = self.dev[console].command(action, target, **params)
        return env, self.gw.command(self.dev[console].cert, token, env)


def new_site(base_dir, name, **kw):
    d = os.path.join(base_dir, name + "-" + str(int(time.time() * 1000)))
    return Site(d, **kw)
