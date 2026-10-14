"""
MOBI-GUARD inside SenseTrust: mobility intelligence (PS-6) meets device trust (PS-13).

MOBI-GUARD (vendor/mobiguard, unchanged) predicts which cell a moving 5G device will be
served by next, how sure it is, and whether to prepare a handover. SenseTrust uses that in
two directions:

1. Impossible movement -> identity alarm. Every mobility report a device sends is signed
   and checked like any other message. Then two independent questions:
     - MOBI-GUARD: how likely did the last four predictions think this serving cell was?
     - Radio continuity: how far did the whole neighbour-signal picture jump since the
       device's previous report? A real device moves through space, so its signals change
       smoothly; a second device using the same identity somewhere else reports a
       different picture.
   Both together = "impossible movement": the identity is being used in two places, so a
   key or SIM has been cloned. It costs the identity trust like any identity mismatch; a
   repeat revokes it. Either alone is only noted, because a real handover can surprise
   the model and a noisy step can jump the signals.

   Measured on MOBI-GUARD's own held-out test trajectories (thresholds set on its
   training trajectories, see tests/test_mobility.py and README): 0 false alarms in 4,345
   genuine reports including 62 real handovers, 87% of single cloned reports caught.

2. Trust -> handover policy. MOBI-GUARD's advice (prepare a handover to the predicted
   cell, monitor, or hold) is only followed for devices SenseTrust currently trusts. A
   quarantined or low-trust device gets "hold": the network does not reserve resources
   for an identity it does not believe.
"""

import math
import os
import sys
import warnings

VENDOR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "vendor", "mobiguard")

P_IMPOSSIBLE = 0.01          # MOBI-GUARD probability below which a cell was "not expected"
RADIO_JUMP_DB = 6.8          # 99.9th percentile of genuine report-to-report change (training set)
HISTORY = 4                  # MOBI-GUARD predicts 4 s ahead: compare with the last 4 predictions
TRUST_FOR_PROACTIVE = 0.7
LIVE_WINDOW = 6              # a track updated within the last 6 reports is still live


def available():
    try:
        _engine()
        return True
    except Exception:
        return False


_cache = {}


def _engine():
    """Load MOBI-GUARD's trained models once (their packages, their artifacts)."""
    if "engine" not in _cache:
        if VENDOR not in sys.path:
            sys.path.insert(0, VENDOR)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")       # models pickled with an older scikit-learn
            from decision.divergence import RouteDivergenceDetector
            from decision.policy import MobilityPolicyEngine
            from decision.uncertainty import UncertaintyEstimator
            from models.inference import MobilityInferenceEngine
            from models.next_cell_model import NextCellPredictor
            from models.weakness_model import WeaknessPredictor
            from simulator.cells import CellNetwork
            art = os.path.join(VENDOR, "artifacts", "models")
            engine = MobilityInferenceEngine(
                NextCellPredictor.load(os.path.join(art, "next_cell_model.joblib")),
                WeaknessPredictor.load(os.path.join(art, "weakness_model.joblib")))
        _cache["engine"] = engine
        _cache["uncertainty"] = UncertaintyEstimator()
        _cache["network"] = CellNetwork.default_6_cell_network()
        _cache["policy"] = lambda: MobilityPolicyEngine(RouteDivergenceDetector(_cache["network"]))
    return _cache["engine"]


def cells():
    _engine()
    return list(_cache["network"].get_cell_ids())


def _radio(t):
    return [t.get("neighbor_%s_rsrp" % c, -130.0) for c in cells()]


class MobilityTrust:
    """
    Per-identity mobility state. Reports are sorted into signal tracks: a report joins the
    track whose last report it continues smoothly. One real device makes one live track
    (after a gap it may start a new one, and the old one goes quiet). The same identity
    feeding two live tracks at once is two devices, so a cloned key or SIM.
    """

    def __init__(self):
        _engine()
        self._ids = {}

    def _state(self, identity):
        if identity not in self._ids:
            self._ids[identity] = {"history": [], "predictions": [], "policy": _cache["policy"](),
                                   "tracks": [], "primary": None, "n": 0}
        return self._ids[identity]

    @staticmethod
    def _jump(a, b):
        """Signal change between two reports, per neighbour, per root second elapsed."""
        dt = max(1.0, abs(a.get("timestamp", 0.0) - b.get("timestamp", 0.0)))
        rms = math.sqrt(sum((x - y) ** 2 for x, y in zip(_radio(a), _radio(b))) / len(cells()))
        return rms / math.sqrt(dt)

    def check(self, identity, telemetry, trust_score=1.0, quarantined=False):
        """
        Returns {"verdict": consistent | unexpected | impossible, "evidence": {...},
                 "prediction": {...} | None, "advice": {...}} for one signed, verified report.
        """
        st = self._state(identity)
        st["n"] += 1
        n, cell = st["n"], telemetry.get("current_cell")
        judged = bool(telemetry.get("telemetry_quality_ok", True)) and bool(
            telemetry.get("is_rsrp_valid", True))
        evidence = {"cell": cell}
        verdict = "consistent"
        primary = st["primary"]
        if not st["tracks"]:
            track = {"last": telemetry, "count": 1, "seen": n, "born": n}
            st["tracks"].append(track)
            st["primary"] = primary = track
        else:
            jumps = [(self._jump(telemetry, tk["last"]), tk) for tk in st["tracks"]]
            best, track = min(jumps, key=lambda x: x[0])
            p = max((pr.get(cell, 0.0) for pr in st["predictions"]), default=1.0)
            evidence.update({"radio_jump_db": round(best, 1), "p_expected": round(p, 4),
                             "previous_cell": primary["last"].get("current_cell")})
            if best > RADIO_JUMP_DB and judged:
                # Continues no known track: a new one.
                unexpected_cell = cell != primary["last"].get("current_cell") and p < P_IMPOSSIBLE
                live = n - primary["seen"] <= LIVE_WINDOW
                track = {"last": telemetry, "count": 1, "seen": n, "born": n}
                st["tracks"] = [primary, track] if live else [track]
                if live and unexpected_cell:
                    verdict = "impossible"            # a cell MOBI-GUARD ruled out, and a signal break
                    evidence["why"] = "a cell MOBI-GUARD ruled out, reached with a break in the signals"
                else:
                    verdict = "unexpected"
                if not live:
                    st["primary"] = primary = track   # the device reappeared after a gap
            else:
                track["last"], track["count"], track["seen"] = telemetry, track["count"] + 1, n
                other = [tk for tk in st["tracks"] if tk is not track]
                newer = max([track] + other, key=lambda tk: tk["born"])
                older = track if newer is not track else (other[0] if other else track)
                # Two devices: the older track kept reporting after the newer one appeared.
                if other and judged and newer["count"] >= 2 and older["seen"] > newer["born"] and \
                        n - other[0]["seen"] <= LIVE_WINDOW:
                    verdict = "impossible"            # two live signal tracks, one identity
                    evidence["why"] = "two signal tracks reporting at the same time"
                elif other and track is not primary and primary["seen"] < track["born"]:
                    # The old track went quiet when this one began: the same device moved on.
                    st["tracks"], st["primary"] = [track], track
                    primary = track
            if verdict == "impossible":
                evidence["tracks"] = len(st["tracks"])

        if track is not primary or verdict == "impossible":
            # Reports off the device's own track never steer its predictions or its handovers.
            return {"verdict": verdict, "evidence": evidence, "prediction": None,
                    "advice": {"action": "HOLD", "candidate": None,
                               "reason": "report does not continue this device's signal track"}}

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            inf = _engine().run_inference(telemetry, st["history"][-3:])
            unc = _cache["uncertainty"].evaluate(inf["probabilities"])
            decision = st["policy"].evaluate(telemetry, inf, unc, step_index=n)
        st["history"] = (st["history"] + [telemetry])[-6:]
        st["predictions"] = (st["predictions"] + [inf["probabilities"]])[-HISTORY:]

        action, reason = decision.action, decision.reason
        if quarantined or trust_score < TRUST_FOR_PROACTIVE:
            if action not in ("HOLD_RECHECK", "MONITOR_RECHECK"):
                reason = "MOBI-GUARD advised %s; held because the identity is not trusted (%.2f)" % (
                    action, trust_score)
            action = "HOLD"
        prediction = {"next_cell": unc.predicted_cell, "confidence": round(unc.confidence, 3),
                      "uncertainty": unc.uncertainty_level,
                      "weakness_risk": inf["weakness_risk"]}
        return {"verdict": verdict, "evidence": evidence, "prediction": prediction,
                "advice": {"action": action, "candidate": decision.candidate_cell, "reason": reason}}


def trajectory(scenario, seed, ue_id="UE", traj_index=0):
    """A drive generated by MOBI-GUARD's own simulator, as a list of telemetry reports."""
    import yaml
    _engine()
    from simulator.generator import SyntheticDatasetGenerator
    with open(os.path.join(VENDOR, "config", "config.yaml")) as f:
        cfg = yaml.safe_load(f)
    gen = SyntheticDatasetGenerator(cfg)
    df = gen.generate_single_trajectory(scenario, "%s-%d" % (scenario, seed), ue_id, seed,
                                        traj_index=traj_index)
    keep = [c for c in df.columns if c not in ("target_next_cell", "current_weakening_label")]
    return [{k: (v.item() if hasattr(v, "item") else v) for k, v in row.items()}
            for row in df[keep].to_dict("records")]
