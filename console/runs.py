"""
Self-contained runs the console starts on request: a pilot (OPC UA shadow mode) session,
a MOBI-GUARD drive, and the scripted scenarios. Each uses its own gateway, separate from the
live plant, and returns plain JSON-ready data.
"""

import asyncio
import json
import os
import socket
import tempfile

from sensetrust import scenarios

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EPOCH = 1_760_000_000.0


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ── Pilot: OPC UA shadow mode ───────────────────────────────────────────────

PILOT_CASES = {
    "normal": "A normal shift",
    "attack": "LT-101 is compromised behind the PLC and reports a third of the real level",
    "fault": "LT-101's transmitter freezes",
}


def pilot(case="attack", seconds=300):
    try:
        from asyncua import Client
    except ImportError:
        return {"error": "OPC UA support is not installed: pip install -r requirements.txt"}
    from sensetrust.gateway import Gateway
    from sensetrust.opcua import OpcUaShadowMonitor, PlantOpcUaServer, SimulatedPlc

    port, base, start, tick = _free_port(), tempfile.mkdtemp(prefix="sensetrust-pilot-"), 120, {"t": 0}

    async def run():
        gw = Gateway(os.path.join(base, "gw"), clock=lambda: EPOCH + tick["t"])
        server = await PlantOpcUaServer(gw.ca, os.path.join(base, "plc"), port=port).start()
        series, detected = [], None
        try:
            eps = await Client(server.url).connect_and_get_server_endpoints()
            plc = SimulatedPlc(server)
            mon = await OpcUaShadowMonitor(gw, server.url).connect()
            try:
                for _ in range(seconds):
                    if plc.t == start and case == "attack":
                        plc.tamper = lambda t, s, v: v * 0.35 if s == "LT-101" and t > start else v
                    if plc.t == start and case == "fault":
                        frozen = {}
                        plc.tamper = (lambda t, s, v: frozen.setdefault("v", v)
                                      if s == "LT-101" and t > start else v)
                    reported = await plc.step()
                    tick["t"] = plc.t
                    if await mon.poll() and detected is None:
                        detected = plc.t - start
                    series.append([plc.t, round(plc.plant.h, 3), round(reported["LT-101"], 3)])
            finally:
                await mon.disconnect()
            return {
                "case": case, "seconds": seconds, "change_at": start if case != "normal" else None,
                "endpoint": "%s, %s" % (eps[0].SecurityPolicyUri.split("#")[-1],
                                        eps[0].SecurityMode.name),
                "values_read": mon.ticks * 5, "series": series, "detected_after": detected,
                "alerts": [{"t": int(ev["ts"] - EPOCH), "sensor": ev["subject"],
                            "kind": ev["kind"].replace("_", " "), "detail": ev["detail"]}
                           for ev in gw.events if ev.get("shadow")],
                "revoked": sorted(gw.trust.quarantined()),
                "overflow_s": plc.plant.overflow_seconds,
            }
        finally:
            await server.stop()
            gw.close()

    return asyncio.run(run())


# ── Mobility: MOBI-GUARD drive ──────────────────────────────────────────────

def mobility(with_copy=True):
    from sensetrust import mobility as mob
    if not mob.available():
        return {"error": "MOBI-GUARD dependencies are not installed: pip install -r requirements.txt"}
    from sensetrust.devices import DeviceIdentity
    from sensetrust.gateway import Gateway
    clock = {"t": EPOCH}
    gw = Gateway(tempfile.mkdtemp(prefix="sensetrust-mob-"), clock=lambda: clock["t"])
    truck = DeviceIdentity.commission(gw.ca, "TRK-07", "vehicle", lambda: clock["t"])
    drive, other = mob.trajectory("highway_exit", seed=7), mob.trajectory("urban_grid", seed=11)
    real, copies, advice, alarm_t, revoked_t = [], [], {}, None, None
    for k, r in enumerate(drive):
        clock["t"] = EPOCH + r["timestamp"]
        d = gw.mobility_report(truck.cert, truck.envelope(radio=r))
        m = d.get("mobility") or {}
        if m:
            advice[m["advice"]["action"]] = advice.get(m["advice"]["action"], 0) + 1
        pred = m.get("prediction") or {}
        real.append({"t": k, "x": round(r["x"]), "y": round(r["y"]), "cell": r["current_cell"],
                     "next": pred.get("next_cell"), "conf": pred.get("confidence"),
                     "advice": (m.get("advice") or {}).get("action"), "effect": d["effect"]})
        if with_copy and k >= 70 and k % 5 == 0 and k < len(other):
            f = dict(other[k], timestamp=r["timestamp"] + 0.5)
            d = gw.mobility_report(truck.cert, truck.envelope(radio=f))
            copies.append({"t": k, "x": round(f["x"]), "y": round(f["y"]), "cell": f["current_cell"],
                           "verdict": (d.get("mobility") or {}).get("verdict"), "effect": d["effect"]})
        if alarm_t is None and any(e["kind"] == "impossible_movement" for e in gw.events):
            alarm_t = k
        if revoked_t is None and gw.trust.is_quarantined("TRK-07"):
            revoked_t = k
    cells = [{"id": cid, "x": c.x, "y": c.y} for cid, c in mob._cache["network"].cells.items()]
    events = [{"kind": e["kind"].replace("_", " "), "detail": e["detail"]} for e in gw.events
              if e["kind"] in ("impossible_movement", "quarantine")]
    out = {"cells": cells, "real": real, "copies": copies, "advice": advice, "alarm_t": alarm_t,
           "revoked_t": revoked_t, "events": events, "with_copy": with_copy,
           "handovers_prepared": advice.get("PROACTIVE_CANDIDATE", 0) + advice.get("RE_EVALUATING", 0)}
    gw.close()
    return out


# ── Scripted scenarios and the measured evaluation ──────────────────────────

def scenario_list():
    out = []
    for sid, name, keywords, fn in scenarios.SCENARIOS:
        out.append({"id": sid, "name": name, "ps13": keywords,
                    "story": " ".join((fn.__doc__ or "").split())})
    return out


def scenario(sid):
    cal = scenarios.load_calibration(os.path.join(ROOT, "results", "calibration.pkl"))
    for s, name, keywords, fn in scenarios.SCENARIOS:
        if s == sid:
            kw = ({"calibration": cal} if fn in (scenarios.s2_stolen_key_false_data,
                                                 scenarios.s5_genuine_fault) else {})
            r = fn(tempfile.mkdtemp(prefix="sensetrust-sc-"), **kw)
            res = {"id": sid, "name": name, "passed": r["passed"],
                   "observed": json.loads(json.dumps(r["observed"], default=str))}
            if sid == "S2" and "_log" in r:
                res["series"] = [[x["t"], round(x["true_level"], 3), round(x["reported_level"], 3),
                                  round(x["control_level"], 3)] for x in r["_log"]]
            return res
    return {"error": "unknown scenario %s" % sid}


def evaluation():
    path = os.path.join(ROOT, "results", "metrics.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        d = json.load(f)["detector"]
    return {"attacks_detected": d["summary"]["attack"]["detection_rate"],
            "faults_detected": d["summary"]["fault"]["detection_rate"],
            "fault_called_attack": d["summary"]["fault_wrongly_called_attack_rate"],
            "false_alarms_per_hour": d["normal"]["false_alarms_per_hour"]}
