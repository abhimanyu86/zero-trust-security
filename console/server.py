"""
SenseTrust operator console (prototype): a web app over the real gateway.

    python -m console.server            # http://localhost:8501

The live plant (console/engine.py) runs in a background thread at 6x real time. The page
(console/static/) polls /api/state once a second and sends operator actions back; every
action that changes the plant is a fingerprint-backed, signed command decided by the same
gateway policy as everything else.
"""

import argparse
import contextlib
import os
import threading
import time

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from sensetrust.plant import H_MAX, OVERFLOW, SENSORS

from . import runs
from .engine import (CONSOLE, SEVERITY, TRANSPORT, LivePlant, describe, device_state, status)

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
NOISY = ("telemetry_denied", "m2m_denied", "mobility_denied")

_lock = threading.RLock()
_state = {"plant": None}


@contextlib.asynccontextmanager
async def _lifespan(app):
    plant()
    threading.Thread(target=_ticker, daemon=True).start()
    yield


app = FastAPI(title="SenseTrust console", docs_url=None, redoc_url=None, lifespan=_lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


def plant():
    with _lock:
        if _state["plant"] is None:
            _state["plant"] = LivePlant()
        return _state["plant"]


def _ticker():
    while True:
        try:
            with _lock:
                if _state["plant"] is not None:
                    _state["plant"].advance()
        except Exception:                       # never let the clock thread die
            pass
        time.sleep(0.2)


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


# ── live state ───────────────────────────────────────────────────────────────

def _snapshot(p):
    gw = p.gw
    last = p.site.log[-1]
    level, head, text = status(p)
    incidents = []
    for inc in p.incidents():
        title, what, did, todo = describe(inc, p)
        incidents.append({
            "id": inc["id"], "type": inc["type"], "subject": inc["subject"],
            "severity": SEVERITY.get(inc["type"], "warning"), "title": title, "what": what,
            "did": did, "todo": todo, "status": inc["status"], "first": inc["first"],
            "last": inc["last"], "count": inc["count"], "device_state": inc.get("device_state"),
            "events": inc["events"]})
    devices = []
    for r in p.device_rows():
        devices.append({"id": r["Device"], "role": r["Role"], "status": r["Status"],
                        "trust": r["Trust"], "link": r["Link"], "sim": r["5G SIM"],
                        "slice": r["5G slice"], "serial": r["Certificate"],
                        "expires": r["Expires in"], "state": device_state(p, r["Device"])})
    activity = [{"t": t, "who": "you", "text": text} for t, text in p.notes[-20:]]
    for e in gw.events[-60:]:
        if e["kind"] in NOISY:
            continue
        activity.append({"t": int(e["ts"] - p.site.t0), "who": "gateway",
                         "text": "%s: %s" % (e["subject"], e["detail"]), "severity": e["severity"]})
    activity.sort(key=lambda a: a["t"], reverse=True)
    links = {}
    for d in list(SENSORS) + [CONSOLE, "rogue"]:
        links[d] = {"allow": p.by_device[(d, "allow")], "deny": p.by_device[(d, "deny")],
                    "state": device_state(p, d) if d != "rogue" else "rogue"}
    return {
        "t": p.t, "running": p.running,
        "status": {"level": level, "head": head, "text": text},
        "metrics": {"checked": p.checked(), "refused": p.denied(),
                    "open": sum(1 for i in incidents if i["status"] != "resolved"),
                    "overflow_s": p.site.plant.overflow_seconds},
        "plant": {"true": last["true_level"], "reported": last["reported_level"],
                  "control": last["control_level"], "source": last["control_source"],
                  "pump": bool(last["pump"]), "valve": last["valve"], "rim": OVERFLOW,
                  "hmax": H_MAX},
        "series": [[r["t"], round(r["true_level"], 3),
                    None if r["reported_level"] is None else round(r["reported_level"], 3),
                    None if r["control_level"] is None else round(r["control_level"], 3)]
                   for r in p.site.log[-300:]],
        "links": links, "transport": TRANSPORT, "devices": devices, "incidents": incidents,
        "activity": activity[:16],
        "last_action": ({"ok": p.last_action[0], "message": p.last_action[1],
                         "fingerprint": p.last_fingerprint} if p.last_action else None),
    }


@app.get("/api/state")
def state():
    with _lock:
        return _snapshot(plant())


# ── what the attacker or the plant does ──────────────────────────────────────

ATTACKS = {
    "false_data": lambda p, a: p.inject_false_data(a.get("target", "LT-101")),
    "fault": lambda p, a: p.inject_fault(a.get("target", "LT-101")),
    "rogue": lambda p, a: p.rogue_device(),
    "spoof": lambda p, a: p.spoof_login(),
    "impostor": lambda p, a: p.impostor_login(),
    "token": lambda p, a: p.stolen_token(),
}


@app.post("/api/simulate/{name}")
def simulate(name: str, args: dict = Body(default={})):
    if name not in ATTACKS:
        raise HTTPException(404, "unknown event")
    with _lock:
        p = plant()
        ATTACKS[name](p, args)
        return {"ok": True, "note": p.notes[-1][1] if p.notes else ""}


# ── what the operator does ───────────────────────────────────────────────────

@app.post("/api/action")
def action(args: dict = Body(...)):
    name, target = args.get("action"), args.get("target")
    with _lock:
        p = plant()
        p.last_action = None
        if name == "reinstate":
            p.reinstate(target)
        elif name == "revoke":
            p.revoke(target)
        elif name == "close_maintenance":
            p.close_maintenance(target)
        elif name == "technician_reenrol":
            p.technician_reenrol(target)
        elif name == "commission":
            ident = (target or "").strip().upper()
            if not ident or len(ident) > 24:
                raise HTTPException(400, "give the device an ID of up to 24 characters")
            p.commission(ident, args.get("role", "sensor"))
        elif name in ("acknowledge", "resolve"):
            p.incident_status[target] = "acknowledged" if name == "acknowledge" else "resolved"
            return {"ok": True}
        else:
            raise HTTPException(404, "unknown action")
        ok, msg = p.last_action or (False, "nothing happened")
        return {"ok": ok, "message": msg, "fingerprint": p.last_fingerprint}


@app.post("/api/plant")
def plant_control(args: dict = Body(...)):
    with _lock:
        if args.get("reset"):
            _state["plant"] = LivePlant()
        elif "running" in args:
            plant().running = bool(args["running"])
        return {"ok": True}


# ── self-contained runs ──────────────────────────────────────────────────────

@app.post("/api/pilot")
def pilot(args: dict = Body(default={})):
    case = args.get("case", "attack")
    if case not in runs.PILOT_CASES:
        raise HTTPException(400, "unknown case")
    return runs.pilot(case, max(180, min(600, int(args.get("seconds", 300)))))


@app.post("/api/mobility")
def mobility(args: dict = Body(default={})):
    return runs.mobility(bool(args.get("copy", True)))


@app.get("/api/scenarios")
def scenarios():
    return {"scenarios": runs.scenario_list(), "evaluation": runs.evaluation()}


@app.post("/api/scenarios/{sid}")
def run_scenario(sid: str):
    r = runs.scenario(sid)
    if "error" in r:
        raise HTTPException(404, r["error"])
    return JSONResponse(r)


def main():
    import uvicorn
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8501)
    a = ap.parse_args()
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
