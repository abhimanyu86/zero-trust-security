"""The console's pages. Each live page refreshes itself and catches the plant up first."""

import json
import os
import socket
import tempfile

import pandas as pd
import streamlit as st

import ui
from engine import ROOT
from sensetrust import scenarios
from sensetrust.plant import OVERFLOW

REFRESH = 1.0
PAGES = {}                 # filled in by app.py


def engine():
    return st.session_state.engine


# ── Overview ────────────────────────────────────────────────────────────────

def overview():
    st.title("Plant overview")
    _overview_live()


@st.fragment(run_every=REFRESH)
def _overview_live():
    e = engine()
    e.advance()
    ui.status_banner(e)
    open_incidents = [i for i in e.incidents() if i["status"] != "resolved"]
    c = st.columns(5)
    c[0].metric("Plant time", ui.clock(e.t))
    c[1].metric("Messages checked", f"{e.checked():,}")
    c[2].metric("Refused", f"{e.denied():,}")
    c[3].metric("Open incidents", len(open_incidents))
    c[4].metric("Overflow so far", "%d s" % e.site.plant.overflow_seconds)
    st.subheader("Plant and its links")
    _, mid, _ = st.columns([0.06, 1, 0.06])
    with mid:
        ui.plant_map(e)
    st.subheader("Tank level, last 5 minutes")
    ui.level_chart(e, height=280)
    if open_incidents:
        st.subheader("Needs attention")
        for inc in open_incidents[:2]:
            ui.incident_card(inc, e)
        st.page_link(PAGES["incidents"], label="Go to incidents")


# ── Incidents ───────────────────────────────────────────────────────────────

def incidents():
    st.title("Incidents")
    st.caption("Grouped from every decision the gateway made. Actions that change the plant ask "
               "for the supervisor's fingerprint and go to the gateway as signed commands.")
    show_closed = st.toggle("Show resolved", value=False)
    _incidents_live(show_closed)


@st.fragment(run_every=2.0)
def _incidents_live(show_closed):
    e = engine()
    e.advance()
    ui.action_result(e)
    incs = [i for i in e.incidents() if show_closed or i["status"] != "resolved"]
    if not incs:
        st.info("No open incidents. Use the Attack lab to stage one.")
        return
    for inc in incs:
        ui.incident_card(inc, e)
        s, iid = inc["subject"], inc["id"]
        if inc["status"] != "resolved":
            buttons = []
            state = inc.get("device_state")
            if inc["type"] == "attack" and state == "revoked":
                buttons.append(("Approve re-enrolment", "re", e.reinstate, (s,), "primary",
                                "Fingerprint step-up, then a signed device.reinstate command"))
            if inc["type"] == "attack" and state == "awaiting re-enrolment":
                buttons.append(("Technician: enrol new key", "en", e.technician_reenrol, (s,),
                                "primary", "On site: the device generates a new key and enrols"))
            if inc["type"] == "fault" and state == "maintenance":
                buttons.append(("Close maintenance", "mc", e.close_maintenance, (s,), "primary",
                                "Fingerprint, then a signed maintenance.close command"))
            if inc["status"] == "open":
                buttons.append(("Acknowledge", "ack", _set_status, (iid, "acknowledged"),
                                "secondary", None))
            buttons.append(("Resolve", "res", _set_status, (iid, "resolved"), "secondary", None))
            widths = [1.6 if b[4] == "primary" else 0.9 for b in buttons]
            cols = st.columns(widths + [max(0.5, 7 - sum(widths))])
            for col, (label, k, fn, args, kind, tip) in zip(cols, buttons):
                col.button(label, key=k + iid, type=kind, on_click=fn, args=args, help=tip)
        st.write("")


def _set_status(iid, status):
    engine().incident_status[iid] = status


# ── Devices & identity ──────────────────────────────────────────────────────

def devices():
    st.title("Devices and identity")
    st.caption("Every device holds its own key and a 30-day certificate from the plant CA. "
               "On private 5G, its SIM address and network slice must match the certificate.")
    _devices_live()
    st.subheader("Commission a new device")
    with st.form("commission", clear_on_submit=True, border=False):
        c1, c2, c3 = st.columns([2, 2, 1.4])
        ident = c1.text_input("Device ID", placeholder="e.g. TT-201")
        role = c2.selectbox("Role", ["sensor", "actuator", "console"])
        c3.write("")
        if c3.form_submit_button("Issue token and enrol", type="primary") and ident.strip():
            engine().commission(ident.strip(), role)
    st.caption("The admin issues a one-time token that fixes the device ID and role. The device "
               "generates its key, sends a certificate request with the token, and the CA signs it. "
               "The CA never sees the private key.")


@st.fragment(run_every=2.0)
def _devices_live():
    e = engine()
    e.advance()
    ui.action_result(e)
    ca = e.gw.ca
    c = st.columns(4)
    c[0].metric("Plant CA", "ECDSA P-256")
    c[1].metric("Devices", len(e.site.dev))
    c[2].metric("On revocation list", len(ca._revoked))
    c[3].metric("Awaiting re-enrolment", len(e.gw.pending_enrolments))
    df = pd.DataFrame(e.device_rows())
    st.dataframe(df, hide_index=True, use_container_width=True,
                 column_config={"Trust": st.column_config.ProgressColumn(
                     "Trust", min_value=0.0, max_value=1.0, format="%.2f")})
    names = [r["Device"] for r in e.device_rows()]
    c1, c2, c3, c4 = st.columns([2, 1.3, 1.6, 1.8])
    pick = c1.selectbox("Device", names, label_visibility="collapsed", key="dev_pick")
    row = next(r for r in e.device_rows() if r["Device"] == pick)
    if row["Status"] in ("Trusted", "Maintenance"):
        c2.button("Revoke", key="rv", on_click=e.revoke, args=(pick,),
                  help="Lost, stolen or decommissioned. Needs the supervisor's fingerprint.")
    if row["Status"] == "Revoked":
        c3.button("Approve re-enrolment", key="ra", type="primary", on_click=e.reinstate, args=(pick,))
    if row["Status"] == "Awaiting re-enrolment":
        c4.button("Technician: enrol new key", key="te", type="primary",
                  on_click=e.technician_reenrol, args=(pick,))


# ── Pilot (shadow mode) ─────────────────────────────────────────────────────

def pilot():
    st.title("Pilot: shadow mode")
    st.markdown(
        "At a new site SenseTrust starts by **reading only**. It connects to the plant's own "
        "PLC over OPC UA (encrypted, certificate-checked, read-only), runs the physics check, "
        "and raises alerts. It never blocks or writes anything. This is how a plant gets "
        "evidence before it lets us protect it.")
    try:
        import asyncua  # noqa: F401
    except ImportError:
        st.warning("OPC UA support is not installed. Run: pip install -r requirements.txt")
        return
    c1, c2 = st.columns([2, 1])
    case = c1.radio("What happens behind the PLC", [
        "Nothing: a normal shift",
        "LT-101 is compromised and reports a third of the real level",
        "LT-101's transmitter freezes"], index=1)
    minutes = c2.slider("Minutes of plant time", 3, 10, 5)
    if st.button("Run shadow-mode session", type="primary"):
        with st.spinner("Connecting to the PLC over OPC UA and watching…"):
            st.session_state.pilot = _run_pilot(case, minutes * 60)
    rep = st.session_state.get("pilot")
    if rep:
        _pilot_report(rep)


def _run_pilot(case, seconds):
    import asyncio

    from asyncua import Client
    from sensetrust.gateway import Gateway
    from sensetrust.opcua import OpcUaShadowMonitor, PlantOpcUaServer, SimulatedPlc

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    base = tempfile.mkdtemp(prefix="sensetrust-pilot-")
    start = 120

    tick = {"t": 0}

    async def run():
        gw = Gateway(os.path.join(base, "gw"), clock=lambda: 1_760_000_000.0 + tick["t"])
        server = await PlantOpcUaServer(gw.ca, os.path.join(base, "plc"), port=port).start()
        rows, detected = [], None
        try:
            eps = await Client(server.url).connect_and_get_server_endpoints()
            plc = SimulatedPlc(server)
            mon = await OpcUaShadowMonitor(gw, server.url).connect()
            try:
                for _ in range(seconds):
                    if plc.t == start and case.startswith("LT-101 is"):
                        plc.tamper = lambda t, s_, v: v * 0.35 if s_ == "LT-101" and t > start else v
                    if plc.t == start and case.startswith("LT-101's"):
                        frozen = {}
                        plc.tamper = (lambda t, s_, v: frozen.setdefault("v", v)
                                      if s_ == "LT-101" and t > start else v)
                    reported = await plc.step()
                    tick["t"] = plc.t
                    diags = await mon.poll()
                    if diags and detected is None:
                        detected = plc.t - start
                    rows.append({"t": plc.t, "True level": plc.plant.h,
                                 "LT-101 reports": reported["LT-101"]})
            finally:
                await mon.disconnect()
            return {
                "case": case, "seconds": seconds,
                "endpoint": "%s, %s" % (eps[0].SecurityPolicyUri.split("#")[-1],
                                        eps[0].SecurityMode.name),
                "reads": mon.ticks, "rows": rows, "detected_after": detected,
                "alerts": [{"Plant time": ui.clock(int(ev["ts"] - 1_760_000_000.0)),
                            "Sensor": ev["subject"],
                            "Alert": ev["kind"].replace("_", " "), "Detail": ev["detail"]}
                           for ev in gw.events if ev.get("shadow")],
                "revoked": sorted(gw.trust.quarantined()),
                "overflow": plc.plant.overflow_seconds,
            }
        finally:
            await server.stop()
            gw.close()

    return asyncio.run(run())


def _pilot_report(rep):
    st.subheader("Session report")
    c = st.columns(4)
    c[0].metric("Values read", f"{rep['reads'] * 5:,}", help="5 values per second, one OPC UA read")
    c[1].metric("Alerts", len(rep["alerts"]))
    c[2].metric("Detected after", "%s s" % rep["detected_after"] if rep["detected_after"] is not None
                else "nothing to detect")
    c[3].metric("Blocked or revoked", len(rep["revoked"]))
    st.caption("Connection: OPC UA %s, plant-CA certificates on both sides, read-only." % rep["endpoint"])
    ui.levels_chart(pd.DataFrame(rep["rows"]), height=240)
    if rep["alerts"]:
        st.dataframe(pd.DataFrame(rep["alerts"]), hide_index=True, use_container_width=True)
    if rep["overflow"]:
        st.warning("The tank overflowed for %d s: in shadow mode the PLC keeps trusting the bad "
                   "sensor. Switching the site to enforcement mode is what prevents this (see "
                   "the Attack lab, where the same attack causes no overflow)." % rep["overflow"])


# ── Attack lab ──────────────────────────────────────────────────────────────

LAB = [
    ("Stolen key: LT-101 lies", "inject_false_data",
     "An attacker has LT-101's real key and reports the tank at a third of its level. "
     "Every cryptographic check passes; physics does not.", True),
    ("Rogue device joins", "rogue_device",
     "A device with a certificate from an attacker's CA claims to be PT-101.", False),
    ("Finger photo on a phone", "spoof_login",
     "Someone holds a picture of the supervisor's finger up to the reader.", False),
    ("Someone else's finger", "impostor_login",
     "A different person tries the supervisor's account.", False),
    ("Stolen session token", "stolen_token",
     "The supervisor's valid token is copied and used from console-02.", False),
]
NORMAL = [
    ("LT-101 transmitter freezes", "inject_fault",
     "A real hardware fault, no attacker. Should become a maintenance ticket, not an alarm."),
    ("PT-101 transmitter freezes", ("inject_fault", "PT-101"),
     "Same fault on the pressure sensor."),
]


def lab():
    st.title("Attack lab")
    st.caption("Stage attacks and faults on the live plant, then watch the Overview and "
               "Incidents pages respond. Reset the plant at any time from the sidebar.")
    e = engine()
    left, right = st.columns([1, 1.7], gap="large")
    with left:
        st.subheader("Attacks")
        for label, fn, text, primary in LAB:
            st.button(label, key="lab" + fn, type="primary" if primary else "secondary",
                      on_click=getattr(e, fn), use_container_width=True)
            st.caption(text)
        st.subheader("Normal plant events")
        for label, fn, text in NORMAL:
            name, args = (fn, ()) if isinstance(fn, str) else (fn[0], fn[1:])
            st.button(label, key="lab" + label, on_click=getattr(e, name), args=args,
                      use_container_width=True)
            st.caption(text)
    with right:
        _lab_live()


@st.fragment(run_every=REFRESH)
def _lab_live():
    e = engine()
    e.advance()
    ui.status_banner(e)
    ui.level_chart(e, window=240, height=240)
    st.subheader("Activity")
    rows = [(t, 0, "you", text) for t, text in e.notes]
    for ev in e.gw.events:
        if ev["kind"] in ("telemetry_denied", "m2m_denied"):
            continue
        rows.append((int(ev["ts"] - e.site.t0), 1, "gateway",
                     "%s: %s" % (ev["subject"], ev["detail"])))
    if rows:
        rows.sort(key=lambda r: (r[0], r[1]), reverse=True)
        df = pd.DataFrame([{"Plant time": ui.clock(t), "Who": who, "What": what}
                           for t, _, who, what in rows[:12]])
        st.dataframe(df, hide_index=True, use_container_width=True)


# ── Scenarios and evaluation ────────────────────────────────────────────────

def scenarios_page():
    st.title("Scripted scenarios")
    st.caption("Eleven end-to-end runs against the real gateway. Pass or fail is computed from "
               "what happened, not asserted by hand.")
    cal = scenarios.load_calibration(os.path.join(ROOT, "results", "calibration.pkl"))
    names = {"%s  %s" % (sid, name): (sid, kw, fn) for sid, name, kw, fn in scenarios.SCENARIOS}
    c1, c2 = st.columns([3, 1])
    choice = c1.selectbox("Scenario", list(names))
    sid, keywords, fn = names[choice]
    c2.write("")
    run = c2.button("Run scenario", type="primary", use_container_width=True)
    st.markdown("**PS-13 capability:** %s" % keywords)
    st.markdown(" ".join((fn.__doc__ or "").split()))
    if run or st.session_state.get("sid") != sid:
        kw = ({"calibration": cal}
              if fn in (scenarios.s2_stolen_key_false_data, scenarios.s5_genuine_fault) else {})
        with st.spinner("Running against the gateway…"):
            st.session_state.result = fn(tempfile.mkdtemp(prefix="sensetrust-ui-"), **kw)
            st.session_state.sid = sid
    r = st.session_state.result
    verdict = ("Skipped (dependency not installed)" if r["passed"] is None
               else "Passed" if r["passed"] else "Failed")
    (st.success if r["passed"] else st.warning if r["passed"] is None else st.error)(verdict)
    if sid == "S2":
        o = r["observed"]
        c = st.columns(4)
        c[0].metric("Overflow, conventional plant", "%d s" % o["baseline"]["overflow_seconds"])
        c[1].metric("Overflow, with SenseTrust", "%d s" % o["zero_trust"]["overflow_seconds"])
        c[2].metric("Attack detected after", "%s s" % o["zero_trust"]["attack_detected_after_s"])
        c[3].metric("LT-101 certificate", "revoked" if o["zero_trust"]["LT101_revoked"] else "valid")
        log = pd.DataFrame(r["_log"]).set_index("t").rename(columns={
            "true_level": "True level", "reported_level": "LT-101 reports",
            "control_level": "Pump control uses"})
        st.markdown("The attacker reports the tank 1.2 m lower than it is from t = 120 s. "
                    "Overflow above %.1f m." % OVERFLOW)
        st.line_chart(log[["LT-101 reports", "Pump control uses", "True level"]],
                      color=[ui.ALARM, ui.FAULT, ui.INK], height=260)
    with st.expander("Full observed result", expanded=sid != "S2"):
        st.json({k: v for k, v in r["observed"].items()}, expanded=True)

    metrics_path = os.path.join(ROOT, "results", "metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path) as f:
            m = json.load(f)
        st.subheader("Measured on 324 injected faults and attacks")
        d = m["detector"]
        c = st.columns(4)
        c[0].metric("Attacks detected", "%.0f%%" % (100 * d["summary"]["attack"]["detection_rate"]))
        c[1].metric("Faults detected", "%.0f%%" % (100 * d["summary"]["fault"]["detection_rate"]))
        c[2].metric("Faults wrongly called attacks",
                    "%.1f%%" % (100 * d["summary"]["fault_wrongly_called_attack_rate"]))
        c[3].metric("False alarms per hour, normal running", d["normal"]["false_alarms_per_hour"])
