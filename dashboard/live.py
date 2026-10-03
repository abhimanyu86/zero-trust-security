"""
Live plant: the real gateway in front of the simulated water-treatment skid, running in
real time. Inject an attack or a fault while it runs and watch the gateway respond.
"""

import os
import tempfile

import pandas as pd
import streamlit as st

from sensetrust import scenarios
from sensetrust.ca import CertificateAuthority
from sensetrust.devices import DeviceIdentity
from sensetrust.plant import OVERFLOW
from sensetrust.site import DEVICES, Site
from sensetrust.synthetic import make_template, recapture, screen_recapture_image

SIM_SECONDS_PER_TICK = 3      # plant seconds advanced per refresh
TICK = 0.5                    # real seconds between refreshes -> 6x real time
WINDOW = 300                  # seconds of history on the chart
NOISY = ("telemetry_denied", "m2m_denied")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _new_site():
    cal = scenarios.load_calibration(os.path.join(ROOT, "results", "calibration.pkl"))
    site = Site(tempfile.mkdtemp(prefix="sensetrust-live-"), calibration=cal, level=1.3)
    st.session_state.site = site
    st.session_state.injected = None
    st.session_state.notes = []


def _note(text):
    site = st.session_state.site
    st.session_state.notes.append((site.plant.t, text))


def _inject_false_data():
    site = st.session_state.site
    start = site.plant.t + 1
    # A plausible lie: always in range and smoothly varying, just a third of the truth.
    site.tamper = lambda t, s, v: v * 0.35 if (s == "LT-101" and t >= start) else v
    st.session_state.injected = "Stolen-key attack on LT-101 since t=%d s" % start
    _note("Attacker with LT-101's real key starts reporting the tank at a third of its real level")


def _inject_fault():
    site = st.session_state.site
    start, frozen = site.plant.t + 1, {}
    site.tamper = lambda t, s, v: frozen.setdefault("v", v) if (s == "LT-101" and t >= start) else v
    st.session_state.injected = "LT-101 transmitter frozen since t=%d s (hardware fault)" % start
    _note("LT-101 transmitter freezes (real hardware fault, no attacker)")


def _rogue_device():
    site = st.session_state.site
    rogue_ca = CertificateAuthority(tempfile.mkdtemp(prefix="rogue-ca-"), name="Attacker CA")
    rogue_ca.issue("PT-101", "sensor")
    rogue = DeviceIdentity.load(rogue_ca, "PT-101", site.clock)
    d = site.gw.telemetry(rogue.cert, rogue.envelope(value=5.0))
    _note("Rogue device claiming to be PT-101 sends a reading: %s" % d["effect"].upper())


def _spoof_login():
    site = st.session_state.site
    r = site.login("asha", image=screen_recapture_image())
    _note("Supervisor's finger photo held up on a phone: login %s" % ("ALLOWED" if r["ok"] else "DENIED"))


def _genuine_command():
    site = st.session_state.site
    r = site.login("asha", minutiae=recapture(site.finger("asha"), seed=site.plant.t, rotation=20))
    if not r["ok"]:
        _note("Genuine login failed: %s" % "; ".join(r["reasons"]))
        return
    _, d = site.send_command(r["token"], "valve.set", "XV-101", position=0.6)
    _note("Supervisor logs in with real finger (match %.2f) and sets valve XV-101: %s"
          % (r["score"], d["effect"].upper()))


def _impostor_login():
    site = st.session_state.site
    r = site.login("asha", minutiae=recapture(make_template(seed=4242), seed=1))
    _note("Someone else's finger used for the supervisor's account: login %s"
          % ("ALLOWED" if r["ok"] else "DENIED"))


def _cert_status(site, ident):
    if site.gw.trust.is_quarantined(ident):
        return "REVOKED (quarantined)"
    if ident in site.gw.degraded:
        return "valid, value excluded (maintenance)"
    return "valid"


def render():
    if "site" not in st.session_state:
        _new_site()

    st.title("SenseTrust · live plant")
    st.caption("The real zero-trust gateway in front of a simulated water-treatment skid, running "
               "in real time (6× speed). Inject an attack or a fault and watch what the gateway does.")

    with st.sidebar:
        st.subheader("Attack the plant")
        st.button("Stolen-key false data on LT-101", on_click=_inject_false_data, type="primary",
                  use_container_width=True)
        st.button("Rogue device joins the network", on_click=_rogue_device, use_container_width=True)
        st.button("Finger photo on a phone screen", on_click=_spoof_login, use_container_width=True)
        st.button("Someone else's finger", on_click=_impostor_login, use_container_width=True)
        st.subheader("Normal events")
        st.button("Freeze LT-101 (hardware fault)", on_click=_inject_fault, use_container_width=True)
        st.button("Supervisor logs in + sets valve", on_click=_genuine_command, use_container_width=True)
        st.divider()
        st.button("Reset plant", on_click=_new_site, use_container_width=True)
        running = st.toggle("Running", value=True)

    _live(running)


@st.fragment(run_every=TICK)
def _live(running):
    site = st.session_state.site
    if running:
        for _ in range(SIM_SECONDS_PER_TICK):
            site.step()
    if not site.log:
        site.step()

    last = site.log[-1]
    revoked = sorted(site.gw.trust.quarantined())
    if revoked:
        st.error("Attack detected. Quarantined and certificate revoked: %s. The plant runs on the "
                 "remaining trusted instruments." % ", ".join(revoked))
    elif site.gw.degraded:
        st.info("Hardware fault on %s: maintenance ticket raised, value excluded from control, "
                "identity kept." % ", ".join(sorted(site.gw.degraded)))
    elif st.session_state.injected:
        st.warning(st.session_state.injected)
    else:
        st.success("Normal operation, all identities trusted")
    if st.session_state.injected and (revoked or site.gw.degraded):
        st.caption("Injected: " + st.session_state.injected)

    c = st.columns(5)
    c[0].metric("Plant time", "%d s" % last["t"])
    c[1].metric("True tank level", "%.2f m" % last["true_level"])
    c[2].metric("LT-101 reports", "—" if last["reported_level"] is None else "%.2f m" % last["reported_level"])
    c[3].metric("Pump P-101", "running" if last["pump"] else "stopped")
    c[4].metric("Overflow so far", "%d s" % site.plant.overflow_seconds,
                help="Seconds above the %.1f m rim" % OVERFLOW)

    left, right = st.columns([3, 2])
    with left:
        df = pd.DataFrame(site.log[-WINDOW:]).set_index("t")
        df = df.rename(columns={"true_level": "true level", "reported_level": "LT-101 reports",
                                "control_level": "pump controller uses"})
        st.markdown("**Tank level (m), last %d s.** Tank overflows above %.1f m." % (WINDOW, OVERFLOW))
        # Streamlit assigns colours to columns in alphabetical order.
        st.line_chart(df[["LT-101 reports", "pump controller uses", "true level"]],
                      color=["#c2410c", "#0f6e78", "#16202a"], height=300)
        st.caption("Pump controller fed by: **%s**" % last["control_source"])
    with right:
        st.markdown("**Devices**")
        rows = [{"device": i, "role": r, "trust": round(site.gw.trust.score(i), 2),
                 "certificate": _cert_status(site, i)} for i, r in DEVICES.items()]
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        tickets = site.gw.tickets
        if tickets:
            st.markdown("**Maintenance tickets**")
            for tk in tickets:
                st.markdown("- %s: %s" % (tk["sensor"], tk["kind"].replace("_", " ")))

    st.markdown("**Gateway event log** (newest first)")
    events, counts = [], {}
    for e in site.gw.events:
        if e["kind"] in NOISY:
            counts[(e["kind"], e["subject"])] = counts.get((e["kind"], e["subject"]), 0) + 1
            if counts[(e["kind"], e["subject"])] > 1:
                continue
        events.append({"t": int(e["ts"] - site.t0), "severity": e["severity"],
                       "event": e["kind"].replace("_", " "), "who": e["subject"], "detail": e["detail"]})
    for t, text in st.session_state.notes:
        events.append({"t": t, "severity": "you", "event": "you did", "who": "demo", "detail": text})
    for (kind, subj), n in counts.items():
        if n > 1:
            events.append({"t": last["t"], "severity": "warning", "event": kind.replace("_", " "),
                            "who": subj, "detail": "%d further messages denied the same way" % (n - 1)})
    if events:
        ev = pd.DataFrame(events).sort_values("t", ascending=False, kind="stable").head(15)
        st.dataframe(ev, hide_index=True, use_container_width=True)
    else:
        st.caption("No events yet. Use the buttons on the left.")

