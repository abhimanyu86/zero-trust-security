"""
SenseTrust demo dashboard.

    streamlit run dashboard/app.py

Two pages: "Live plant" runs the gateway and the simulated plant in real time and lets you
inject attacks and faults; "Scripted scenarios" runs the seven end-to-end scenarios.
"""

import json
import os
import sys
import tempfile

import pandas as pd
import streamlit as st

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sensetrust import scenarios  # noqa: E402
from sensetrust.plant import OVERFLOW  # noqa: E402

import live  # noqa: E402

st.set_page_config(page_title="SenseTrust — Zero-Trust CPS", layout="wide")


def scripted():
    st.title("SenseTrust — scripted scenarios")
    st.caption("Every request is authenticated, authorised and checked against plant physics on its "
               "own merits. Simulated water-treatment skid · YellowSense Technologies")
    cal = scenarios.load_calibration(os.path.join(ROOT, "results", "calibration.pkl"))
    names = {"%s — %s" % (sid, name): (sid, kw, fn) for sid, name, kw, fn in scenarios.SCENARIOS}
    choice = st.sidebar.radio("Scenario", list(names))
    sid, keywords, fn = names[choice]
    st.sidebar.markdown("**PS-13 capability:** " + keywords)
    st.sidebar.markdown(fn.__doc__ or "")

    if st.sidebar.button("Run scenario", type="primary") or "result" not in st.session_state \
            or st.session_state.get("sid") != sid:
        base = tempfile.mkdtemp(prefix="sensetrust-ui-")
        kw = {"calibration": cal} if fn in (scenarios.s2_stolen_key_false_data, scenarios.s5_genuine_fault) else {}
        with st.spinner("Running against the live gateway…"):
            st.session_state.result = fn(base, **kw)
            st.session_state.sid = sid

    r = st.session_state.result
    st.subheader(("✅ " if r["passed"] else "❌ ") + choice)

    if sid == "S2":
        o = r["observed"]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Overflow — conventional", "%d s" % o["baseline"]["overflow_seconds"])
        c2.metric("Overflow — zero trust", "%d s" % o["zero_trust"]["overflow_seconds"])
        c3.metric("Attack detected after", "%s s" % o["zero_trust"]["attack_detected_after_s"])
        c4.metric("LT-101 certificate", "revoked" if o["zero_trust"]["LT101_revoked"] else "valid")
        log = pd.DataFrame(r["_log"]).set_index("t")
        st.markdown("**Tank level (m).** The attacker, holding LT-101's real key, reports the tank 1.2 m "
                    "lower than it is from t=120 s. Rim at %.1f m." % OVERFLOW)
        st.line_chart(log[["true_level", "reported_level", "control_level"]])
        st.markdown("**Trust scores.**")
        st.line_chart(log[["trust_LT", "trust_PT", "trust_FT"]])
        ev = pd.DataFrame([{k: e[k] for k in ("ts", "severity", "kind", "subject", "detail")}
                           for e in r["_events"] if e["kind"] != "login"])
        if not ev.empty:
            ev["t"] = (ev["ts"] - ev["ts"].min()).astype(int)
            st.markdown("**Gateway events** (first 25)")
            st.dataframe(ev.drop(columns="ts").head(25), use_container_width=True)
    else:
        st.json(r["observed"], expanded=True)

    metrics_path = os.path.join(ROOT, "results", "metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path) as f:
            m = json.load(f)
        st.divider()
        st.subheader("Measured evaluation (results/metrics.json)")
        d = m["detector"]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Attacks detected", "%.0f%%" % (100 * d["summary"]["attack"]["detection_rate"]))
        c2.metric("Faults detected", "%.0f%%" % (100 * d["summary"]["fault"]["detection_rate"]))
        c3.metric("Faults wrongly called attack", "%.1f%%" % (100 * d["summary"]["fault_wrongly_called_attack_rate"]))
        c4.metric("False alarms / hour (normal)", d["normal"]["false_alarms_per_hour"])
        st.dataframe(pd.DataFrame(d["cells"]), use_container_width=True)


st.navigation([st.Page(live.render, title="Live plant", url_path="live", default=True),
               st.Page(scripted, title="Scripted scenarios", url_path="scenarios")]).run()
