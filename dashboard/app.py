"""
SenseTrust operator console (prototype).

    streamlit run dashboard/app.py

A product-shaped console on top of the real gateway and a simulated water plant:
Overview, Incidents, Devices and identity, Pilot (OPC UA shadow mode), Attack lab and
Scripted scenarios. Every decision shown is made by the SenseTrust gateway; console
actions that change the plant are fingerprint-backed, signed commands.
"""

import os
import sys

import streamlit as st

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import ui  # noqa: E402
import views  # noqa: E402
from engine import LivePlant  # noqa: E402

st.set_page_config(page_title="SenseTrust console", page_icon=os.path.join(HERE, "assets",
                   "yellowsense-mark.png"), layout="wide")
ui.inject_css()
st.logo(os.path.join(HERE, "assets", "yellowsense-mark.png"), size="large")

if "engine" not in st.session_state:
    st.session_state.engine = LivePlant()


def _reset():
    st.session_state.engine = LivePlant()
    st.session_state.pop("pilot", None)
    st.session_state.pop("mobility", None)


pages = {
    "overview": st.Page(views.overview, title="Overview", url_path="overview", default=True),
    "incidents": st.Page(views.incidents, title="Incidents", url_path="incidents"),
    "devices": st.Page(views.devices, title="Devices and identity", url_path="devices"),
    "pilot": st.Page(views.pilot, title="Pilot: shadow mode", url_path="pilot"),
    "mobility": st.Page(views.mobility_page, title="Mobility (MOBI-GUARD)", url_path="mobility"),
    "lab": st.Page(views.lab, title="Attack lab", url_path="lab"),
    "scenarios": st.Page(views.scenarios_page, title="Scripted scenarios", url_path="scenarios"),
}
views.PAGES.update(pages)
nav = st.navigation({"Operate": [pages["overview"], pages["incidents"], pages["devices"]],
                     "Prove": [pages["mobility"], pages["pilot"], pages["lab"], pages["scenarios"]]})

with st.sidebar:
    st.markdown("### SenseTrust")
    e = st.session_state.engine
    e.running = st.toggle("Plant running", value=e.running,
                          help="The simulated plant runs at 6x real time.")
    st.button("Reset plant", on_click=_reset, use_container_width=True)
    st.markdown('<p class="proto">Prototype console by YellowSense Technologies. The plant is '
                'simulated; every decision on these pages is made by the real SenseTrust '
                'gateway.</p>', unsafe_allow_html=True)

nav.run()
