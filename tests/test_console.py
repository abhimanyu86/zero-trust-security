"""The operator console: every page renders, and its actions go through the gateway."""

import os

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest      # noqa: E402

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "dashboard", "app.py")
PAGES = ["overview", "incidents", "devices", "lab", "scenarios", "pilot", "mobility"]


def _render(page, dashboard_dir):
    import os
    import sys
    sys.path.insert(0, dashboard_dir)
    sys.path.insert(0, os.path.dirname(dashboard_dir))
    import streamlit as st
    import views
    from engine import LivePlant
    if "engine" not in st.session_state:
        st.session_state.engine = LivePlant()
        st.session_state.engine.inject_false_data()
        for _ in range(60):
            st.session_state.engine.site.step()
    views.PAGES.setdefault("incidents", st.Page(views.incidents, title="Incidents",
                                                url_path="incidents"))
    {"overview": views.overview, "incidents": views.incidents, "devices": views.devices,
     "lab": views.lab, "scenarios": views.scenarios_page, "pilot": views.pilot,
     "mobility": views.mobility_page}[page]()


@pytest.mark.parametrize("page", PAGES)
def test_page_renders_without_errors(page):
    at = AppTest.from_function(_render, args=(page, os.path.dirname(APP)), default_timeout=120)
    at.run()
    assert not at.exception, [e.value for e in at.exception]


def test_full_app_starts():
    at = AppTest.from_file(APP, default_timeout=120)
    at.run()
    assert not at.exception, [e.value for e in at.exception]


def test_attack_then_reinstate_flow():
    import sys
    sys.path.insert(0, os.path.dirname(APP))
    from engine import LivePlant
    e = LivePlant()
    for _ in range(100):
        e.site.step()
    e.inject_false_data()
    for _ in range(40):
        e.site.step()
    attack = [i for i in e.incidents() if i["type"] == "attack"]
    assert attack and attack[0]["device_state"] == "revoked"
    assert e.reinstate("LT-101")[0]
    assert e.technician_reenrol("LT-101")[0]
    for _ in range(100):
        e.site.step()
    rows = {r["Device"]: r["Status"] for r in e.device_rows()}
    assert rows["LT-101"] == "Trusted" and e.site.plant.overflow_seconds == 0
    e.gw.close()
