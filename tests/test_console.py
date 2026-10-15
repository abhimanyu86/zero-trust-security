"""The operator console: the web app is served and its API drives the real gateway."""

import time

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient      # noqa: E402

from console import server                      # noqa: E402


@pytest.fixture
def client():
    with TestClient(server.app) as c:
        c.post("/api/plant", json={"reset": True})
        yield c


def _wait(c, cond, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = c.get("/api/state").json()
        if cond(s):
            return s
        time.sleep(0.5)
    raise AssertionError("condition not reached")


def test_page_and_assets_are_served(client):
    page = client.get("/")
    assert page.status_code == 200 and "SenseTrust" in page.text
    for asset in ("app.js", "app.css", "yellowsense-mark.png"):
        assert client.get("/static/" + asset).status_code == 200


def test_live_state_runs_and_describes_the_plant(client):
    s = _wait(client, lambda s: s["t"] > 3)
    assert s["status"]["level"] == "ok" and s["metrics"]["refused"] == 0
    assert {d["id"] for d in s["devices"]} >= {"LT-101", "PT-101", "FT-101", "console-01"}
    assert s["links"]["LT-101"]["allow"] > 0 and len(s["series"]) > 3


def test_attack_then_fingerprint_approved_recovery(client):
    client.post("/api/simulate/false_data", json={"target": "LT-101"})
    s = _wait(client, lambda s: any(i["type"] == "attack" for i in s["incidents"]))
    inc = next(i for i in s["incidents"] if i["type"] == "attack")
    assert inc["severity"] == "critical" and "false readings" in inc["title"]
    assert s["status"]["level"] == "alarm"
    r = client.post("/api/action", json={"action": "reinstate", "target": "LT-101"}).json()
    assert r["ok"] and r["fingerprint"]["ok"]
    r = client.post("/api/action", json={"action": "technician_reenrol", "target": "LT-101"}).json()
    assert r["ok"]
    s = _wait(client, lambda s: next(d for d in s["devices"] if d["id"] == "LT-101")["status"] == "Trusted")
    client.post("/api/action", json={"action": "resolve", "target": inc["id"]})
    assert client.get("/api/state").json()["metrics"]["open"] == 0


def test_rogue_device_and_bad_input_are_refused(client):
    client.post("/api/simulate/rogue")
    s = client.get("/api/state").json()
    assert s["links"]["rogue"]["deny"] == 1
    assert any(i["type"] == "rogue" for i in s["incidents"])
    assert client.post("/api/simulate/nonsense").status_code == 404
    assert client.post("/api/action", json={"action": "commission", "target": ""}).status_code == 400


def test_scenarios_are_listed_and_run(client):
    r = client.get("/api/scenarios").json()
    assert len(r["scenarios"]) >= 12
    assert client.post("/api/scenarios/S1").json()["passed"] is True
