"""5G binding: certificate, SIM address and slice must agree."""

import os
import time

import pytest

from sensetrust.devices import DeviceIdentity
from sensetrust.fiveg import FiveGBinding
from sensetrust.gateway import Gateway

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLE = os.path.join(ROOT, "config", "5g_subscribers.json")


@pytest.fixture
def binding():
    return FiveGBinding.load(TABLE)


def test_matching_sim_and_slice_is_allowed(binding):
    ok, reason = binding.check("LT-101", "telemetry", "10.46.0.11")
    assert ok and "imsi-001010000000101" in reason


def test_key_on_another_devices_sim_is_refused(binding):
    ok, reason = binding.check("LT-101", "telemetry", "10.46.0.12")
    assert not ok and "PT-101" in reason


def test_unknown_address_inside_a_slice_is_refused(binding):
    ok, reason = binding.check("LT-101", "telemetry", "10.46.0.200")
    assert not ok and "no enrolled SIM" in reason


def test_subscriber_must_arrive_over_5g(binding):
    ok, reason = binding.check("LT-101", "telemetry", "192.168.1.50")
    assert not ok and "outside every slice" in reason


def test_slice_limits_traffic_kind(binding):
    assert not binding.check("LT-101", "command", "10.46.0.11")[0]
    assert binding.check("console-02", "command", "10.45.0.21")[0]
    assert not binding.check("console-02", "telemetry", "10.45.0.21")[0]


def test_maintenance_slice_closed_until_opened(binding):
    assert binding.check("vendor-01", "telemetry", "10.47.0.31") == (False, "maintenance slice is closed")
    binding.maintenance_open = True
    assert binding.check("vendor-01", "telemetry", "10.47.0.31")[0]


def test_wired_devices_unaffected(binding):
    assert binding.check("console-01", "command", "192.168.10.5")[0]
    assert binding.check("console-01", "command", None)[0]


def test_table_rejects_address_outside_its_slice_pool():
    with pytest.raises(ValueError):
        FiveGBinding({"telemetry": {"pool": "10.46.0.0/24"}},
                     [{"identity": "X", "supi": "imsi-1", "ip": "10.45.0.5", "slice": "telemetry"}])


def test_gateway_denies_and_penalises_binding_failures(tmp_path, binding):
    gw = Gateway(str(tmp_path / "gw"))
    gw.network = binding
    dev = DeviceIdentity.commission(gw.ca, "LT-101", "sensor", time.time)
    assert gw.telemetry(dev.cert, dev.envelope(value=1.0), source_ip="10.46.0.11")["effect"] == "allow"
    d = gw.telemetry(dev.cert, dev.envelope(value=1.0), source_ip="10.46.0.12")
    assert d["effect"] == "deny" and d["reasons"][0].startswith("5G binding")
    assert gw.trust.score("LT-101") < 1.0
    gw.close()
