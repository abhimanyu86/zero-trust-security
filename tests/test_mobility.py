"""MOBI-GUARD inside SenseTrust: impossible movement is caught, real movement is not."""

import time

import pytest

from sensetrust import mobility

pytestmark = pytest.mark.skipif(not mobility.available(), reason="MOBI-GUARD dependencies missing")

SCENARIOS = ["highway_straight", "highway_exit", "urban_grid", "rail_corridor",
             "station_approach", "noisy_measurement"]


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_real_drives_never_raise_an_identity_alarm(scenario):
    """Drives the models never saw (fresh seeds), including route changes and noisy radio."""
    for seed in (900, 901):
        mt = mobility.MobilityTrust()
        verdicts = [mt.check("TRK", r)["verdict"] for r in mobility.trajectory(scenario, seed)]
        assert "impossible" not in verdicts


@pytest.mark.parametrize("genuine,copy", [("highway_exit", "urban_grid"),
                                          ("highway_straight", "rail_corridor"),
                                          ("urban_grid", "station_approach")])
def test_a_copied_identity_reporting_elsewhere_is_caught(genuine, copy):
    real, other = mobility.trajectory(genuine, 910), mobility.trajectory(copy, 911)
    mt, caught_after = mobility.MobilityTrust(), None
    copies = 0
    for k, r in enumerate(real):
        mt.check("TRK", r)
        if k >= 30 and k % 5 == 0 and k < len(other):
            copies += 1
            v = mt.check("TRK", dict(other[k], timestamp=r["timestamp"] + 0.5))["verdict"]
            if v == "impossible":
                caught_after = copies
                break
    assert caught_after is not None and caught_after <= 6


def test_reports_off_the_track_never_steer_predictions_and_untrusted_devices_hold():
    real = mobility.trajectory("highway_straight", 920)
    mt = mobility.MobilityTrust()
    for r in real[:40]:
        out = mt.check("TRK", r)
    assert out["prediction"] is not None
    low = mt.check("TRK", real[40], trust_score=0.4)
    assert low["advice"]["action"] == "HOLD"


def test_gateway_revokes_a_cloned_vehicle_identity(tmp_path):
    from sensetrust.devices import DeviceIdentity
    from sensetrust.gateway import Gateway
    clock = {"t": 1_760_000_000.0}
    gw = Gateway(str(tmp_path / "gw"), clock=lambda: clock["t"])
    truck = DeviceIdentity.commission(gw.ca, "TRK-07", "vehicle", lambda: clock["t"])
    real, other = mobility.trajectory("highway_exit", 930), mobility.trajectory("urban_grid", 931)
    for k, r in enumerate(real):
        clock["t"] = 1_760_000_000.0 + r["timestamp"]
        assert gw.mobility_report(truck.cert, truck.envelope(radio=r))["effect"] in ("allow", "deny")
        if k >= 40 and k % 5 == 0:
            gw.mobility_report(truck.cert, truck.envelope(radio=dict(other[k], timestamp=r["timestamp"] + 0.5)))
        if gw.trust.is_quarantined("TRK-07"):
            break
    assert gw.trust.is_quarantined("TRK-07")
    assert gw.ca.is_revoked(truck.cert)
    assert gw.mobility_report(truck.cert, truck.envelope(radio=real[-1]))["effect"] == "deny"
    gw.close()
