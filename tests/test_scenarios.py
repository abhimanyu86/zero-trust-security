"""The seven demo scenarios, end to end, as a regression suite."""

import pytest

from sensetrust import scenarios


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    return {r["id"]: r for r in scenarios.run_all(str(tmp_path_factory.mktemp("sc")))}


@pytest.mark.parametrize("sid", [s[0] for s in scenarios.SCENARIOS])
def test_scenario_passes(results, sid):
    assert results[sid]["passed"], results[sid]["observed"]


def test_s2_quantifies_physical_impact(results):
    obs = results["S2"]["observed"]
    assert obs["baseline"]["overflow_seconds"] > 0
    assert obs["zero_trust"]["overflow_seconds"] == 0
    assert obs["zero_trust"]["attack_detected_after_s"] <= 10


def test_biometric_templates_are_encrypted_and_iso_fir_roundtrips(tmp_path):
    from sensetrust.site import Site
    site = Site(str(tmp_path / "s"))
    raw = open(site.gw.operators.path).read()
    assert "minutiae" not in raw and "direction" not in raw        # sealed at rest
    fir = site.gw.operators.enrolled_fir("asha")
    assert fir["finger"]["width"] == 256 and fir["finger"]["height"] == 256
    assert fir["header"]["image_resolution_x"] == 500 and fir["finger"]["finger_position"] == 2
