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
    assert obs["zero_trust"]["honest_sensors_revoked"] == []     # only the liar is cut off


def test_biometric_templates_are_encrypted_and_iso_fir_roundtrips(tmp_path):
    from sensetrust.site import Site
    site = Site(str(tmp_path / "s"))
    raw = open(site.gw.operators.path).read()
    assert "minutiae" not in raw and "direction" not in raw        # sealed at rest
    fir = site.gw.operators.enrolled_fir("asha")
    assert fir["finger"]["width"] == 256 and fir["finger"]["height"] == 256
    assert fir["header"]["image_resolution_x"] == 500 and fir["finger"]["finger_position"] == 2


@pytest.mark.parametrize("start", [10, 120, 300])
@pytest.mark.parametrize("kind", ["attack", "fault"])
def test_live_site_convicts_only_the_culprit(tmp_path, kind, start):
    """
    The live dashboard's two injections, at different points in the fill cycle: an
    in-range lie from LT-101 must be called an attack with only LT-101 revoked; a frozen
    LT-101 must be a fault with nothing revoked. Either way no other sensor is flagged —
    a culprit's bad readings must not make honest instruments look wrong.
    """
    from sensetrust.site import Site
    site = Site(str(tmp_path / "s"), level=1.3)
    site.run(start)
    frozen = {}
    if kind == "attack":
        site.tamper = lambda t, s, v: v * 0.35 if (s == "LT-101" and t > start) else v
    else:
        site.tamper = lambda t, s, v: frozen.setdefault("v", v) if (s == "LT-101" and t > start) else v
    site.run(400)
    diag = [(e["kind"], e["subject"]) for e in site.gw.events
            if e["kind"] in ("attack_detected", "fault_detected", "ambiguous_anomaly")]
    expected = "attack_detected" if kind == "attack" else "fault_detected"
    assert diag == [(expected, "LT-101")]
    assert sorted(site.gw.trust.quarantined()) == (["LT-101"] if kind == "attack" else [])
    assert site.plant.overflow_seconds == 0
    site.gw.close()
