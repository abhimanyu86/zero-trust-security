import random

import pytest

from sensetrust.policy import PolicyEngine
from sensetrust.simulation import Injection, make_injection, run_episode
from sensetrust.trust import QUARANTINE, TrustRegistry


def first(res):
    return res.first_diagnosis()


def test_normal_operation_raises_no_alarm():
    for seed in range(3):
        assert run_episode(seed, duration=600).diagnoses == []


@pytest.mark.parametrize("sensor", ["LT-101", "PT-101"])
def test_stuck_transmitter_is_a_fault(sensor):
    d = first(run_episode(1, duration=600, injection=Injection(sensor, "stuck", 200)))
    assert d.sensor == sensor and d.verdict == "fault" and d.kind == "stuck_value"


def test_dropout_is_a_fault():
    d = first(run_episode(2, duration=400, injection=Injection("FT-101", "dropout", 200)))
    assert d.verdict == "fault" and d.kind == "dropout"


@pytest.mark.parametrize("sensor", ["LT-101", "PT-101"])
def test_false_data_offset_is_an_attack(sensor):
    inj = make_injection("fdi_offset", sensor, 200, random.Random(3))
    d = first(run_episode(3, duration=500, injection=inj))
    assert d.sensor == sensor and d.verdict == "attack"
    assert d.t - 200 < 10


def test_noisy_freeze_is_an_attack_not_a_stuck_fault():
    d = first(run_episode(4, duration=600, injection=Injection("LT-101", "fdi_freeze", 200)))
    assert d.verdict == "attack"


def test_slow_drift_is_reported_as_ambiguous():
    inj = make_injection("drift", "PT-101", 200, random.Random(5))
    d = first(run_episode(5, duration=700, injection=inj))
    assert d is not None and d.verdict == "ambiguous"


def test_zero_trust_response_prevents_overflow():
    inj = Injection("LT-101", "fdi_offset", 120, {"offset": -1.2})
    blind = run_episode(6, duration=700, injection=inj, respond=False)
    zt = run_episode(6, duration=700, injection=inj, respond=True)
    assert blind.overflow_seconds > 0
    assert zt.overflow_seconds == 0


def test_trust_registry_quarantines_on_attack_but_not_on_fault():
    tr = TrustRegistry()
    assert not tr.penalise("FT-101", "fault_detected")
    assert tr.score("FT-101") == 1.0
    assert tr.penalise("LT-101", "attack_detected")
    assert tr.is_quarantined("LT-101") and tr.score("LT-101") < QUARANTINE


BASE_CMD = {"cert_ok": True, "cert_reason": "ok", "role": "console", "token_ok": True,
            "token_reason": "ok", "cert_serial": 42, "sig_ok": True, "replay_ok": True,
            "replay_reason": "ok", "now": 10_000, "plant_under_attack": False,
            "target_quarantined": False}


def claims(**kw):
    c = {"sub": "asha", "scope": ["actuate", "override"], "amr": ["fingerprint", "liveness", "mtls"],
         "auth_time": 10_000 - 60, "cnf": "42"}
    c.update(kw)
    return c


def test_policy_allows_fresh_biometric_critical_command():
    d = PolicyEngine().decide_command({**BASE_CMD, "action": "pump.force_on", "claims": claims()})
    assert d.effect == "allow"


def test_policy_steps_up_when_under_attack():
    d = PolicyEngine().decide_command({**BASE_CMD, "plant_under_attack": True,
                                       "action": "pump.force_on", "claims": claims()})
    assert d.effect == "step_up"


def test_policy_steps_up_without_biometric_amr():
    d = PolicyEngine().decide_command({**BASE_CMD, "action": "interlock.bypass",
                                       "claims": claims(amr=["mtls"])})
    assert d.effect == "step_up"


def test_policy_denies_token_bound_to_other_console():
    d = PolicyEngine().decide_command({**BASE_CMD, "action": "valve.set", "claims": claims(cnf="7")})
    assert d.effect == "deny"


def test_policy_denies_missing_scope():
    d = PolicyEngine().decide_command({**BASE_CMD, "action": "device.reinstate", "claims": claims()})
    assert d.effect == "deny" and "scope" in d.reasons[0]


def test_policy_default_denies_unknown_action():
    d = PolicyEngine().decide_command({**BASE_CMD, "action": "firmware.flash", "claims": claims()})
    assert d.effect == "deny"
