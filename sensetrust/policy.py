"""
Policy decision point.

Every request — telemetry from a sensor, a command from an operator, a message from one
device to another — is evaluated here, individually, with everything known about it at
that moment. There is no "inside the network" and no session that stays trusted. Default
is deny; each rule names the conditions under which it allows.

Critical actuator commands get continuous verification: the operator must have passed
a *fresh* fingerprint + liveness check, and "fresh" gets stricter while the plant is
under active attack.
"""

from dataclasses import dataclass, field

STEP_UP_MAX_AGE_S = 300          # normal: biometric within the last 5 minutes
STEP_UP_MAX_AGE_UNDER_ATTACK_S = 30
BIOMETRIC_AMR = {"fingerprint", "liveness"}

# action -> (required scope, critical?)
ACTIONS = {
    "valve.set": ("actuate", False),
    "valve.open_full": ("actuate", True),
    "pump.force_on": ("actuate", True),
    "pump.force_off": ("actuate", False),
    "interlock.bypass": ("override", True),
    "device.reinstate": ("admin", True),
}


@dataclass
class Decision:
    effect: str                      # "allow" | "deny" | "step_up"
    reasons: list = field(default_factory=list)

    @property
    def allowed(self):
        return self.effect == "allow"

    def as_dict(self):
        return {"effect": self.effect, "reasons": self.reasons}


def deny(*reasons):
    return Decision("deny", list(reasons))


class PolicyEngine:

    def decide_telemetry(self, ctx):
        """ctx: cert_ok, cert_reason, role, cert_identity, claimed_identity, sig_ok,
        replay_ok, replay_reason, rate_ok, quarantined, trust."""
        if not ctx["cert_ok"]:
            return deny("device identity rejected: " + ctx["cert_reason"])
        if ctx["role"] != "sensor":
            return deny("role %r may not publish telemetry" % ctx["role"])
        if ctx["claimed_identity"] != ctx["cert_identity"]:
            return deny("payload claims %r but certificate is %r"
                        % (ctx["claimed_identity"], ctx["cert_identity"]))
        if not ctx["sig_ok"]:
            return deny("message signature invalid")
        if not ctx["replay_ok"]:
            return deny("anti-replay: " + ctx["replay_reason"])
        if not ctx["rate_ok"]:
            return deny("rate limit exceeded")
        if ctx["quarantined"]:
            return deny("device quarantined")
        return Decision("allow", ["trust %.2f" % ctx["trust"]])

    def decide_command(self, ctx):
        """ctx: cert_ok, cert_reason, role, token_ok, token_reason, claims,
        cert_serial, action, sig_ok, replay_ok, replay_reason, now, plant_under_attack,
        target_quarantined."""
        if not ctx["cert_ok"]:
            return deny("console identity rejected: " + ctx["cert_reason"])
        if ctx["role"] != "console":
            return deny("commands must come from an operator console")
        if not ctx["token_ok"]:
            return deny("operator token rejected: " + ctx["token_reason"])
        claims = ctx["claims"]
        if claims.get("cnf") != str(ctx["cert_serial"]):
            return deny("token is bound to a different console (stolen token?)")
        if not ctx["sig_ok"]:
            return deny("command signature invalid")
        if not ctx["replay_ok"]:
            return deny("anti-replay: " + ctx["replay_reason"])
        action = ctx["action"]
        if action not in ACTIONS:
            return deny("unknown action %r" % action)
        scope, critical = ACTIONS[action]
        if scope not in claims["scope"]:
            return deny("operator %s lacks scope %r" % (claims["sub"], scope))
        if ctx.get("target_quarantined") and action != "device.reinstate":
            return deny("target device is quarantined")
        if critical:
            max_age = (STEP_UP_MAX_AGE_UNDER_ATTACK_S if ctx["plant_under_attack"]
                       else STEP_UP_MAX_AGE_S)
            if not BIOMETRIC_AMR <= set(claims["amr"]):
                return Decision("step_up", ["critical action requires fingerprint + liveness"])
            age = ctx["now"] - claims["auth_time"]
            if age > max_age:
                return Decision("step_up", ["critical action: biometric is %ds old, max %ds%s"
                                            % (age, max_age, " (plant under attack)"
                                               if ctx["plant_under_attack"] else "")])
        return Decision("allow", ["%s by %s" % (action, claims["sub"])])

    def decide_m2m(self, ctx):
        """ctx: cert_ok, cert_reason, role, sig_ok, replay_ok, replay_reason, trust,
        quarantined, degraded, min_trust, msg_type."""
        if not ctx["cert_ok"]:
            return deny("peer identity rejected: " + ctx["cert_reason"])
        if not ctx["sig_ok"]:
            return deny("peer message signature invalid")
        if not ctx["replay_ok"]:
            return deny("anti-replay: " + ctx["replay_reason"])
        if ctx["quarantined"]:
            return deny("peer quarantined")
        if ctx.get("degraded") and ctx["msg_type"] == "level":
            return deny("peer degraded (%s): process value not usable until maintenance"
                        % ctx["degraded"])
        if ctx["trust"] < ctx["min_trust"]:
            return deny("peer trust %.2f below M2M minimum" % ctx["trust"])
        if ctx["msg_type"] == "level" and ctx["role"] != "sensor":
            return deny("only sensors may publish process values")
        return Decision("allow", ["peer trust %.2f" % ctx["trust"]])
