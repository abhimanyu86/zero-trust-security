"""
Dynamic trust: every identity carries a score that its own behaviour moves.

A valid certificate says *who* a device is. It says nothing about whether the device is
behaving. Trust starts at 1.0, drops sharply on security evidence (bad signatures,
replays, being caught lying about the physics) and recovers slowly with clean traffic.
Below QUARANTINE the device is cut off and its certificate revoked — automatically, in
the same second, not after someone reads an alert.

Physical faults cost almost nothing: a broken sensor is not an adversary, and revoking
it would only make the maintenance crew's job harder.
"""

import threading

QUARANTINE = 0.3
M2M_MIN_TRUST = 0.6
RECOVERY_PER_MESSAGE = 0.002

PENALTY = {
    "bad_signature": 0.35,
    "identity_mismatch": 0.5,
    "replay": 0.35,
    "stale_timestamp": 0.1,
    "rate_limited": 0.05,
    "attack_detected": 1.0,        # caught lying about the process: straight to quarantine
    "ambiguous_anomaly": 0.2,      # drift or stealthy ramp: watch closely, don't revoke
    "fault_detected": 0.0,
    "policy_violation": 0.25,
}


class TrustRegistry:

    def __init__(self):
        self._score = {}
        self._quarantined = {}
        self._lock = threading.Lock()

    def score(self, identity):
        return self._score.get(identity, 1.0)

    def is_quarantined(self, identity):
        return identity in self._quarantined

    def quarantined(self):
        return dict(self._quarantined)

    def penalise(self, identity, reason):
        """Returns True if this penalty pushed the identity into quarantine."""
        with self._lock:
            s = max(0.0, self.score(identity) - PENALTY[reason])
            self._score[identity] = s
            if s < QUARANTINE and identity not in self._quarantined:
                self._quarantined[identity] = reason
                return True
            return False

    def reward(self, identity):
        with self._lock:
            if identity not in self._quarantined:
                self._score[identity] = min(1.0, self.score(identity) + RECOVERY_PER_MESSAGE)

    def snapshot(self):
        return {k: round(v, 3) for k, v in self._score.items()}
