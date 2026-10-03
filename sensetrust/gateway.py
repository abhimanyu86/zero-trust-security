"""
The zero-trust gateway: policy enforcement point for everything that touches the plant.

Transport-independent on purpose. `server.py` puts it behind mutual TLS over HTTPS and
passes in the certificate the TLS handshake verified; the simulator and tests call it
directly with the same certificate objects. Either way, the same code decides.

Per request:
    1. identity    certificate issued by the plant CA, valid, not revoked, right role
    2. integrity   payload signature verifies against that certificate's key
    3. freshness   timestamp within skew, nonce unseen, sequence increasing
    4. behaviour   rate limit, trust score, quarantine status
    5. policy      PolicyEngine decides allow / deny / step-up
    6. evidence    denials feed the trust registry and the anomaly detector

And once per second, over the accepted telemetry:
    7. physics     FaultAttackDetector checks the readings against each other
    8. response    attack -> quarantine + revoke; fault -> maintenance ticket;
                   ambiguous -> ticket + reduced trust
"""

import json
import os
import threading
import time
from collections import deque

from .anomaly import FaultAttackDetector
from .biometric import OperatorRegistry
from .ca import CertificateAuthority, load_cert
from .crypto import SealedStore, TokenError, TokenService, verify_envelope
from .plant import SENSORS
from .policy import PolicyEngine
from .replay import RateLimiter, ReplayGuard
from .trust import M2M_MIN_TRUST, TrustRegistry

ATTACK_MEMORY_S = 600
DENY_TO_PENALTY = [
    ("signature", "bad_signature"),
    ("payload claims", "identity_mismatch"),
    ("replay", "replay"),
    ("stale_timestamp", "stale_timestamp"),
    ("rate limit", "rate_limited"),
]


class Gateway:

    def __init__(self, data_dir, calibration=None, clock=time.time):
        os.makedirs(data_dir, exist_ok=True)
        self.dir = data_dir
        self.clock = clock
        self.ca = CertificateAuthority(os.path.join(data_dir, "pki"))
        self.tokens = TokenService(os.path.join(data_dir, "token_signing.key"))
        self.store = SealedStore(key_path=os.path.join(data_dir, "storage.key"))
        self.operators = OperatorRegistry(self.store, os.path.join(data_dir, "operators.sealed.json"))
        self.trust = TrustRegistry()
        self.replay = ReplayGuard(clock)
        self.rate = RateLimiter(rate_per_s=5.0, burst=10, clock=clock)
        self.policy = PolicyEngine()
        self.detector = FaultAttackDetector(calibration)
        self.events = []
        self.tickets = []
        self.latency_us = deque(maxlen=5000)
        self._frame = {}
        self._certs = {}
        self.degraded = {}          # sensor -> reason: faulty, not hostile; kept out of control loops
        self._last_attack_t = None
        self._lock = threading.RLock()
        self._telemetry_log = open(os.path.join(data_dir, "telemetry.sealed.jsonl"), "a")

    # ── bookkeeping ──────────────────────────────────────────────────────────

    def _event(self, kind, severity, subject, detail, **extra):
        e = {"ts": round(self.clock(), 3), "kind": kind, "severity": severity,
             "subject": subject, "detail": detail, **extra}
        self.events.append(e)
        return e

    def _check_cert(self, peer_cert, expected_role=None):
        ok, reason, identity, role = self.ca.verify(peer_cert, expected_role)
        cert = None
        if peer_cert is not None:
            try:
                cert = load_cert(peer_cert)
            except Exception:
                cert = None
        if ok:
            self._certs[identity] = cert
        return ok, reason, identity, role, cert

    def _penalise_for(self, identity, decision_reasons):
        text = " ".join(decision_reasons)
        for needle, penalty in DENY_TO_PENALTY:
            if needle in text:
                self.detector.note_channel_event(identity, penalty)
                if self.trust.penalise(identity, penalty):
                    self._quarantine(identity, penalty)
                return

    def _quarantine(self, identity, reason):
        cert = self._certs.get(identity)
        if cert is not None and not self.ca.is_revoked(cert):
            self.ca.revoke(cert, reason)
        self._event("quarantine", "critical", identity,
                    "identity quarantined and certificate revoked (%s)" % reason)

    @property
    def under_attack(self):
        return (self._last_attack_t is not None
                and self.clock() - self._last_attack_t < ATTACK_MEMORY_S)

    # ── telemetry ────────────────────────────────────────────────────────────

    def telemetry(self, peer_cert, envelope):
        t0 = time.perf_counter()
        with self._lock:
            cert_ok, cert_reason, identity, role, cert = self._check_cert(peer_cert)
            body = envelope.get("body", {}) if isinstance(envelope, dict) else {}
            sig_ok = cert is not None and verify_envelope(cert.public_key(), envelope)
            replay_ok, replay_reason = (self.replay.check(identity, body.get("nonce"),
                                                          body.get("ts", 0), body.get("seq"))
                                        if cert_ok and sig_ok else (True, "not checked"))
            rate_ok = self.rate.allow(identity) if cert_ok else True
            ctx = {"cert_ok": cert_ok, "cert_reason": cert_reason, "role": role,
                   "cert_identity": identity, "claimed_identity": body.get("device_id"),
                   "sig_ok": sig_ok, "replay_ok": replay_ok, "replay_reason": replay_reason,
                   "rate_ok": rate_ok, "quarantined": self.trust.is_quarantined(identity),
                   "trust": self.trust.score(identity)}
            decision = self.policy.decide_telemetry(ctx)
            if decision.allowed:
                self.trust.reward(identity)
                self._frame[identity] = body.get("value")
                sealed = self.store.seal("telemetry:%s:%s" % (identity, body.get("seq")), body)
                self._telemetry_log.write(json.dumps(sealed) + "\n")
            else:
                self._event("telemetry_denied", "warning", identity or "unknown",
                            "; ".join(decision.reasons))
                if cert_ok:
                    self._penalise_for(identity, decision.reasons)
        self.latency_us.append((time.perf_counter() - t0) * 1e6)
        return decision.as_dict()

    def process_tick(self, pump, valve):
        """Run the physics check over this second's accepted telemetry."""
        with self._lock:
            # Quarantined and degraded sensors are out of the physics check as well as the
            # control loop: their values are already known to be wrong, and feeding them in
            # would make the honest instruments disagree with them and look faulty.
            readings = {s: (None if self.trust.is_quarantined(s) or s in self.degraded
                            else self._frame.get(s)) for s in SENSORS}
            self._frame = {}
            diagnoses = self.detector.update(readings, pump, valve)
            for d in diagnoses:
                ev = d.as_dict()
                if d.verdict == "attack":
                    self._last_attack_t = self.clock()
                    self._event("attack_detected", "critical", d.sensor,
                                "%s — sensor disagrees with plant physics" % d.kind, diagnosis=ev)
                    if self.trust.penalise(d.sensor, "attack_detected"):
                        self._quarantine(d.sensor, "attack_detected: " + d.kind)
                elif d.verdict == "fault":
                    self._event("fault_detected", "info", d.sensor,
                                "%s — maintenance ticket raised, identity untouched" % d.kind,
                                diagnosis=ev)
                    self.tickets.append({"sensor": d.sensor, "type": "maintenance", "kind": d.kind})
                    self.degraded[d.sensor] = d.kind
                else:
                    self._event("ambiguous_anomaly", "warning", d.sensor,
                                "slow divergence: calibration drift or stealth attack — "
                                "inspection ticket + reduced trust", diagnosis=ev)
                    self.tickets.append({"sensor": d.sensor, "type": "inspect", "kind": d.kind})
                    self.degraded[d.sensor] = d.kind
                    if self.trust.penalise(d.sensor, "ambiguous_anomaly"):
                        self._quarantine(d.sensor, "ambiguous_anomaly")
            return diagnoses

    def safe_level(self):
        """Level for control when LT-101 cannot be trusted: pressure-derived / observer."""
        d = self.detector
        cands = [h["L2"] for h in d.history[-1:] if h["L2"] is not None]
        if d.L3 is not None:
            cands.append(d.L3)
        return sum(cands) / len(cands) if cands else None

    # ── operators ────────────────────────────────────────────────────────────

    def operator_login(self, peer_cert, operator_id, minutiae, image_bgr):
        t0 = time.perf_counter()
        with self._lock:
            cert_ok, cert_reason, identity, role, cert = self._check_cert(peer_cert, "console")
            if not cert_ok:
                self._event("login_denied", "warning", operator_id, "console rejected: " + cert_reason)
                return {"ok": False, "reasons": ["console rejected: " + cert_reason]}
            result = self.operators.verify(operator_id, minutiae, image_bgr)
            if not result.ok:
                self._event("login_denied", "critical" if not result.live else "warning",
                            operator_id, "; ".join(result.reasons), console=identity,
                            match_score=result.score)
                if not result.live and self.trust.penalise("operator:" + operator_id, "policy_violation"):
                    self._event("quarantine", "critical", operator_id, "operator locked after spoof attempts")
                return {"ok": False, "reasons": result.reasons, "score": result.score,
                        "live": result.live}
            if self.trust.is_quarantined("operator:" + operator_id):
                return {"ok": False, "reasons": ["operator locked"]}
            prof = self.operators.profile(operator_id)
            token = self.tokens.issue(operator_id, prof["role"], prof["scopes"],
                                      amr=["fingerprint", "liveness", "mtls"], ttl=900,
                                      bind_cert_serial=cert.serial_number, now=self.clock())
            self._event("login", "info", operator_id,
                        "fingerprint %.2f + liveness ok on %s" % (result.score, identity))
        self.latency_us.append((time.perf_counter() - t0) * 1e6)
        return {"ok": True, "token": token, "score": result.score}

    def command(self, peer_cert, token, envelope):
        t0 = time.perf_counter()
        with self._lock:
            cert_ok, cert_reason, identity, role, cert = self._check_cert(peer_cert)
            body = envelope.get("body", {})
            try:
                claims, token_ok, token_reason = self.tokens.verify(token, now=self.clock()), True, "ok"
            except TokenError as e:
                claims, token_ok, token_reason = {}, False, str(e)
            sig_ok = cert is not None and verify_envelope(cert.public_key(), envelope)
            replay_ok, replay_reason = (self.replay.check(identity, body.get("nonce"), body.get("ts", 0))
                                        if cert_ok and sig_ok else (True, "not checked"))
            target = body.get("target")
            ctx = {"cert_ok": cert_ok, "cert_reason": cert_reason, "role": role,
                   "token_ok": token_ok, "token_reason": token_reason, "claims": claims,
                   "cert_serial": cert.serial_number if cert is not None else None,
                   "action": body.get("action"), "sig_ok": sig_ok, "replay_ok": replay_ok,
                   "replay_reason": replay_reason, "now": self.clock(),
                   "plant_under_attack": self.under_attack,
                   "target_quarantined": bool(target) and self.trust.is_quarantined(target)}
            decision = self.policy.decide_command(ctx)
            who = claims.get("sub", identity or "unknown")
            sev = {"allow": "info", "step_up": "warning", "deny": "warning"}[decision.effect]
            self._event("command_" + decision.effect, sev, who,
                        "%s -> %s: %s" % (body.get("action"), target, "; ".join(decision.reasons)))
            if decision.allowed and body.get("action") == "device.reinstate":
                self._reinstate(target, who)
        self.latency_us.append((time.perf_counter() - t0) * 1e6)
        return decision.as_dict()

    def _reinstate(self, identity, by):
        """After maintenance: fresh key + certificate, trust reset. Old cert stays revoked."""
        role = "sensor" if identity in SENSORS else "actuator"
        self.ca.issue(identity, role)
        self.trust._quarantined.pop(identity, None)
        self.trust._score[identity] = 0.7
        self.detector.alarmed.pop(identity, None)
        self.degraded.pop(identity, None)
        self._event("reinstated", "info", identity, "new certificate issued, approved by %s" % by)

    # ── machine-to-machine ───────────────────────────────────────────────────

    def authorize_m2m(self, peer_cert, envelope, msg_type):
        """
        Trust service for device-to-device messages (e.g. LT-101 -> P-101 level feed).
        The receiving device asks: is this peer who it says, is the message intact and
        fresh, and is the peer *currently* trustworthy?
        """
        t0 = time.perf_counter()
        with self._lock:
            cert_ok, cert_reason, identity, role, cert = self._check_cert(peer_cert)
            body = envelope.get("body", {})
            sig_ok = cert is not None and verify_envelope(cert.public_key(), envelope)
            replay_ok, replay_reason = (self.replay.check("m2m:" + str(identity), body.get("nonce"),
                                                          body.get("ts", 0), body.get("seq"))
                                        if cert_ok and sig_ok else (True, "not checked"))
            ctx = {"cert_ok": cert_ok, "cert_reason": cert_reason, "role": role,
                   "sig_ok": sig_ok, "replay_ok": replay_ok, "replay_reason": replay_reason,
                   "trust": self.trust.score(identity),
                   "quarantined": self.trust.is_quarantined(identity), "msg_type": msg_type,
                   "degraded": self.degraded.get(identity),
                   "min_trust": M2M_MIN_TRUST}
            decision = self.policy.decide_m2m(ctx)
            if not decision.allowed:
                self._event("m2m_denied", "warning", identity or "unknown", "; ".join(decision.reasons))
        self.latency_us.append((time.perf_counter() - t0) * 1e6)
        return decision.as_dict()

    # ── views ────────────────────────────────────────────────────────────────

    def state(self):
        return {"trust": self.trust.snapshot(), "quarantined": self.trust.quarantined(),
                "degraded": dict(self.degraded),
                "revoked": self.ca.revoked(), "under_attack": self.under_attack,
                "tickets": list(self.tickets), "events": self.events[-200:]}

    def close(self):
        self._telemetry_log.close()

