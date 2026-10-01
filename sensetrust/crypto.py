"""
Cryptographic building blocks: request signing, short-lived access tokens, and
encryption at rest.

- Request signing (ECDSA P-256, the device's own certificate key): every message a
  device sends is signed over a canonical JSON encoding, so the payload is bound to the
  identity even if it is relayed through a broker or stored and forwarded.
- Access tokens (Ed25519): issued to operators after biometric login. Short-lived, scoped,
  and record *how* the operator authenticated (amr) and *when* (auth_time), which the
  policy engine uses for step-up decisions.
- Sealed storage (AES-256-GCM): biometric templates and telemetry are encrypted before
  they touch disk, with the record's identity bound in as associated data so a ciphertext
  cannot be swapped between records.
"""

import base64
import json
import os
import time
import uuid

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical(obj):
    """Deterministic bytes for signing: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ── request signing ──────────────────────────────────────────────────────────

def sign_envelope(private_key, body):
    """Wrap `body` in a signed envelope: {"body": ..., "sig": base64 ECDSA-SHA256}."""
    sig = private_key.sign(canonical(body), ec.ECDSA(hashes.SHA256()))
    return {"body": body, "sig": b64e(sig)}


def verify_envelope(public_key, envelope):
    try:
        public_key.verify(b64d(envelope["sig"]), canonical(envelope["body"]),
                          ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False


def new_nonce():
    return uuid.uuid4().hex


# ── access tokens ────────────────────────────────────────────────────────────

class TokenError(Exception):
    pass


class TokenService:
    """
    Compact signed tokens: b64(header).b64(claims).b64(Ed25519 signature).

    Deliberately minimal rather than a general JWT library: one algorithm, no "alg"
    negotiation, so the classic alg=none / algorithm-confusion attacks do not exist.
    """

    HEADER = {"typ": "ST", "alg": "Ed25519"}

    def __init__(self, key_path=None):
        if key_path and os.path.exists(key_path):
            with open(key_path, "rb") as f:
                self._key = serialization.load_pem_private_key(f.read(), password=None)
        else:
            self._key = ed25519.Ed25519PrivateKey.generate()
            if key_path:
                with open(key_path, "wb") as f:
                    f.write(self._key.private_bytes(serialization.Encoding.PEM,
                                                    serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))
                os.chmod(key_path, 0o600)
        self._pub = self._key.public_key()
        self._revoked_jti = set()

    def issue(self, subject, role, scopes, amr, ttl=300, bind_cert_serial=None, now=None):
        now = int(now if now is not None else time.time())
        claims = {"sub": subject, "role": role, "scope": sorted(scopes), "amr": sorted(amr),
                  "iat": now, "auth_time": now, "exp": now + ttl, "jti": uuid.uuid4().hex}
        if bind_cert_serial is not None:
            # Token is only usable over a connection presenting this certificate
            # (sender-constrained, in the spirit of RFC 8705).
            claims["cnf"] = str(bind_cert_serial)
        head = b64e(canonical(self.HEADER))
        body = b64e(canonical(claims))
        sig = b64e(self._key.sign((head + "." + body).encode()))
        return "%s.%s.%s" % (head, body, sig)

    def verify(self, token, now=None):
        try:
            head, body, sig = token.split(".")
            self._pub.verify(b64d(sig), (head + "." + body).encode())
            if json.loads(b64d(head)) != self.HEADER:
                raise TokenError("unexpected token header")
            claims = json.loads(b64d(body))
        except TokenError:
            raise
        except (ValueError, InvalidSignature, AttributeError):
            raise TokenError("invalid token signature or format")
        now = now if now is not None else time.time()
        if claims["exp"] < now:
            raise TokenError("token expired")
        if claims["jti"] in self._revoked_jti:
            raise TokenError("token revoked")
        return claims

    def revoke(self, jti):
        self._revoked_jti.add(jti)


# ── encryption at rest ───────────────────────────────────────────────────────

class SealedStore:
    """AES-256-GCM record sealing with the record ID bound in as associated data."""

    def __init__(self, key=None, key_path=None):
        if key is None and key_path and os.path.exists(key_path):
            with open(key_path, "rb") as f:
                key = f.read()
        if key is None:
            key = AESGCM.generate_key(bit_length=256)
            if key_path:
                with open(key_path, "wb") as f:
                    f.write(key)
                os.chmod(key_path, 0o600)
        self._aead = AESGCM(key)

    def seal(self, record_id, obj):
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, canonical(obj), record_id.encode())
        return {"id": record_id, "n": b64e(nonce), "ct": b64e(ct)}

    def open(self, sealed, record_id=None):
        rid = record_id if record_id is not None else sealed["id"]
        try:
            pt = self._aead.decrypt(b64d(sealed["n"]), b64d(sealed["ct"]), rid.encode())
        except InvalidTag:
            raise ValueError("sealed record failed authentication (tampered or wrong record id)")
        return json.loads(pt)
