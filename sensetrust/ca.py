"""
Device identity: a small private certificate authority.

Every device, operator console and the gateway itself gets an X.509 certificate issued
here. The certificate *is* the identity: the subject CN is the device ID and the OU is its
role (sensor, actuator, console, gateway). Nothing in the system trusts an identity that
is only asserted in a request body — it has to be backed by a certificate this CA signed,
still within its validity window and not revoked.

Keys are ECDSA P-256: small, fast, and supported by the constrained TLS stacks on real
field devices (mbedTLS, wolfSSL).

Field devices never get a key from the CA. They generate their own key pair, prove they
hold it by signing a certificate request (PKCS#10 CSR), and redeem a one-time enrolment
token that an administrator created for that device ID and role (the EST pattern,
RFC 7030). The CA stores certificates only, so a copy of the CA's disk gives an attacker
no device keys. `issue()` (CA-generated key) remains for the gateway's own certificate,
which lives on the same host as the CA, and for building attacker CAs in tests.
"""

import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import ssl
import threading
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROLES = ("sensor", "actuator", "console", "gateway", "broker", "service")
SERVER_ROLES = ("gateway", "broker")      # TLS servers; everything else is a TLS client

DEVICE_CERT_DAYS = 30                     # short-lived: renewed on site, automatically
ENROLMENT_TOKEN_TTL_S = 24 * 3600


class EnrolmentError(Exception):
    pass


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def load_cert(data):
    """PEM or DER bytes (or a PEM str) -> x509.Certificate."""
    if isinstance(data, x509.Certificate):
        return data
    if isinstance(data, str):
        data = data.encode()
    if data.lstrip().startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def identity_of(cert):
    """(device_id, role) from a certificate's subject."""
    cert = load_cert(cert)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    return (cn[0].value if cn else None, ou[0].value if ou else None)


class CertificateAuthority:
    """
    Issues, verifies and revokes device certificates.

    State lives in `directory`: ca.key / ca.crt, one <id>.key / <id>.crt per issued
    identity, and revoked.json (serial -> reason). Revocation takes effect on the very
    next request because `verify` consults the list on every call — there is no cached
    "already authenticated" state anywhere.
    """

    def __init__(self, directory, name="SenseTrust Plant CA"):
        self.dir = directory
        os.makedirs(os.path.join(directory, "issued"), exist_ok=True)
        self._lock = threading.Lock()
        key_path = os.path.join(directory, "ca.key")
        crt_path = os.path.join(directory, "ca.crt")
        if os.path.exists(key_path) and os.path.exists(crt_path):
            with open(key_path, "rb") as f:
                self.key = serialization.load_pem_private_key(f.read(), password=None)
            with open(crt_path, "rb") as f:
                self.cert = x509.load_pem_x509_certificate(f.read())
        else:
            self.key = ec.generate_private_key(ec.SECP256R1())
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name),
                                 x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YellowSense")])
            self.cert = (x509.CertificateBuilder()
                         .subject_name(subject).issuer_name(subject)
                         .public_key(self.key.public_key())
                         .serial_number(x509.random_serial_number())
                         .not_valid_before(_now() - dt.timedelta(minutes=5))
                         .not_valid_after(_now() + dt.timedelta(days=3650))
                         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                         .add_extension(x509.KeyUsage(False, False, False, False, False,
                                                      True, True, False, False), critical=True)
                         .sign(self.key, hashes.SHA256()))
            with open(key_path, "wb") as f:
                f.write(_key_pem(self.key))
            os.chmod(key_path, 0o600)
            with open(crt_path, "wb") as f:
                f.write(self.cert.public_bytes(serialization.Encoding.PEM))
        self._revoked_path = os.path.join(directory, "revoked.json")
        self._revoked = {}
        if os.path.exists(self._revoked_path):
            with open(self._revoked_path) as f:
                self._revoked = json.load(f)
        self._tokens_path = os.path.join(directory, "enrolment_tokens.json")
        self._tokens = {}
        if os.path.exists(self._tokens_path):
            with open(self._tokens_path) as f:
                self._tokens = json.load(f)
        self.crl_path = os.path.join(directory, "crl.pem")
        self.on_revoke = []           # callbacks, e.g. reload the MQTT broker's CRL
        self.write_crl()

    @property
    def ca_cert_path(self):
        return os.path.join(self.dir, "ca.crt")

    def paths(self, identity):
        base = os.path.join(self.dir, "issued", identity)
        return base + ".key", base + ".crt"

    # ── issuance ─────────────────────────────────────────────────────────────

    def _sign_cert(self, identity, role, public_key, days, hostnames=(), now=None, uri=None):
        if role not in ROLES:
            raise ValueError("unknown role %r" % role)
        now = now or _now()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity),
                             x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role),
                             x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YellowSense")])
        eku = ([ExtendedKeyUsageOID.SERVER_AUTH] if role in SERVER_ROLES
                else [ExtendedKeyUsageOID.CLIENT_AUTH])
        builder = (x509.CertificateBuilder()
                   .subject_name(subject).issuer_name(self.cert.subject)
                   .public_key(public_key)
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - dt.timedelta(minutes=5))
                   .not_valid_after(now + dt.timedelta(days=days))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage(eku), critical=False))
        
        sans = []
        if hostnames:
            for h in hostnames:
                try:
                    sans.append(x509.IPAddress(ipaddress.ip_address(h)))
                except ValueError:
                    sans.append(x509.DNSName(h))
        if uri:
            sans.append(x509.UniformResourceIdentifier(uri))
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

        cert = builder.sign(self.key, hashes.SHA256())
        with open(self.paths(identity)[1], "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return cert

    def issue(self, identity, role, public_key=None, days=DEVICE_CERT_DAYS, hostnames=(), uri=None, now=None):
        """Issue a certificate where the CA generates the key. Returns (key, cert)."""
        key_path, crt_path = self.paths(identity)
        if public_key is None:
            key = ec.generate_private_key(ec.SECP256R1())
            with open(key_path, "wb") as f:
                f.write(_key_pem(key))
            os.chmod(key_path, 0o600)
            public_key = key.public_key()
        else:
            key = None
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    key = serialization.load_pem_private_key(f.read(), password=None)
        cert = self._sign_cert(identity, role, public_key, days, hostnames, now, uri)
        return key, cert

    def current_cert(self, identity):
        """The most recently issued certificate for `identity`, or None."""
        path = self.paths(identity)[1]
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    # ── enrolment: device-generated keys, one-time tokens ───────────────────

    @staticmethod
    def _token_hash(secret):
        return hashlib.sha256(secret.encode()).hexdigest()

    def _save_tokens(self):
        tmp = self._tokens_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self._tokens, f, indent=2)
        os.replace(tmp, self._tokens_path)

    def create_enrolment_token(self, identity, role, ttl_s=ENROLMENT_TOKEN_TTL_S, now=None):
        if role not in ROLES or role in SERVER_ROLES:
            raise ValueError("devices cannot enrol as %r" % role)
        now = now if now is not None else time.time()
        token_id = secrets.token_hex(4)
        secret = secrets.token_urlsafe(24)
        with self._lock:
            self._tokens[token_id] = {"identity": identity, "role": role,
                                      "hash": self._token_hash(secret),
                                      "expires": now + ttl_s, "used": False}
            self._save_tokens()
        return "%s.%s" % (token_id, secret)

    def enrol(self, token, csr_pem, days=DEVICE_CERT_DAYS, now=None):
        now_s = now if now is not None else time.time()
        try:
            token_id, secret = token.split(".", 1)
        except (AttributeError, ValueError):
            raise EnrolmentError("malformed enrolment token")
        try:
            csr = x509.load_pem_x509_csr(csr_pem if isinstance(csr_pem, bytes) else csr_pem.encode())
        except ValueError:
            raise EnrolmentError("unparseable CSR")
        with self._lock:
            rec = self._tokens.get(token_id)
            if rec is None:
                raise EnrolmentError("unknown enrolment token")
            if rec["used"]:
                raise EnrolmentError("enrolment token already used")
            if now_s > rec["expires"]:
                raise EnrolmentError("enrolment token expired")
            if not hmac.compare_digest(rec["hash"], self._token_hash(secret)):
                raise EnrolmentError("enrolment token secret does not match")
            if not csr.is_signature_valid:
                raise EnrolmentError("CSR signature invalid: requester does not hold the key")
            cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not cn or cn[0].value != rec["identity"]:
                raise EnrolmentError("CSR is for %r but the token is for %r"
                                     % (cn[0].value if cn else None, rec["identity"]))
            rec["used"] = True
            rec["used_at"] = now_s
            self._save_tokens()
        return self._sign_cert(rec["identity"], rec["role"], csr.public_key(), days,
                               now=dt.datetime.fromtimestamp(now_s, dt.timezone.utc))

    def renew(self, presented_cert, csr_pem, days=DEVICE_CERT_DAYS, now=None):
        now_s = now if now is not None else time.time()
        ok, reason, identity, role = self.verify(presented_cert)
        if not ok:
            raise EnrolmentError("renewal refused: " + reason)
        if role in SERVER_ROLES:
            raise EnrolmentError("renewal refused: server identities are not renewed this way")
        presented_cert = load_cert(presented_cert)
        current = self.current_cert(identity)
        if current is None or current.serial_number != presented_cert.serial_number:
            raise EnrolmentError("renewal refused: not the current certificate for %s" % identity)
        try:
            csr = x509.load_pem_x509_csr(csr_pem if isinstance(csr_pem, bytes) else csr_pem.encode())
        except ValueError:
            raise EnrolmentError("renewal refused: unparseable CSR")
        if not csr.is_signature_valid:
            raise EnrolmentError("renewal refused: CSR signature invalid")
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn or cn[0].value != identity:
            raise EnrolmentError("renewal refused: CSR names a different device")
        old_pub = presented_cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        new_pub = csr.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if old_pub == new_pub:
            raise EnrolmentError("renewal refused: renewal must rotate to a new key")
        cert = self._sign_cert(identity, role, csr.public_key(), days,
                               now=dt.datetime.fromtimestamp(now_s, dt.timezone.utc))
        self.revoke(presented_cert, "superseded")
        return cert

    # ── revocation ───────────────────────────────────────────────────────────

    def revoke(self, cert, reason="unspecified"):
        cert = load_cert(cert)
        with self._lock:
            self._revoked[str(cert.serial_number)] = {
                "identity": identity_of(cert)[0], "reason": reason, "at": _now().isoformat()}
            tmp = self._revoked_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._revoked, f, indent=2)
            os.replace(tmp, self._revoked_path)
            self.write_crl()
        for callback in list(self.on_revoke):
            callback(cert)

    def write_crl(self):
        now = _now()
        builder = (x509.CertificateRevocationListBuilder()
                   .issuer_name(self.cert.subject)
                   .last_update(now - dt.timedelta(minutes=5))
                   .next_update(now + dt.timedelta(days=1)))
        for serial, rec in self._revoked.items():
            when = dt.datetime.fromisoformat(rec["at"]) if rec.get("at") else now
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder().serial_number(int(serial))
                .revocation_date(when).build())
        crl = builder.sign(self.key, hashes.SHA256())
        tmp = self.crl_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
        os.replace(tmp, self.crl_path)

    def is_revoked(self, cert):
        return str(load_cert(cert).serial_number) in self._revoked

    def revoked(self):
        return dict(self._revoked)

    # ── verification ─────────────────────────────────────────────────────────

    def verify(self, cert, expected_role=None):
        if cert is None:
            return False, "no client certificate", None, None
        try:
            cert = load_cert(cert)
        except Exception:
            return False, "unparseable certificate", None, None
        identity, role = identity_of(cert)
        try:
            cert.verify_directly_issued_by(self.cert)
        except (InvalidSignature, ValueError, TypeError):
            return False, "certificate not issued by plant CA", identity, role
        now = _now()
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            return False, "certificate expired or not yet valid", identity, role
        if self.is_revoked(cert):
            return False, "certificate revoked (%s)" % self._revoked[str(cert.serial_number)]["reason"], identity, role
        if expected_role and role != expected_role:
            return False, "role %r not permitted here (need %r)" % (role, expected_role), identity, role
        return True, "ok", identity, role

    # ── TLS contexts ─────────────────────────────────────────────────────────

    def server_context(self, identity):
        key_path, crt_path = self.paths(identity)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(crt_path, key_path)
        ctx.load_verify_locations(self.ca_cert_path)
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def client_context(self, identity):
        key_path, crt_path = self.paths(identity)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_verify_locations(self.ca_cert_path)
        ctx.load_cert_chain(crt_path, key_path)
        return ctx