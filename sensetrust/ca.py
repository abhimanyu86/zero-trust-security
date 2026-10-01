"""
Device identity: a small private certificate authority.

Every device, operator console and the gateway itself gets an X.509 certificate issued
here. The certificate *is* the identity: the subject CN is the device ID and the OU is its
role (sensor, actuator, console, gateway). Nothing in the system trusts an identity that
is only asserted in a request body — it has to be backed by a certificate this CA signed,
still within its validity window and not revoked.

Keys are ECDSA P-256: small, fast, and supported by the constrained TLS stacks on real
field devices (mbedTLS, wolfSSL).
"""

import datetime as dt
import ipaddress
import json
import os
import ssl
import threading

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROLES = ("sensor", "actuator", "console", "gateway")


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

    @property
    def ca_cert_path(self):
        return os.path.join(self.dir, "ca.crt")

    def paths(self, identity):
        base = os.path.join(self.dir, "issued", identity)
        return base + ".key", base + ".crt"

    # ── issuance ─────────────────────────────────────────────────────────────

    def issue(self, identity, role, days=365, hostnames=()):
        """Issue a key + certificate for `identity`. Returns (key, cert)."""
        if role not in ROLES:
            raise ValueError("unknown role %r" % role)
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity),
                             x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role),
                             x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YellowSense")])
        eku = [ExtendedKeyUsageOID.SERVER_AUTH] if role == "gateway" else [ExtendedKeyUsageOID.CLIENT_AUTH]
        builder = (x509.CertificateBuilder()
                   .subject_name(subject).issuer_name(self.cert.subject)
                   .public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(_now() - dt.timedelta(minutes=5))
                   .not_valid_after(_now() + dt.timedelta(days=days))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage(eku), critical=False))
        if hostnames:
            sans = []
            for h in hostnames:
                try:
                    sans.append(x509.IPAddress(ipaddress.ip_address(h)))
                except ValueError:
                    sans.append(x509.DNSName(h))
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        cert = builder.sign(self.key, hashes.SHA256())
        key_path, crt_path = self.paths(identity)
        with open(key_path, "wb") as f:
            f.write(_key_pem(key))
        os.chmod(key_path, 0o600)
        with open(crt_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return key, cert

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

    def is_revoked(self, cert):
        return str(load_cert(cert).serial_number) in self._revoked

    def revoked(self):
        return dict(self._revoked)

    # ── verification ─────────────────────────────────────────────────────────

    def verify(self, cert, expected_role=None):
        """
        Full check of a presented certificate. Returns (ok, reason, identity, role).

        Checks, in order: issued by this CA (signature), inside its validity window,
        not revoked, and — when asked — carries the expected role.
        """
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
        """Gateway side: TLS 1.3 only, client certificate REQUIRED (mutual TLS)."""
        key_path, crt_path = self.paths(identity)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(crt_path, key_path)
        ctx.load_verify_locations(self.ca_cert_path)
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def client_context(self, identity):
        """Device side: presents its own certificate, pins the plant CA for the server."""
        key_path, crt_path = self.paths(identity)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_verify_locations(self.ca_cert_path)
        ctx.load_cert_chain(crt_path, key_path)
        return ctx
