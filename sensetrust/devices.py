"""
Client-side identities: sensors, actuators, operator consoles.

A device creates its own key pair. The private key never leaves the device: the CA only
ever sees a certificate request (CSR) signed with it. On real hardware the key is
generated inside a secure element or TPM and cannot be read out at all
(tools/hsm_enrol_demo.sh shows the same enrolment with a key held in a PKCS#11 token).
"""

import itertools
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .ca import load_cert
from .crypto import new_nonce, sign_envelope


def make_csr(key, identity):
    """PKCS#10 request for `identity`, self-signed with `key` (proof of possession)."""
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity)]))
           .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM)


class DeviceIdentity:
    """A device holding its private key and certificate, signing every message it sends."""

    def __init__(self, identity, key, cert, clock):
        self.identity = identity
        self.key = key
        self.cert = load_cert(cert) if cert is not None else None
        self.clock = clock
        self._seq = itertools.count(1)

    # ── provisioning ─────────────────────────────────────────────────────────

    @classmethod
    def generate(cls, identity, clock):
        """A new, not-yet-enrolled device: fresh key pair, no certificate."""
        return cls(identity, ec.generate_private_key(ec.SECP256R1()), None, clock)

    def csr(self):
        return make_csr(self.key, self.identity)

    def enrol(self, ca, token, **kw):
        """Commissioning: redeem the one-time token. (Over the network: POST /v1/enrol.)"""
        self.cert = ca.enrol(token, self.csr(), **kw)
        return self.cert

    def renew(self, ca, **kw):
        """Rotate to a new key; the current certificate authorises the renewal."""
        new_key = ec.generate_private_key(ec.SECP256R1())
        cert = ca.renew(self.cert, make_csr(new_key, self.identity), **kw)
        self.key, self.cert = new_key, cert
        return cert

    def save(self, directory):
        """Write key + certificate to the device's own storage. Returns (key_path, cert_path)."""
        os.makedirs(directory, exist_ok=True)
        key_path = os.path.join(directory, self.identity + ".key")
        crt_path = os.path.join(directory, self.identity + ".crt")
        with open(key_path, "wb") as f:
            f.write(self.key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        os.chmod(key_path, 0o600)
        with open(crt_path, "wb") as f:
            f.write(self.cert.public_bytes(serialization.Encoding.PEM))
        return key_path, crt_path

    @classmethod
    def load(cls, ca, identity, clock):
        """Load an identity whose key the CA generated (gateway-host identities, test CAs)."""
        key_path, crt_path = ca.paths(identity)
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        with open(crt_path, "rb") as f:
            cert = f.read()
        return cls(identity, key, cert, clock)

    @classmethod
    def commission(cls, ca, identity, role, clock, **kw):
        """Generate a key on the device and enrol it with a fresh one-time token."""
        dev = cls.generate(identity, clock)
        dev.enrol(ca, ca.create_enrolment_token(identity, role), **kw)
        return dev

    # ── messages ─────────────────────────────────────────────────────────────

    def envelope(self, **fields):
        body = {"device_id": self.identity, "nonce": new_nonce(), "ts": self.clock(),
                "seq": next(self._seq), **fields}
        return sign_envelope(self.key, body)

    def command(self, action, target, **params):
        body = {"device_id": self.identity, "nonce": new_nonce(), "ts": self.clock(),
                "action": action, "target": target, "params": params}
        return sign_envelope(self.key, body)
