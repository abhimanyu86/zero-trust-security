"""Client-side identities: sensors, actuators, operator consoles."""

import itertools

from cryptography.hazmat.primitives import serialization

from .ca import load_cert
from .crypto import new_nonce, sign_envelope


class DeviceIdentity:
    """A device holding its private key and certificate, signing every message it sends."""

    def __init__(self, identity, key, cert, clock):
        self.identity = identity
        self.key = key
        self.cert = load_cert(cert)
        self.clock = clock
        self._seq = itertools.count(1)

    @classmethod
    def load(cls, ca, identity, clock):
        key_path, crt_path = ca.paths(identity)
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        with open(crt_path, "rb") as f:
            cert = f.read()
        return cls(identity, key, cert, clock)

    def envelope(self, **fields):
        body = {"device_id": self.identity, "nonce": new_nonce(), "ts": self.clock(),
                "seq": next(self._seq), **fields}
        return sign_envelope(self.key, body)

    def command(self, action, target, **params):
        body = {"device_id": self.identity, "nonce": new_nonce(), "ts": self.clock(),
                "action": action, "target": target, "params": params}
        return sign_envelope(self.key, body)
