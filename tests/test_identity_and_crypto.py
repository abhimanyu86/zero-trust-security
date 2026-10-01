import threading
import time

import pytest

from sensetrust.ca import CertificateAuthority
from sensetrust.crypto import SealedStore, TokenError, TokenService, sign_envelope, verify_envelope
from sensetrust.devices import DeviceIdentity
from sensetrust.gateway import Gateway
from sensetrust.replay import RateLimiter, ReplayGuard
from sensetrust.server import post, serve


@pytest.fixture
def ca(tmp_path):
    return CertificateAuthority(str(tmp_path / "pki"))


def test_issued_certificate_verifies_with_role(ca):
    _, cert = ca.issue("LT-101", "sensor")
    ok, reason, ident, role = ca.verify(cert, expected_role="sensor")
    assert ok and ident == "LT-101" and role == "sensor"


def test_certificate_from_foreign_ca_is_rejected(ca, tmp_path):
    rogue = CertificateAuthority(str(tmp_path / "rogue"))
    _, cert = rogue.issue("LT-101", "sensor")
    ok, reason, _, _ = ca.verify(cert)
    assert not ok and "not issued by plant CA" in reason


def test_revocation_is_immediate_and_persistent(ca):
    _, cert = ca.issue("PT-101", "sensor")
    ca.revoke(cert, "test")
    assert not ca.verify(cert)[0]
    reloaded = CertificateAuthority(ca.dir)
    assert not reloaded.verify(cert)[0]


def test_wrong_role_rejected(ca):
    _, cert = ca.issue("XV-101", "actuator")
    ok, reason, _, _ = ca.verify(cert, expected_role="console")
    assert not ok and "role" in reason


def test_envelope_signature_detects_tampering(ca):
    key, _ = ca.issue("FT-101", "sensor")
    env = sign_envelope(key, {"device_id": "FT-101", "value": 0.007})
    assert verify_envelope(key.public_key(), env)
    env["body"]["value"] = 0.0
    assert not verify_envelope(key.public_key(), env)


def test_token_roundtrip_expiry_and_tamper():
    ts = TokenService()
    tok = ts.issue("asha", "shift_supervisor", ["actuate"], ["fingerprint", "liveness"], ttl=60, now=1000)
    assert ts.verify(tok, now=1010)["sub"] == "asha"
    with pytest.raises(TokenError):
        ts.verify(tok, now=2000)
    head, body, sig = tok.split(".")
    with pytest.raises(TokenError):
        ts.verify(head + "." + body[:-2] + "AA." + sig, now=1010)


def test_token_from_other_issuer_rejected():
    tok = TokenService().issue("x", "operator", [], [], now=1000)
    with pytest.raises(TokenError):
        TokenService().verify(tok, now=1001)


def test_sealed_store_binds_record_id():
    st = SealedStore()
    sealed = st.seal("operator:asha", {"minutiae": [1, 2, 3]})
    assert st.open(sealed) == {"minutiae": [1, 2, 3]}
    with pytest.raises(ValueError):
        st.open(sealed, "operator:ravi")      # swapping ciphertext between records fails


def test_replay_guard_nonce_seq_and_skew():
    now = [1000.0]
    g = ReplayGuard(clock=lambda: now[0])
    assert g.check("a", "n1", 1000, 1)[0]
    assert g.check("a", "n1", 1000, 2) == (False, "replay")
    assert g.check("a", "n2", 1000, 1) == (False, "replay")      # sequence went backwards
    assert g.check("a", "n3", 900, 3) == (False, "stale_timestamp")


def test_rate_limiter():
    now = [0.0]
    rl = RateLimiter(rate_per_s=1, burst=3, clock=lambda: now[0])
    assert [rl.allow("d") for _ in range(4)] == [True, True, True, False]
    now[0] += 1.0
    assert rl.allow("d")


def test_mutual_tls_over_real_sockets(tmp_path):
    """No plant-CA certificate: the TLS handshake itself fails. With one: request reaches policy."""
    import socket
    import ssl

    gw = Gateway(str(tmp_path / "gw"))
    gw.ca.issue("gateway", "gateway", hostnames=("127.0.0.1",))
    gw.ca.issue("PT-101", "sensor")
    httpd = serve(gw, "127.0.0.1", 0)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        dev = DeviceIdentity.load(gw.ca, "PT-101", time.time)
        status, resp = post(gw.ca.client_context("PT-101"), "127.0.0.1", port, "/v1/telemetry",
                            dev.envelope(value=12.3))
        assert status == 200 and resp["effect"] == "allow"

        # Client with no certificate: server demands one; handshake/first read fails.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(gw.ca.ca_cert_path)
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as s:
                    s.sendall(b"GET /v1/state HTTP/1.1\r\nHost: x\r\n\r\n")
                    if not s.recv(1):
                        raise ConnectionError("closed")

        # Client with a certificate from a different CA: rejected at handshake.
        rogue = CertificateAuthority(str(tmp_path / "rogue"))
        rogue.issue("PT-101", "sensor")
        rctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        rctx.load_verify_locations(gw.ca.ca_cert_path)
        rctx.load_cert_chain(*reversed(rogue.paths("PT-101")))
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            post(rctx, "127.0.0.1", port, "/v1/telemetry", dev.envelope(value=1.0))

        # Revoked mid-life: TLS still completes (CA signature is valid) but policy denies.
        gw.ca.revoke(dev.cert, "test")
        status, resp = post(gw.ca.client_context("PT-101"), "127.0.0.1", port, "/v1/telemetry",
                            dev.envelope(value=12.3))
        assert status == 403 and "revoked" in resp["reasons"][0]
    finally:
        httpd.shutdown()
        gw.close()
