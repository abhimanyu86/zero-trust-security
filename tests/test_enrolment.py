"""Device enrolment: device-generated keys, one-time tokens, renewal, CRL, network endpoint."""

import os
import ssl
import threading
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sensetrust.ca import CertificateAuthority, EnrolmentError, identity_of
from sensetrust.devices import DeviceIdentity, make_csr
from sensetrust.gateway import Gateway
from sensetrust.server import post, serve_enrolment


def test_device_key_never_reaches_the_ca(tmp_path):
    ca = CertificateAuthority(str(tmp_path))
    dev = DeviceIdentity.commission(ca, "LT-101", "sensor", time.time)
    assert not os.path.exists(ca.paths("LT-101")[0])
    ok, _, ident, role = ca.verify(dev.cert)
    assert ok and (ident, role) == ("LT-101", "sensor")
    life = dev.cert.not_valid_after_utc - dev.cert.not_valid_before_utc
    assert life.days <= 31
    # Only a hash of each token secret is stored.
    tok_secret = ca.create_enrolment_token("X-1", "sensor").split(".", 1)[1]
    assert tok_secret not in open(os.path.join(str(tmp_path), "enrolment_tokens.json")).read()


def test_token_is_single_use_expires_and_needs_the_secret(tmp_path):
    ca = CertificateAuthority(str(tmp_path))
    tok = ca.create_enrolment_token("PT-101", "sensor", ttl_s=60)
    DeviceIdentity.generate("PT-101", time.time).enrol(ca, tok)
    with pytest.raises(EnrolmentError, match="already used"):
        DeviceIdentity.generate("PT-101", time.time).enrol(ca, tok)
    tok2 = ca.create_enrolment_token("PT-101", "sensor", ttl_s=60)
    with pytest.raises(EnrolmentError, match="expired"):
        DeviceIdentity.generate("PT-101", time.time).enrol(ca, tok2, now=time.time() + 120)
    tok3 = ca.create_enrolment_token("PT-101", "sensor")
    with pytest.raises(EnrolmentError, match="secret"):
        DeviceIdentity.generate("PT-101", time.time).enrol(ca, tok3.split(".")[0] + ".guess")
    with pytest.raises(EnrolmentError, match="unknown"):
        DeviceIdentity.generate("PT-101", time.time).enrol(ca, "deadbeef.x")


def test_token_fixes_identity_and_role(tmp_path):
    ca = CertificateAuthority(str(tmp_path))
    tok = ca.create_enrolment_token("FT-101", "sensor")
    with pytest.raises(EnrolmentError, match="token is for"):
        DeviceIdentity.generate("P-101", time.time).enrol(ca, tok)
    tok = ca.create_enrolment_token("FT-101", "sensor")
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "FT-101"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "console")])).sign(key, hashes.SHA256()))
    cert = ca.enrol(tok, csr.public_bytes(serialization.Encoding.PEM))
    assert identity_of(cert) == ("FT-101", "sensor")
    with pytest.raises(ValueError):
        ca.create_enrolment_token("evil", "gateway")


def test_renewal_rotates_key_and_retires_old_cert(tmp_path):
    ca = CertificateAuthority(str(tmp_path))
    dev = DeviceIdentity.commission(ca, "LT-101", "sensor", time.time)
    old = dev.cert
    with pytest.raises(EnrolmentError, match="new key"):
        ca.renew(old, make_csr(dev.key, "LT-101"))
    dev.renew(ca)
    assert dev.cert.serial_number != old.serial_number
    assert ca.is_revoked(old) and not ca.is_revoked(dev.cert)
    with pytest.raises(EnrolmentError, match="revoked"):
        ca.renew(old, make_csr(ec.generate_private_key(ec.SECP256R1()), "LT-101"))


def test_revoked_or_foreign_device_cannot_renew(tmp_path):
    ca = CertificateAuthority(str(tmp_path))
    dev = DeviceIdentity.commission(ca, "LT-101", "sensor", time.time)
    ca.revoke(dev.cert, "attack_detected")
    with pytest.raises(EnrolmentError, match="revoked"):
        dev.renew(ca)
    rogue = CertificateAuthority(str(tmp_path / "rogue"))
    rdev = DeviceIdentity.commission(rogue, "PT-101", "sensor", time.time)
    with pytest.raises(EnrolmentError, match="not issued by plant CA"):
        ca.renew(rdev.cert, make_csr(ec.generate_private_key(ec.SECP256R1()), "PT-101"))


def test_crl_lists_revoked_serials(tmp_path):
    ca = CertificateAuthority(str(tmp_path))
    dev = DeviceIdentity.commission(ca, "LT-101", "sensor", time.time)
    seen = []
    ca.on_revoke.append(seen.append)
    ca.revoke(dev.cert, "attack_detected")
    crl = x509.load_pem_x509_crl(open(ca.crl_path, "rb").read())
    assert crl.is_signature_valid(ca.cert.public_key())
    assert crl.get_revoked_certificate_by_serial_number(dev.cert.serial_number) is not None
    assert seen and seen[0].serial_number == dev.cert.serial_number


def test_reinstatement_requires_a_new_key(tmp_path):
    gw = Gateway(str(tmp_path / "gw"))
    dev = DeviceIdentity.commission(gw.ca, "LT-101", "sensor", time.time)
    gw.ca.revoke(dev.cert, "attack_detected")
    gw._reinstate("LT-101", "asha")
    assert gw.telemetry(dev.cert, dev.envelope(value=1.0))["effect"] == "deny"
    fresh = DeviceIdentity.generate("LT-101", time.time)
    fresh.enrol(gw.ca, gw.pending_enrolments["LT-101"])
    assert gw.telemetry(fresh.cert, fresh.envelope(value=1.0))["effect"] == "allow"
    gw.close()


def test_enrolment_endpoint_over_tls(tmp_path):
    gw = Gateway(str(tmp_path / "gw"))
    gw.ca.issue("gateway", "gateway", hostnames=("127.0.0.1",))
    httpd = serve_enrolment(gw, "127.0.0.1", 0)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        server_only = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        server_only.load_verify_locations(gw.ca.ca_cert_path)
        dev = DeviceIdentity.generate("FT-101", time.time)
        tok = gw.ca.create_enrolment_token("FT-101", "sensor")
        status, resp = post(server_only, "127.0.0.1", port, "/v1/enrol",
                            {"token": tok, "csr": dev.csr().decode()})
        assert status == 200
        dev.cert = x509.load_pem_x509_certificate(resp["cert"].encode())
        assert gw.ca.verify(dev.cert)[0]

        status, resp = post(server_only, "127.0.0.1", port, "/v1/enrol",
                            {"token": tok, "csr": dev.csr().decode()})
        assert status == 403 and "already used" in resp["error"]

        new_key = ec.generate_private_key(ec.SECP256R1())
        status, resp = post(server_only, "127.0.0.1", port, "/v1/renew",
                            {"csr": make_csr(new_key, "FT-101").decode()})
        assert status == 403 and "no client certificate" in resp["error"]

        key_path, crt_path = dev.save(str(tmp_path / "device"))
        mtls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        mtls.load_verify_locations(gw.ca.ca_cert_path)
        mtls.load_cert_chain(crt_path, key_path)
        status, resp = post(mtls, "127.0.0.1", port, "/v1/renew",
                            {"csr": make_csr(new_key, "FT-101").decode()})
        assert status == 200
        assert gw.ca.is_revoked(dev.cert)
    finally:
        httpd.shutdown()
        gw.close()


def _supervisor_command(site, action, target):
    from sensetrust.synthetic import recapture
    r = site.login("asha", minutiae=recapture(site.finger("asha"), seed=3, rotation=10))
    assert r["ok"]
    return site.send_command(r["token"], action, target)[1]


def test_reinstated_sensor_rejoins_after_sending_many_messages(tmp_path):
    """The new key starts a new message sequence, and the silence while waiting for the
    technician is not mistaken for a dropout fault."""
    from sensetrust.site import Site
    site = Site(str(tmp_path / "s"), level=1.3)
    site.run(100)
    site.tamper = lambda t, s, v: v * 0.35 if s == "LT-101" else v
    site.run(40)
    assert site.gw.trust.is_quarantined("LT-101")
    assert _supervisor_command(site, "device.reinstate", "LT-101")["effect"] == "allow"
    site.run(60)                                   # old key still refused; no fault raised
    kinds = [e["kind"] for e in site.gw.events if e["subject"] == "LT-101"]
    assert "fault_detected" not in kinds
    fresh = DeviceIdentity.generate("LT-101", site.clock)
    fresh.enrol(site.gw.ca, site.gw.pending_enrolments.pop("LT-101"))
    site.dev["LT-101"], site.tamper = fresh, None
    site.run(200)
    assert "re_enrolled" in [e["kind"] for e in site.gw.events]
    assert site.log[-1]["denied"] == [] and site.log[-1]["control_source"] == "LT-101"
    site.gw.close()


def test_admin_revoke_and_maintenance_close_are_fingerprint_gated_commands(tmp_path):
    from sensetrust.site import Site
    site = Site(str(tmp_path / "s"), level=1.3)
    site.run(5)
    assert _supervisor_command(site, "device.revoke", "XV-101")["effect"] == "allow"
    assert site.gw.ca.is_revoked(site.dev["XV-101"].cert)
    site.gw.degraded["PT-101"] = "stuck_value"
    assert _supervisor_command(site, "maintenance.close", "PT-101")["effect"] == "allow"
    assert "PT-101" not in site.gw.degraded
    # A token without the fingerprint claim cannot revoke anything.
    tok = site.gw.tokens.issue("asha", "shift_supervisor", ["admin"], ["mtls"], ttl=60,
                               bind_cert_serial=site.dev["console-01"].cert.serial_number,
                               now=site.clock())
    env = site.dev["console-01"].command("device.revoke", "P-101")
    assert site.gw.command(site.dev["console-01"].cert, tok, env)["effect"] == "step_up"
    site.gw.close()
