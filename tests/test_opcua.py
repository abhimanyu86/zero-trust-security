"""OPC UA shadow mode: a secured, read-only plant server and SenseTrust's monitor."""

import asyncio
import socket

import pytest

pytest.importorskip("asyncua")

from asyncua import Client, ua                                    # noqa: E402

from sensetrust.ca import CertificateAuthority                    # noqa: E402
from sensetrust.gateway import Gateway                            # noqa: E402
from sensetrust.opcua import (OpcUaShadowMonitor, PlantOpcUaServer,  # noqa: E402
                              SimulatedPlc)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run(tmp_path, body):
    """Start gateway + PLC server, run `body(gw, server)`, always shut down."""
    async def main():
        gw = Gateway(str(tmp_path / "gw"))
        server = await PlantOpcUaServer(gw.ca, str(tmp_path / "plc"), port=_free_port()).start()
        try:
            return await body(gw, server)
        finally:
            await server.stop()
            gw.close()
    return asyncio.run(main())


def test_only_signed_and_encrypted_endpoints(tmp_path):
    async def body(gw, server):
        return await Client(server.url).connect_and_get_server_endpoints()
    endpoints = run(tmp_path, body)
    assert endpoints
    for ep in endpoints:
        assert ep.SecurityPolicyUri.endswith("#Basic256Sha256")
        assert ep.SecurityMode == ua.MessageSecurityMode.SignAndEncrypt


def test_monitor_with_plant_certificate_connects_and_reads(tmp_path):
    async def body(gw, server):
        await server.publish({"LT-101": 1.4, "PT-101": 13.7, "FT-101": 0.8, "Pump": 1, "Valve": 0.6})
        mon = await OpcUaShadowMonitor(gw, server.url).connect()
        try:
            return await mon.read()
        finally:
            await mon.disconnect()
    assert run(tmp_path, body)["LT-101"] == pytest.approx(1.4)


def test_rogue_ca_certificate_refused(tmp_path):
    async def body(gw, server):
        rogue = CertificateAuthority(str(tmp_path / "rogue"), name="Attacker CA")
        mon = OpcUaShadowMonitor(gw, server.url, ca=rogue)
        with pytest.raises(Exception) as e:
            await mon.connect()
        return str(e.value)
    assert "BadCertificateUntrusted" in run(tmp_path, body)


def test_client_without_certificate_refused(tmp_path):
    async def body(gw, server):
        with pytest.raises(Exception) as e:
            async with Client(server.url):      # no security set -> asks for policy None
                pass
        return str(e.value)
    assert "No matching endpoints" in run(tmp_path, body)


def test_revoked_monitor_cannot_reconnect(tmp_path):
    async def body(gw, server):
        mon = await OpcUaShadowMonitor(gw, server.url).connect()
        await mon.disconnect()
        gw.ca.revoke(gw.ca.current_cert(mon.identity), "key_compromise")
        with pytest.raises(Exception) as e:
            await mon.connect()
        return str(e.value)
    assert "BadCertificateRevoked" in run(tmp_path, body)


def test_values_are_read_only(tmp_path):
    async def body(gw, server):
        mon = await OpcUaShadowMonitor(gw, server.url).connect()
        try:
            with pytest.raises(ua.UaStatusCodeError) as e:
                await mon.client.write_values([mon.nodes["LT-101"]], [2.9])
            return e.value.code, (await mon.read())["LT-101"]
        finally:
            await mon.disconnect()
    code, value = run(tmp_path, body)
    assert code in (ua.StatusCodes.BadUserAccessDenied, ua.StatusCodes.BadNotWritable)
    assert value == 0.0                        # unchanged


def _shadow_run(tmp_path, tamper, start=120, seconds=400):
    async def body(gw, server):
        plc = SimulatedPlc(server)
        mon = await OpcUaShadowMonitor(gw, server.url).connect()
        try:
            for _ in range(start):
                await plc.step()
                await mon.poll()
            plc.tamper = tamper
            for _ in range(seconds):
                await plc.step()
                await mon.poll()
        finally:
            await mon.disconnect()
        diag = [(e["kind"], e["subject"]) for e in gw.events
                if e["kind"] in ("attack_detected", "fault_detected", "ambiguous_anomaly")]
        assert all(e.get("shadow") for e in gw.events if e["kind"].endswith("_detected"))
        return diag, gw.trust.quarantined(), {d: gw.ca.verify(gw.ca.current_cert(d))[0]
                                              for d in ("plc-01", "sensetrust-opcua-monitor")}
    return run(tmp_path, body)


def test_tampered_sensor_raises_alert_but_nothing_is_revoked(tmp_path):
    diag, quarantined, certs_ok = _shadow_run(
        tmp_path, lambda t, s, v: v * 0.35 if s == "LT-101" and t > 120 else v)
    assert diag == [("attack_detected", "LT-101")]
    assert not quarantined and all(certs_ok.values())


def test_frozen_sensor_is_a_fault_not_an_attack(tmp_path):
    frozen = {}
    diag, quarantined, _ = _shadow_run(
        tmp_path, lambda t, s, v: frozen.setdefault("v", v) if s == "LT-101" and t > 120 else v)
    assert diag == [("fault_detected", "LT-101")]
    assert not quarantined
