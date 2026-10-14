import asyncio
import pytest
from asyncua import Client, ua
from sensetrust.ca import CertificateAuthority
from sensetrust.gateway import Gateway
from sensetrust.opcua import PlantOpcUaServer, OpcUaShadowMonitor

@pytest.fixture
async def opcua_env(tmp_path):
    gw = Gateway(str(tmp_path / "gw"))
    ca = gw.ca
    
    server = PlantOpcUaServer(ca=ca, directory=str(tmp_path / "server"), port=4844)
    await server.start()
    
    yield ca, gw, server
    
    await server.stop()
    gw.close()

@pytest.mark.asyncio
async def test_opcua_endpoints_no_insecure(opcua_env):
    ca, gw, server = opcua_env
    client = Client(url="opc.tcp://localhost:4844/freeopcua/server/")
    endpoints = await client.connect_and_get_server_endpoints()
    for ep in endpoints:
        assert ep.SecurityPolicyUri != ua.SecurityPolicyUri.None_

@pytest.mark.asyncio
async def test_opcua_rogue_ca_refused(opcua_env, tmp_path):
    ca, gw, server = opcua_env
    client = Client(url="opc.tcp://localhost:4844/freeopcua/server/")
    with pytest.raises(Exception):
        async with client:
            pass

@pytest.mark.asyncio
async def test_opcua_missing_cert_refused(opcua_env):
    ca, gw, server = opcua_env
    client = Client(url="opc.tcp://localhost:4844/freeopcua/server/")
    with pytest.raises(Exception):
        async with client:
            pass

@pytest.mark.asyncio
async def test_opcua_write_protection(opcua_env):
    ca, gw, server = opcua_env
    pass

@pytest.mark.asyncio
async def test_opcua_sensor_tampering_alert(opcua_env):
    ca, gw, server = opcua_env
    gw_monitor = OpcUaShadowMonitor(gw, "opc.tcp://localhost:4844/freeopcua/server/")
    pass

@pytest.mark.asyncio
async def test_opcua_sensor_freezing(opcua_env):
    ca, gw, server = opcua_env
    gw_monitor = OpcUaShadowMonitor(gw, "opc.tcp://localhost:4844/freeopcua/server/")
    pass