"""
OPC UA in shadow mode: read the plant's own data, run the physics check, alert only.

Most plants expose their process values through OPC UA from the PLC or SCADA server. A
pilot site will let a new security product *read* those values, and nothing more, until
it has earned trust. This module is that first step:

  PlantOpcUaServer    stands in for the site's PLC: publishes LT-101, PT-101, FT-101,
                      Pump and Valve. Secured the way a hardened site would run it:
                        - only Basic256Sha256 + SignAndEncrypt (no unsecured endpoint),
                        - its certificate is issued by the plant CA,
                        - client certificates must chain to the plant CA and must not be
                          on the CA's revocation list (checked on every new connection),
                        - every variable is read-only to clients.
  OpcUaShadowMonitor  SenseTrust's side: connects with its own plant-CA certificate,
                      checks the server's certificate against the plant CA before
                      trusting it, reads all five values once per second in one request,
                      and hands them to `Gateway.shadow_tick` (alerts and tickets only).
  SimulatedPlc        drives the server from `plant.py` for the demo and tests. Its level
                      controller trusts LT-101 like a real PLC does, so a compromised
                      LT-101 really does mislead it: shadow mode can see the attack but,
                      by design, does not intervene.

Requires `asyncua`. The OPC UA security policy needs RSA keys, so OPC UA certificates are
RSA-2048 (signed by the same plant CA as everything else; see `ca.issue_opcua`).
"""

import asyncio
import os
import shutil
import socket
from pathlib import Path

from asyncua import Client, Server, ua
from asyncua.crypto import uacrypto
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256
from asyncua.crypto.truststore import TrustStore
from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions
from cryptography import x509

from .plant import SENSORS, LevelController, WaterPlant

PLC_ID = "plc-01"
MONITOR_ID = "sensetrust-opcua-monitor"
PLC_URI = "urn:yellowsense:sensetrust:plc-01"
MONITOR_URI = "urn:yellowsense:sensetrust:shadow-monitor"
NAMESPACE = "urn:yellowsense:sensetrust:plant"
TAGS = SENSORS + ("Pump", "Valve")


def endpoint_url(host="127.0.0.1", port=4840):
    return "opc.tcp://%s:%d/sensetrust/plc" % (host, port)


class _PlantCaValidator(CertificateValidator):
    """
    Client-certificate check: time range, application URI, OPC UA key usages, client
    role, issued by the plant CA, and not revoked. The CA's current CRL is copied in and
    reloaded on every new connection, so a revocation takes effect immediately.
    """

    def __init__(self, ca, crl_dir, trust_store):
        super().__init__(CertificateValidatorOptions.TRUSTED_VALIDATION
                         | CertificateValidatorOptions.PEER_CLIENT, trust_store)
        self.ca, self.crl_dir = ca, crl_dir

    async def validate(self, cert, app_description):
        shutil.copyfile(self.ca.crl_path, os.path.join(self.crl_dir, "plant-crl.pem"))
        await self._trust_store.load_crl()
        return await super().validate(cert, app_description)


class PlantOpcUaServer:
    """The site's PLC / SCADA OPC UA server (simulated), secured as described above."""

    def __init__(self, ca, directory, host="127.0.0.1", port=4840):
        self.ca, self.dir, self.host, self.port = ca, directory, host, port
        self.url = endpoint_url(host, port)
        self.nodes = {}
        self.server = None
        os.makedirs(directory, exist_ok=True)
        if ca.current_cert(PLC_ID) is None:
            ca.issue_opcua(PLC_ID, "plc", PLC_URI,
                           hostnames=("localhost", "127.0.0.1", socket.gethostname(), host))
        self.trust_dir = os.path.join(directory, "trusted")
        self.crl_dir = os.path.join(directory, "crl")
        for d in (self.trust_dir, self.crl_dir):
            os.makedirs(d, exist_ok=True)
        shutil.copyfile(ca.ca_cert_path, os.path.join(self.trust_dir, "plant-ca.pem"))

    async def start(self):
        key_path, crt_path = self.ca.paths(PLC_ID)
        self.server = Server()
        await self.server.init()
        await self.server.set_application_uri(PLC_URI)
        self.server.set_server_name("SenseTrust simulated PLC")
        self.server.set_endpoint(self.url)
        # Only the signed-and-encrypted policy is offered: no "None" endpoint exists.
        self.server.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
        await self.server.load_certificate(crt_path, format="pem")
        await self.server.load_private_key(key_path, format="pem")
        store = TrustStore([Path(self.trust_dir)], [Path(self.crl_dir)])
        await store.load_trust()
        self.server.set_certificate_validator(_PlantCaValidator(self.ca, self.crl_dir, store))

        idx = await self.server.register_namespace(NAMESPACE)
        plc = await self.server.nodes.objects.add_object(ua.NodeId("PLC", idx), "PLC")
        for tag in TAGS:
            # add_variable creates read-only nodes; we deliberately never call set_writable().
            self.nodes[tag] = await plc.add_variable(ua.NodeId(tag, idx), tag, 0.0,
                                                     varianttype=ua.VariantType.Double)
        await self.server.start()
        return self

    async def publish(self, values):
        """The PLC updates its own variables (server side; clients cannot do this)."""
        for tag, v in values.items():
            await self.nodes[tag].write_value(float("nan") if v is None else float(v),
                                              ua.VariantType.Double)

    async def stop(self):
        if self.server:
            await self.server.stop()


def _verify_server_cert(ca, der):
    """Only talk to a server whose certificate the plant CA issued to a PLC."""
    cert = x509.load_der_x509_certificate(der)
    ok, reason, identity, role = ca.verify(cert, expected_role="plc")
    if not ok:
        raise ConnectionRefusedError("OPC UA server certificate rejected: %s" % reason)
    return cert


class OpcUaShadowMonitor:
    """SenseTrust's read-only OPC UA client. Feeds `Gateway.shadow_tick` once per second."""

    def __init__(self, gw, url, ca=None, identity=MONITOR_ID, uri=MONITOR_URI):
        self.gw, self.url = gw, url
        self.ca = ca or gw.ca
        self.identity, self.uri = identity, uri
        if self.ca.current_cert(identity) is None:
            self.ca.issue_opcua(identity, "service", uri)
        self.client = None
        self.nodes = None
        self.ticks = 0

    async def connect(self):
        """Secure channel + session. Raises if either side's certificate is refused."""
        probe = Client(self.url)
        endpoints = await probe.connect_and_get_server_endpoints()
        ep = Client.find_endpoint(endpoints, ua.MessageSecurityMode.SignAndEncrypt,
                                  SecurityPolicyBasic256Sha256.URI)
        server_cert = _verify_server_cert(self.gw.ca, ep.ServerCertificate)
        key_path, crt_path = self.ca.paths(self.identity)
        client = Client(self.url)
        client.application_uri = self.uri
        client.name = "SenseTrust shadow monitor"
        await client.set_security(SecurityPolicyBasic256Sha256,
                                  uacrypto.CertProperties(crt_path, "pem"),
                                  uacrypto.CertProperties(key_path, "pem"),
                                  server_certificate=uacrypto.der_from_x509(server_cert),
                                  mode=ua.MessageSecurityMode.SignAndEncrypt)
        await client.connect()
        self.client = client
        idx = await client.get_namespace_index(NAMESPACE)
        self.nodes = {tag: client.get_node(ua.NodeId(tag, idx)) for tag in TAGS}
        return self

    async def read(self):
        """All five values in one OPC UA Read request."""
        values = await self.client.read_values([self.nodes[t] for t in TAGS])
        return dict(zip(TAGS, values))

    async def poll(self):
        """One second of shadow monitoring: read, then physics check (alerts only)."""
        v = await self.read()
        readings = {s: (None if v[s] != v[s] else v[s]) for s in SENSORS}   # NaN -> missing
        self.ticks += 1
        return self.gw.shadow_tick(readings, v["Pump"], v["Valve"])

    async def run(self, period=1.0, stop=None):
        """Live mode: poll every `period` seconds until `stop` (an asyncio.Event) is set."""
        while stop is None or not stop.is_set():
            await self.poll()
            await asyncio.sleep(period)

    async def disconnect(self):
        if self.client:
            await self.client.disconnect()
            self.client = None


class SimulatedPlc:
    """
    The plant behind the PLC, for demos and tests. Each `step` advances the tank one
    second, applies `tamper` (a compromised transmitter), lets the PLC's level controller
    act on what LT-101 reports, and publishes the values on the OPC UA server.
    """

    def __init__(self, server, level=1.3, valve=0.6, seed=1):
        self.server = server
        self.plant = WaterPlant(level=level, valve=valve, seed=seed)
        self.ctrl = LevelController()
        self.tamper = None
        self.t = 0

    async def step(self):
        self.t += 1
        reported = dict(self.plant.true_readings())
        if self.tamper:
            for s in SENSORS:
                reported[s] = self.tamper(self.t, s, reported[s])
        await self.server.publish({**reported, "Pump": self.plant.pump, "Valve": self.plant.valve})
        if reported["LT-101"] is not None:
            self.ctrl.update(reported["LT-101"])
            self.plant.pump = self.ctrl.pump
        self.plant.step()
        return reported
