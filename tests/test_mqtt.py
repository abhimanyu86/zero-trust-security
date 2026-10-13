"""MQTT over mutual TLS through a real Mosquitto broker (skipped if mosquitto is absent)."""

import os
import socket
import time

import pytest

from sensetrust.ca import CertificateAuthority
from sensetrust.devices import DeviceIdentity
from sensetrust.gateway import Gateway
from sensetrust.mqtt import (MQTT_NOT_AUTHORIZED, TELEMETRY, MosquittoBroker, MqttDevice,
                             MqttGatewayBridge, broker_available)

pytestmark = pytest.mark.skipif(not broker_available(), reason="mosquitto not installed")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def plant(tmp_path):
    gw = Gateway(str(tmp_path / "gw"))
    port = _free_port()
    broker = MosquittoBroker(gw.ca, str(tmp_path / "broker"), port=port).start()
    bridge = MqttGatewayBridge(gw, port=port).start()
    yield gw, broker, bridge, port, tmp_path
    bridge.stop()
    broker.stop()
    gw.close()


def test_device_publishes_on_its_own_topic(plant):
    gw, broker, bridge, port, tmp = plant
    dev = DeviceIdentity.commission(gw.ca, "PT-101", "sensor", time.time)
    m = MqttDevice(dev, str(tmp / "pt"), gw.ca.ca_cert_path, port=port)
    assert m.connect()[0]
    assert m.publish(dev.envelope(value=12.0)) == 0
    got = bridge.wait_for(1)
    assert got[0]["device"] == "PT-101" and got[0]["decision"]["effect"] == "allow"
    m.close()


def test_broker_acl_blocks_posting_as_another_device(plant):
    gw, broker, bridge, port, tmp = plant
    dev = DeviceIdentity.commission(gw.ca, "LT-101", "sensor", time.time)
    m = MqttDevice(dev, str(tmp / "lt"), gw.ca.ca_cert_path, port=port)
    assert m.connect()[0]
    rc = m.publish(dev.envelope(value=0.1, device_id="PT-101"), topic=TELEMETRY + "PT-101")
    assert rc == MQTT_NOT_AUTHORIZED
    time.sleep(0.4)
    assert bridge.received == []
    m.close()


def test_only_plant_ca_certificates_connect(plant):
    gw, broker, bridge, port, tmp = plant
    rogue = CertificateAuthority(str(tmp / "rogue"))
    rdev = DeviceIdentity.commission(rogue, "PT-101", "sensor", time.time)
    assert not MqttDevice(rdev, str(tmp / "r"), gw.ca.ca_cert_path, port=port).connect()[0]
    dev = DeviceIdentity.commission(gw.ca, "PT-101", "sensor", time.time)
    assert not MqttDevice(dev, str(tmp / "n"), gw.ca.ca_cert_path, port=port, use_cert=False).connect()[0]


def test_revocation_reaches_gateway_and_broker(plant):
    gw, broker, bridge, port, tmp = plant
    dev = DeviceIdentity.commission(gw.ca, "LT-101", "sensor", time.time)
    m = MqttDevice(dev, str(tmp / "lt"), gw.ca.ca_cert_path, port=port)
    assert m.connect()[0]
    gw.ca.revoke(dev.cert, "attack_detected")
    # Gateway: the very next message from the revoked device is denied.
    m.publish(dev.envelope(value=1.0))
    got = bridge.wait_for(1)
    assert got, "the gateway bridge received nothing"
    assert got[-1]["decision"]["effect"] == "deny"
    m.close()
    # Broker: once it re-reads the CRL, the revoked device cannot reconnect.
    # (Done after the publish: on Windows a reload restarts the broker.)
    broker.reload()
    time.sleep(1)
    assert not MqttDevice(dev, str(tmp / "lt2"), gw.ca.ca_cert_path, port=port).connect()[0]


def test_broker_config_is_mtls_only(plant):
    gw, broker, bridge, port, tmp = plant
    conf = open(broker.conf_path).read()
    for line in ("require_certificate true", "use_identity_as_username true",
                 "tls_version tlsv1.3", "crlfile", "acl_file"):
        assert line in conf
    assert "allow_anonymous true" not in conf
    if os.name != "nt":   # Windows has no POSIX file modes
        assert oct(os.stat(broker.acl_path).st_mode)[-3:] == "600"
