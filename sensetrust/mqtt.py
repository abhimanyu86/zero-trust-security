"""
Industrial transport: MQTT over mutual TLS 1.3, with the gateway enforcing every message.

Three layers, each of which would stop a forged reading on its own:

  1. Broker handshake (Mosquitto). Only clients holding a certificate from the plant CA
     connect at all, and the CA's revocation list (CRL) is loaded, so a quarantined
     device cannot reconnect. The certificate's CN becomes the MQTT username.
  2. Broker ACL. A device may publish only on its own topic, plant/telemetry/<its ID>.
     A stolen LT-101 key cannot post as PT-101: the broker refuses the publish.
  3. Gateway. The bridge receives each message and runs the same checks as the HTTPS
     path: the signature must verify against the current certificate for the topic's
     device, the certificate must be valid and unrevoked, the message fresh, the rate
     normal, the sender trusted, and the value consistent with plant physics.

Topics:
    plant/telemetry/<device-id>      signed envelope from that device (QoS 1)
"""

import getpass
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import time

import paho.mqtt.client as mqtt

TELEMETRY = "plant/telemetry/"
BRIDGE_ID = "gateway-mqtt"
MQTT_NOT_AUTHORIZED = 135


WINDOWS_MOSQUITTO = [drive + r":\Program Files\mosquitto\mosquitto.exe" for drive in "CDE"] + \
                    [drive + r":\Program Files (x86)\mosquitto\mosquitto.exe" for drive in "CDE"] + \
                    [drive + r":\mosquitto\mosquitto.exe" for drive in "CDE"]


def mosquitto_path():
    """
    Where to find Mosquitto: the MOSQUITTO environment variable (the .exe or its folder),
    then the PATH, then the usual Windows install folders on drives C, D and E.
    """
    env = os.environ.get("MOSQUITTO")
    if env:
        for candidate in (env, os.path.join(env, "mosquitto.exe"), os.path.join(env, "mosquitto")):
            if os.path.isfile(candidate):
                return candidate
    found = shutil.which("mosquitto")
    if found:
        return found
    return next((p for p in WINDOWS_MOSQUITTO if os.path.exists(p)), None)


def broker_available():
    return mosquitto_path() is not None


class MosquittoBroker:
    """Runs a Mosquitto broker configured for the plant: mTLS only, per-device ACL, CRL."""

    def __init__(self, ca, directory, host="127.0.0.1", port=8883):
        self.ca, self.dir, self.host, self.port = ca, directory, host, port
        self.proc = None
        os.makedirs(directory, exist_ok=True)
        if ca.current_cert("mqtt-broker") is None:
            ca.issue("mqtt-broker", "broker", hostnames=("localhost", "127.0.0.1", host))
        key_path, crt_path = ca.paths("mqtt-broker")
        self.acl_path = os.path.join(directory, "acl")
        with open(self.acl_path, "w") as f:
            f.write("# The gateway's bridge reads every device topic.\n"
                    "user %s\ntopic read %s#\n\n"
                    "# Every device may publish on its own topic and nowhere else.\n"
                    "pattern write %s%%u\n" % (BRIDGE_ID, TELEMETRY, TELEMETRY))
        os.chmod(self.acl_path, 0o600)
        self.conf_path = os.path.join(directory, "mosquitto.conf")
        lines = [
            "per_listener_settings true",
            "persistence false",
            "log_dest file %s" % os.path.join(directory, "mosquitto.log"),
            "log_type error", "log_type warning", "log_type notice",
            "listener %d %s" % (port, host),
            "protocol mqtt",
            "cafile %s" % ca.ca_cert_path,
            "certfile %s" % crt_path,
            "keyfile %s" % key_path,
            "tls_version tlsv1.3",
            "require_certificate true",
            "use_identity_as_username true",
            "crlfile %s" % ca.crl_path,
            "acl_file %s" % self.acl_path,
        ]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            # Mosquitto drops root to the 'mosquitto' user, which cannot read 0600 keys.
            lines.insert(0, "user %s" % getpass.getuser())
        with open(self.conf_path, "w") as f:
            f.write("\n".join(lines) + "\n")

    def start(self, timeout=10):
        self.proc = subprocess.Popen([mosquitto_path(), "-c", self.conf_path],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("mosquitto exited; see %s" % os.path.join(self.dir, "mosquitto.log"))
            try:
                socket.create_connection((self.host, self.port), timeout=0.5).close()
                return self
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("mosquitto did not start listening on %s:%d" % (self.host, self.port))

    def reload(self, *_):
        """Re-read the CRL (and ACL): revoked devices can no longer connect."""
        if not (self.proc and self.proc.poll() is None):
            return
        if hasattr(signal, "SIGHUP"):
            self.proc.send_signal(signal.SIGHUP)
            time.sleep(0.3)
        else:
            # Windows has no SIGHUP: restart the broker; clients reconnect on their own.
            self.stop()
            self.start()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def _client(client_id, ca_path, cert_path, key_path):
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id,
                    protocol=mqtt.MQTTv5)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(ca_path)
    if cert_path:
        ctx.load_cert_chain(cert_path, key_path)
    c.tls_set_context(ctx)
    return c


class MqttDevice:
    """A field device publishing its signed readings over MQTT with its own certificate."""

    def __init__(self, device, directory, ca_path, host="127.0.0.1", port=8883, use_cert=True):
        self.device = device
        if use_cert:
            key_path, crt_path = device.save(directory)
        else:
            key_path = crt_path = None
        self.client = _client(device.identity, ca_path, crt_path, key_path)
        self.host, self.port = host, port
        self._acks = {}
        self._acked = threading.Condition()
        self.client.on_publish = self._on_publish

    def _on_publish(self, client, userdata, mid, reason_code, properties):
        with self._acked:
            self._acks[mid] = int(reason_code.value if hasattr(reason_code, "value") else reason_code)
            self._acked.notify_all()

    def connect(self, timeout=5):
        """Returns (ok, reason). TLS refusals surface here, before any message is sent."""
        try:
            rc = self.client.connect(self.host, self.port, keepalive=30)
        except (ssl.SSLError, OSError) as e:
            return False, "TLS handshake refused: %s" % (getattr(e, "reason", None) or e)
        if rc != 0:
            return False, "connect failed rc=%s" % rc
        self.client.loop_start()
        connected = threading.Event()
        self.client.on_connect = lambda *a: connected.set()
        self.client.on_disconnect = lambda *a: connected.set()
        if not connected.wait(timeout) or not self.client.is_connected():
            self.client.loop_stop()
            return False, "broker closed the connection (certificate rejected or revoked)"
        return True, "connected"

    def publish(self, envelope, topic=None, timeout=5):
        """Publish at QoS 1. Returns the broker's MQTT v5 reason code (0 = accepted)."""
        topic = topic or TELEMETRY + self.device.identity
        info = self.client.publish(topic, json.dumps(envelope), qos=1)
        with self._acked:
            self._acked.wait_for(lambda: info.mid in self._acks, timeout)
            return self._acks.get(info.mid)

    def close(self):
        try:
            self.client.disconnect()
        finally:
            self.client.loop_stop()


class MqttGatewayBridge:
    """
    The gateway's MQTT client. Every message on plant/telemetry/<id> goes through the
    gateway's full check, using the CA's current certificate for <id>: the broker ACL
    says which device could have published, the signature proves it actually did.
    """

    def __init__(self, gw, host="127.0.0.1", port=8883):
        self.gw = gw
        if gw.ca.current_cert(BRIDGE_ID) is None:
            gw.ca.issue(BRIDGE_ID, "service")
        key_path, crt_path = gw.ca.paths(BRIDGE_ID)
        self.client = _client(BRIDGE_ID, gw.ca.ca_cert_path, crt_path, key_path)
        self.client.on_message = self._on_message
        self.host, self.port = host, port
        self.received = []
        self._cv = threading.Condition()

    def start(self, timeout=5):
        ready = threading.Event()
        self.client.on_subscribe = lambda *a: ready.set()
        self.client.on_connect = lambda c, u, f, rc, p: c.subscribe(TELEMETRY + "+", qos=1)
        self.client.connect(self.host, self.port, keepalive=30)
        self.client.loop_start()
        if not ready.wait(timeout):
            raise RuntimeError("gateway bridge could not subscribe")
        return self

    def _on_message(self, client, userdata, msg):
        device_id = msg.topic[len(TELEMETRY):]
        try:
            envelope = json.loads(msg.payload)
        except ValueError:
            envelope = {}
        decision = self.gw.telemetry(self.gw.ca.current_cert(device_id), envelope)
        with self._cv:
            self.received.append({"topic": msg.topic, "device": device_id,
                                  "value": envelope.get("body", {}).get("value"),
                                  "decision": decision})
            self._cv.notify_all()

    def wait_for(self, n, timeout=5):
        with self._cv:
            self._cv.wait_for(lambda: len(self.received) >= n, timeout)
            return list(self.received)

    def stop(self):
        self.client.disconnect()
        self.client.loop_stop()
