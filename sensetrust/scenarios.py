"""
Scripted attack/fault scenarios — the live demo, and an end-to-end regression suite.

    python -m sensetrust.scenarios            # run all, print a summary, write results/scenarios.json

Every scenario states what should happen, runs the real gateway against the simulated
plant, and reports what did happen. `passed` is computed, not asserted by hand.
"""

import copy
import json
import os
import sys
import tempfile

from .ca import CertificateAuthority
from .crypto import sign_envelope
from .devices import DeviceIdentity
from .plant import OVERFLOW
from .site import Site
from .synthetic import make_template, recapture, ridge_image, screen_recapture_image


def s1_rogue_device(base):
    """A device that was never enrolled tries to publish as LT-101."""
    site = Site(os.path.join(base, "s1"))
    site.run(5)
    rogue_ca = CertificateAuthority(os.path.join(base, "s1-rogue-ca"), name="Attacker CA")
    rogue_ca.issue("LT-101", "sensor")
    rogue = DeviceIdentity.load(rogue_ca, "LT-101", site.clock)
    d1 = site.gw.telemetry(rogue.cert, rogue.envelope(value=0.5))
    d2 = site.gw.telemetry(None, {"body": {"device_id": "LT-101", "value": 0.5}, "sig": ""})
    ok = d1["effect"] == "deny" and d2["effect"] == "deny"
    return {"observed": {"cloned_identity_cert": d1, "no_certificate": d2}, "passed": ok}


def s2_stolen_key_false_data(base, calibration=None):
    """
    Attacker extracts LT-101's real key and reports the tank 1.2 m lower than it is, so the
    pump controller keeps filling. Run twice: a conventional setup where the controller
    believes any correctly-keyed device, and with the zero-trust response.
    """
    def tamper(t, s, v):
        return v - 1.2 if (s == "LT-101" and t >= 120) else v

    out = {}
    for zt in (False, True):
        site = Site(os.path.join(base, "s2-" + ("zt" if zt else "baseline")),
                    calibration=calibration, zero_trust=zt, level=1.2)
        site.tamper = tamper
        site.run(600)
        attack = next((e for e in site.gw.events if e["kind"] == "attack_detected"), None)
        post = site.gw.telemetry(site.dev["LT-101"].cert, site.dev["LT-101"].envelope(value=1.0))
        r = {"overflow_seconds": site.plant.overflow_seconds,
             "max_true_level_m": round(max(x["true_level"] for x in site.log), 3)}
        if zt:
            r.update({
                "attack_detected_after_s": None if attack is None else int(attack["ts"] - site.t0) - 120,
                "diagnosis": None if attack is None else attack["diagnosis"],
                "LT101_revoked": site.gw.ca.is_revoked(site.dev["LT-101"].cert),
                "honest_sensors_revoked": [s for s in ("PT-101", "FT-101")
                                           if site.gw.ca.is_revoked(site.dev[s].cert)],
                "LT101_next_message": post,
                "control_source_at_end": site.log[-1]["control_source"]})
        out["zero_trust" if zt else "baseline"] = r
        if zt:
            out["log"] = site.log
            out["events"] = site.gw.events
    zt, base_ = out["zero_trust"], out["baseline"]
    ok = (base_["overflow_seconds"] > 0 and zt["overflow_seconds"] == 0
          and zt["LT101_revoked"] and zt["LT101_next_message"]["effect"] == "deny"
          and zt["honest_sensors_revoked"] == []
          and zt["diagnosis"] is not None and zt["diagnosis"]["verdict"] == "attack")
    return {"observed": {k: v for k, v in out.items() if k not in ("log", "events")},
            "passed": ok, "_log": out.get("log"), "_events": out.get("events")}


def s3_fingerprint_spoof(base):
    """Critical command: someone holds up a photo of the supervisor's finger on a phone."""
    site = Site(os.path.join(base, "s3"))
    site.run(5)
    spoof = site.login("asha", image=screen_recapture_image())
    impostor = site.login("asha", minutiae=recapture(make_template(seed=4242), seed=3))
    genuine = site.login("asha", minutiae=recapture(site.finger("asha"), seed=5, rotation=25))
    cmd = None
    if genuine["ok"]:
        _, cmd = site.send_command(genuine["token"], "pump.force_on", "P-101")
    ok = (not spoof["ok"] and not impostor["ok"] and genuine["ok"]
          and cmd is not None and cmd["effect"] == "allow")
    strip = lambda d: {k: v for k, v in d.items() if k != "token"}
    return {"observed": {"screen_replay_login": strip(spoof), "impostor_finger_login": strip(impostor),
                         "genuine_live_login": strip(genuine), "critical_command_after_login": cmd},
            "passed": ok}


def s4_api_replay(base):
    """A captured, validly signed command and telemetry message are sent a second time."""
    site = Site(os.path.join(base, "s4"))
    site.run(5)
    login = site.login("ravi")
    env, first = site.send_command(login["token"], "valve.set", "XV-101", position=0.5)
    again = site.gw.command(site.dev["console-01"].cert, login["token"], copy.deepcopy(env))
    tel = site.dev["PT-101"].envelope(value=12.0)
    t1 = site.gw.telemetry(site.dev["PT-101"].cert, tel)
    t2 = site.gw.telemetry(site.dev["PT-101"].cert, copy.deepcopy(tel))
    site.now += 120                                 # a message held back and sent later
    late = site.dev["PT-101"].envelope(value=12.0)
    late["body"]["ts"] -= 120
    late = sign_envelope(site.dev["PT-101"].key, late["body"])
    t3 = site.gw.telemetry(site.dev["PT-101"].cert, late)
    ok = (first["effect"] == "allow" and again["effect"] == "deny" and t1["effect"] == "allow"
          and t2["effect"] == "deny" and t3["effect"] == "deny")
    return {"observed": {"command_first": first, "command_replayed": again,
                         "telemetry_first": t1, "telemetry_replayed": t2,
                         "telemetry_stale": t3}, "passed": ok}


def s5_genuine_fault(base, calibration=None):
    """
    LT-101's transmitter freezes — a real hardware fault, no attacker. The right response
    is a maintenance ticket and taking the value out of the control loop, *not* revoking
    the device's identity.
    """
    site = Site(os.path.join(base, "s5"), calibration=calibration, level=1.3)
    frozen = {}

    def tamper(t, s, v):
        if s == "LT-101" and t >= 100:
            return frozen.setdefault("v", v)
        return v
    site.tamper = tamper
    site.run(600)
    diag = [e for e in site.gw.events if e["kind"] in ("fault_detected", "attack_detected",
                                                     "ambiguous_anomaly")]
    first = diag[0] if diag else None
    ok = (first is not None and first["kind"] == "fault_detected" and first["subject"] == "LT-101"
          and not site.gw.ca.is_revoked(site.dev["LT-101"].cert)
          and not site.gw.trust.is_quarantined("LT-101")
          and site.log[-1]["control_source"] == "gateway-consensus"
          and site.plant.overflow_seconds == 0)
    return {"observed": {"first_diagnosis": first,
                         "detected_after_s": None if first is None else int(first["ts"] - site.t0) - 100,
                         "LT101_revoked": site.gw.ca.is_revoked(site.dev["LT-101"].cert),
                         "LT101_trust": site.gw.trust.score("LT-101"),
                         "control_source_at_end": site.log[-1]["control_source"],
                         "overflow_seconds": site.plant.overflow_seconds,
                         "tickets": site.gw.tickets}, "passed": ok}


def s6_stolen_token(base):
    """Ravi's session token is lifted from console-01 and replayed from console-02."""
    site = Site(os.path.join(base, "s6"))
    site.run(5)
    login = site.login("ravi", console="console-01")
    _, d = site.send_command(login["token"], "pump.force_off", "P-101", console="console-02")
    _, esc = site.send_command(login["token"], "interlock.bypass", "P-101", console="console-01")
    ok = d["effect"] == "deny" and esc["effect"] == "deny"
    return {"observed": {"token_from_other_console": d, "privilege_escalation": esc}, "passed": ok}


def s7_m2m_forgery(base):
    """A forged 'tank is low' message to the pump controller, signed with a key the CA never saw."""
    site = Site(os.path.join(base, "s7"))
    site.run(5)
    from cryptography.hazmat.primitives.asymmetric import ec
    forged = sign_envelope(ec.generate_private_key(ec.SECP256R1()),
                           {"device_id": "LT-101", "nonce": "x" * 32, "ts": site.now, "seq": 10**6,
                            "value": 0.2, "kind": "level"})
    d_forged = site.gw.authorize_m2m(site.dev["LT-101"].cert, forged, "level")
    d_actuator = site.gw.authorize_m2m(site.dev["XV-101"].cert,
                                       site.dev["XV-101"].envelope(value=0.2, kind="level"), "level")
    d_genuine = site.gw.authorize_m2m(site.dev["LT-101"].cert,
                                      site.dev["LT-101"].envelope(value=1.4, kind="level"), "level")
    ok = d_forged["effect"] == "deny" and d_actuator["effect"] == "deny" and d_genuine["effect"] == "allow"
    return {"observed": {"forged_signature": d_forged, "actuator_posing_as_sensor": d_actuator,
                         "genuine_peer": d_genuine}, "passed": ok}


def s8_device_enrolment(base):
    """
    Commissioning a new flow meter, FT-102. The device makes its own key; the CA only
    signs a request. Then an attacker tries to abuse the enrolment and renewal paths.
    """
    import time as _t

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from .ca import EnrolmentError, identity_of

    def attempt(fn):
        try:
            fn()
            return {"ok": True}
        except EnrolmentError as e:
            return {"ok": False, "reason": str(e)}

    site = Site(os.path.join(base, "s8"))
    site.run(5)
    ca = site.gw.ca
    token = ca.create_enrolment_token("FT-102", "sensor")
    dev = DeviceIdentity.generate("FT-102", site.clock)
    cert = dev.enrol(ca, token)
    days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
    ca_holds_key = os.path.exists(ca.paths("FT-102")[0])
    first = site.gw.telemetry(dev.cert, dev.envelope(value=0.4))

    # The same token, used again by an attacker with their own key.
    thief = DeviceIdentity.generate("FT-102", site.clock)
    reuse = attempt(lambda: thief.enrol(ca, token))

    # A sensor token, with a CSR that asks to be an operator console.
    tok2 = ca.create_enrolment_token("FT-103", "sensor")
    k = ec.generate_private_key(ec.SECP256R1())
    greedy_csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "FT-103"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "console")])).sign(k, hashes.SHA256()))
    greedy = ca.enrol(tok2, greedy_csr.public_bytes(serialization.Encoding.PEM))
    greedy_role = identity_of(greedy)[1]

    # A token that turns up after it has expired.
    tok3 = ca.create_enrolment_token("FT-104", "sensor", ttl_s=3600)
    expired = attempt(lambda: DeviceIdentity.generate("FT-104", site.clock).enrol(
        ca, tok3, now=_t.time() + 2 * 3600))

    # Routine renewal: new key, old certificate retired.
    old_cert, old_key = dev.cert, dev.key
    dev.renew(ca)
    old_msg = sign_envelope(old_key, {"device_id": "FT-102", "nonce": "a" * 32,
                                      "ts": site.now, "seq": 999, "value": 0.4})
    old_after = site.gw.telemetry(old_cert, old_msg)
    new_after = site.gw.telemetry(dev.cert, dev.envelope(value=0.41))

    # A quarantined device tries to renew itself back into the plant.
    ca.revoke(dev.cert, "attack_detected")
    comeback = attempt(lambda: dev.renew(ca))

    ok = (first["effect"] == "allow" and not ca_holds_key and days <= 31
          and not reuse["ok"] and greedy_role == "sensor" and not expired["ok"]
          and old_after["effect"] == "deny" and new_after["effect"] == "allow"
          and not comeback["ok"])
    return {"observed": {"enrolled": {"certificate_days": days, "ca_holds_device_key": ca_holds_key,
                                      "first_reading": first},
                         "token_reused_by_attacker": reuse,
                         "csr_asks_for_console_role": {"issued_role": greedy_role},
                         "expired_token": expired,
                         "after_renewal": {"old_certificate": old_after, "new_certificate": new_after},
                         "quarantined_device_renews": comeback}, "passed": ok}


def s9_mqtt_transport(base):
    """
    Readings travel over MQTT (the standard industrial IoT protocol) through a real
    Mosquitto broker. A stolen LT-101 key tries to post as PT-101; a rogue device and a
    device with no certificate try to connect; LT-101 is revoked and tries to reconnect.
    """
    import socket
    import time as _t

    from .mqtt import (MQTT_NOT_AUTHORIZED, TELEMETRY, MosquittoBroker, MqttDevice,
                       MqttGatewayBridge, broker_available)
    if not broker_available():
        return {"observed": {"skipped": "mosquitto is not installed (see README: MQTT demo)"},
                "passed": None}
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    site = Site(os.path.join(base, "s9"))
    site.run(5)
    ca = site.gw.ca
    broker = MosquittoBroker(ca, os.path.join(base, "s9-broker"), port=port).start()
    bridge = MqttGatewayBridge(site.gw, port=port).start()
    lt = MqttDevice(site.dev["LT-101"], os.path.join(base, "s9-LT-101"), ca.ca_cert_path, port=port)
    try:
        connected = lt.connect()
        rc_own = lt.publish(site.dev["LT-101"].envelope(value=1.40))
        delivered = bridge.wait_for(1)
        rc_spoof = lt.publish(site.dev["LT-101"].envelope(value=0.10, device_id="PT-101"),
                              topic=TELEMETRY + "PT-101")
        _t.sleep(0.5)
        spoof_reached_gateway = any(m["device"] == "PT-101" for m in bridge.received)

        rogue_ca = CertificateAuthority(os.path.join(base, "s9-rogue-ca"), name="Attacker CA")
        rogue = DeviceIdentity.commission(rogue_ca, "PT-101", "sensor", site.clock)
        rogue_conn = MqttDevice(rogue, os.path.join(base, "s9-rogue"), ca.ca_cert_path,
                                port=port).connect()
        anon_conn = MqttDevice(site.dev["PT-101"], os.path.join(base, "s9-anon"), ca.ca_cert_path,
                               port=port, use_cert=False).connect()

        # Revoked while connected: the gateway refuses the very next message. Then the
        # broker reloads its revocation list and the device cannot reconnect.
        ca.revoke(site.dev["LT-101"].cert, "attack_detected")
        lt.publish(site.dev["LT-101"].envelope(value=1.41))
        after_revoke = bridge.wait_for(2)[-1]["decision"]
        lt.close()
        broker.reload()
        _t.sleep(1.0)
        reconnect = MqttDevice(site.dev["LT-101"], os.path.join(base, "s9-LT-101b"), ca.ca_cert_path,
                               port=port).connect()
    finally:
        bridge.stop()
        broker.stop()
    ok = (connected[0] and rc_own == 0 and bool(delivered)
          and delivered[0]["decision"]["effect"] == "allow"
          and rc_spoof == MQTT_NOT_AUTHORIZED and not spoof_reached_gateway
          and not rogue_conn[0] and not anon_conn[0]
          and after_revoke["effect"] == "deny" and not reconnect[0])
    return {"observed": {"own_topic": {"broker_reason_code": rc_own,
                                       "gateway": delivered[0]["decision"] if delivered else None},
                         "posting_as_PT-101": {"broker_reason_code": rc_spoof,
                                               "meaning": "135 = not authorised",
                                               "reached_gateway": spoof_reached_gateway},
                         "attacker_ca_connect": rogue_conn[1], "no_certificate_connect": anon_conn[1],
                         "message_on_open_connection_after_revocation": after_revoke,
                         "reconnect_after_revocation": reconnect[1]}, "passed": ok}


def s10_5g_binding(base):
    """
    Private 5G: the gateway checks that the certificate, the SIM's address and the slice
    all match. Subscriber data is the sample table in config/5g_subscribers.json; the
    5G core itself is not running in this PoC.
    """
    from .fiveg import FiveGBinding
    site = Site(os.path.join(base, "s10"))
    site.run(5)
    gw = site.gw
    gw.network = FiveGBinding.load(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "config", "5g_subscribers.json"))
    lt = site.dev["LT-101"]

    genuine = gw.telemetry(lt.cert, lt.envelope(value=1.40), source_ip="10.46.0.11")

    rogue_ca = CertificateAuthority(os.path.join(base, "s10-rogue-ca"), name="Attacker CA")
    thief = DeviceIdentity.commission(rogue_ca, "LT-101", "sensor", site.clock)
    stolen_sim = gw.telemetry(thief.cert, thief.envelope(value=0.2), source_ip="10.46.0.11")

    key_on_other_sim = gw.telemetry(lt.cert, lt.envelope(value=0.2), source_ip="10.46.0.12")
    key_on_unknown_sim = gw.telemetry(lt.cert, lt.envelope(value=0.2), source_ip="10.46.0.99")

    login = site.login("asha", console="console-02")
    env = site.dev["console-02"].command("pump.force_on", "P-101")
    on_control = gw.command(site.dev["console-02"].cert, login["token"], env, source_ip="10.45.0.21")
    ft = site.dev["FT-101"]
    sensor_cmd = gw.command(ft.cert, login["token"], ft.command("pump.force_on", "P-101"),
                            source_ip="10.46.0.13")
    lt_revoked = gw.ca.is_revoked(lt.cert)

    vendor = DeviceIdentity.commission(gw.ca, "vendor-01", "service", site.clock)
    maintenance = gw.telemetry(vendor.cert, vendor.envelope(value=0), source_ip="10.47.0.31")

    wired = site.login("ravi", console="console-01")
    wired_cmd = gw.command(site.dev["console-01"].cert, wired["token"],
                           site.dev["console-01"].command("valve.set", "XV-101", position=0.5),
                           source_ip="192.168.10.5")

    ok = (genuine["effect"] == "allow" and stolen_sim["effect"] == "deny"
          and key_on_other_sim["effect"] == "deny" and key_on_unknown_sim["effect"] == "deny"
          and lt_revoked
          and on_control["effect"] == "allow" and sensor_cmd["effect"] == "deny"
          and "slice" in sensor_cmd["reasons"][0]
          and maintenance["effect"] == "deny" and wired_cmd["effect"] == "allow")
    return {"observed": {"genuine_LT101_on_its_SIM": genuine,
                         "stolen_SIM_without_the_device_key": stolen_sim,
                         "LT101_key_on_PT101_SIM": key_on_other_sim,
                         "LT101_key_on_unknown_SIM": key_on_unknown_sim,
                         "LT101_revoked_as_stolen_key": lt_revoked,
                         "command_from_tablet_on_control_slice": on_control,
                         "command_from_sensor_on_telemetry_slice": sensor_cmd,
                         "vendor_on_closed_maintenance_slice": maintenance,
                         "wired_console_unaffected": wired_cmd}, "passed": ok}


def s11_opcua_shadow(base):
    """
    Pilot-site mode. SenseTrust may only read the plant's OPC UA server (the PLC). The
    LT-101 transmitter behind the PLC is compromised and reports the tank 65% low, so the
    PLC overfills the tank. SenseTrust must spot it from physics alone and raise an
    incident, without revoking or blocking anything. A rogue client and a client without
    a certificate try to connect; SenseTrust tries to write a value.
    """
    try:
        import asyncio
        import socket

        from asyncua import Client, ua
        from .gateway import Gateway
        from .opcua import OpcUaShadowMonitor, PlantOpcUaServer, SimulatedPlc
    except ImportError:
        return {"observed": {"skipped": "asyncua is not installed (pip install -r requirements.txt)"},
                "passed": None}
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    start = 120

    async def run():
        gw = Gateway(os.path.join(base, "s11"))
        server = await PlantOpcUaServer(gw.ca, os.path.join(base, "s11-plc"), port=port).start()
        obs = {}
        try:
            eps = await Client(server.url).connect_and_get_server_endpoints()
            obs["endpoints_offered"] = sorted({"%s/%s" % (e.SecurityPolicyUri.split("#")[-1],
                                                          e.SecurityMode.name) for e in eps})
            rogue = CertificateAuthority(os.path.join(base, "s11-rogue-ca"), name="Attacker CA")
            try:
                await OpcUaShadowMonitor(gw, server.url, ca=rogue).connect()
                obs["rogue_client"] = "connected"
            except Exception as e:
                obs["rogue_client"] = "refused: %s" % (
                    "BadCertificateUntrusted" if "Untrusted" in str(e) else type(e).__name__)
            try:
                async with Client(server.url):
                    obs["no_certificate_client"] = "connected"
            except Exception as e:
                obs["no_certificate_client"] = "refused: %s" % str(e).split(",")[0][:60]

            plc = SimulatedPlc(server)
            mon = await OpcUaShadowMonitor(gw, server.url).connect()
            try:
                try:
                    await mon.client.write_values([mon.nodes["LT-101"]], [2.9])
                    obs["monitor_write_attempt"] = "accepted"
                except ua.UaStatusCodeError as e:
                    obs["monitor_write_attempt"] = "refused: %s" % type(e).__name__
                detected_at = None
                for _ in range(start + 300):
                    if plc.t == start:
                        plc.tamper = lambda t, s, v: v * 0.35 if s == "LT-101" and t > start else v
                    await plc.step()
                    if any(d.verdict == "attack" for d in await mon.poll()) and detected_at is None:
                        detected_at = plc.t - start
            finally:
                await mon.disconnect()
            obs["diagnoses"] = [(e["kind"], e["subject"]) for e in gw.events
                                if e["kind"] in ("attack_detected", "fault_detected",
                                                 "ambiguous_anomaly")]
            obs["attack_detected_after_s"] = detected_at
            obs["quarantined"] = sorted(gw.trust.quarantined())
            obs["tickets"] = gw.tickets
            obs["tank_level_at_end_m"] = round(plc.plant.h, 2)
            obs["note"] = ("shadow mode alerts only: the PLC kept trusting LT-101; "
                           "enforcement mode (S2) is what prevents the overflow")
            return obs
        finally:
            await server.stop()
            gw.close()

    obs = asyncio.run(run())
    passed = (obs["endpoints_offered"] == ["Basic256Sha256/SignAndEncrypt"]
              and obs["rogue_client"].startswith("refused")
              and obs["no_certificate_client"].startswith("refused")
              and obs["monitor_write_attempt"].startswith("refused")
              and obs["diagnoses"] == [("attack_detected", "LT-101")]
              and obs["attack_detected_after_s"] is not None
              and obs["quarantined"] == [])
    return {"observed": obs, "passed": passed}


SCENARIOS = [
    ("S1", "Rogue / cloned device", "Device identity, mTLS", s1_rogue_device),
    ("S2", "Stolen key + false data injection", "Anomaly detection, M2M trust, revocation", s2_stolen_key_false_data),
    ("S3", "Fingerprint photo replay on critical command", "Authentication (biometric + liveness)", s3_fingerprint_spoof),
    ("S4", "API request replay", "Secure APIs", s4_api_replay),
    ("S5", "Genuine sensor fault", "Fault vs attack separation", s5_genuine_fault),
    ("S6", "Stolen session token", "Secure access (sender-constrained tokens, least privilege)", s6_stolen_token),
    ("S7", "Forged M2M interlock", "Machine-to-machine trust", s7_m2m_forgery),
    ("S8", "Device enrolment and renewal abuse", "Device identity lifecycle", s8_device_enrolment),
    ("S9", "MQTT: stolen key posts as another sensor", "Secure APIs over MQTT, encryption", s9_mqtt_transport),
    ("S10", "5G: key and SIM must belong together", "Device identity on private 5G, slices", s10_5g_binding),
    ("S11", "OPC UA shadow mode: compromised sensor behind the PLC",
     "Anomaly detection on read-only plant data, secure OPC UA", s11_opcua_shadow),
]

def load_calibration(path="results/calibration.pkl"):
    if os.path.exists(path):
        import pickle
        with open(path, "rb") as f:
            return pickle.load(f)
    return None


def run_all(base=None, calibration=None):
    base = base or tempfile.mkdtemp(prefix="sensetrust-")
    results = []
    for sid, name, keywords, fn in SCENARIOS:
        kw = {"calibration": calibration} if fn in (s2_stolen_key_false_data, s5_genuine_fault) else {}
        r = fn(base, **kw)
        results.append({"id": sid, "name": name, "ps13": keywords, **r})
    return results


def main():
    cal = load_calibration()
    results = run_all(calibration=cal)
    os.makedirs("results", exist_ok=True)
    with open("results/scenarios.json", "w") as f:
        json.dump([{k: v for k, v in r.items() if not k.startswith("_")} for r in results],
                  f, indent=2, default=str)
    width = max(len(r["name"]) for r in results)
    for r in results:
        status = "SKIP" if r["passed"] is None else ("PASS" if r["passed"] else "FAIL")
        print("%-3s  %-*s  %s   [%s]" % (r["id"], width, r["name"], status, r["ps13"]))
    s2 = next(r for r in results if r["id"] == "S2")["observed"]
    print("\nS2 physical impact: baseline overflow %ds (peak %.2f m, rim at %.1f m)  vs  zero-trust %ds (peak %.2f m)"
          % (s2["baseline"]["overflow_seconds"], s2["baseline"]["max_true_level_m"], OVERFLOW,
             s2["zero_trust"]["overflow_seconds"], s2["zero_trust"]["max_true_level_m"]))
    sys.exit(0 if all(r["passed"] is not False for r in results) else 1)


if __name__ == "__main__":
    main()
