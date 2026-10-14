"""
The live plant behind the operator console (console/server.py).

One `LivePlant` for the demo: the real gateway in front of the simulated water
plant, advanced in step with the wall clock (SPEED plant seconds per real second), plus
the operator-side state the console needs: who is logged in, incident status, injected
attacks and faults, and counts of every gateway decision.

Nothing here bypasses the gateway. Console actions that change the plant (revoke,
reinstate, close maintenance, set the valve) are signed commands from console-01 with
the supervisor's fingerprint-backed token, decided by the same policy engine as
everything else.
"""

import json
import os
import tempfile
import time
from collections import Counter

from sensetrust import scenarios
from sensetrust.ca import CertificateAuthority
from sensetrust.devices import DeviceIdentity
from sensetrust.plant import SENSORS
from sensetrust.site import DEVICES, OPERATORS, Site
from sensetrust.synthetic import make_template, recapture, screen_recapture_image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEED = 6                 # plant seconds per real second
MAX_STEPS_PER_REFRESH = 30
CONSOLE = "console-01"
SUPERVISOR = "asha"

# How each device reaches the gateway in the reference deployment (docs/architecture.md).
TRANSPORT = {
    "LT-101": "MQTT over mTLS 1.3", "PT-101": "MQTT over mTLS 1.3", "FT-101": "MQTT over mTLS 1.3",
    "P-101": "HTTPS mTLS 1.3", "XV-101": "HTTPS mTLS 1.3",
    "console-01": "HTTPS mTLS 1.3 (wired)", "console-02": "HTTPS mTLS 1.3",
}


def _load_5g():
    try:
        with open(os.path.join(ROOT, "config", "5g_subscribers.json")) as f:
            data = json.load(f)
        return {s["identity"]: s for s in data["subscribers"]}
    except (OSError, ValueError, KeyError):
        return {}


class LivePlant:

    def __init__(self):
        cal = scenarios.load_calibration(os.path.join(ROOT, "results", "calibration.pkl"))
        self.dir = tempfile.mkdtemp(prefix="sensetrust-console-")
        self.site = Site(self.dir, calibration=cal, level=1.3)
        self.gw = self.site.gw
        self.running = True
        self._wall = time.monotonic()
        self._carry = 0.0
        self.tampers = {}                    # sensor -> (description, fn(t, v))
        self.notes = []                      # (plant t, text): what the operator did
        self.incident_status = {}            # incident id -> "acknowledged" | "resolved"
        self.subscribers = _load_5g()
        self.counts = Counter()              # gateway decisions: (kind, effect)
        self.by_device = Counter()           # (device, effect): drives the message animation
        self.last_fingerprint = None         # what the reader saw on the last step-up
        self.roles = dict(DEVICES)
        self.last_action = None              # (ok, message) for the console to show
        self._wrap_gateway()
        self.site.step()

    # ── plant clock ──────────────────────────────────────────────────────────

    @property
    def t(self):
        return self.site.plant.t

    def advance(self):
        """Catch the plant up with the wall clock. Safe to call from every page refresh."""
        now = time.monotonic()
        if self.running:
            self._carry += (now - self._wall) * SPEED
            n = min(int(self._carry), MAX_STEPS_PER_REFRESH)
            self._carry -= int(self._carry)
            for _ in range(n):
                self.site.step()
        self._wall = now

    def _wrap_gateway(self):
        for kind in ("telemetry", "command", "authorize_m2m"):
            original = getattr(self.gw, kind)

            def counted(*a, _orig=original, _kind=kind, **k):
                d = _orig(*a, **k)
                self.counts[(_kind, d["effect"])] += 1
                env = a[1] if len(a) > 1 and isinstance(a[1], dict) else (a[2] if len(a) > 2 else {})
                who = (env.get("body") or {}).get("device_id", "unknown")
                if d["effect"] != "allow" and "not issued by plant CA" in " ".join(d["reasons"]):
                    who = "rogue"
                self.by_device[(who, "allow" if d["effect"] == "allow" else "deny")] += 1
                return d
            setattr(self.gw, kind, counted)

    def checked(self):
        return sum(self.counts.values())

    def denied(self):
        return sum(n for (k, e), n in self.counts.items() if e != "allow")

    # ── what the attacker / the plant does (Attack lab) ──────────────────────

    def _apply_tampers(self):
        tampers = dict(self.tampers)
        self.site.tamper = (lambda t, s, v: tampers[s][1](t, v) if s in tampers else v) \
            if tampers else None

    def note(self, text):
        self.notes.append((self.t, text))

    def inject_false_data(self, sensor="LT-101"):
        start = self.t + 1
        self.tampers[sensor] = ("stolen-key false data",
                                lambda t, v: v * 0.35 if t >= start else v)
        self._apply_tampers()
        self.note("Attacker with %s's real key starts reporting a third of the true value" % sensor)

    def inject_fault(self, sensor="LT-101"):
        frozen = {}
        start = self.t + 1
        self.tampers[sensor] = ("transmitter frozen",
                                lambda t, v: frozen.setdefault("v", v) if t >= start else v)
        self._apply_tampers()
        self.note("%s transmitter freezes (hardware fault, no attacker)" % sensor)

    def rogue_device(self):
        rogue_ca = CertificateAuthority(tempfile.mkdtemp(prefix="rogue-ca-"), name="Attacker CA")
        rogue = DeviceIdentity.commission(rogue_ca, "PT-101", "sensor", self.site.clock)
        d = self.gw.telemetry(rogue.cert, rogue.envelope(value=5.0))
        self.note("Rogue device claiming to be PT-101 sends a reading: %s" % d["effect"].upper())

    def spoof_login(self):
        r = self.site.login(SUPERVISOR, image=screen_recapture_image())
        self.note("Supervisor's finger photo held up on a phone screen: login %s"
                  % ("ALLOWED" if r["ok"] else "DENIED"))

    def impostor_login(self):
        r = self.site.login(SUPERVISOR, minutiae=recapture(make_template(seed=4242), seed=1))
        self.note("Someone else's finger on the supervisor's account: login %s"
                  % ("ALLOWED" if r["ok"] else "DENIED"))

    def stolen_token(self):
        """A valid supervisor token, copied off console-01, replayed from console-02."""
        r = self._fingerprint()
        if not r["ok"]:
            return
        _, d = self.site.send_command(r["token"], "valve.set", "XV-101", console="console-02",
                                      position=0.9)
        self.note("Supervisor's token stolen and used from console-02: %s" % d["effect"].upper())

    # ── what the operator does (console actions) ─────────────────────────────

    def _fingerprint(self):
        """The supervisor's genuine finger on console-01's reader (fingerprint + liveness)."""
        return self.site.login(SUPERVISOR, minutiae=recapture(self.site.finger(SUPERVISOR),
                                                              seed=self.t, rotation=15))

    def command(self, action, target, **params):
        """Fingerprint step-up, then a signed command from console-01. Returns (ok, message)."""
        r = self._fingerprint()
        self.last_fingerprint = {"ok": r["ok"], "score": round(r.get("score") or 0, 2),
                                 "operator": SUPERVISOR, "console": CONSOLE}
        if not r["ok"]:
            self.last_action = (False, "Fingerprint check failed: %s" % "; ".join(r["reasons"]))
            return self.last_action
        _, d = self.site.send_command(r["token"], action, target, **params)
        who = OPERATORS[SUPERVISOR]["role"].replace("_", " ")
        ok = d["effect"] == "allow"
        msg = ("Fingerprint + liveness verified (match %.2f) for %s on %s. Gateway: %s — %s"
               % (r["score"], who, CONSOLE, d["effect"].upper(), "; ".join(d["reasons"])))
        self.note("%s %s → %s" % (action, target, d["effect"].upper()))
        self.last_action = (ok, msg)
        return self.last_action

    def reinstate(self, identity):
        return self.command("device.reinstate", identity)

    def revoke(self, identity):
        return self.command("device.revoke", identity)

    def close_maintenance(self, identity):
        """Technician repaired the instrument; supervisor closes the ticket."""
        if identity in self.tampers and "frozen" in self.tampers[identity][0]:
            del self.tampers[identity]
            self._apply_tampers()
        return self.command("maintenance.close", identity)

    def technician_reenrol(self, identity):
        """
        On site: the device is re-flashed (attacker's foothold gone), generates a NEW key
        and redeems the one-time token the supervisor's approval produced.
        """
        token = self.gw.pending_enrolments.pop(identity, None)
        if token is None:
            self.last_action = (False, "No approved re-enrolment for %s" % identity)
            return self.last_action
        dev = DeviceIdentity.generate(identity, self.site.clock)
        dev.enrol(self.gw.ca, token)
        self.site.dev[identity] = dev
        self.tampers.pop(identity, None)
        self._apply_tampers()
        self.note("Technician re-flashed %s; it generated a new key and enrolled (serial %x…)"
                  % (identity, dev.cert.serial_number >> 120))
        self.last_action = (True, "%s re-enrolled with a new key. The old certificate stays revoked."
                            % identity)
        return self.last_action

    def commission(self, identity, role):
        """A brand-new device: the admin issues a one-time token; the device enrols."""
        if identity in self.site.dev:
            self.last_action = (False, "%s already exists" % identity)
            return self.last_action
        token = self.gw.ca.create_enrolment_token(identity, role)
        dev = DeviceIdentity.generate(identity, self.site.clock)
        dev.enrol(self.gw.ca, token)
        self.site.dev[identity] = dev
        self.roles[identity] = role
        self.note("New %s %s commissioned: one-time token redeemed, key generated on the device"
                  % (role, identity))
        self.last_action = (True, "%s enrolled. Its private key never left the device." % identity)
        return self.last_action

    # ── read models for the pages ────────────────────────────────────────────

    def device_rows(self):
        rows = []
        for ident, dev in self.site.dev.items():
            role = self.roles.get(ident, "sensor")
            cert = dev.cert
            q = self.gw.trust.is_quarantined(ident)
            revoked = self.gw.ca.is_revoked(cert)
            if ident in self.gw.pending_enrolments:
                status = "Awaiting re-enrolment"
            elif q or revoked:
                status = "Revoked"
            elif ident in self.gw.degraded:
                status = "Maintenance"
            else:
                status = "Trusted"
            days = (cert.not_valid_after_utc.timestamp() - time.time()) / 86400
            sub = self.subscribers.get(ident)
            rows.append({
                "Device": ident, "Role": role, "Status": status,
                "Trust": round(self.gw.trust.score(ident), 2),
                "Link": TRANSPORT.get(ident, "HTTPS mTLS 1.3"),
                "5G SIM": sub["ip"] if sub else "—",
                "5G slice": sub["slice"] if sub else "—",
                "Certificate": "%x…" % (cert.serial_number >> 120),
                "Expires in": "%d days" % max(0, days),
            })
        return rows

    def incidents(self):
        """Gateway events grouped into incidents an operator acts on, newest first."""
        out, done = {}, []
        for e in self.gw.events:
            kind, subj = e["kind"], e["subject"]
            t = int(e["ts"] - self.site.t0)
            if kind == "attack_detected":
                key = ("attack", subj)
            elif kind == "fault_detected":
                key = ("fault", subj)
            elif kind == "ambiguous_anomaly":
                key = ("inspect", subj)
            elif (kind == "telemetry_denied" and "identity rejected" in e["detail"]
                  and "revoked" not in e["detail"]):
                key = ("rogue", subj)
            elif kind == "login_denied":
                key = ("spoof" if "presentation attack" in e["detail"] else "login", subj)
            elif kind == "command_deny" and "different console" in e["detail"]:
                key = ("token", subj)
            else:
                continue
            inc = out.get(key)
            if inc is None or self.incident_status.get(inc["id"]) == "resolved":
                iid = "%s:%s:%d" % (key[0], key[1], t)
                inc = out[key] = {"id": iid, "type": key[0], "subject": subj, "first": t, "last": t,
                                  "count": 0, "event": e, "events": []}
                done.append(inc)
            inc["last"] = t
            inc["count"] += 1
            if len(inc["events"]) < 6:
                inc["events"].append({"t": t, "detail": e["detail"]})
        incs = done
        for inc in incs:
            inc["status"] = self.incident_status.get(inc["id"], "open")
            s = inc["subject"]
            if inc["type"] in ("attack", "rogue") and s in SENSORS:
                inc["device_state"] = ("awaiting re-enrolment" if s in self.gw.pending_enrolments
                                       else "revoked" if self.gw.trust.is_quarantined(s) else "trusted")
            elif inc["type"] == "fault":
                inc["device_state"] = "maintenance" if s in self.gw.degraded else "repaired"
        return sorted(incs, key=lambda i: i["first"], reverse=True)


# ── words for people ─────────────────────────────────────────────────────────

SEVERITY = {"attack": "critical", "rogue": "critical", "spoof": "critical", "token": "critical",
            "fault": "maintenance", "inspect": "warning", "login": "warning"}


def person(op):
    return "Supervisor %s" % op.capitalize() if op == SUPERVISOR else op.capitalize()


def _times(n):
    return "1 attempt" if n == 1 else "%d attempts" % n


def describe(inc, plant):
    """(title, what happened, what SenseTrust did, what to do) in plain words."""
    s, n, typ = inc["subject"], inc["count"], inc["type"]
    kind = (inc["event"].get("diagnosis") or {}).get("kind", "").replace("_", " ")
    if typ == "attack":
        refused = sum(1 for e in plant.gw.events if e["subject"] == s
                      and e["kind"] in ("telemetry_denied", "m2m_denied") and "revoked" in e["detail"])
        return ("%s is sending false readings" % s,
                "Its values contradict what pressure and flow say the tank is doing, while its own "
                "signal looks healthy. That is someone using its key to lie (%s)." % kind,
                "Revoked its certificate and cut it off within the same second. Pump control "
                "switched to a physics-based level. %d further messages refused." % refused,
                "Inspect the device on site. Once it is clean, approve re-enrolment with your "
                "fingerprint; the technician then enrols it with a new key.")
    if typ == "fault":
        return ("%s looks broken, not attacked" % s,
                "Its signal shows a hardware failure pattern (%s) and nothing suspicious on its "
                "network channel." % kind,
                "Raised a maintenance ticket and stopped using its value in control. Its identity "
                "and certificate are untouched.",
                "Send a technician. After the repair, close maintenance so its value is used again.")
    if typ == "inspect":
        return ("%s is drifting slowly" % s,
                "A slow, smooth divergence from physics: calibration drift or a patient attacker. "
                "The data alone cannot tell which.",
                "Raised an inspection ticket and lowered its trust score.",
                "Check its calibration on site.")
    if typ == "rogue":
        return ("Unknown device posing as %s" % s,
                "A device presented a certificate this plant's CA never issued (%s)." % _times(n),
                "Refused every message before it reached the controller.",
                "Find it: check the switch port or 5G SIM it connected from.")
    if typ == "spoof":
        return ("Finger photo used on %s's account" % person(s),
                "Someone held a picture of the supervisor's finger up to the reader. Liveness "
                "detection saw a screen's pixel pattern.",
                "Refused the login. Repeated attempts lock the account.",
                "Check who was at the console at that time.")
    if typ == "login":
        return ("Wrong finger on %s's account" % person(s),
                "A fingerprint that does not match the enrolled supervisor (%s)." % _times(n),
                "Refused the login.",
                "Confirm with the supervisor whether this was them.")
    if typ == "token":
        return ("%s's session used from another console" % person(s),
                "A valid session token, copied from console-01, was replayed from console-02.",
                "Refused: a token only works from the console certificate it was issued to.",
                "Treat console-01 as compromised: check it for malware and end the operator's "
                "sessions.")
    return (typ, "", "", "")


def status(plant):
    gw = plant.gw
    revoked = sorted(s for s in gw.trust.quarantined() if not s.startswith("operator:"))
    if revoked:
        return ("alarm", "Attack contained",
                "%s cut off and %s. The plant runs on the instruments it can still trust."
                % (", ".join(revoked), "its certificate revoked" if len(revoked) == 1
                   else "their certificates revoked"))
    if gw.degraded:
        return ("fault", "Maintenance needed",
                "%s looks broken, not attacked. Its value is set aside until it is repaired."
                % ", ".join(sorted(gw.degraded)))
    if gw.pending_enrolments:
        return ("fault", "Waiting for a technician",
                "Re-enrolment approved for %s. It must enrol a new key on site."
                % ", ".join(sorted(gw.pending_enrolments)))
    return ("ok", "Normal operation",
            "Every device is who it says it is, and every reading agrees with plant physics.")


def device_state(plant, ident):
    gw = plant.gw
    if ident in gw.pending_enrolments:
        return "pending"
    if gw.trust.is_quarantined(ident):
        return "revoked"
    if ident in gw.degraded:
        return "fault"
    return "ok"
