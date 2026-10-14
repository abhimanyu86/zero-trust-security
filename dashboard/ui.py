"""
Look and shared pieces of the operator console.

Design rule borrowed from control-room alarm practice (ISA-18.2 / high-performance HMI):
the screen stays quiet when the plant is normal and only abnormal things get colour.
Brand: YellowSense yellow and white, Syne for headings, Overpass for text.
"""

import html

import altair as alt
import pandas as pd
import streamlit as st

from sensetrust.plant import H_MAX, OVERFLOW

INK = "#2B2B2B"
MUTED = "#6B6B6B"
LINE = "#E6DFC8"
PAPER = "#FFFDF7"
YELLOW = "#FDD835"
AMBER = "#F9A825"
AMBER_TEXT = "#9A5B00"
PALE = "#FFF3C4"
ALARM = "#C62828"
ALARM_BG = "#FDECEA"
FAULT = "#0F6E78"
FAULT_BG = "#E3F2F3"
OK = "#2E7D32"

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@600;700;800&family=Overpass:wght@400;600;700&display=swap');
html, body, [class*="css"], .stMarkdown, .stText, button, input, textarea, select {
  font-family: 'Overpass', Arial, sans-serif;
}
h1, h2, h3, h4 { font-family: 'Syne', Arial, sans-serif !important; color: %(ink)s; letter-spacing: -0.01em; }
h1 { font-weight: 800 !important; font-size: 2.0rem !important; }
h3 { font-weight: 700 !important; font-size: 1.15rem !important; }
.block-container { padding-top: 2.2rem; max-width: 1280px; }
[data-testid="stSidebar"] { background: #FFF9E6; border-right: 1px solid %(line)s; }
button[kind="primary"], button[data-testid="stBaseButton-primary"] {
  background: %(yellow)s !important; color: %(ink)s !important; border: 1px solid %(amber)s !important;
  font-weight: 700;
}
button[kind="primary"]:hover, button[data-testid="stBaseButton-primary"]:hover { background: %(amber)s !important; }
button:focus-visible { outline: 3px solid %(amber_text)s !important; outline-offset: 2px; }
[data-testid="stMetricValue"] { font-family: 'Syne', Arial, sans-serif; font-weight: 700; }
[data-testid="stMetricLabel"] p { color: %(muted)s; }

.st-status { border-radius: 10px; padding: 14px 18px; margin: 4px 0 18px; font-size: 1.05rem;
  border: 1px solid %(line)s; background: #FFFFFF; display: flex; gap: 14px; align-items: baseline; }
.st-status b { font-family: 'Syne', Arial, sans-serif; font-size: 1.15rem; white-space: nowrap; }
.st-status.ok b { color: %(ok)s; }
.st-status.alarm { background: %(alarm_bg)s; border-color: %(alarm)s; }
.st-status.alarm b { color: %(alarm)s; }
.st-status.fault { background: %(fault_bg)s; border-color: %(fault)s; }
.st-status.fault b { color: %(fault)s; }

.inc { border: 1px solid %(line)s; border-left: 6px solid %(line)s; border-radius: 8px;
  background: #FFFFFF; padding: 14px 18px 6px; margin-bottom: 4px; }
.inc.critical { border-left-color: %(alarm)s; }
.inc.maintenance { border-left-color: %(fault)s; }
.inc.warning { border-left-color: %(amber)s; }
.inc.closed { opacity: .62; }
.inc h4 { margin: 0 0 2px; font-size: 1.08rem; }
.inc .meta { color: %(muted)s; font-size: .88rem; margin-bottom: 8px; }
.inc dl { display: grid; grid-template-columns: 9.5rem 1fr; gap: 4px 14px; margin: 0 0 8px; }
.inc dt { color: %(muted)s; font-size: .9rem; }
.inc dd { margin: 0; font-size: .95rem; }
.tag { display: inline-block; border-radius: 4px; padding: 1px 8px; font-size: .8rem; font-weight: 700;
  margin-right: 6px; }
.tag.critical { background: %(alarm_bg)s; color: %(alarm)s; }
.tag.maintenance { background: %(fault_bg)s; color: %(fault)s; }
.tag.warning { background: %(pale)s; color: %(amber_text)s; }
.tag.closed { background: #EEEEEE; color: %(muted)s; }
.proto { font-size: .8rem; color: %(muted)s; line-height: 1.35; }
.mapbox svg { width: 100%%; height: auto; display: block; }
@media (max-width: 640px) { .inc dl { grid-template-columns: 1fr; } }
</style>
""" % {"ink": INK, "line": LINE, "yellow": YELLOW, "amber": AMBER, "amber_text": AMBER_TEXT,
       "muted": MUTED, "ok": OK, "alarm": ALARM, "alarm_bg": ALARM_BG, "fault": FAULT,
       "fault_bg": FAULT_BG, "pale": PALE}


def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)


def clock(t):
    return "%d:%02d" % (t // 60, t % 60)


def esc(s):
    return html.escape(str(s))


# ── plant status in one sentence ─────────────────────────────────────────────

def status(engine):
    gw = engine.gw
    revoked = sorted(s for s in gw.trust.quarantined() if not s.startswith("operator:"))
    pending = sorted(gw.pending_enrolments)
    if revoked:
        names = ", ".join(revoked)
        return ("alarm", "Attack contained",
                "%s cut off and %s revoked. The plant is running on the instruments it can "
                "still trust." % (names, "its certificate" if len(revoked) == 1 else "their certificates"))
    if gw.degraded:
        names = ", ".join(sorted(gw.degraded))
        return ("fault", "Maintenance needed",
                "%s looks broken, not attacked. Its value is set aside until a technician "
                "repairs it; its identity is untouched." % names)
    if pending:
        return ("fault", "Waiting for a technician",
                "Re-enrolment approved for %s. The device must enrol a new key on site."
                % ", ".join(pending))
    return ("ok", "Normal operation",
            "Every device is who it says it is, and every reading agrees with plant physics.")


def status_banner(engine):
    cls, head, text = status(engine)
    st.markdown('<div class="st-status %s"><b>%s</b><span>%s</span></div>'
                % (cls, esc(head), esc(text)), unsafe_allow_html=True)


# ── the plant and its links, drawn live ─────────────────────────────────────

def _state(engine, ident):
    gw = engine.gw
    if ident in gw.pending_enrolments:
        return "pending"
    if gw.trust.is_quarantined(ident):
        return "revoked"
    if ident in gw.degraded:
        return "fault"
    return "ok"


STATE_STYLE = {"ok": (INK, "", "#FFFFFF"), "revoked": (ALARM, "6 5", ALARM_BG),
               "fault": (FAULT, "6 5", FAULT_BG), "pending": (AMBER_TEXT, "2 5", PALE)}
STATE_WORD = {"ok": "trusted", "revoked": "revoked", "fault": "maintenance",
              "pending": "awaiting new key"}


def plant_map(engine):
    """Field devices, their links to the gateway, the controller, and the tank itself."""
    last = engine.site.log[-1]
    left = [("LT-101", "Level", "MQTT over mTLS 1.3", 52), ("PT-101", "Pressure", "MQTT over mTLS 1.3", 138),
            ("FT-101", "Flow", "MQTT over mTLS 1.3", 224),
            ("console-01", "Console", "HTTPS mTLS + fingerprint", 310)]
    gx, gy = 330, 180
    parts = ['<svg viewBox="0 0 820 370" xmlns="http://www.w3.org/2000/svg" role="img" '
             'aria-label="Plant map: devices, their links to the SenseTrust gateway, and the tank">',
             '<style>text{font-family:Overpass,Arial,sans-serif;fill:%s}'
             '.h{font-family:Syne,Arial,sans-serif;font-weight:700}</style>' % INK]
    for ident, what, link, y in left:
        st_ = _state(engine, ident)
        color, dash, fill = STATE_STYLE[st_]
        parts.append('<line x1="186" y1="%d" x2="%d" y2="%.1f" stroke="%s" stroke-width="2.2" '
                     'stroke-dasharray="%s"/>' % (y, gx - 50, gy + (y - 180) * 0.3, color, dash))
        parts.append('<rect x="10" y="%d" width="176" height="68" rx="8" fill="%s" stroke="%s" '
                     'stroke-width="1.5"/>' % (y - 32, fill, color if st_ != "ok" else LINE))
        parts.append('<text x="22" y="%d" class="h" font-size="16">%s</text>' % (y - 10, ident))
        parts.append('<text x="22" y="%d" font-size="12.5" fill="%s">%s, %s</text>'
                     % (y + 9, color if st_ != "ok" else MUTED, what, STATE_WORD[st_]))
        parts.append('<text x="22" y="%d" font-size="11" fill="%s">%s</text>' % (y + 26, MUTED, link))
    # gateway
    under = engine.gw.trust.quarantined() or engine.gw.degraded
    parts.append('<path d="M%d %d l46 18 v44 c0 34 -26 54 -46 64 c-20 -10 -46 -30 -46 -64 v-44 z" '
                 'fill="%s" stroke="%s" stroke-width="2"/>'
                 % (gx, gy - 66, YELLOW if not under else PALE, AMBER_TEXT))
    parts.append('<text x="%d" y="%d" text-anchor="middle" class="h" font-size="15">SenseTrust</text>'
                  % (gx, gy - 6))
    parts.append('<text x="%d" y="%d" text-anchor="middle" font-size="11">gateway</text>' % (gx, gy + 10))
    parts.append('<text x="%d" y="%d" text-anchor="middle" font-size="10.5" fill="%s">identity, '
                 'policy, physics</text>' % (gx, gy + 92, MUTED))
    # controller
    src = last["control_source"]
    trusted_feed = src == "LT-101"
    parts.append('<line x1="%d" y1="%d" x2="462" y2="%d" stroke="%s" stroke-width="2"/>'
                 % (gx + 48, gy, gy, INK))
    parts.append('<rect x="462" y="%d" width="150" height="66" rx="8" fill="#FFFFFF" stroke="%s"/>'
                 % (gy - 32, LINE))
    parts.append('<text x="474" y="%d" class="h" font-size="15">Pump control</text>' % (gy - 10))
    parts.append('<text x="474" y="%d" font-size="12" fill="%s">uses %s</text>'
                 % (gy + 8, ALARM if not trusted_feed else MUTED,
                    "LT-101" if trusted_feed else "physics estimate"))
    parts.append('<text x="474" y="%d" font-size="12" fill="%s">pump %s</text>'
                 % (gy + 23, MUTED, "running" if last["pump"] else "stopped"))
    parts.append('<line x1="612" y1="%d" x2="650" y2="%d" stroke="%s" stroke-width="2"/>' % (gy, gy, INK))
    # tank
    tx, ty, tw, th = 650, 40, 150, 300
    scale = th / H_MAX
    true_h = max(0.0, min(H_MAX, last["true_level"]))
    water_y = ty + th - true_h * scale
    rim_y = ty + th - OVERFLOW * scale
    parts.append('<rect x="%d" y="%d" width="%d" height="%d" fill="#BBDEFB" opacity=".75"/>'
                 % (tx, water_y, tw, ty + th - water_y))
    parts.append('<rect x="%d" y="%d" width="%d" height="%d" fill="none" stroke="%s" stroke-width="2"/>'
                 % (tx, ty, tw, th, INK))
    parts.append('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="%s" stroke-dasharray="4 3"/>'
                 % (tx - 6, rim_y, tx + tw + 6, rim_y, ALARM))
    parts.append('<text x="%d" y="%.1f" font-size="10.5" fill="%s">overflow %.1f m</text>'
                 % (tx + 4, rim_y - 5, ALARM, OVERFLOW))
    parts.append('<text x="%d" y="%.1f" class="h" font-size="15">%.2f m</text>'
                 % (tx + 10, min(water_y + 22, ty + th - 8), true_h))
    parts.append('<text x="%d" y="%.1f" font-size="10.5">true level</text>'
                 % (tx + 10, min(water_y + 36, ty + th - 2) if water_y + 36 < ty + th else ty + th - 22))
    rep = last["reported_level"]
    if rep is not None and abs(rep - true_h) > 0.08:
        ry = ty + th - max(0.0, min(H_MAX, rep)) * scale
        parts.append('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="%s" stroke-width="3"/>'
                     % (tx - 14, ry, tx + 26, ry, ALARM))
        parts.append('<text x="%d" y="%.1f" text-anchor="end" font-size="11" fill="%s">LT-101 says '
                     '%.2f m</text>' % (tx - 18, ry + 4, ALARM, rep))
    parts.append('<text x="%d" y="%d" font-size="11" fill="%s">Tank T-101</text>' % (tx, ty - 10, MUTED))
    parts.append("</svg>")
    st.markdown('<div class="mapbox">%s</div>' % "".join(parts), unsafe_allow_html=True)


def level_chart(engine, window=300, height=260):
    log = engine.site.log[-window:]
    df = pd.DataFrame([{"t": r["t"], "True level": r["true_level"],
                        "LT-101 reports": r["reported_level"],
                        "Pump control uses": r["control_level"]} for r in log])
    levels_chart(df, height)


def levels_chart(df, height=260):
    """Lines for whichever of the three level series `df` has, with the overflow rim."""
    long = df.melt("t", var_name="series", value_name="level").dropna()
    series = [(n, c) for n, c in (("True level", INK), ("LT-101 reports", ALARM),
                                  ("Pump control uses", FAULT)) if n in df.columns]
    colors = alt.Scale(domain=[n for n, _ in series], range=[c for _, c in series])
    lines = alt.Chart(long).mark_line(strokeWidth=2).encode(
        x=alt.X("t:Q", title="plant time (s)"),
        y=alt.Y("level:Q", title="tank level (m)", scale=alt.Scale(domain=[0, H_MAX])),
        color=alt.Color("series:N", scale=colors, legend=alt.Legend(orient="top", title=None)),
        strokeDash=alt.condition(alt.datum.series == "Pump control uses",
                                 alt.value([6, 4]), alt.value([1, 0])))
    rim = alt.Chart(pd.DataFrame({"y": [OVERFLOW]})).mark_rule(
        color=ALARM, strokeDash=[4, 3]).encode(y="y:Q")
    st.altair_chart((lines + rim).properties(height=height), use_container_width=True)


# ── incidents in plain words ────────────────────────────────────────────────

SEVERITY = {"attack": "critical", "rogue": "critical", "spoof": "critical", "token": "critical",
            "fault": "maintenance", "inspect": "warning", "login": "warning"}
SEVERITY_WORD = {"critical": "Critical", "maintenance": "Maintenance", "warning": "Warning"}


def _times(n):
    return "1 attempt" if n == 1 else "%d attempts" % n


def person(op):
    return "Supervisor %s" % op.capitalize() if op == "asha" else op.capitalize()


def describe(inc, engine):
    """(title, what happened, what SenseTrust did, what you should do)."""
    s, n, typ = inc["subject"], inc["count"], inc["type"]
    kind = (inc["event"].get("diagnosis") or {}).get("kind", "").replace("_", " ")
    if typ == "attack":
        refused = sum(1 for e in engine.gw.events if e["subject"] == s
                      and e["kind"] in ("telemetry_denied", "m2m_denied") and "revoked" in e["detail"])
        return ("%s is sending false readings" % s,
                "Its values contradict what pressure and flow say the tank is doing, while its own "
                "signal looks healthy. That is someone using its key to lie (%s)." % kind,
                "Revoked %s's certificate and cut it off within the same second. Pump control "
                "switched to a physics-based level. %d further messages from it refused." % (s, refused),
                "Inspect the device on site. Once it is clean, approve re-enrolment with your "
                "fingerprint; the technician then enrols it with a new key.")
    if typ == "fault":
        return ("%s looks broken, not attacked" % s,
                "Its signal shows a hardware failure pattern (%s), and nothing suspicious on its "
                "network channel." % kind,
                "Raised a maintenance ticket and stopped using its value in control. Its identity "
                "and certificate are untouched.",
                "Send a technician. After the repair, close maintenance so its value is used again.")
    if typ == "inspect":
        return ("%s is drifting slowly" % s,
                "A slow, smooth divergence from physics. That is either calibration drift or a "
                "patient attacker; the data alone cannot tell which.",
                "Raised an inspection ticket and lowered its trust score.",
                "Check its calibration on site.")
    if typ == "rogue":
        return ("Unknown device posing as %s" % s,
                "A device presented a certificate this plant's CA never issued (%s)." % _times(n),
                "Refused every message before it reached the controller.",
                "Find it: check the switch port or 5G SIM it connected from.")
    if typ == "spoof":
        return ("Finger photo used on %s's account" % person(s),
                "Someone held up a picture of the supervisor's finger. Liveness detection saw the "
                "screen's pixel pattern.",
                "Refused the login. Repeated attempts lock the account.",
                "Check who was at the console at that time.")
    if typ == "login":
        return ("Wrong finger on %s's account" % person(s),
                "A fingerprint that does not match the enrolled supervisor (%s)." % _times(n),
                "Refused the login.",
                "Confirm with the supervisor whether this was them.")
    if typ == "token":
        return ("%s's login used from another console" % person(s),
                "A valid session token, copied from console-01, was replayed from a different "
                "console.",
                "Refused: tokens only work from the console certificate they were issued to.",
                "Treat console-01 as compromised: check it for malware and rotate the operator's "
                "sessions.")
    return (typ, "", "", "")


def incident_card(inc, engine):
    sev = SEVERITY.get(inc["type"], "warning")
    title, what, did, todo = describe(inc, engine)
    closed = inc["status"] == "resolved"
    tag_cls = "closed" if closed else sev
    tag = "Resolved" if closed else SEVERITY_WORD[sev]
    ack = " Acknowledged." if inc["status"] == "acknowledged" else ""
    span = ("Plant time %s." % clock(inc["first"]) if inc["first"] == inc["last"]
            else "Plant time %s to %s, %d events." % (clock(inc["first"]), clock(inc["last"]),
                                                       inc["count"]))
    st.markdown(
        '<div class="inc %s%s"><h4><span class="tag %s">%s</span>%s</h4>'
        '<div class="meta">%s%s</div><dl>'
        '<dt>What happened</dt><dd>%s</dd><dt>What SenseTrust did</dt><dd>%s</dd>'
        '<dt>What to do</dt><dd>%s</dd></dl></div>'
        % (sev, " closed" if closed else "", tag_cls, tag, esc(title), span, ack,
           esc(what), esc(did), esc(todo)), unsafe_allow_html=True)


def action_result(engine):
    if engine.last_action:
        ok, msg = engine.last_action
        (st.success if ok else st.error)(msg)
