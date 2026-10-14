/* SenseTrust console: a small single-page app over /api. No build step. */
'use strict';

const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const clock = t => `${Math.floor(t / 60)}:${String(Math.floor(t % 60)).padStart(2, '0')}`;
const fmt = n => Number(n).toLocaleString('en-IN');
const SVGNS = 'http://www.w3.org/2000/svg';

async function api(path, body) {
  const opt = body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  const r = await fetch(path, opt);
  if (!r.ok) {
    let m = r.statusText;
    try { m = (await r.json()).detail || m; } catch (e) { /* keep status text */ }
    throw new Error(m);
  }
  return r.json();
}

function toast(text, bad) {
  const el = document.createElement('div');
  el.className = 'toast' + (bad ? ' bad' : '');
  el.textContent = text;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), 5200);
}

/* Re-render a container only when its markup changed, so buttons survive the 1 s poll. */
function paint(el, html) {
  if (el && el._html !== html) { el.innerHTML = html; el._html = html; }
}

const PAGES = {
  overview: { title: 'Overview', sub: 'The water plant, its devices and every message they send' },
  incidents: { title: 'Incidents', sub: 'What the gateway saw, in plain words, and what to do next' },
  devices: { title: 'Devices and identity', sub: 'Certificates, trust and 5G bindings for every machine' },
  mobility: { title: 'Mobility', sub: 'MOBI-GUARD predicts where moving machines go; SenseTrust checks they are who they say' },
  pilot: { title: 'Pilot: shadow mode', sub: 'Read-only OPC UA monitoring, the way a new site starts' },
  scenarios: { title: 'Scenarios and results', sub: 'Twelve scripted attacks against the real gateway, and the measured evaluation' },
};

let S = null;          // latest /api/state
let view = null;       // current page: { update(state) }
const ui = { incident: null, device: null, filter: 'all', scenario: 'S2', scenarioResults: {} };

/* ── shell ───────────────────────────────────────────────────────────────── */

function route() {
  const name = (location.hash.replace(/^#\//, '').split('?')[0]) || 'overview';
  const page = PAGES[name] ? name : 'overview';
  document.querySelectorAll('.nav a').forEach(a => a.classList.toggle('on', a.dataset.page === page));
  $('#title').textContent = PAGES[page].title;
  $('#subtitle').textContent = PAGES[page].sub;
  const host = $('#view');
  host.innerHTML = '';
  host._html = null;
  view = MOUNT[page](host);
  if (S && view.update) view.update(S);
  $('main').scrollTop = 0;
}

function chrome(s) {
  $('#clock').textContent = clock(s.t);
  const pill = $('#pill');
  pill.className = 'pill' + (s.status.level === 'ok' ? '' : ' ' + s.status.level);
  $('#pill-text').textContent = s.status.head;
  const n = s.metrics.open;
  const c = $('#inc-count');
  c.hidden = !n;
  c.textContent = n;
  $('#run-btn').textContent = s.running ? 'Pause' : 'Resume';
}

async function poll() {
  try {
    S = await api('/api/state');
    chrome(S);
    if (view && view.update) view.update(S);
  } catch (e) {
    $('#pill-text').textContent = 'Console server not reachable';
  }
  setTimeout(poll, 1000);
}

/* ── simulate drawer ─────────────────────────────────────────────────────── */

const EVENTS = [
  ['Attacks', [
    ['false_data', { target: 'LT-101' }, 'Stolen key: LT-101 lies', 'An attacker with LT-101\'s real key reports the tank at a third of its level. Every cryptographic check passes; physics does not.'],
    ['rogue', {}, 'Rogue device joins', 'A device with a certificate from an attacker\'s CA claims to be PT-101.'],
    ['spoof', {}, 'Finger photo on a phone', 'Someone holds a picture of the supervisor\'s finger up to the reader.'],
    ['impostor', {}, 'Someone else\'s finger', 'A different person tries the supervisor\'s account.'],
    ['token', {}, 'Stolen session token', 'The supervisor\'s valid session is copied and used from console-02.'],
  ]],
  ['Plant events', [
    ['fault', { target: 'LT-101' }, 'LT-101 transmitter freezes', 'A real hardware fault, no attacker. Should become a maintenance ticket, not an alarm.'],
    ['fault', { target: 'PT-101' }, 'PT-101 transmitter freezes', 'The same fault on the pressure sensor.'],
  ]],
];

function buildDrawer() {
  $('#drawer-body').innerHTML = EVENTS.map(([group, items]) => `<h3>${group}</h3>` + items.map(([n, a, title, text], i) =>
    `<button class="event ${group === 'Attacks' ? 'attack' : 'fault'}" data-sim="${n}" data-args='${JSON.stringify(a)}'><b>${esc(title)}</b><span>${esc(text)}</span></button>`).join('')).join('');
}
function drawer(open) {
  $('#drawer').classList.toggle('open', open);
}

/* ── fingerprint step-up ─────────────────────────────────────────────────── */

const FP = `<div class="fp scan" id="fp"><svg viewBox="0 0 112 112" aria-hidden="true"><g class="ridges">
${[6, 12, 18, 24, 30, 36, 42].map((r, i) => `<ellipse cx="56" cy="60" rx="${r * 0.78}" ry="${r}" stroke-dasharray="${18 + i * 9} ${4 + (i % 3) * 3}" stroke-dashoffset="${i * 7}"/>`).join('')}
</g><rect class="beam" x="10" y="8" width="92" height="4" rx="2"/></svg></div>`;

const STEP_UP = {
  reinstate: t => [`Approve re-enrolment of ${t}`, `The old certificate stays revoked. Approving issues a one-time token so a technician can enrol ${t} with a new key.`],
  revoke: t => [`Revoke ${t}`, `${t} is cut off at once and its certificate goes on the revocation list.`],
  close_maintenance: t => [`Close maintenance on ${t}`, `Confirms the repair, so ${t}'s readings are used in the physics check and in control again.`],
};

function modal(html) {
  $('#modal-card').innerHTML = html;
  $('#modal').classList.add('show');
  $('#scrim').classList.add('show');
}
function closeModal() {
  $('#modal').classList.remove('show');
  $('#scrim').classList.remove('show');
}

async function stepUp(action, target) {
  const [title, text] = STEP_UP[action](target);
  modal(`<h2 id="modal-title">${esc(title)}</h2><p>${esc(text)} This is a critical action: the gateway needs a fresh fingerprint and liveness check from the supervisor on console-01.</p>
    ${FP}<div id="fp-out"><p style="text-align:center">Reading the supervisor's finger&hellip;</p></div>`);
  const wait = new Promise(r => setTimeout(r, 1300));
  let res;
  try { res = await api('/api/action', { action, target }); } catch (e) { res = { ok: false, message: e.message }; }
  await wait;
  const fp = res.fingerprint || {};
  $('#fp').className = 'fp ' + (fp.ok ? 'done' : 'fail');
  $('#fp-out').innerHTML = `<div class="result ${res.ok ? 'ok' : 'bad'}">${fp.ok ? `Fingerprint matched (score ${fp.score}) and liveness passed for Supervisor Asha on console-01.` : 'Fingerprint check failed.'}<br>${esc(res.message.split('Gateway: ')[1] ? 'Gateway decision: ' + res.message.split('Gateway: ')[1] : res.message)}</div>
    <p style="font-size:12px">Simulated reader: it presents the supervisor's enrolled synthetic finger. The match and liveness check are the real YellowSense engine.</p>
    <div class="row"><button class="btn primary" data-close>Done</button></div>`;
  refresh();
}

async function act(action, target, extra) {
  if (STEP_UP[action]) return stepUp(action, target);
  try {
    const r = await api('/api/action', Object.assign({ action, target }, extra || {}));
    if (r.message) toast(r.message, !r.ok);
  } catch (e) { toast(e.message, true); }
  refresh();
}

async function refresh() {
  try { S = await api('/api/state'); chrome(S); if (view && view.update) view.update(S); } catch (e) { /* next poll */ }
}

/* ── shared drawing ──────────────────────────────────────────────────────── */

function lineChart(svg, rows, opt) {
  // rows: [[x, y1, y2, ...]]; opt: {series: [{i, color, dash}], ymax, rule, xfmt, marks}
  const W = 880, H = opt.h || 250, L = 44, R = 26, T = 16, B = 30;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  if (!rows.length) { svg.innerHTML = ''; return; }
  const x0 = rows[0][0], x1 = Math.max(rows[rows.length - 1][0], x0 + 1);
  const X = x => L + (x - x0) / (x1 - x0) * (W - L - R);
  const Y = y => T + (1 - y / opt.ymax) * (H - T - B);
  let g = '<g class="grid">';
  for (let y = 0; y <= opt.ymax; y += 1) g += `<line x1="${L}" x2="${W - R}" y1="${Y(y)}" y2="${Y(y)}"/>`;
  g += '</g><g class="axis">';
  for (let y = 0; y <= opt.ymax; y += 1) g += `<text x="${L - 8}" y="${Y(y) + 4}" text-anchor="end">${y} m</text>`;
  const step = opt.xstep || 60;
  for (let x = Math.ceil(x0 / step) * step; x <= x1; x += step) g += `<text x="${X(x)}" y="${H - 8}" text-anchor="middle">${opt.xfmt ? opt.xfmt(x) : x}</text>`;
  g += '</g>';
  if (opt.rule != null) g += `<line x1="${L}" x2="${W - R}" y1="${Y(opt.rule)}" y2="${Y(opt.rule)}" stroke="#C62828" stroke-dasharray="5 4"/><text x="${W - R}" y="${Y(opt.rule) - 6}" text-anchor="end" font-size="11" fill="#C62828">overflow ${opt.rule.toFixed(1)} m</text>`;
  (opt.marks || []).forEach(m => { g += `<line x1="${X(m.x)}" x2="${X(m.x)}" y1="${T}" y2="${H - B}" stroke="${m.color}" stroke-dasharray="3 4"/><text x="${X(m.x) + 6}" y="${T + 12}" font-size="11" fill="${m.color}">${esc(m.label)}</text>`; });
  opt.series.forEach(s => {
    const pts = rows.filter(r => r[s.i] != null).map(r => `${X(r[0]).toFixed(1)},${Y(Math.min(opt.ymax, r[s.i])).toFixed(1)}`).join(' ');
    g += `<polyline points="${pts}" fill="none" stroke="${s.color}" stroke-width="${s.w || 2.2}" ${s.dash ? `stroke-dasharray="${s.dash}"` : ''} stroke-linejoin="round"/>`;
  });
  svg.innerHTML = g;
}
const legend = items => `<div class="legend">${items.map(([c, t, dash]) => `<span><i style="background:${dash ? `repeating-linear-gradient(90deg,${c} 0 6px,transparent 6px 10px)` : c}"></i>${esc(t)}</span>`).join('')}</div>`;

/* ── Overview ────────────────────────────────────────────────────────────── */

const DEVS = [
  { id: 'LT-101', what: 'Level', y: 40, end: [326, 172] },
  { id: 'PT-101', what: 'Pressure', y: 130, end: [323, 200] },
  { id: 'FT-101', what: 'Flow', y: 220, end: [323, 228] },
  { id: 'console-01', what: 'Console', y: 310, end: [328, 258] },
];
const STATE_WORD = { ok: 'trusted', revoked: 'revoked', fault: 'maintenance', pending: 'awaiting new key' };
const TANK = { x: 740, y: 44, w: 124, h: 380 };

function mapSvg() {
  let s = `<svg viewBox="0 0 880 470" role="img" aria-label="Plant map: devices, their links to the SenseTrust gateway, pump control and the tank">`;
  DEVS.concat([{ id: 'rogue', y: 396, end: [334, 290] }]).forEach(d => {
    const c = d.y + 32, [ex, ey] = d.end;
    s += `<path class="link" id="lk-${d.id}" d="M210 ${c} C270 ${c} 266 ${ey} ${ex} ${ey}"/>`;
  });
  DEVS.forEach(d => {
    s += `<g class="dev" id="dv-${d.id}"><rect x="20" y="${d.y}" width="190" height="64" rx="9"/>
      <text class="nm" x="34" y="${d.y + 24}">${d.id}</text><text class="st" x="34" y="${d.y + 42}" id="st-${d.id}">${d.what}, trusted</text>
      <text class="ln" x="34" y="${d.y + 57}" id="ln-${d.id}"></text></g>`;
  });
  s += `<g class="dev ghost" id="ghost"><rect x="20" y="396" width="190" height="64" rx="9"/><text class="nm" x="34" y="420" fill="#C62828">Unknown device</text>
      <text class="st" x="34" y="438" fill="#C62828">attacker's certificate</text><text class="ln" x="34" y="453">claims to be PT-101</text></g>`;
  s += `<path class="link" id="lk-ctl" d="M478 214 H540"/><path class="link" d="M700 214 H740"/>`;
  s += `<g class="shield" id="shield"><path d="M400 120 l78 30 v70 c0 56 -44 90 -78 106 c-34 -16 -78 -50 -78 -106 v-70 z"/>
      <text x="400" y="214" text-anchor="middle">SenseTrust</text><text x="400" y="234" text-anchor="middle" font-size="12" font-family="var(--body)" font-weight="400">gateway</text></g>
      <text x="400" y="352" text-anchor="middle" font-size="11.5" fill="#6B6B6B">identity, policy, physics</text>`;
  s += `<g class="ctl"><rect x="540" y="178" width="160" height="72" rx="9"/><text x="554" y="202" font-weight="700" font-size="14">Pump control</text>
      <text x="554" y="221" font-size="12" id="ctl-src" fill="#6B6B6B">uses LT-101</text><text x="554" y="238" font-size="12" id="ctl-pump" fill="#6B6B6B">pump stopped</text></g>`;
  const rimY = TANK.y + TANK.h - 3.0 * TANK.h / 3.2;
  s += `<g class="tank"><text x="${TANK.x}" y="${TANK.y - 12}" font-size="12" fill="#6B6B6B">Tank T-101</text>
      <rect class="water" id="water" x="${TANK.x}" y="${TANK.y + TANK.h}" width="${TANK.w}" height="0"/>
      <rect class="wall" x="${TANK.x}" y="${TANK.y}" width="${TANK.w}" height="${TANK.h}" rx="3"/>
      <line class="rim" x1="${TANK.x - 6}" x2="${TANK.x + TANK.w + 6}" y1="${rimY}" y2="${rimY}"/>
      <text x="${TANK.x + 6}" y="${rimY - 6}" font-size="11" fill="#C62828">overflow</text>
      <text x="${TANK.x + 10}" y="${TANK.y + TANK.h - 30}" font-family="var(--head)" font-weight="800" font-size="20" id="lvl">0.00 m</text>
      <text x="${TANK.x + 10}" y="${TANK.y + TANK.h - 12}" font-size="11.5" fill="#1A1A1A">true level</text>
      <line class="lie" id="lie" x1="${TANK.x - 14}" x2="${TANK.x + 28}" y1="0" y2="0" visibility="hidden"/>
      <text id="lie-t" x="${TANK.x - 18}" y="0" text-anchor="end" font-size="12" fill="#C62828" font-weight="700" visibility="hidden"></text></g>`;
  s += `<g id="pkts"></g></svg>`;
  return s;
}

function packets(svg) {
  const dots = [];
  const layer = $('#pkts', svg);
  let alive = true;
  function frame(now) {
    if (!alive) return;
    for (let i = dots.length - 1; i >= 0; i--) {
      const d = dots[i], p = (now - d.start) / d.dur;
      if (p < 0) { d.el.setAttribute('opacity', 0); continue; }
      const stop = d.deny ? 0.84 : 1;
      if (p >= (d.deny ? 1.25 : 1)) { d.el.remove(); dots.splice(i, 1); continue; }
      const pt = d.path.getPointAtLength(Math.min(p, stop) * d.len);
      d.el.setAttribute('cx', pt.x);
      d.el.setAttribute('cy', pt.y);
      d.el.setAttribute('opacity', d.deny && p > stop ? Math.max(0, 1 - (p - stop) * 4) : 1);
      if (d.deny && p > stop) d.el.setAttribute('r', 4 + (p - stop) * 14);
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
  return {
    send(id, deny, delay) {
      const path = $('#lk-' + id, svg);
      if (!path || dots.length > 80) return;
      const el = document.createElementNS(SVGNS, 'circle');
      el.setAttribute('r', 4);
      el.setAttribute('class', 'pkt');
      el.setAttribute('fill', deny ? '#C62828' : '#EB7009');
      el.setAttribute('stroke', '#fff');
      el.setAttribute('stroke-width', 1.2);
      layer.appendChild(el);
      dots.push({ el, path, len: path.getTotalLength(), start: performance.now() + (delay || 0), dur: 900, deny });
    },
    stop() { alive = false; },
  };
}

function mountOverview(host) {
  host.innerHTML = `
  <div class="kpis">
    <div class="panel kpi"><span>Messages checked</span><b class="num" id="k-checked">0</b><small>each on its own merits</small></div>
    <div class="panel kpi" id="k-ref-box"><span>Refused</span><b class="num" id="k-refused">0</b><small>identity, signature, replay or trust</small></div>
    <div class="panel kpi" id="k-open-box"><span>Open incidents</span><b class="num" id="k-open">0</b><small><a href="#/incidents">see incidents</a></small></div>
    <div class="panel kpi" id="k-ovf-box"><span>Tank overflow</span><b class="num" id="k-ovf">0 s</b><small>seconds above the rim</small></div>
  </div>
  <div class="ov">
    <div class="panel map"><header><h2>Plant and its links</h2><span class="hint">dots are messages; red ones are refused at the gateway</span></header>
      <div class="statusline" id="ov-status"></div>${mapSvg()}</div>
    <div class="stack">
      <div class="panel"><header><h2>Needs attention</h2></header><div class="body" id="ov-inc"></div></div>
      <div class="panel"><header><h2>Latest activity</h2></header><div class="body" id="ov-act"></div></div>
    </div>
  </div>
  <div class="panel chart" style="margin-top:18px"><header><h2>Tank level</h2><span class="hint">last 5 minutes of plant time</span></header>
    ${legend([['#1A1A1A', 'True level'], ['#C62828', 'LT-101 reports'], ['#0F6E78', 'Pump control uses', true]])}
    <svg id="ov-chart"></svg></div>`;
  const svg = $('.map svg', host);
  const pk = packets(svg);
  let prev = null, rogueUntil = 0;
  window.addEventListener('hashchange', () => pk.stop(), { once: true });
  return {
    update(s) {
      $('#k-checked').textContent = fmt(s.metrics.checked);
      $('#k-refused').textContent = fmt(s.metrics.refused);
      $('#k-open').textContent = s.metrics.open;
      $('#k-ovf').textContent = s.metrics.overflow_s + ' s';
      $('#k-open-box').classList.toggle('alarm', s.metrics.open > 0);
      $('#k-ovf-box').classList.toggle('alarm', s.metrics.overflow_s > 0);
      $('#ov-status').textContent = s.status.text;
      DEVS.forEach(d => {
        const st = (s.links[d.id] || {}).state || 'ok';
        $('#dv-' + d.id, svg).setAttribute('class', 'dev ' + st);
        $('#lk-' + d.id, svg).setAttribute('class', 'link ' + st);
        $('#st-' + d.id, svg).textContent = `${d.what}, ${STATE_WORD[st]}`;
        $('#ln-' + d.id, svg).textContent = (s.transport[d.id] || '').replace(' (wired)', '');
      });
      $('#shield', svg).setAttribute('class', 'shield' + (s.status.level === 'alarm' ? ' alert' : ''));
      const p = s.plant, trusted = p.source === 'LT-101';
      const src = $('#ctl-src', svg);
      src.textContent = trusted ? 'uses LT-101' : 'uses physics estimate';
      src.setAttribute('class', trusted ? '' : 'warn');
      $('#ctl-pump', svg).textContent = p.pump ? 'pump running' : 'pump stopped';
      const sc = TANK.h / p.hmax, h = Math.max(0, Math.min(p.hmax, p.true));
      const w = $('#water', svg);
      w.setAttribute('y', TANK.y + TANK.h - h * sc);
      w.setAttribute('height', h * sc);
      $('#lvl', svg).textContent = h.toFixed(2) + ' m';
      const lie = $('#lie', svg), lt = $('#lie-t', svg);
      if (p.reported != null && Math.abs(p.reported - p.true) > 0.08) {
        const ry = TANK.y + TANK.h - Math.max(0, Math.min(p.hmax, p.reported)) * sc;
        lie.setAttribute('y1', ry); lie.setAttribute('y2', ry); lie.setAttribute('visibility', 'visible');
        lt.setAttribute('y', ry + 4); lt.textContent = `LT-101 says ${p.reported.toFixed(2)} m`; lt.setAttribute('visibility', 'visible');
      } else { lie.setAttribute('visibility', 'hidden'); lt.setAttribute('visibility', 'hidden'); }
      if (prev) {
        Object.keys(s.links).forEach(id => {
          const a = s.links[id].allow - (prev.links[id] || { allow: 0 }).allow;
          const dn = s.links[id].deny - (prev.links[id] || { deny: 0 }).deny;
          for (let i = 0; i < Math.min(a, 3); i++) pk.send(id, false, i * 300);
          for (let i = 0; i < Math.min(dn, 3); i++) pk.send(id, true, 150 + i * 300);
          if (id === 'rogue' && dn > 0) rogueUntil = Date.now() + 9000;
        });
        if (s.t !== prev.t) pk.send('ctl', false, 450);
      }
      $('#ghost', svg).classList.toggle('show', Date.now() < rogueUntil);
      svg.parentNode.classList.toggle('rogue', Date.now() < rogueUntil);
      prev = s;
      lineChart($('#ov-chart'), s.series, { h: 210, ymax: 3.2, rule: p.rim, xfmt: clock, xstep: 60,
        series: [{ i: 1, color: '#1A1A1A' }, { i: 2, color: '#C62828' }, { i: 3, color: '#0F6E78', dash: '6 4' }] });
      const open = s.incidents.filter(i => i.status !== 'resolved').slice(0, 3);
      paint($('#ov-inc'), open.length ? `<div class="list">${open.map(i => incidentItem(i)).join('')}</div>`
        : '<div class="empty">Nothing needs attention. Use "Simulate an event" to stage one.</div>');
      paint($('#ov-act'), activity(s.activity.slice(0, 6)));
    },
  };
}

function activity(rows) {
  if (!rows.length) return '<div class="empty">No activity yet.</div>';
  return `<ul class="timeline">${rows.map(a => `<li><b class="num">${clock(a.t)}</b>${a.who === 'you' ? '<span class="tag warning">you</span> ' : ''}${esc(a.text)}</li>`).join('')}</ul>`;
}

/* ── Incidents ───────────────────────────────────────────────────────────── */

const SEV_WORD = { critical: 'Critical', maintenance: 'Maintenance', warning: 'Warning' };
function incidentItem(i) {
  return `<button class="item ${i.severity}${i.status === 'resolved' ? ' resolved' : ''}${ui.incident === i.id ? ' on' : ''}" data-inc="${esc(i.id)}">
    <span><span class="tag ${i.status === 'resolved' ? 'muted' : i.severity}">${i.status === 'resolved' ? 'Resolved' : SEV_WORD[i.severity]}</span>${i.status === 'acknowledged' ? ' <span class="tag muted">Acknowledged</span>' : ''}</span>
    <b>${esc(i.title)}</b><small class="num">Plant time ${clock(i.first)}${i.count > 1 ? `, ${i.count} events` : ''}</small></button>`;
}

function incidentActions(i) {
  if (i.status === 'resolved') return '';
  const b = [];
  if (i.type === 'attack' && i.device_state === 'revoked') b.push(`<button class="btn primary" data-act="reinstate" data-target="${i.subject}">Approve re-enrolment</button>`);
  if (i.type === 'attack' && i.device_state === 'awaiting re-enrolment') b.push(`<button class="btn primary" data-act="technician_reenrol" data-target="${i.subject}">Technician: enrol new key</button>`);
  if (i.type === 'fault' && i.device_state === 'maintenance') b.push(`<button class="btn primary" data-act="close_maintenance" data-target="${i.subject}">Close maintenance</button>`);
  if (i.status === 'open') b.push(`<button class="btn" data-act="acknowledge" data-target="${esc(i.id)}">Acknowledge</button>`);
  b.push(`<button class="btn" data-act="resolve" data-target="${esc(i.id)}">Resolve</button>`);
  return `<div class="actions">${b.join('')}</div>`;
}

function mountIncidents(host) {
  host.innerHTML = `<div class="toolbar"><div class="seg" id="inc-filter"><button data-f="open" class="on">Open</button><button data-f="all">All</button></div></div>
    <div class="split"><div class="list" id="inc-list"></div><div class="panel detail"><div class="body" id="inc-detail"></div></div></div>`;
  let filter = 'open';
  $('#inc-filter', host).addEventListener('click', e => {
    const b = e.target.closest('button'); if (!b) return;
    filter = b.dataset.f;
    host.querySelectorAll('#inc-filter button').forEach(x => x.classList.toggle('on', x === b));
    if (S) this_.update(S);
  });
  const this_ = {
    update(s) {
      const list = s.incidents.filter(i => filter === 'all' || i.status !== 'resolved');
      if (!list.find(i => i.id === ui.incident)) ui.incident = list.length ? list[0].id : null;
      paint($('#inc-list'), list.length ? list.map(incidentItem).join('') : '<div class="panel empty">No open incidents. Use "Simulate an event" to stage one.</div>');
      const i = s.incidents.find(x => x.id === ui.incident);
      paint($('#inc-detail'), !i ? '<div class="empty">Select an incident.</div>' : `
        <span class="tag ${i.severity}">${SEV_WORD[i.severity]}</span>
        <h2>${esc(i.title)}</h2><div class="meta num">${esc(i.subject)}, plant time ${clock(i.first)}${i.last !== i.first ? ' to ' + clock(i.last) : ''}${i.count > 1 ? `, ${i.count} events` : ''}</div>
        <dl class="dl"><dt>What happened</dt><dd>${esc(i.what)}</dd><dt>What SenseTrust did</dt><dd>${esc(i.did)}</dd><dt>What to do</dt><dd>${esc(i.todo)}</dd></dl>
        ${incidentActions(i)}
        <ul class="timeline">${i.events.map(e => `<li><b class="num">${clock(e.t)}</b>${esc(e.detail)}</li>`).join('')}</ul>`);
    },
  };
  return this_;
}

/* ── Devices ─────────────────────────────────────────────────────────────── */

const STATUS_TAG = { 'Trusted': 'ok', 'Revoked': 'critical', 'Maintenance': 'maintenance', 'Awaiting re-enrolment': 'warning' };
function mountDevices(host) {
  host.innerHTML = `<div class="toolbar"><div class="seg" id="dev-filter"><button data-f="all" class="on">All devices</button><button data-f="attention">Needs attention</button></div>
      <div class="grow" style="flex:1"></div><button class="btn primary" id="commission">Commission a device</button></div>
    <div class="split" style="grid-template-columns:minmax(0,1fr) 340px"><div class="panel" style="overflow:auto"><table class="tbl"><thead><tr><th>Device</th><th>Role</th><th>Status</th><th>Trust</th><th>Link</th><th>Private 5G</th><th>Certificate</th></tr></thead><tbody id="dev-rows"></tbody></table></div>
    <div class="panel"><div class="body" id="dev-detail"></div></div></div>`;
  let filter = 'all';
  $('#dev-filter', host).addEventListener('click', e => {
    const b = e.target.closest('button'); if (!b) return;
    filter = b.dataset.f;
    host.querySelectorAll('#dev-filter button').forEach(x => x.classList.toggle('on', x === b));
    if (S) me.update(S);
  });
  $('#commission', host).addEventListener('click', commissionDialog);
  const me = {
    update(s) {
      const rows = s.devices.filter(d => filter === 'all' || d.status !== 'Trusted');
      if (!ui.device || !s.devices.find(d => d.id === ui.device)) ui.device = s.devices[0].id;
      paint($('#dev-rows'), rows.map(d => `<tr class="row${d.id === ui.device ? ' on' : ''}" data-dev="${esc(d.id)}">
        <td><b>${esc(d.id)}</b></td><td>${esc(d.role)}</td><td><span class="tag ${STATUS_TAG[d.status]}">${esc(d.status)}</span></td>
        <td class="num"><span class="bar ${d.trust < 0.3 ? 'low' : d.trust < 0.7 ? 'mid' : ''}"><i style="width:${Math.round(d.trust * 100)}%"></i></span>${d.trust.toFixed(2)}</td>
        <td>${esc(d.link)}</td><td>${d.sim === '—' ? '<span style="color:var(--faint)">wired</span>' : esc(d.sim + ', ' + d.slice)}</td><td class="mono">${esc(d.serial)}</td></tr>`).join(''));
      const d = s.devices.find(x => x.id === ui.device);
      const btn = d.status === 'Revoked' ? `<button class="btn primary" data-act="reinstate" data-target="${d.id}">Approve re-enrolment</button>`
        : d.status === 'Awaiting re-enrolment' ? `<button class="btn primary" data-act="technician_reenrol" data-target="${d.id}">Technician: enrol new key</button>`
        : `<button class="btn danger" data-act="revoke" data-target="${d.id}">Revoke</button>`;
      paint($('#dev-detail'), `<span class="tag ${STATUS_TAG[d.status]}">${esc(d.status)}</span><h2 style="font:800 22px var(--head);margin:8px 0 2px">${esc(d.id)}</h2>
        <div class="meta" style="color:var(--muted);font-size:13px">${esc(d.role)}, trust ${d.trust.toFixed(2)}</div>
        <div class="facts"><div><span>Certificate</span><b class="mono">${esc(d.serial)}</b></div><div><span>Expires in</span><b>${esc(d.expires)}</b></div>
        <div><span>Link to gateway</span>${esc(d.link)}</div><div><span>Private 5G</span>${d.sim === '—' ? 'not on 5G' : esc(d.sim) + '<br>' + esc(d.slice) + ' slice'}</div></div>
        <p style="font-size:13px;color:var(--muted);margin:0 0 14px">The device made its own key and enrolled with a one-time token; the plant CA never saw the private key.</p>
        <div class="actions">${btn}</div>`);
    },
  };
  return me;
}

function commissionDialog() {
  modal(`<h2 id="modal-title">Commission a device</h2><p>The admin issues a one-time token that fixes the device's ID and role. The device makes its own key, sends a certificate request with the token, and the plant CA signs it.</p>
    <form id="cform" class="grid" style="gap:12px"><label class="field">Device ID<input name="id" required maxlength="24" placeholder="e.g. TT-201" autocomplete="off"></label>
    <label class="field">Role<select name="role"><option>sensor</option><option>actuator</option><option>console</option><option>vehicle</option></select></label>
    <div class="row"><button type="button" class="btn" data-close>Cancel</button><button class="btn primary">Issue token and enrol</button></div></form>`);
  $('#cform input').focus();
  $('#cform').addEventListener('submit', async e => {
    e.preventDefault();
    const f = new FormData(e.target);
    closeModal();
    await act('commission', f.get('id'), { role: f.get('role') });
  });
}

/* ── Mobility ────────────────────────────────────────────────────────────── */

function mountMobility(host) {
  host.innerHTML = `<div class="two">
    <div class="stack">
      <div class="panel"><header><h2>Run a drive</h2></header><div class="body">
        <p style="margin:0 0 12px;font-size:14px">Service vehicle <b>TRK-07</b> drives the site on private 5G, including an unplanned exit. MOBI-GUARD predicts its next cell and prepares handovers. SenseTrust checks that every report comes from the one device holding the identity.</p>
        <div class="radio"><label><input type="radio" name="mc" value="0"> The vehicle drives its route, nothing else</label>
        <label><input type="radio" name="mc" value="1" checked> Someone copied its key and reports as TRK-07 from elsewhere</label></div>
        <button class="btn primary" id="mob-run" style="margin-top:14px">Run drive</button></div></div>
      <div class="panel"><header><h2>What happened</h2></header><div class="body" id="mob-out"><div class="empty">Run a drive to see MOBI-GUARD and SenseTrust work together.</div></div></div>
    </div>
    <div class="panel cellmap"><header><h2>Six 5G cells, one vehicle</h2><span class="hint" id="mob-hint">triangles are cells</span></header>
      ${legend([['#1A1A1A', 'TRK-07, the real vehicle'], ['#C62828', 'reports signed with its copied key']])}<svg id="mob-svg" viewBox="0 0 880 500"></svg></div></div>`;
  let timer = null;
  window.addEventListener('hashchange', () => clearInterval(timer), { once: true });
  const svg = $('#mob-svg', host);
  const X = x => 40 + (x + 300) / 4300 * 800, Y = y => 460 - (y + 100) / 2000 * 420;
  function draw(r, upto) {
    let g = '';
    r.cells.forEach(c => { g += `<path d="M${X(c.x)} ${Y(c.y) - 12} l10 18 h-20 z" fill="#EB7009"/><text x="${X(c.x)}" y="${Y(c.y) - 18}" text-anchor="middle" font-size="12" fill="#6B6B6B">${c.id.replace('_', ' ')}</text>`; });
    const pts = r.real.filter(p => p.t <= upto);
    g += `<polyline fill="none" stroke="#1A1A1A" stroke-width="2.6" stroke-linejoin="round" points="${pts.map(p => `${X(p.x).toFixed(1)},${Y(p.y).toFixed(1)}`).join(' ')}"/>`;
    const last = pts[pts.length - 1];
    r.copies.filter(c => c.t <= upto).forEach(c => {
      const caught = c.verdict === 'impossible' || c.effect !== 'allow';
      g += `<circle cx="${X(c.x)}" cy="${Y(c.y)}" r="6" fill="#C62828" opacity="${caught ? 1 : .55}"/>`;
      if (r.alarm_t === c.t) g += `<circle cx="${X(c.x)}" cy="${Y(c.y)}" r="16" fill="none" stroke="#C62828" stroke-width="2"/><text x="${X(c.x) + 22}" y="${Y(c.y) + 4}" font-size="12.5" font-weight="700" fill="#C62828">copy caught</text>`;
    });
    if (last) {
      const revoked = r.revoked_t != null && upto >= r.revoked_t;
      g += `<circle cx="${X(last.x)}" cy="${Y(last.y)}" r="9" fill="${revoked ? '#FDECEA' : '#FFAE09'}" stroke="${revoked ? '#C62828' : '#1A1A1A'}" stroke-width="2"/>`;
      g += `<text x="${X(last.x) + 14}" y="${Y(last.y) - 10}" font-size="12.5" font-weight="700">TRK-07</text>`;
      if (last.next && !revoked) g += `<text x="${X(last.x) + 14}" y="${Y(last.y) + 6}" font-size="11.5" fill="#6B6B6B">next: ${last.next.replace('_', ' ')}${last.conf != null ? ' (' + Math.round(last.conf * 100) + '%)' : ''}</text>`;
      if (revoked) g += `<text x="${X(last.x) + 14}" y="${Y(last.y) + 6}" font-size="11.5" fill="#C62828">identity revoked</text>`;
    }
    svg.innerHTML = g;
  }
  function report(r, done) {
    const adv = r.advice, a = (k) => adv[k] || 0;
    $('#mob-out').innerHTML = `<div class="kpis three" style="gap:10px;margin-bottom:12px">
      <div><span style="color:var(--muted);font-size:12px">Handovers</span><b style="font:700 22px var(--head);display:block">${r.handovers_prepared}</b></div>
      <div><span style="color:var(--muted);font-size:12px">Copy caught at</span><b style="font:700 22px var(--head);display:block">${r.alarm_t != null ? 't = ' + r.alarm_t + ' s' : r.with_copy ? 'not caught' : 'no copy'}</b></div>
      <div><span style="color:var(--muted);font-size:12px">TRK-07</span><b style="font:700 22px var(--head);display:block;color:${r.revoked_t != null ? 'var(--alarm)' : 'var(--ok)'}">${r.revoked_t != null ? 'revoked' : 'trusted'}</b></div></div>
      <p style="font-size:13.5px;margin:0 0 8px">MOBI-GUARD's advice for the real vehicle: monitor ${a('MONITOR_RECHECK')}, prepare handover ${a('PROACTIVE_CANDIDATE') + a('RE_EVALUATING')}, hold ${a('HOLD') + a('HOLD_RECHECK')}. <i>Hold</i> includes what SenseTrust forces while the identity is under suspicion.</p>
      ${r.events.length ? `<ul class="timeline">${r.events.map(e => `<li>${esc(e.detail)}</li>`).join('')}</ul>` : '<p style="font-size:13.5px;color:var(--ok);margin:0">No identity alarm: the unplanned exit is a real move, and the signal track stays continuous.</p>'}`;
  }
  $('#mob-run', host).addEventListener('click', async e => {
    const btn = e.target; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Driving';
    clearInterval(timer);
    try {
      const r = await api('/api/mobility', { copy: $('input[name=mc]:checked', host).value === '1' });
      if (r.error) throw new Error(r.error);
      let t = 0; const end = r.real[r.real.length - 1].t;
      timer = setInterval(() => { t += 2; draw(r, t); if (t >= end) { clearInterval(timer); report(r, true); } }, 45);
    } catch (err) { toast(err.message, true); }
    btn.disabled = false; btn.textContent = 'Run drive';
  });
  return {};
}

/* ── Pilot ───────────────────────────────────────────────────────────────── */

function mountPilot(host) {
  host.innerHTML = `<div class="two">
    <div class="panel"><header><h2>Start a session</h2></header><div class="body">
      <p style="margin:0 0 12px;font-size:14px">A new site lets SenseTrust read and nothing else. It connects to the plant's PLC over OPC UA (encrypted, certificate-checked, read-only), runs the physics check and raises alerts. It never blocks or writes anything.</p>
      <div class="radio"><label><input type="radio" name="pc" value="normal"> A normal shift</label>
      <label><input type="radio" name="pc" value="attack" checked> LT-101 is compromised behind the PLC</label>
      <label><input type="radio" name="pc" value="fault"> LT-101's transmitter freezes</label></div>
      <label class="field" style="margin-top:12px">Plant time<select id="pmin"><option value="180">3 minutes</option><option value="300" selected>5 minutes</option><option value="480">8 minutes</option></select></label>
      <button class="btn primary" id="p-run" style="margin-top:14px">Run session</button></div></div>
    <div class="stack" id="p-out"><div class="panel empty">Run a session to get the report a pilot site would see.</div></div></div>`;
  $('#p-run', host).addEventListener('click', async e => {
    const btn = e.target; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Watching the PLC';
    try {
      const r = await api('/api/pilot', { case: $('input[name=pc]:checked', host).value, seconds: +$('#pmin', host).value });
      if (r.error) throw new Error(r.error);
      $('#p-out').innerHTML = `<div class="kpis">
        <div class="panel kpi"><span>Values read</span><b class="num">${fmt(r.values_read)}</b><small>5 per second, one OPC UA read</small></div>
        <div class="panel kpi"><span>Alerts</span><b class="num">${r.alerts.length}</b></div>
        <div class="panel kpi"><span>Detected after</span><b class="num">${r.detected_after != null ? r.detected_after + ' s' : '—'}</b></div>
        <div class="panel kpi"><span>Blocked or revoked</span><b class="num">${r.revoked.length}</b><small>shadow mode never acts</small></div></div>
        <div class="panel chart"><header><h2>What the PLC reported</h2><span class="hint">OPC UA ${esc(r.endpoint)}, plant-CA certificates on both sides</span></header>
          ${legend([['#1A1A1A', 'True level'], ['#C62828', 'LT-101 reports']])}<svg id="p-chart"></svg></div>
        ${r.alerts.length ? `<div class="panel"><header><h2>Alerts raised</h2></header><div class="body"><ul class="timeline">${r.alerts.map(a => `<li><b class="num">${clock(a.t)}</b>${esc(a.sensor)}: ${esc(a.detail)}</li>`).join('')}</ul></div></div>` : ''}
        ${r.overflow_s ? `<div class="panel"><div class="body" style="font-size:14px">The tank overflowed for <b>${r.overflow_s} s</b>: in shadow mode the PLC keeps trusting the bad sensor. Enforcement mode is what prevents this; on the Overview, the same attack causes no overflow.</div></div>` : ''}`;
      lineChart($('#p-chart'), r.series, { ymax: 3.2, rule: 3.0, xfmt: clock, xstep: 60,
        marks: r.change_at ? [{ x: r.change_at, color: '#6B6B6B', label: r.case === 'attack' ? 'attack starts' : 'fault starts' }] : [],
        series: [{ i: 1, color: '#1A1A1A' }, { i: 2, color: '#C62828' }] });
    } catch (err) { toast(err.message, true); }
    btn.disabled = false; btn.textContent = 'Run session';
  });
  return {};
}

/* ── Scenarios ───────────────────────────────────────────────────────────── */

function flatten(obj, pre, out) {
  out = out || [];
  Object.entries(obj || {}).forEach(([k, v]) => {
    const key = (pre ? pre + ': ' : '') + k.replace(/_/g, ' ');
    if (v && typeof v === 'object' && !Array.isArray(v) && (pre || '').split(':').length < 2) flatten(v, key, out);
    else out.push([key, Array.isArray(v) ? v.map(x => typeof x === 'object' ? JSON.stringify(x) : x).join('; ') : (typeof v === 'object' ? JSON.stringify(v) : String(v))]);
  });
  return out;
}

function mountScenarios(host) {
  host.innerHTML = `<div class="kpis" id="evals"></div><div class="split" style="margin-top:18px"><div class="list" id="sc-list"></div><div class="panel"><div class="body" id="sc-detail"></div></div></div>`;
  let list = [];
  api('/api/scenarios').then(r => {
    list = r.scenarios;
    const e = r.evaluation;
    if (e) $('#evals').innerHTML = `
      <div class="panel kpi"><span>Attacks detected</span><b>${Math.round(e.attacks_detected * 100)}%</b><small>of injected attacks, 324 episodes</small></div>
      <div class="panel kpi"><span>Faults detected</span><b>${Math.round(e.faults_detected * 100)}%</b><small>correct sensor named every time</small></div>
      <div class="panel kpi"><span>Faults called attacks</span><b>${(e.fault_called_attack * 100).toFixed(1)}%</b><small>needless revocations</small></div>
      <div class="panel kpi"><span>False alarms</span><b>${e.false_alarms_per_hour}</b><small>per hour of normal running</small></div>`;
    render();
  });
  function render() {
    $('#sc-list').innerHTML = list.map(s => {
      const r = ui.scenarioResults[s.id];
      const dot = !r ? '' : r.passed === true ? 'pass' : r.passed === false ? 'fail' : '';
      return `<button class="scen${s.id === ui.scenario ? ' on' : ''}" data-sc="${s.id}"><b>${s.id}</b><span>${esc(s.name)}</span><i class="dot ${dot}"></i></button>`;
    }).join('');
    const s = list.find(x => x.id === ui.scenario) || list[0];
    if (!s) return;
    const r = ui.scenarioResults[s.id];
    const v = !r ? '' : r.running ? '<span class="spinner"></span>' : r.passed === true ? '<span class="verdict pass">Passed</span>' : r.passed === false ? '<span class="verdict fail">Failed</span>' : '<span class="verdict skip">Skipped: a dependency is not installed</span>';
    $('#sc-detail').innerHTML = `<span class="tag warning">${esc(s.ps13)}</span><h2 style="font:800 22px var(--head);margin:8px 0 6px">${s.id}: ${esc(s.name)}</h2>
      <p style="margin:0 0 14px">${esc(s.story)}</p><div class="toolbar"><button class="btn primary" data-run="${s.id}" ${r && r.running ? 'disabled' : ''}>Run against the gateway</button>${v}</div>
      ${r && r.series ? `<div class="chart">${legend([['#1A1A1A', 'True level'], ['#C62828', 'LT-101 reports'], ['#0F6E78', 'Pump control uses', true]])}<svg id="sc-chart"></svg></div>` : ''}
      ${r && r.observed ? `<dl class="dl obs">${flatten(r.observed).map(([k, val]) => `<dt>${esc(k)}</dt><dd>${esc(val)}</dd>`).join('')}</dl>` : ''}`;
    if (r && r.series) lineChart($('#sc-chart'), r.series, { ymax: 3.2, rule: 3.0, xstep: 60, series: [{ i: 1, color: '#1A1A1A' }, { i: 2, color: '#C62828' }, { i: 3, color: '#0F6E78', dash: '6 4' }] });
  }
  host.addEventListener('click', async e => {
    const pick = e.target.closest('[data-sc]');
    if (pick) { ui.scenario = pick.dataset.sc; render(); return; }
    const run = e.target.closest('[data-run]');
    if (!run) return;
    const id = run.dataset.run;
    ui.scenarioResults[id] = { running: true };
    render();
    try { ui.scenarioResults[id] = await api('/api/scenarios/' + id, {}); } catch (err) { delete ui.scenarioResults[id]; toast(err.message, true); }
    render();
  });
  return {};
}

const MOUNT = { overview: mountOverview, incidents: mountIncidents, devices: mountDevices, mobility: mountMobility, pilot: mountPilot, scenarios: mountScenarios };

/* ── events ──────────────────────────────────────────────────────────────── */

document.addEventListener('click', async e => {
  const t = e.target;
  const inc = t.closest('[data-inc]');
  if (inc) { ui.incident = inc.dataset.inc; if (!location.hash.startsWith('#/incidents')) location.hash = '#/incidents'; else if (S) view.update(S); return; }
  const dev = t.closest('[data-dev]');
  if (dev) { ui.device = dev.dataset.dev; if (S) view.update(S); return; }
  const a = t.closest('[data-act]');
  if (a) { act(a.dataset.act, a.dataset.target); return; }
  const sim = t.closest('[data-sim]');
  if (sim) {
    try {
      const r = await api('/api/simulate/' + sim.dataset.sim, JSON.parse(sim.dataset.args || '{}'));
      toast(r.note || 'Done');
    } catch (err) { toast(err.message, true); }
    refresh();
    return;
  }
  if (t.closest('[data-close]')) closeModal();
});
$('#sim-btn').addEventListener('click', () => drawer(true));
function setRail(collapsed) {
  document.querySelector('.app').classList.toggle('collapsed', collapsed);
  try { localStorage.setItem('st-rail', collapsed ? '1' : '0'); } catch (e) { /* storage unavailable */ }
}
$('#rail-toggle').addEventListener('click', () => setRail(!document.querySelector('.app').classList.contains('collapsed')));
try { if (localStorage.getItem('st-rail') === '1') setRail(true); } catch (e) { /* storage unavailable */ }
$('#drawer-close').addEventListener('click', () => drawer(false));
$('#scrim').addEventListener('click', () => { drawer(false); closeModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') { drawer(false); closeModal(); if (!$('#welcome').hidden) welcome(false); } });
$('#run-btn').addEventListener('click', async () => { if (S) { await api('/api/plant', { running: !S.running }); refresh(); } });
$('#reset-btn').addEventListener('click', async () => { await api('/api/plant', { reset: true }); ui.incident = null; toast('Fresh plant started'); refresh(); });
window.addEventListener('hashchange', route);

/* ── welcome and guided tour ─────────────────────────────────────────────── */

const TOUR = [
  ['#sim-btn', 'Play the attacker', 'Open this on any page to stage an attack or a real fault on the live plant. Try "Stolen key: LT-101 lies" first.'],
  ['.map', 'Watch every message', 'Each dot is one message travelling to the gateway. Refused ones stop red at the shield. The tank shows the true level next to what a lying sensor claims.'],
  ['#pill', 'The plant at a glance', 'Green when every device and reading checks out. It turns red when an attack is contained and teal when a device needs maintenance.'],
  ['[data-page=incidents]', 'Act on what happened', 'Each incident says what happened, what SenseTrust did and what to do next. Critical actions ask for the supervisor\'s fingerprint.'],
  ['[data-page=devices]', 'Every machine\'s identity', 'Certificates, trust scores and private 5G bindings. Revoke a device or commission a new one here.'],
  ['[data-page=mobility]', 'Machines that move', 'MOBI-GUARD predicts where a vehicle connects next; SenseTrust catches a copied identity reporting from somewhere else.'],
  ['#help-btn', 'Come back any time', 'This button brings back the welcome screen and this tour.'],
];
let tourAt = 0;

function welcome(show) {
  $('#welcome').hidden = !show;
  if (!show) { try { localStorage.setItem('st-welcomed', '1'); } catch (e) { /* storage unavailable */ } }
  else $('#tour-start').focus();
}

function placeTour() {
  const [sel, title, text] = TOUR[tourAt];
  const el = document.querySelector(sel);
  if (!el) return;
  const r = el.getBoundingClientRect(), pad = 6;
  Object.assign($('#spot').style, { top: r.top - pad + 'px', left: r.left - pad + 'px', width: r.width + pad * 2 + 'px', height: r.height + pad * 2 + 'px' });
  $('#tip-step').textContent = `Step ${tourAt + 1} of ${TOUR.length}`;
  $('#tip-title').textContent = title;
  $('#tip-text').textContent = text;
  $('#tip-back').disabled = tourAt === 0;
  $('#tip-next').textContent = tourAt === TOUR.length - 1 ? 'Finish' : 'Next';
  const tip = $('#tip'), tw = 320, th = tip.offsetHeight || 190, vw = innerWidth, vh = innerHeight;
  let top = r.bottom + 14, left = Math.min(Math.max(16, r.left), vw - tw - 16);
  if (top + th > vh - 16) top = Math.max(16, r.top - th - 14);
  if (r.height > vh * 0.5) { top = Math.max(16, r.top + 16); left = r.right + 16 + tw < vw ? r.right + 16 : Math.max(16, r.left + 16); }
  Object.assign(tip.style, { top: top + 'px', left: left + 'px' });
}

function tour(step) {
  if (step >= TOUR.length || step < 0) { $('#tour').hidden = true; return; }
  tourAt = step;
  $('#tour').hidden = false;
  const el = document.querySelector(TOUR[step][0]);
  if (el && el.scrollIntoView) el.scrollIntoView({ block: 'center', behavior: 'instant' });
  requestAnimationFrame(placeTour);
  $('#tip-next').focus();
}

$('#help-btn').addEventListener('click', () => welcome(true));
$('#welcome-skip').addEventListener('click', () => welcome(false));
$('#tour-start').addEventListener('click', () => {
  welcome(false);
  if (!location.hash.startsWith('#/overview') && location.hash) location.hash = '#/overview';
  if (document.querySelector('.app').classList.contains('collapsed')) setRail(false);
  setTimeout(() => tour(0), 250);
});
$('#tip-next').addEventListener('click', () => tour(tourAt + 1));
$('#tip-back').addEventListener('click', () => tour(tourAt - 1));
$('#tip-skip').addEventListener('click', () => tour(-1));
window.addEventListener('resize', () => { if (!$('#tour').hidden) placeTour(); });
document.addEventListener('keydown', e => {
  if ($('#tour').hidden) return;
  if (e.key === 'Escape') tour(-1);
  if (e.key === 'ArrowRight') tour(tourAt + 1);
  if (e.key === 'ArrowLeft') tour(tourAt - 1);
});

buildDrawer();
route();
poll();
let welcomed = false;
try { welcomed = localStorage.getItem('st-welcomed') === '1'; } catch (e) { /* storage unavailable */ }
if (!welcomed) welcome(true);
