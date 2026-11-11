/**
 * NetScan — Application entry & view controller
 * Includes discovery pipeline + agent pull for field scans.
 */
import {
  createSession, createDevice, createRelationship, createAlert,
  uuid, nowISO, CONFIDENCE, DEVICE_CATEGORIES, RELATIONSHIP_TYPES,
  normalizeMac, isValidIPv4
} from './models.js';
import * as storage from './storage.js';
import { importDevicesFromCSV, importSessionJSON } from './import.js';
import { detectBackend, BROWSER_CAPABILITIES } from './capabilities.js';
import { TopologyRenderer } from './topology.js';
import { getAdapterCapabilities, runAdapters, getAvailableAdapters } from './adapters/registry.js';
import { processDiscoveryResults } from './pipeline.js';

let sessionsMeta = [];
let currentSession = null;
let currentView = 'overview';
let topology = null;
const backend = detectBackend();

const $ = (sel) => document.querySelector(sel);
const main = $('#main-content');
const sessionSelect = $('#session-select');
const navDrawer = $('#nav-drawer');
const navOverlay = $('#nav-overlay');
const inspector = $('#device-inspector');
const capabilityModal = $('#capability-modal');

function toast(msg, type = '') {
  const el = document.createElement('div');
  el.className = 'toast' + (type ? ` toast-${type}` : '');
  el.textContent = msg;
  $('#toast-container').appendChild(el);
  setTimeout(() => el.remove(), 3200);
}
function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function fmtTime(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString(undefined, { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' }); }
  catch { return iso; }
}
function catClass(cat) {
  if (!cat) return 'unknown';
  const c = cat.toLowerCase();
  if (c.includes('router')) return 'router';
  if (c.includes('firewall')) return 'firewall';
  if (c.includes('switch')) return 'switch';
  if (c.includes('access') || c.includes('ap')) return 'ap';
  if (c.includes('server') || c.includes('nas')) return 'server';
  if (c.includes('desktop') || c.includes('laptop') || c.includes('phone') || c.includes('tablet')) return 'endpoint';
  return 'unknown';
}

async function refreshSessionList() {
  sessionsMeta = await storage.listSessions();
  sessionSelect.innerHTML = '';
  if (!sessionsMeta.length) {
    const opt = document.createElement('option');
    opt.value = ''; opt.textContent = 'No sessions';
    sessionSelect.appendChild(opt); return;
  }
  for (const s of sessionsMeta) {
    const opt = document.createElement('option');
    opt.value = s.id;
    opt.textContent = `${s.siteName}${s.clientName ? ' · ' + s.clientName : ''} (${s.deviceCount})`;
    sessionSelect.appendChild(opt);
  }
  if (currentSession) sessionSelect.value = currentSession.id;
}
async function switchSession(id) {
  if (!id) return;
  const s = await storage.loadSession(id);
  if (!s) { toast('Session not found', 'error'); return; }
  currentSession = s;
  await renderView(currentView);
  toast('Loaded: ' + s.siteName);
}
async function createNewSession() {
  const name = prompt('Site / network name:', 'Field Site');
  if (!name) return;
  const session = createSession({ siteName: name.trim() });
  session.devices.push(createDevice({
    hostname: 'Gateway', category: 'Router', status: 'unknown',
    discoverySource: 'manual', confidence: CONFIDENCE.UNKNOWN, isManual: true, mapX: 180, mapY: 120
  }));
  await storage.saveSession(session);
  currentSession = session;
  await refreshSessionList();
  sessionSelect.value = session.id;
  await renderView(currentView);
  toast('Session created');
}
async function persist() {
  if (currentSession) await storage.saveSession(currentSession);
}

function openNav() { navDrawer.classList.add('open'); navOverlay.classList.add('open'); }
function closeNav() { navDrawer.classList.remove('open'); navOverlay.classList.remove('open'); }
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    item.classList.add('active');
    currentView = item.dataset.view;
    closeNav();
    renderView(currentView);
  });
});
$('#nav-toggle').addEventListener('click', openNav);
navOverlay.addEventListener('click', closeNav);
$('#session-new').addEventListener('click', createNewSession);
sessionSelect.addEventListener('change', e => switchSession(e.target.value));

function renderCapabilityPanel() {
  const body = $('#capability-body');
  let html = `<p class="text-secondary mb-16" style="font-size:13px;line-height:1.5">Backend: <strong class="text-cyan">${backend.name}</strong>. For real LAN discovery use the local agent.</p>`;
  const sections = [
    ['Available', BROWSER_CAPABILITIES.filter(c => c.available === true), 'available'],
    ['Partial', BROWSER_CAPABILITIES.filter(c => c.available === 'partial'), 'partial'],
    ['Requires agent', BROWSER_CAPABILITIES.filter(c => c.available === false), 'unavailable']
  ];
  for (const [title, items, cls] of sections) {
    if (!items.length) continue;
    html += `<div class="cap-section"><h3>${title}</h3>`;
    for (const c of items) {
      html += `<div class="cap-item"><div class="cap-status ${cls}"></div><div class="cap-info">
        <div class="cap-name">${c.name}</div><div class="cap-desc">${c.description || c.reason || ''}</div></div></div>`;
    }
    html += '</div>';
  }
  body.innerHTML = html;
}
$('#capability-btn').addEventListener('click', () => {
  renderCapabilityPanel();
  capabilityModal.classList.remove('closed');
  capabilityModal.classList.add('open');
});
capabilityModal.querySelector('.modal-close').addEventListener('click', () => {
  capabilityModal.classList.remove('open');
  capabilityModal.classList.add('closed');
});

function openInspector(deviceId) {
  const d = currentSession?.devices.find(x => x.id === deviceId);
  if (!d) return;
  $('#inspector-title').textContent = d.hostname || d.ipAddress || 'Device';
  const rels = (currentSession.relationships || []).filter(r => r.sourceDeviceId === d.id || r.destDeviceId === d.id);
  $('#inspector-body').innerHTML = `
    <div class="insp-section"><h3>Identity</h3>
      <div class="insp-row"><span class="insp-label">Hostname</span><span class="insp-value mono">${esc(d.hostname)||'—'}</span></div>
      <div class="insp-row"><span class="insp-label">IP</span><span class="insp-value mono">${esc(d.ipAddress)||'—'}</span></div>
      <div class="insp-row"><span class="insp-label">MAC</span><span class="insp-value mono">${esc(d.macAddress)||'—'}</span></div>
      <div class="insp-row"><span class="insp-label">Category</span><span class="insp-value"><span class="cat-badge cat-${catClass(d.category)}">${esc(d.category)}</span></span></div>
      <div class="insp-row"><span class="insp-label">Manufacturer</span><span class="insp-value">${esc(d.manufacturer)||'—'}</span></div>
    </div>
    <div class="insp-section"><h3>Status</h3>
      <div class="insp-row"><span class="insp-label">Status</span><span class="insp-value"><span class="status-dot status-${d.status}"></span>${d.status}</span></div>
      <div class="insp-row"><span class="insp-label">Confidence</span><span class="insp-value"><span class="conf-badge conf-${(d.confidence||'unknown').toLowerCase()}">${d.confidence||'UNKNOWN'}</span></span></div>
      <div class="insp-row"><span class="insp-label">Source</span><span class="insp-value mono">${esc(d.discoverySource)}</span></div>
    </div>
    <div class="insp-section"><h3>Relationships (${rels.length})</h3>
      ${rels.length ? rels.map(r => {
        const oid = r.sourceDeviceId === d.id ? r.destDeviceId : r.sourceDeviceId;
        const o = currentSession.devices.find(x => x.id === oid);
        return `<div class="evidence-item"><div>${esc(r.type)} → <strong>${esc(o?.hostname||o?.ipAddress||oid.slice(0,8))}</strong></div>
          <div class="ev-source">${r.confidence} · ${esc(r.discoverySource)}</div></div>`;
      }).join('') : '<p class="text-muted" style="font-size:12px">None</p>'}
    </div>
    <div class="insp-section"><h3>Notes</h3>
      <textarea class="form-textarea" id="insp-notes" rows="3">${esc(d.notes)}</textarea>
      <div class="mt-8 flex gap-8">
        <button class="btn btn-primary btn-sm" id="insp-save-notes">Save</button>
        <button class="btn btn-secondary btn-sm" id="insp-edit">Edit</button>
      </div></div>`;
  $('#insp-save-notes')?.addEventListener('click', async () => {
    d.notes = $('#insp-notes').value; await persist(); toast('Saved', 'success');
  });
  $('#insp-edit')?.addEventListener('click', () => { closeInspector(); showDeviceForm(d); });
  inspector.classList.remove('closed'); inspector.classList.add('open');
}
function closeInspector() { inspector.classList.remove('open'); inspector.classList.add('closed'); }
$('#inspector-close').addEventListener('click', closeInspector);

async function renderView(name) {
  if (!currentSession && name !== 'settings') {
    main.innerHTML = `<div class="view active"><div class="empty-state">
      <h3>No session</h3><button class="btn btn-primary" id="empty-new-session">New Session</button></div></div>`;
    $('#empty-new-session')?.addEventListener('click', createNewSession); return;
  }
  const map = {
    overview: renderOverview, map: renderMap, devices: renderDevices,
    infrastructure: renderInfrastructure, alerts: renderAlerts, history: renderHistory,
    reports: renderReports, settings: renderSettings,
    traffic: () => renderPlaceholder('Traffic', 'Needs SNMP/agent'),
    diagnostics: () => renderPlaceholder('Diagnostics', 'Needs agent')
  };
  (map[name] || (() => { main.innerHTML = '<div class="view active"><p>Unknown</p></div>'; }))();
}
function renderPlaceholder(title, msg) {
  main.innerHTML = `<div class="view active"><div class="view-header"><h1 class="view-title">${title}</h1></div>
    <div class="empty-state"><h3>${title}</h3><p>${msg}</p><span class="badge badge-err">Backend required</span></div></div>`;
}

function renderOverview() {
  const s = currentSession, devices = s.devices || [];
  const online = devices.filter(d => d.status === 'online').length;
  const offline = devices.filter(d => d.status === 'offline').length;
  const unknown = devices.filter(d => !d.status || d.status === 'unknown').length;
  const alerts = (s.alerts || []).filter(a => !a.resolved).length;
  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">${esc(s.siteName)}</h1>
      <div class="view-actions">
        <button class="btn btn-primary btn-sm" id="ov-discover">Run Discovery</button>
        <button class="btn btn-secondary btn-sm" id="ov-refresh">Refresh</button>
      </div></div>
    <div class="stat-grid mb-16">
      <div class="stat-card"><div class="stat-label">Devices</div><div class="stat-value">${devices.length}</div></div>
      <div class="stat-card"><div class="stat-label">Online</div><div class="stat-value text-green">${online}</div></div>
      <div class="stat-card"><div class="stat-label">Offline</div><div class="stat-value">${offline}</div></div>
      <div class="stat-card"><div class="stat-label">Unknown</div><div class="stat-value text-orange">${unknown}</div></div>
      <div class="stat-card"><div class="stat-label">Alerts</div><div class="stat-value ${alerts?'text-red':''}">${alerts}</div></div>
    </div>
    <div class="card"><div class="card-header"><span class="card-title">Field discovery</span></div>
      <p class="text-secondary" style="font-size:13px;line-height:1.5">Browser cannot scan the LAN. Run the <strong>local agent</strong> on a computer on-site, then import or pull results under Reports. Demo discovery still works here for pipeline testing.</p>
      <div class="flex gap-8" style="flex-wrap:wrap;margin-top:8px">
        <span class="badge badge-ok">Agent ARP</span>
        <span class="badge badge-ok">Import JSON</span>
        <span class="badge badge-warn">Demo sample</span>
      </div>
    </div>
  </div>`;
  $('#ov-refresh')?.addEventListener('click', () => renderOverview());
  $('#ov-discover')?.addEventListener('click', () => runDiscovery());
}

function renderMap() {
  const s = currentSession;
  main.innerHTML = `<div class="view active" style="padding:12px;height:100%;display:flex;flex-direction:column">
    <div class="view-header" style="margin-bottom:10px"><h1 class="view-title">Network Map</h1>
      <div class="view-actions">
        <button class="btn btn-secondary btn-sm" id="map-add-rel">+ Relationship</button>
        <button class="btn btn-secondary btn-sm" id="map-add-dev">+ Device</button>
      </div></div>
    <div class="filter-chips mb-8">
      <span class="chip active" data-filter="all">All</span>
      <span class="chip" data-filter="infra">Infrastructure</span>
      <span class="chip" data-filter="endpoints">Endpoints</span>
    </div>
    <div class="map-container" id="map-container">
      <div class="map-controls">
        <button class="map-ctrl-btn" id="zoom-in">+</button>
        <button class="map-ctrl-btn" id="zoom-out">−</button>
        <button class="map-ctrl-btn" id="zoom-reset">↻</button>
      </div>
      <div class="map-legend">
        <div class="legend-item"><span class="legend-line verified"></span> Verified</div>
        <div class="legend-item"><span class="legend-line observed"></span> Observed</div>
        <div class="legend-item"><span class="legend-line inferred"></span> Inferred</div>
      </div>
    </div></div>`;
  topology = new TopologyRenderer($('#map-container'), {
    onSelect: id => openInspector(id),
    onPositionChange: async (id, x, y) => {
      const d = s.devices.find(x => x.id === id);
      if (d) { d.mapX = x; d.mapY = y; await persist(); }
    }
  });
  topology.setData(s.devices, s.relationships);
  $('#zoom-in')?.addEventListener('click', () => topology.zoomIn());
  $('#zoom-out')?.addEventListener('click', () => topology.zoomOut());
  $('#zoom-reset')?.addEventListener('click', () => topology.resetView());
  $('#map-add-dev')?.addEventListener('click', () => showDeviceForm());
  $('#map-add-rel')?.addEventListener('click', () => showRelationshipForm());
}

function renderDevices() {
  const devices = currentSession.devices || [];
  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">Devices (${devices.length})</h1>
      <div class="view-actions">
        <button class="btn btn-primary btn-sm" id="dev-add">+ Add</button>
        <button class="btn btn-secondary btn-sm" id="dev-import">Import CSV</button>
        <button class="btn btn-secondary btn-sm" id="dev-export">Export CSV</button>
      </div></div>
    ${!devices.length ? `<div class="empty-state"><h3>No devices</h3>
      <p>Pull from agent, import JSON/CSV, or add manually.</p>
      <button class="btn btn-primary" id="dev-empty-add">Add Device</button></div>`
    : `<div class="table-wrap"><table class="data-table"><thead><tr>
      <th>Status</th><th>Hostname</th><th>IP</th><th>MAC</th><th>Category</th><th>Source</th></tr></thead>
      <tbody>${devices.map(d => `<tr class="clickable" data-id="${d.id}">
        <td><span class="status-dot status-${d.status||'unknown'}"></span></td>
        <td>${esc(d.hostname)||'—'}</td><td class="mono">${esc(d.ipAddress)||'—'}</td>
        <td class="mono" style="font-size:11px">${esc(d.macAddress)||'—'}</td>
        <td><span class="cat-badge cat-${catClass(d.category)}">${esc(d.category)}</span></td>
        <td class="text-muted" style="font-size:11px">${esc(d.discoverySource)}</td></tr>`).join('')}
      </tbody></table></div>`}
    <input type="file" id="csv-file" accept=".csv,text/csv" class="hidden" /></div>`;
  document.querySelectorAll('.data-table tr.clickable').forEach(tr =>
    tr.addEventListener('click', () => openInspector(tr.dataset.id)));
  $('#dev-add')?.addEventListener('click', () => showDeviceForm());
  $('#dev-empty-add')?.addEventListener('click', () => showDeviceForm());
  $('#dev-export')?.addEventListener('click', () => { storage.exportDevicesCSV(currentSession); toast('Exported'); });
  $('#dev-import')?.addEventListener('click', () => $('#csv-file').click());
  $('#csv-file')?.addEventListener('change', async e => {
    const file = e.target.files?.[0]; if (!file) return;
    const { devices: imported } = importDevicesFromCSV(await file.text(), currentSession);
    if (imported.length) {
      currentSession.devices.push(...imported);
      await persist(); toast('Imported ' + imported.length, 'success'); renderDevices();
    }
    e.target.value = '';
  });
}

function showDeviceForm(existing = null) {
  const isEdit = !!existing; const d = existing || {};
  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">${isEdit?'Edit':'Add'} Device</h1>
      <button class="btn btn-secondary btn-sm" id="form-cancel">Cancel</button></div>
    <div class="card">
      <div class="form-row">
        <div class="form-group"><label class="form-label">Hostname</label><input class="form-input" id="f-hostname" value="${esc(d.hostname)}" /></div>
        <div class="form-group"><label class="form-label">IP</label><input class="form-input mono" id="f-ip" value="${esc(d.ipAddress)}" /></div>
      </div>
      <div class="form-row">
        <div class="form-group"><label class="form-label">MAC</label><input class="form-input mono" id="f-mac" value="${esc(d.macAddress)}" /></div>
        <div class="form-group"><label class="form-label">Category</label>
          <select class="form-select" id="f-category">${DEVICE_CATEGORIES.map(c=>`<option value="${c}" ${d.category===c?'selected':''}>${c}</option>`).join('')}</select></div>
      </div>
      <div class="form-group"><label class="form-label">Notes</label><textarea class="form-textarea" id="f-notes">${esc(d.notes)}</textarea></div>
      <button class="btn btn-primary" id="f-save">Save</button>
    </div></div>`;
  $('#form-cancel')?.addEventListener('click', () => renderView(currentView));
  $('#f-save')?.addEventListener('click', async () => {
    const ip = $('#f-ip').value.trim(), mac = normalizeMac($('#f-mac').value.trim());
    if (ip && !isValidIPv4(ip)) { toast('Invalid IP', 'error'); return; }
    if (isEdit) Object.assign(d, { hostname: $('#f-hostname').value.trim(), ipAddress: ip, macAddress: mac,
      category: $('#f-category').value, notes: $('#f-notes').value.trim(), lastObserved: nowISO() });
    else {
      currentSession.devices.push(createDevice({
        hostname: $('#f-hostname').value.trim(), ipAddress: ip, macAddress: mac,
        category: $('#f-category').value, notes: $('#f-notes').value.trim(),
        discoverySource: 'manual', confidence: CONFIDENCE.OBSERVED, isManual: true
      }));
    }
    await persist(); toast('Saved', 'success'); currentView = 'devices'; renderDevices();
  });
}

function showRelationshipForm() {
  const devices = currentSession.devices || [];
  if (devices.length < 2) { toast('Need two devices', 'error'); return; }
  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">Add Relationship</h1>
      <button class="btn btn-secondary btn-sm" id="rel-cancel">Cancel</button></div>
    <div class="card">
      <div class="form-group"><label class="form-label">Source</label>
        <select class="form-select" id="rel-src">${devices.map(d=>`<option value="${d.id}">${esc(d.hostname||d.ipAddress)}</option>`).join('')}</select></div>
      <div class="form-group"><label class="form-label">Destination</label>
        <select class="form-select" id="rel-dst">${devices.map(d=>`<option value="${d.id}">${esc(d.hostname||d.ipAddress)}</option>`).join('')}</select></div>
      <div class="form-group"><label class="form-label">Type</label>
        <select class="form-select" id="rel-type">${RELATIONSHIP_TYPES.map(t=>`<option value="${t}">${t}</option>`).join('')}</select></div>
      <div class="form-group"><label class="form-label">Confidence</label>
        <select class="form-select" id="rel-conf">
          <option value="VERIFIED">VERIFIED</option><option value="OBSERVED" selected>OBSERVED</option>
          <option value="INFERRED">INFERRED</option><option value="UNKNOWN">UNKNOWN</option></select></div>
      <div class="form-group"><label class="form-label">Evidence</label><textarea class="form-textarea" id="rel-evidence"></textarea></div>
      <button class="btn btn-primary" id="rel-save">Create</button>
    </div></div>`;
  $('#rel-cancel')?.addEventListener('click', () => renderView('map'));
  $('#rel-save')?.addEventListener('click', async () => {
    const src = $('#rel-src').value, dst = $('#rel-dst').value;
    if (src === dst) { toast('Must differ', 'error'); return; }
    currentSession.relationships = currentSession.relationships || [];
    currentSession.relationships.push(createRelationship({
      sourceDeviceId: src, destDeviceId: dst, type: $('#rel-type').value,
      confidence: $('#rel-conf').value, evidence: $('#rel-evidence').value.trim(), discoverySource: 'manual'
    }));
    await persist(); toast('Created', 'success'); currentView = 'map'; renderMap();
  });
}

function renderInfrastructure() {
  const infra = (currentSession.devices || []).filter(d =>
    /router|firewall|switch|access point|modem|wireless|network appliance/i.test(d.category));
  main.innerHTML = `<div class="view active"><div class="view-header"><h1 class="view-title">Infrastructure</h1></div>
    ${!infra.length ? '<div class="empty-state"><h3>None yet</h3></div>'
    : `<div class="table-wrap"><table class="data-table"><thead><tr><th>Hostname</th><th>IP</th><th>Category</th></tr></thead>
      <tbody>${infra.map(d=>`<tr class="clickable" data-id="${d.id}"><td>${esc(d.hostname)||'—'}</td>
        <td class="mono">${esc(d.ipAddress)||'—'}</td>
        <td><span class="cat-badge cat-${catClass(d.category)}">${esc(d.category)}</span></td></tr>`).join('')}
      </tbody></table></div>`}</div>`;
  document.querySelectorAll('.data-table tr.clickable').forEach(tr =>
    tr.addEventListener('click', () => openInspector(tr.dataset.id)));
}

function renderAlerts() {
  const alerts = (currentSession.alerts || []).slice().reverse();
  main.innerHTML = `<div class="view active"><div class="view-header"><h1 class="view-title">Alerts</h1></div>
    ${!alerts.length ? '<div class="empty-state"><h3>No alerts</h3></div>'
    : alerts.map(a => `<div class="alert-item"><div class="alert-sev ${a.severity}"></div>
      <div class="alert-body"><div class="alert-title">${esc(a.title)}</div>
      <div class="alert-meta">${esc(a.message)} · ${fmtTime(a.createdAt)}</div></div></div>`).join('')}</div>`;
}

function renderReports() {
  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">Reports</h1></div>
    <div class="card"><div class="card-header"><span class="card-title">Field agent</span></div>
      <p class="text-secondary" style="font-size:13px;line-height:1.5;margin-bottom:10px">
        On a PC on the same Wi‑Fi: <span class="mono">python3 netscan_agent.py --serve</span>
        then pull results here. Or import the JSON file the agent writes.
      </p>
      <div class="form-group"><label class="form-label">Agent URL</label>
        <input class="form-input mono" id="agent-url" placeholder="http://192.168.1.50:8765"
          value="${esc(localStorage.getItem('ns_agent_url')||'')}" /></div>
      <div class="flex gap-8" style="flex-wrap:wrap">
        <button class="btn btn-primary btn-sm" id="agent-pull">Pull session</button>
        <button class="btn btn-secondary btn-sm" id="agent-scan">Re-scan + pull</button>
      </div>
      <div id="agent-status" class="text-muted mt-8" style="font-size:12px"></div>
    </div>
    <div class="card"><div class="card-header"><span class="card-title">Export / Import</span></div>
      <div class="flex gap-8" style="flex-wrap:wrap;margin-bottom:12px">
        <button class="btn btn-primary btn-sm" id="rep-json">Export JSON</button>
        <button class="btn btn-secondary btn-sm" id="rep-csv">Export CSV</button>
      </div>
      <input type="file" id="json-file" accept=".json,application/json" />
    </div></div>`;
  $('#rep-json')?.addEventListener('click', () => { storage.exportSessionJSON(currentSession); toast('Exported'); });
  $('#rep-csv')?.addEventListener('click', () => { storage.exportDevicesCSV(currentSession); toast('Exported'); });
  $('#json-file')?.addEventListener('change', async e => {
    const file = e.target.files?.[0]; if (!file) return;
    const { session } = importSessionJSON(await file.text());
    if (session) {
      await storage.saveSession(session);
      currentSession = session;
      await refreshSessionList();
      sessionSelect.value = session.id;
      toast('Imported ' + session.devices.length + ' devices', 'success');
      currentView = 'map'; renderMap();
    }
    e.target.value = '';
  });
  async function pullAgent(rescan) {
    const url = ($('#agent-url')?.value || '').trim().replace(/\/$/, '');
    if (!url) { toast('Enter agent URL', 'error'); return; }
    localStorage.setItem('ns_agent_url', url);
    const status = $('#agent-status');
    if (status) status.textContent = rescan ? 'Re-scanning…' : 'Pulling…';
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 120000);
      const res = await fetch(url + (rescan ? '/scan' : '/session'), { signal: ctrl.signal });
      clearTimeout(t);
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      if (!data.devices) throw new Error(data.error || 'Bad response');
      const { session } = importSessionJSON(JSON.stringify(data));
      if (!session) throw new Error('Parse failed');
      await storage.saveSession(session);
      currentSession = session;
      await refreshSessionList();
      sessionSelect.value = session.id;
      if (status) status.textContent = 'Loaded ' + session.devices.length + ' devices';
      toast('Agent: ' + session.devices.length + ' devices', 'success');
      currentView = 'map'; renderMap();
    } catch (err) {
      if (status) status.textContent = 'Failed: ' + err.message;
      toast('Agent failed: ' + err.message, 'error');
    }
  }
  $('#agent-pull')?.addEventListener('click', () => pullAgent(false));
  $('#agent-scan')?.addEventListener('click', () => pullAgent(true));
}

function renderSettings() {
  main.innerHTML = `<div class="view active"><div class="view-header"><h1 class="view-title">Settings</h1></div>
    <div class="card"><div class="card-header"><span class="card-title">Session</span></div>
      ${currentSession ? `
        <div class="form-group"><label class="form-label">Site</label>
          <input class="form-input" id="set-site" value="${esc(currentSession.siteName)}" /></div>
        <button class="btn btn-primary btn-sm" id="set-save">Save</button>
        <button class="btn btn-danger btn-sm" id="set-delete">Delete</button>` : '<p class="text-muted">None</p>'}
    </div>
    <div class="card"><p style="font-size:13px"><strong>NetScan v0.3</strong> — field diagnostics PWA + local agent.</p></div></div>`;
  $('#set-save')?.addEventListener('click', async () => {
    currentSession.siteName = $('#set-site').value.trim() || currentSession.siteName;
    await persist(); await refreshSessionList(); toast('Saved', 'success');
  });
  $('#set-delete')?.addEventListener('click', async () => {
    if (!confirm('Delete session?')) return;
    await storage.deleteSession(currentSession.id);
    currentSession = null; await refreshSessionList();
    if (sessionsMeta.length) await switchSession(sessionsMeta[0].id); else renderView('overview');
  });
}

async function runDiscovery() {
  if (!currentSession) { toast('No session', 'error'); return; }
  toast('Running discovery…');
  try {
    const results = await runAdapters(getAvailableAdapters().map(a => a.id).filter(id => !['manual','csv-import'].includes(id)));
    const { summary } = processDiscoveryResults(currentSession, results, { backend: 'browser', trigger: 'manual' });
    await persist();
    toast(`Done: +${summary.newDevices} devices, ${summary.observations} observations`, 'success');
    if (currentView === 'history') renderHistory(); else if (currentView === 'overview') renderOverview();
    else if (currentView === 'devices') renderDevices(); else if (currentView === 'map') renderMap();
  } catch (err) { toast('Failed: ' + err.message, 'error'); }
}

function renderHistory() {
  const runs = currentSession.discoveryRuns || [];
  const caps = getAdapterCapabilities();
  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">Scan History</h1>
      <button class="btn btn-primary btn-sm" id="hist-run">Run Discovery</button></div>
    <div class="card"><div class="card-header"><span class="card-title">Adapters</span></div>
      ${caps.map(c => `<div class="cap-item"><div class="cap-status ${c.available?'available':'unavailable'}"></div>
        <div class="cap-info"><div class="cap-name">${esc(c.name)}
          <span class="badge ${c.available?'badge-ok':'badge-err'}">${c.available?'ready':'unavailable'}</span></div>
          <div class="cap-desc">${esc(c.description||'')}</div></div></div>`).join('')}
    </div>
    <div class="card"><div class="card-header"><span class="card-title">Runs (${runs.length})</span></div>
      ${!runs.length ? '<div class="empty-state"><p>No runs yet. Use agent for real scans.</p></div>'
      : runs.map(run => `<div class="alert-item"><div class="alert-sev info"></div>
        <div class="alert-body"><div class="alert-title">${fmtTime(run.startedAt)} · ${run.observationCount} obs · ${run.deviceCountDelta>=0?'+':''}${run.deviceCountDelta} devices</div>
        <div class="alert-meta">${(run.adapters||[]).map(a=>a.adapterId+': '+a.status).join(' · ')}</div></div></div>`).join('')}
    </div></div>`;
  $('#hist-run')?.addEventListener('click', () => runDiscovery());
}

async function boot() {
  $('#backend-badge').textContent = 'Browser';
  $('#capability-mini').textContent = 'Browser + agent for real scans';
  await refreshSessionList();
  if (sessionsMeta.length) await switchSession(sessionsMeta[0].id);
  else {
    const demo = createSession({ siteName: 'Demo Lab', clientName: 'Internal' });
    const gw = createDevice({ hostname: 'core-gw', ipAddress: '192.168.1.1', macAddress: '00:11:22:33:44:55',
      category: 'Router', status: 'online', discoverySource: 'manual', confidence: CONFIDENCE.OBSERVED, isManual: true, mapX: 180, mapY: 100 });
    const sw = createDevice({ hostname: 'access-sw1', ipAddress: '192.168.1.2', macAddress: '00:11:22:33:44:66',
      category: 'Managed Switch', status: 'online', discoverySource: 'manual', confidence: CONFIDENCE.OBSERVED, isManual: true, mapX: 180, mapY: 220 });
    const pc = createDevice({ hostname: 'tech-laptop', ipAddress: '192.168.1.50', macAddress: 'AA:BB:CC:DD:EE:01',
      category: 'Laptop', status: 'online', discoverySource: 'manual', confidence: CONFIDENCE.OBSERVED, isManual: true, mapX: 280, mapY: 300 });
    demo.devices.push(gw, sw, pc);
    demo.relationships.push(
      createRelationship({ sourceDeviceId: gw.id, destDeviceId: sw.id, type: 'Physical Ethernet link', confidence: CONFIDENCE.VERIFIED, evidence: 'Uplink', discoverySource: 'manual' }),
      createRelationship({ sourceDeviceId: sw.id, destDeviceId: pc.id, type: 'Switch port connection', confidence: CONFIDENCE.INFERRED, evidence: 'Same subnet', discoverySource: 'manual' })
    );
    await storage.saveSession(demo);
    currentSession = demo;
    await refreshSessionList();
    sessionSelect.value = demo.id;
  }
  renderView('overview');
}
boot().catch(err => { console.error(err); toast('Startup error: ' + err.message, 'error'); });
