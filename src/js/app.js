/**
 * NetScan — Application entry & view controller
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
  try {
    return new Date(iso).toLocaleString(undefined, { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
  } catch { return iso; }
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
  if (sessionsMeta.length === 0) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'No sessions';
    sessionSelect.appendChild(opt);
    return;
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
  toast(`Loaded: ${s.siteName}`);
}

async function createNewSession() {
  const name = prompt('Site / network name:', 'Field Site');
  if (!name) return;
  const session = createSession({ siteName: name.trim() });
  const gw = createDevice({
    hostname: 'Gateway', category: 'Router', status: 'unknown',
    discoverySource: 'manual', confidence: CONFIDENCE.UNKNOWN, isManual: true,
    mapX: 180, mapY: 120
  });
  session.devices.push(gw);
  await storage.saveSession(session);
  currentSession = session;
  await refreshSessionList();
  sessionSelect.value = session.id;
  await renderView(currentView);
  toast('Session created');
}

async function persist() {
  if (!currentSession) return;
  await storage.saveSession(currentSession);
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
sessionSelect.addEventListener('change', (e) => switchSession(e.target.value));

function renderCapabilityPanel() {
  const body = $('#capability-body');
  let html = `<p class="text-secondary mb-16" style="font-size:13px;line-height:1.5">
    Current backend: <strong class="text-cyan">${backend.name}</strong>. ${backend.description}</p>`;
  const sections = [
    ['Available in Browser', BROWSER_CAPABILITIES.filter(c => c.available === true), 'available'],
    ['Partially Available', BROWSER_CAPABILITIES.filter(c => c.available === 'partial'), 'partial'],
    ['Requires Native App or Local Agent', BROWSER_CAPABILITIES.filter(c => c.available === false), 'unavailable']
  ];
  for (const [title, items, cls] of sections) {
    if (!items.length) continue;
    html += `<div class="cap-section"><h3>${title}</h3>`;
    for (const c of items) {
      html += `<div class="cap-item"><div class="cap-status ${cls}"></div><div class="cap-info">
        <div class="cap-name">${c.name}</div>
        <div class="cap-desc">${c.description || c.reason || ''}</div>
        <div class="cap-backend">${c.protocol} · ${c.backend}</div>
      </div></div>`;
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
capabilityModal.addEventListener('click', (e) => {
  if (e.target === capabilityModal) {
    capabilityModal.classList.remove('open');
    capabilityModal.classList.add('closed');
  }
});

function openInspector(deviceId) {
  const d = currentSession?.devices.find(x => x.id === deviceId);
  if (!d) return;
  $('#inspector-title').textContent = d.hostname || d.ipAddress || 'Device';
  const body = $('#inspector-body');
  const rels = (currentSession.relationships || []).filter(
    r => r.sourceDeviceId === d.id || r.destDeviceId === d.id
  );
  body.innerHTML = `
    <div class="insp-section"><h3>Identity</h3>
      <div class="insp-row"><span class="insp-label">Hostname</span><span class="insp-value mono">${esc(d.hostname) || '—'}</span></div>
      <div class="insp-row"><span class="insp-label">IP</span><span class="insp-value mono">${esc(d.ipAddress) || '—'}</span></div>
      <div class="insp-row"><span class="insp-label">MAC</span><span class="insp-value mono">${esc(d.macAddress) || '—'}</span></div>
      <div class="insp-row"><span class="insp-label">Category</span><span class="insp-value"><span class="cat-badge cat-${catClass(d.category)}">${esc(d.category)}</span></span></div>
      <div class="insp-row"><span class="insp-label">Manufacturer</span><span class="insp-value">${esc(d.manufacturer) || '—'}</span></div>
      <div class="insp-row"><span class="insp-label">Model</span><span class="insp-value">${esc(d.model) || '—'}</span></div>
    </div>
    <div class="insp-section"><h3>Status & Provenance</h3>
      <div class="insp-row"><span class="insp-label">Status</span><span class="insp-value"><span class="status-dot status-${d.status}"></span>${d.status}</span></div>
      <div class="insp-row"><span class="insp-label">Confidence</span><span class="insp-value"><span class="conf-badge conf-${(d.confidence||'unknown').toLowerCase()}">${d.confidence || 'UNKNOWN'}</span></span></div>
      <div class="insp-row"><span class="insp-label">Source</span><span class="insp-value mono">${esc(d.discoverySource)}</span></div>
      <div class="insp-row"><span class="insp-label">First seen</span><span class="insp-value mono">${fmtTime(d.firstDiscovered)}</span></div>
      <div class="insp-row"><span class="insp-label">Last seen</span><span class="insp-value mono">${fmtTime(d.lastObserved)}</span></div>
    </div>
    <div class="insp-section"><h3>Relationships (${rels.length})</h3>
      ${rels.length === 0
        ? '<p class="text-muted" style="font-size:12px">No relationship records.</p>'
        : rels.map(r => {
            const otherId = r.sourceDeviceId === d.id ? r.destDeviceId : r.sourceDeviceId;
            const other = currentSession.devices.find(x => x.id === otherId);
            return `<div class="evidence-item">
              <div>${esc(r.type)} → <strong>${esc(other?.hostname || other?.ipAddress || otherId.slice(0,8))}</strong></div>
              <div class="ev-source">${r.confidence} · ${esc(r.discoverySource)}</div>
              ${r.evidence ? `<div style="margin-top:4px;font-size:12px">${esc(r.evidence)}</div>` : ''}
            </div>`;
          }).join('')}
    </div>
    <div class="insp-section"><h3>Notes</h3>
      <textarea class="form-textarea" id="insp-notes" rows="3">${esc(d.notes)}</textarea>
      <div class="mt-8 flex gap-8">
        <button class="btn btn-primary btn-sm" id="insp-save-notes">Save notes</button>
        <button class="btn btn-secondary btn-sm" id="insp-edit">Edit device</button>
      </div>
    </div>`;
  $('#insp-save-notes')?.addEventListener('click', async () => {
    d.notes = $('#insp-notes').value;
    await persist();
    toast('Notes saved', 'success');
  });
  $('#insp-edit')?.addEventListener('click', () => { closeInspector(); showDeviceForm(d); });
  inspector.classList.remove('closed');
  inspector.classList.add('open');
}
function closeInspector() {
  inspector.classList.remove('open');
  inspector.classList.add('closed');
}
$('#inspector-close').addEventListener('click', closeInspector);

async function renderView(name) {
  if (!currentSession && name !== 'settings') {
    main.innerHTML = `<div class="view active"><div class="empty-state">
      <h3>No active session</h3>
      <p>Create a new network session to begin.</p>
      <button class="btn btn-primary" id="empty-new-session">New Session</button>
    </div></div>`;
    $('#empty-new-session')?.addEventListener('click', createNewSession);
    return;
  }
  switch (name) {
    case 'overview': return renderOverview();
    case 'map': return renderMap();
    case 'devices': return renderDevices();
    case 'infrastructure': return renderInfrastructure();
    case 'traffic': return renderPlaceholder('Traffic', 'Requires SNMP or local agent.');
    case 'diagnostics': return renderPlaceholder('Diagnostics', 'Requires native agent.');
    case 'alerts': return renderAlerts();
    case 'history': return renderHistory();
    case 'reports': return renderReports();
    case 'settings': return renderSettings();
    default: main.innerHTML = `<div class="view active"><p>Unknown view</p></div>`;
  }
}

function renderPlaceholder(title, msg) {
  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">${title}</h1></div>
    <div class="empty-state"><h3>${title} unavailable in browser</h3>
      <p>${msg}</p><span class="badge badge-err">Backend required</span></div>
  </div>`;
}

function renderOverview() {
  const s = currentSession;
  const devices = s.devices || [];
  const online = devices.filter(d => d.status === 'online').length;
  const offline = devices.filter(d => d.status === 'offline').length;
  const unknown = devices.filter(d => d.status === 'unknown' || !d.status).length;
  const routers = devices.filter(d => /router|firewall|modem/i.test(d.category)).length;
  const switches = devices.filter(d => /switch/i.test(d.category)).length;
  const aps = devices.filter(d => /access point|ap|wireless/i.test(d.category)).length;
  const alerts = (s.alerts || []).filter(a => !a.resolved).length;

  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">${esc(s.siteName)}</h1>
      <div class="view-actions">
        <button class="btn btn-primary btn-sm" id="ov-discover">Run Discovery</button>
        <button class="btn btn-secondary btn-sm" id="ov-refresh">Refresh</button>
      </div></div>
    <div class="card"><div class="card-header"><span class="card-title">Session</span></div>
      <div class="insp-row"><span class="insp-label">Client</span><span class="insp-value">${esc(s.clientName) || '—'}</span></div>
      <div class="insp-row"><span class="insp-label">Location</span><span class="insp-value">${esc(s.location) || '—'}</span></div>
      <div class="insp-row"><span class="insp-label">Updated</span><span class="insp-value mono">${fmtTime(s.updatedAt)}</span></div>
      <div class="insp-row"><span class="insp-label">Backend</span><span class="insp-value"><span class="badge badge-muted">Browser</span></span></div>
    </div>
    <div class="stat-grid mb-16">
      <div class="stat-card"><div class="stat-label">Devices</div><div class="stat-value">${devices.length}</div></div>
      <div class="stat-card"><div class="stat-label">Online</div><div class="stat-value text-green">${online}</div></div>
      <div class="stat-card"><div class="stat-label">Offline</div><div class="stat-value">${offline}</div></div>
      <div class="stat-card"><div class="stat-label">Unknown</div><div class="stat-value text-orange">${unknown}</div></div>
      <div class="stat-card"><div class="stat-label">Routers / GW</div><div class="stat-value">${routers}</div></div>
      <div class="stat-card"><div class="stat-label">Switches</div><div class="stat-value">${switches}</div></div>
      <div class="stat-card"><div class="stat-label">Access Points</div><div class="stat-value">${aps}</div></div>
      <div class="stat-card"><div class="stat-label">Active Alerts</div><div class="stat-value ${alerts ? 'text-red' : ''}">${alerts}</div></div>
    </div>
    <div class="card"><div class="card-header"><span class="card-title">Measurements</span></div>
      <div class="stat-grid">
        <div class="stat-card"><div class="stat-label">Latency</div><div class="stat-value unavailable">Not measured</div><div class="stat-sub">Backend required</div></div>
        <div class="stat-card"><div class="stat-label">Packet Loss</div><div class="stat-value unavailable">Not measured</div><div class="stat-sub">Backend required</div></div>
        <div class="stat-card"><div class="stat-label">Download</div><div class="stat-value unavailable">Not measured</div><div class="stat-sub">Backend required</div></div>
        <div class="stat-card"><div class="stat-label">Upload</div><div class="stat-value unavailable">Not measured</div><div class="stat-sub">Backend required</div></div>
      </div>
    </div>
    <div class="card"><div class="card-header"><span class="card-title">Discovery Capability</span>
      <button class="btn btn-secondary btn-sm" id="ov-cap">Details</button></div>
      <p class="text-secondary" style="font-size:13px;line-height:1.5;margin-bottom:8px">
        Browser-only mode. Use <strong>Run Discovery</strong> to exercise the pipeline (demo sample). Real ARP/mDNS/SNMP need an agent.
      </p>
      <div class="flex gap-8" style="flex-wrap:wrap">
        <span class="badge badge-ok">Manual + Import + Demo</span>
        <span class="badge badge-err">No ARP/ICMP/SNMP</span>
      </div>
    </div>
  </div>`;
  $('#ov-cap')?.addEventListener('click', () => {
    renderCapabilityPanel();
    capabilityModal.classList.remove('closed');
    capabilityModal.classList.add('open');
  });
  $('#ov-refresh')?.addEventListener('click', () => renderOverview());
  $('#ov-discover')?.addEventListener('click', () => runDiscovery());
}

function renderMap() {
  const s = currentSession;
  main.innerHTML = `<div class="view active" style="padding:12px;height:100%;display:flex;flex-direction:column">
    <div class="view-header" style="margin-bottom:10px">
      <h1 class="view-title">Network Map</h1>
      <div class="view-actions">
        <button class="btn btn-secondary btn-sm" id="map-add-rel">+ Relationship</button>
        <button class="btn btn-secondary btn-sm" id="map-add-dev">+ Device</button>
      </div>
    </div>
    <div class="filter-chips mb-8">
      <span class="chip active" data-filter="all">All</span>
      <span class="chip" data-filter="infra">Infrastructure</span>
      <span class="chip" data-filter="endpoints">Endpoints</span>
      <span class="chip" data-filter="offline">Hide offline</span>
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
        <div class="legend-item"><span class="legend-line unknown"></span> Unknown</div>
      </div>
    </div>
  </div>`;
  const container = $('#map-container');
  topology = new TopologyRenderer(container, {
    onSelect: (id) => openInspector(id),
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
  document.querySelectorAll('.filter-chips .chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const f = chip.dataset.filter;
      if (f === 'all') {
        topology.setFilter('categories', new Set());
        topology.setFilter('showOffline', true);
      } else if (f === 'infra') {
        topology.setFilter('categories', new Set([
          'Router','Firewall','Managed Switch','Unmanaged Switch','Access Point','Wireless Controller','Modem','Network Appliance'
        ]));
      } else if (f === 'endpoints') {
        topology.setFilter('categories', new Set([
          'Desktop','Laptop','Server','NAS','Printer','Smartphone','Tablet','Camera','IoT Device','Smart Television','VoIP Phone'
        ]));
      } else if (f === 'offline') {
        topology.setFilter('showOffline', !topology.filters.showOffline);
      }
      document.querySelectorAll('.filter-chips .chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
    });
  });
}

function renderDevices() {
  const s = currentSession;
  const devices = s.devices || [];
  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">Devices (${devices.length})</h1>
      <div class="view-actions">
        <button class="btn btn-primary btn-sm" id="dev-add">+ Add</button>
        <button class="btn btn-secondary btn-sm" id="dev-import">Import CSV</button>
        <button class="btn btn-secondary btn-sm" id="dev-export">Export CSV</button>
      </div>
    </div>
    ${devices.length === 0 ? `<div class="empty-state">
      <h3>No devices yet</h3>
      <p>Add manually, import CSV, or Run Discovery.</p>
      <button class="btn btn-primary" id="dev-empty-add">Add Device</button>
    </div>` : `<div class="table-wrap"><table class="data-table">
      <thead><tr><th>Status</th><th>Hostname</th><th>IP</th><th>MAC</th><th>Category</th><th>Source</th></tr></thead>
      <tbody>${devices.map(d => `<tr class="clickable" data-id="${d.id}">
        <td><span class="status-dot status-${d.status || 'unknown'}"></span></td>
        <td>${esc(d.hostname) || '<span class="text-muted">—</span>'}</td>
        <td class="mono">${esc(d.ipAddress) || '—'}</td>
        <td class="mono" style="font-size:11px">${esc(d.macAddress) || '—'}</td>
        <td><span class="cat-badge cat-${catClass(d.category)}">${esc(d.category)}</span></td>
        <td class="text-muted" style="font-size:11px">${esc(d.discoverySource)}</td>
      </tr>`).join('')}</tbody></table></div>`}
    <input type="file" id="csv-file" accept=".csv,text/csv" class="hidden" />
  </div>`;
  document.querySelectorAll('.data-table tr.clickable').forEach(tr => {
    tr.addEventListener('click', () => openInspector(tr.dataset.id));
  });
  $('#dev-add')?.addEventListener('click', () => showDeviceForm());
  $('#dev-empty-add')?.addEventListener('click', () => showDeviceForm());
  $('#dev-export')?.addEventListener('click', () => { storage.exportDevicesCSV(s); toast('CSV exported'); });
  $('#dev-import')?.addEventListener('click', () => $('#csv-file').click());
  $('#csv-file')?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    const { devices: imported, report } = importDevicesFromCSV(text, s);
    if (imported.length) {
      s.devices.push(...imported);
      for (const d of imported) {
        s.alerts.push(createAlert({
          severity: 'info', title: 'Device imported',
          message: `${d.hostname || d.ipAddress || d.macAddress} added via CSV`, deviceId: d.id
        }));
      }
      await persist();
      toast(`Imported ${imported.length} devices`, 'success');
      renderDevices();
    }
    e.target.value = '';
  });
}

function showDeviceForm(existing = null) {
  const isEdit = !!existing;
  const d = existing || {};
  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">${isEdit ? 'Edit Device' : 'Add Device'}</h1>
      <button class="btn btn-secondary btn-sm" id="form-cancel">Cancel</button></div>
    <div class="card">
      <div class="form-row">
        <div class="form-group"><label class="form-label">Hostname</label>
          <input class="form-input" id="f-hostname" value="${esc(d.hostname)}" /></div>
        <div class="form-group"><label class="form-label">IP Address</label>
          <input class="form-input mono" id="f-ip" value="${esc(d.ipAddress)}" placeholder="192.168.1.10" /></div>
      </div>
      <div class="form-row">
        <div class="form-group"><label class="form-label">MAC Address</label>
          <input class="form-input mono" id="f-mac" value="${esc(d.macAddress)}" placeholder="AA:BB:CC:DD:EE:FF" /></div>
        <div class="form-group"><label class="form-label">Category</label>
          <select class="form-select" id="f-category">
            ${DEVICE_CATEGORIES.map(c => `<option value="${c}" ${d.category === c ? 'selected' : ''}>${c}</option>`).join('')}
          </select></div>
      </div>
      <div class="form-row">
        <div class="form-group"><label class="form-label">Manufacturer</label>
          <input class="form-input" id="f-mfr" value="${esc(d.manufacturer)}" /></div>
        <div class="form-group"><label class="form-label">Model</label>
          <input class="form-input" id="f-model" value="${esc(d.model)}" /></div>
      </div>
      <div class="form-row">
        <div class="form-group"><label class="form-label">Status</label>
          <select class="form-select" id="f-status">
            <option value="unknown" ${d.status==='unknown'?'selected':''}>Unknown</option>
            <option value="online" ${d.status==='online'?'selected':''}>Online</option>
            <option value="offline" ${d.status==='offline'?'selected':''}>Offline</option>
          </select></div>
        <div class="form-group"><label class="form-label">VLAN</label>
          <input class="form-input" id="f-vlan" value="${d.vlan ?? ''}" /></div>
      </div>
      <div class="form-group"><label class="form-label">Notes</label>
        <textarea class="form-textarea" id="f-notes">${esc(d.notes)}</textarea></div>
      <div class="flex gap-8">
        <button class="btn btn-primary" id="f-save">${isEdit ? 'Save' : 'Add Device'}</button>
        ${isEdit ? '<button class="btn btn-danger" id="f-delete">Delete</button>' : ''}
      </div>
    </div>
  </div>`;
  $('#form-cancel')?.addEventListener('click', () => renderView(currentView));
  $('#f-save')?.addEventListener('click', async () => {
    const ip = $('#f-ip').value.trim();
    const mac = normalizeMac($('#f-mac').value.trim());
    if (ip && !isValidIPv4(ip)) { toast('Invalid IPv4 address', 'error'); return; }
    if (isEdit) {
      Object.assign(d, {
        hostname: $('#f-hostname').value.trim(), ipAddress: ip, macAddress: mac,
        category: $('#f-category').value, manufacturer: $('#f-mfr').value.trim(),
        model: $('#f-model').value.trim(), status: $('#f-status').value,
        vlan: $('#f-vlan').value.trim() || null, notes: $('#f-notes').value.trim(),
        lastObserved: nowISO()
      });
    } else {
      const device = createDevice({
        hostname: $('#f-hostname').value.trim(), ipAddress: ip, macAddress: mac,
        category: $('#f-category').value, manufacturer: $('#f-mfr').value.trim(),
        model: $('#f-model').value.trim(), status: $('#f-status').value,
        vlan: $('#f-vlan').value.trim() || null, notes: $('#f-notes').value.trim(),
        discoverySource: 'manual', confidence: CONFIDENCE.OBSERVED, isManual: true
      });
      currentSession.devices.push(device);
      currentSession.alerts.push(createAlert({
        severity: 'info', title: 'Device added',
        message: `${device.hostname || device.ipAddress || 'New device'} registered manually`,
        deviceId: device.id
      }));
    }
    await persist();
    toast(isEdit ? 'Device updated' : 'Device added', 'success');
    currentView = 'devices';
    document.querySelectorAll('.nav-item').forEach(i => i.classList.toggle('active', i.dataset.view === 'devices'));
    renderDevices();
  });
  $('#f-delete')?.addEventListener('click', async () => {
    if (!confirm('Delete this device and its relationships?')) return;
    currentSession.devices = currentSession.devices.filter(x => x.id !== d.id);
    currentSession.relationships = (currentSession.relationships || []).filter(
      r => r.sourceDeviceId !== d.id && r.destDeviceId !== d.id
    );
    await persist();
    toast('Device deleted');
    renderDevices();
  });
}

function showRelationshipForm() {
  const devices = currentSession.devices || [];
  if (devices.length < 2) { toast('Need at least two devices', 'error'); return; }
  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">Add Relationship</h1>
      <button class="btn btn-secondary btn-sm" id="rel-cancel">Cancel</button></div>
    <div class="card">
      <p class="text-secondary mb-16" style="font-size:13px">Relationships drive the topology map.</p>
      <div class="form-group"><label class="form-label">Source</label>
        <select class="form-select" id="rel-src">
          ${devices.map(d => `<option value="${d.id}">${esc(d.hostname || d.ipAddress || d.id.slice(0,8))} (${esc(d.category)})</option>`).join('')}
        </select></div>
      <div class="form-group"><label class="form-label">Destination</label>
        <select class="form-select" id="rel-dst">
          ${devices.map(d => `<option value="${d.id}">${esc(d.hostname || d.ipAddress || d.id.slice(0,8))} (${esc(d.category)})</option>`).join('')}
        </select></div>
      <div class="form-group"><label class="form-label">Type</label>
        <select class="form-select" id="rel-type">
          ${RELATIONSHIP_TYPES.map(t => `<option value="${t}">${t}</option>`).join('')}
        </select></div>
      <div class="form-group"><label class="form-label">Confidence</label>
        <select class="form-select" id="rel-conf">
          <option value="VERIFIED">VERIFIED</option>
          <option value="OBSERVED" selected>OBSERVED</option>
          <option value="INFERRED">INFERRED</option>
          <option value="UNKNOWN">UNKNOWN</option>
        </select></div>
      <div class="form-group"><label class="form-label">Evidence</label>
        <textarea class="form-textarea" id="rel-evidence"></textarea></div>
      <button class="btn btn-primary" id="rel-save">Create Relationship</button>
    </div>
  </div>`;
  $('#rel-cancel')?.addEventListener('click', () => renderView('map'));
  $('#rel-save')?.addEventListener('click', async () => {
    const src = $('#rel-src').value, dst = $('#rel-dst').value;
    if (src === dst) { toast('Source and destination must differ', 'error'); return; }
    const rel = createRelationship({
      sourceDeviceId: src, destDeviceId: dst,
      type: $('#rel-type').value, confidence: $('#rel-conf').value,
      evidence: $('#rel-evidence').value.trim(), discoverySource: 'manual'
    });
    currentSession.relationships = currentSession.relationships || [];
    currentSession.relationships.push(rel);
    await persist();
    toast('Relationship created', 'success');
    currentView = 'map';
    document.querySelectorAll('.nav-item').forEach(i => i.classList.toggle('active', i.dataset.view === 'map'));
    renderMap();
  });
}

function renderInfrastructure() {
  const infra = (currentSession.devices || []).filter(d =>
    /router|firewall|switch|access point|modem|wireless|network appliance/i.test(d.category)
  );
  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">Infrastructure</h1></div>
    ${infra.length === 0
      ? `<div class="empty-state"><h3>No infrastructure devices</h3></div>`
      : `<div class="table-wrap"><table class="data-table">
        <thead><tr><th>Hostname</th><th>IP</th><th>Category</th><th>Model</th></tr></thead>
        <tbody>${infra.map(d => `<tr class="clickable" data-id="${d.id}">
          <td>${esc(d.hostname) || '—'}</td><td class="mono">${esc(d.ipAddress) || '—'}</td>
          <td><span class="cat-badge cat-${catClass(d.category)}">${esc(d.category)}</span></td>
          <td>${esc(d.model) || '—'}</td></tr>`).join('')}</tbody></table></div>`}
  </div>`;
  document.querySelectorAll('.data-table tr.clickable').forEach(tr => {
    tr.addEventListener('click', () => openInspector(tr.dataset.id));
  });
}

function renderAlerts() {
  const alerts = (currentSession.alerts || []).slice().reverse();
  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">Alerts (${alerts.filter(a => !a.resolved).length} open)</h1></div>
    ${alerts.length === 0
      ? `<div class="empty-state"><h3>No alerts</h3></div>`
      : alerts.map(a => `<div class="alert-item">
        <div class="alert-sev ${a.severity}"></div>
        <div class="alert-body">
          <div class="alert-title">${esc(a.title)}</div>
          <div class="alert-meta">${esc(a.message)} · ${fmtTime(a.createdAt)}</div>
        </div></div>`).join('')}
  </div>`;
}

function renderReports() {
  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">Reports</h1></div>
    <div class="card"><div class="card-header"><span class="card-title">Export</span></div>
      <div class="flex gap-8" style="flex-wrap:wrap">
        <button class="btn btn-primary btn-sm" id="rep-json">Export Session JSON</button>
        <button class="btn btn-secondary btn-sm" id="rep-csv">Export Devices CSV</button>
      </div>
    </div>
    <div class="card"><div class="card-header"><span class="card-title">Import Session</span></div>
      <input type="file" id="json-file" accept=".json,application/json" />
    </div>
  </div>`;
  $('#rep-json')?.addEventListener('click', () => { storage.exportSessionJSON(currentSession); toast('Session exported'); });
  $('#rep-csv')?.addEventListener('click', () => { storage.exportDevicesCSV(currentSession); toast('CSV exported'); });
  $('#json-file')?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    const { session } = importSessionJSON(text);
    if (session) {
      await storage.saveSession(session);
      currentSession = session;
      await refreshSessionList();
      sessionSelect.value = session.id;
      toast('Session imported', 'success');
      renderOverview();
    }
    e.target.value = '';
  });
}

function renderSettings() {
  main.innerHTML = `<div class="view active">
    <div class="view-header"><h1 class="view-title">Settings</h1></div>
    <div class="card"><div class="card-header"><span class="card-title">Session</span></div>
      ${currentSession ? `
        <div class="form-group"><label class="form-label">Site Name</label>
          <input class="form-input" id="set-site" value="${esc(currentSession.siteName)}" /></div>
        <div class="form-group"><label class="form-label">Client</label>
          <input class="form-input" id="set-client" value="${esc(currentSession.clientName)}" /></div>
        <div class="form-group"><label class="form-label">Location</label>
          <input class="form-input" id="set-loc" value="${esc(currentSession.location)}" /></div>
        <div class="form-group"><label class="form-label">Notes</label>
          <textarea class="form-textarea" id="set-notes">${esc(currentSession.notes)}</textarea></div>
        <button class="btn btn-primary btn-sm" id="set-save">Save Session</button>
        <button class="btn btn-danger btn-sm" id="set-delete">Delete Session</button>
      ` : '<p class="text-muted">No active session.</p>'}
    </div>
    <div class="card"><div class="card-header"><span class="card-title">About</span></div>
      <p style="font-size:13px;line-height:1.5">
        <strong>NetScan v0.3</strong> — Network Intelligence & Field Diagnostics.<br>
        Vendor-neutral. Browser-first PWA with modular discovery adapters.
      </p>
    </div>
  </div>`;
  $('#set-save')?.addEventListener('click', async () => {
    currentSession.siteName = $('#set-site').value.trim() || currentSession.siteName;
    currentSession.clientName = $('#set-client').value.trim();
    currentSession.location = $('#set-loc').value.trim();
    currentSession.notes = $('#set-notes').value.trim();
    await persist();
    await refreshSessionList();
    toast('Session saved', 'success');
  });
  $('#set-delete')?.addEventListener('click', async () => {
    if (!confirm('Delete this session permanently?')) return;
    await storage.deleteSession(currentSession.id);
    currentSession = null;
    await refreshSessionList();
    if (sessionsMeta.length) await switchSession(sessionsMeta[0].id);
    else renderView('overview');
    toast('Session deleted');
  });
}

async function runDiscovery(adapterIds = null) {
  if (!currentSession) { toast('No session', 'error'); return; }
  toast('Running discovery…');
  const ids = adapterIds || getAvailableAdapters().map(a => a.id);
  const runnable = ids.filter(id => !['manual', 'csv-import'].includes(id));
  const toRun = runnable.length ? runnable : ids;
  const startedAt = new Date().toISOString();
  try {
    const results = await runAdapters(toRun, {});
    const { summary } = processDiscoveryResults(currentSession, results, {
      startedAt,
      backend: 'browser',
      trigger: 'manual'
    });
    await persist();
    toast(`Discovery done: ${summary.newDevices} new, ${summary.updatedDevices} updated, ${summary.observations} observations`, 'success');
    if (currentView === 'history') renderHistory();
    else if (currentView === 'overview') renderOverview();
    else if (currentView === 'devices') renderDevices();
    else if (currentView === 'map') renderMap();
  } catch (err) {
    console.error(err);
    toast('Discovery failed: ' + err.message, 'error');
  }
}

function renderHistory() {
  const runs = currentSession.discoveryRuns || [];
  const caps = getAdapterCapabilities();

  main.innerHTML = `<div class="view active">
    <div class="view-header">
      <h1 class="view-title">Scan History</h1>
      <div class="view-actions">
        <button class="btn btn-primary btn-sm" id="hist-run">Run Discovery</button>
      </div>
    </div>

    <div class="card">
      <div class="card-header"><span class="card-title">Adapters</span></div>
      <div style="display:flex;flex-direction:column;gap:6px">
        ${caps.map(c => `
          <div class="cap-item" style="margin:0">
            <div class="cap-status ${c.available ? 'available' : 'unavailable'}"></div>
            <div class="cap-info">
              <div class="cap-name">${esc(c.name)}
                <span class="badge ${c.available ? 'badge-ok' : 'badge-err'}" style="margin-left:6px">${c.available ? 'ready' : 'unavailable'}</span>
              </div>
              <div class="cap-desc">${esc(c.description || '')}</div>
              <div class="cap-backend">${esc(c.protocol)} · ${esc(c.backend)}
                ${c.lastRunAt ? ` · last ${fmtTime(c.lastRunAt)}` : ''}
                ${c.lastResultCount ? ` · ${c.lastResultCount} results` : ''}
              </div>
            </div>
          </div>
        `).join('')}
      </div>
    </div>

    <div class="card">
      <div class="card-header"><span class="card-title">Discovery Runs (${runs.length})</span></div>
      ${runs.length === 0
        ? `<div class="empty-state" style="padding:24px 12px">
            <h3>No discovery runs yet</h3>
            <p>Tap <strong>Run Discovery</strong> to exercise available adapters. In browser mode this runs the demo sample so you can verify the pipeline.</p>
          </div>`
        : runs.map(run => `
          <div class="alert-item" style="margin-bottom:8px">
            <div class="alert-sev ${run.errors?.length ? 'high' : 'info'}"></div>
            <div class="alert-body">
              <div class="alert-title">${fmtTime(run.startedAt)} · ${run.observationCount} observations · ${run.deviceCountDelta >= 0 ? '+' : ''}${run.deviceCountDelta} devices</div>
              <div class="alert-meta">
                ${(run.adapters || []).map(a => `${a.adapterId}: ${a.status}${a.resultCount ? ' ('+a.resultCount+')' : ''}`).join(' · ')}
              </div>
            </div>
          </div>
        `).join('')}
    </div>
  </div>`;

  $('#hist-run')?.addEventListener('click', () => runDiscovery());
}

async function boot() {
  $('#backend-badge').textContent = 'Browser';
  $('#capability-mini').textContent = 'Browser-only · Limited discovery';
  await refreshSessionList();
  if (sessionsMeta.length > 0) {
    await switchSession(sessionsMeta[0].id);
  } else {
    const demo = createSession({ siteName: 'Demo Lab', clientName: 'Internal', location: 'Field demo' });
    const gw = createDevice({ hostname: 'core-gw', ipAddress: '192.168.1.1', macAddress: '00:11:22:33:44:55',
      category: 'Router', manufacturer: 'Generic', status: 'online', discoverySource: 'manual',
      confidence: CONFIDENCE.OBSERVED, isManual: true, mapX: 180, mapY: 100 });
    const sw = createDevice({ hostname: 'access-sw1', ipAddress: '192.168.1.2', macAddress: '00:11:22:33:44:66',
      category: 'Managed Switch', status: 'online', discoverySource: 'manual',
      confidence: CONFIDENCE.OBSERVED, isManual: true, mapX: 180, mapY: 220 });
    const ap = createDevice({ hostname: 'ap-office', ipAddress: '192.168.1.10', macAddress: '00:11:22:33:44:77',
      category: 'Access Point', status: 'online', discoverySource: 'manual',
      confidence: CONFIDENCE.OBSERVED, isManual: true, mapX: 80, mapY: 300 });
    const pc = createDevice({ hostname: 'tech-laptop', ipAddress: '192.168.1.50', macAddress: 'AA:BB:CC:DD:EE:01',
      category: 'Laptop', status: 'online', discoverySource: 'manual',
      confidence: CONFIDENCE.OBSERVED, isManual: true, mapX: 280, mapY: 300 });
    demo.devices.push(gw, sw, ap, pc);
    demo.relationships.push(
      createRelationship({ sourceDeviceId: gw.id, destDeviceId: sw.id, type: 'Physical Ethernet link',
        confidence: CONFIDENCE.VERIFIED, evidence: 'Direct uplink', discoverySource: 'manual' }),
      createRelationship({ sourceDeviceId: sw.id, destDeviceId: ap.id, type: 'Switch port connection',
        confidence: CONFIDENCE.OBSERVED, evidence: 'Port 5', discoverySource: 'manual' }),
      createRelationship({ sourceDeviceId: sw.id, destDeviceId: pc.id, type: 'Switch port connection',
        confidence: CONFIDENCE.INFERRED, evidence: 'Same subnet', discoverySource: 'manual' })
    );
    demo.alerts.push(createAlert({
      severity: 'info', title: 'Demo session loaded',
      message: 'Sample topology with evidence-based relationships.'
    }));
    await storage.saveSession(demo);
    currentSession = demo;
    await refreshSessionList();
    sessionSelect.value = demo.id;
  }
  renderView('overview');
}

boot().catch(err => {
  console.error(err);
  toast('Startup error: ' + err.message, 'error');
});
