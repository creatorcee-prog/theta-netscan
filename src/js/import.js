/**
 * CSV / JSON import with validation.
 * Never silently discard data. Report malformed records.
 */

import { createDevice, createRelationship, createSession, normalizeMac, isValidIPv4, isValidMac, uuid, nowISO, CONFIDENCE } from './models.js';

export function parseCSV(text) {
  const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n').filter(l => l.trim());
  if (lines.length < 1) return { headers: [], rows: [], errors: ['Empty CSV'] };

  const parseLine = (line) => {
    const result = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (inQuotes) {
        if (ch === '"') {
          if (line[i + 1] === '"') { current += '"'; i++; }
          else inQuotes = false;
        } else current += ch;
      } else {
        if (ch === '"') inQuotes = true;
        else if (ch === ',') { result.push(current.trim()); current = ''; }
        else current += ch;
      }
    }
    result.push(current.trim());
    return result;
  };

  const headers = parseLine(lines[0]).map(h => h.toLowerCase().replace(/\s+/g, ''));
  const rows = [];
  const errors = [];

  for (let i = 1; i < lines.length; i++) {
    const values = parseLine(lines[i]);
    if (values.every(v => !v)) continue;
    const obj = {};
    headers.forEach((h, idx) => { obj[h] = values[idx] ?? ''; });
    obj._line = i + 1;
    rows.push(obj);
  }
  return { headers, rows, errors };
}

const COLUMN_MAP = {
  hostname: ['hostname', 'host', 'name', 'devicename'],
  ipAddress: ['ipaddress', 'ip', 'ipv4', 'address'],
  macAddress: ['macaddress', 'mac', 'hwaddr', 'hardware'],
  manufacturer: ['manufacturer', 'vendor', 'oui', 'make'],
  model: ['model', 'product'],
  category: ['category', 'type', 'devicetype', 'role'],
  os: ['os', 'operatingsystem', 'platform'],
  status: ['status', 'state'],
  vlan: ['vlan', 'vlanid'],
  subnet: ['subnet', 'network'],
  gateway: ['gateway', 'gw', 'defaultgateway'],
  notes: ['notes', 'comment', 'description'],
  tags: ['tags', 'label', 'labels']
};

function mapRow(row) {
  const mapped = {};
  for (const [field, aliases] of Object.entries(COLUMN_MAP)) {
    for (const a of aliases) {
      if (row[a] !== undefined && row[a] !== '') {
        mapped[field] = row[a];
        break;
      }
    }
  }
  return mapped;
}

export function importDevicesFromCSV(csvText, existingSession) {
  const { rows, errors: parseErrors } = parseCSV(csvText);
  const devices = [];
  const warnings = [];
  const errors = [...parseErrors];
  const seenMac = new Set();
  const seenIp = new Set();

  for (const row of rows) {
    const m = mapRow(row);
    const line = row._line;

    if (!m.ipAddress && !m.macAddress && !m.hostname) {
      errors.push(`Line ${line}: skipped — no hostname, IP, or MAC`);
      continue;
    }

    if (m.ipAddress && !isValidIPv4(m.ipAddress)) {
      warnings.push(`Line ${line}: invalid IPv4 "${m.ipAddress}" — kept as-is`);
    }
    if (m.macAddress) {
      const norm = normalizeMac(m.macAddress);
      if (!isValidMac(m.macAddress)) {
        warnings.push(`Line ${line}: MAC "${m.macAddress}" looks invalid`);
      }
      m.macAddress = norm || m.macAddress;
      if (seenMac.has(m.macAddress)) {
        warnings.push(`Line ${line}: duplicate MAC ${m.macAddress}`);
      }
      seenMac.add(m.macAddress);
    }
    if (m.ipAddress) {
      if (seenIp.has(m.ipAddress)) {
        warnings.push(`Line ${line}: duplicate IP ${m.ipAddress}`);
      }
      seenIp.add(m.ipAddress);
    }

    if (existingSession) {
      if (m.macAddress && existingSession.devices.some(d => d.macAddress === m.macAddress)) {
        warnings.push(`Line ${line}: MAC ${m.macAddress} already exists in session — will create new record`);
      }
    }

    const device = createDevice({
      hostname: m.hostname || '',
      ipAddress: m.ipAddress || '',
      macAddress: m.macAddress || '',
      manufacturer: m.manufacturer || '',
      model: m.model || '',
      category: m.category || 'Unknown Device',
      os: m.os || '',
      status: (m.status || 'unknown').toLowerCase(),
      vlan: m.vlan ? Number(m.vlan) || m.vlan : null,
      subnet: m.subnet || '',
      gateway: m.gateway || '',
      notes: m.notes || '',
      tags: m.tags ? m.tags.split(/[;|]/).map(t => t.trim()).filter(Boolean) : [],
      discoverySource: 'csv-import',
      confidence: CONFIDENCE.OBSERVED,
      isManual: false
    });
    devices.push(device);
  }

  return {
    devices,
    report: {
      totalRows: rows.length,
      imported: devices.length,
      errors,
      warnings
    }
  };
}

export function importSessionJSON(jsonText) {
  let data;
  try {
    data = JSON.parse(jsonText);
  } catch (e) {
    return { session: null, report: { errors: ['Invalid JSON: ' + e.message], warnings: [] } };
  }

  const errors = [];
  const warnings = [];

  if (!data || typeof data !== 'object') {
    return { session: null, report: { errors: ['Root must be an object'], warnings: [] } };
  }

  if (Array.isArray(data)) {
    const session = createSession({ siteName: 'Imported Devices' });
    data.forEach((d, i) => {
      if (!d || typeof d !== 'object') {
        warnings.push(`Item ${i}: not an object — skipped`);
        return;
      }
      session.devices.push(createDevice({
        ...d,
        id: d.id || uuid(),
        discoverySource: d.discoverySource || 'json-import',
        isManual: false
      }));
    });
    return { session, report: { imported: session.devices.length, errors, warnings } };
  }

  if (!data.id) {
    data.id = uuid();
    warnings.push('Missing session id — generated new one');
  }
  if (!data.siteName) {
    data.siteName = 'Imported Session';
    warnings.push('Missing siteName — using default');
  }

  const arrays = ['devices', 'interfaces', 'subnets', 'vlans', 'relationships',
    'observations', 'discoveryRuns', 'diagnosticRuns', 'trafficSamples', 'alerts', 'notesList'];
  for (const key of arrays) {
    if (!Array.isArray(data[key])) {
      if (data[key] != null) warnings.push(`"${key}" was not an array — reset`);
      data[key] = [];
    }
  }

  data.devices = data.devices.map((d, i) => {
    if (!d.id) { d.id = uuid(); warnings.push(`Device ${i}: missing id`); }
    if (d.macAddress) d.macAddress = normalizeMac(d.macAddress);
    return createDevice(d);
  });

  data.relationships = data.relationships.map((r, i) => {
    if (!r.sourceDeviceId || !r.destDeviceId) {
      warnings.push(`Relationship ${i}: missing source or dest — kept for review`);
    }
    return createRelationship(r);
  });

  data.schemaVersion = data.schemaVersion || 1;
  data.updatedAt = nowISO();

  return {
    session: data,
    report: {
      devices: data.devices.length,
      relationships: data.relationships.length,
      errors,
      warnings
    }
  };
}
