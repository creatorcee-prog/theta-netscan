/**
 * NetScan — Normalized Data Model
 * All entities use stable UUIDs. Observations are separate from current summaries.
 */

export function uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export function nowISO() {
  return new Date().toISOString();
}

/** Confidence levels for relationships and observations */
export const CONFIDENCE = {
  VERIFIED: 'VERIFIED',
  OBSERVED: 'OBSERVED',
  INFERRED: 'INFERRED',
  UNKNOWN: 'UNKNOWN'
};

/** Device categories */
export const DEVICE_CATEGORIES = [
  'Router', 'Firewall', 'Managed Switch', 'Unmanaged Switch',
  'Access Point', 'Wireless Controller', 'Modem',
  'Desktop', 'Laptop', 'Server', 'NAS',
  'Printer', 'Camera', 'VoIP Phone',
  'Smartphone', 'Tablet', 'Smart Television',
  'IoT Device', 'Network Appliance', 'Unknown Device'
];

/** Relationship types */
export const RELATIONSHIP_TYPES = [
  'Physical Ethernet link',
  'Wireless association',
  'Router-to-router connection',
  'Switch uplink',
  'Switch port connection',
  'Logical network membership',
  'Unknown relationship'
];

/** Create a new empty NetworkSession */
export function createSession(opts = {}) {
  const id = opts.id || uuid();
  return {
    id,
    siteName: opts.siteName || 'New Site',
    clientName: opts.clientName || '',
    location: opts.location || '',
    notes: opts.notes || '',
    createdAt: opts.createdAt || nowISO(),
    updatedAt: nowISO(),
    devices: opts.devices || [],
    interfaces: opts.interfaces || [],
    subnets: opts.subnets || [],
    vlans: opts.vlans || [],
    relationships: opts.relationships || [],
    observations: opts.observations || [],
    discoveryRuns: opts.discoveryRuns || [],
    diagnosticRuns: opts.diagnosticRuns || [],
    trafficSamples: opts.trafficSamples || [],
    alerts: opts.alerts || [],
    notesList: opts.notesList || [],
    schemaVersion: 1
  };
}

/** Create a Device record */
export function createDevice(opts = {}) {
  return {
    id: opts.id || uuid(),
    hostname: opts.hostname || '',
    ipAddress: opts.ipAddress || '',
    macAddress: opts.macAddress || '',
    manufacturer: opts.manufacturer || '',
    model: opts.model || '',
    category: opts.category || 'Unknown Device',
    os: opts.os || '',
    vlan: opts.vlan || null,
    subnet: opts.subnet || '',
    gateway: opts.gateway || '',
    connectionMethod: opts.connectionMethod || '',
    status: opts.status || 'unknown',
    firstDiscovered: opts.firstDiscovered || nowISO(),
    lastObserved: opts.lastObserved || nowISO(),
    discoverySource: opts.discoverySource || 'manual',
    confidence: opts.confidence || CONFIDENCE.UNKNOWN,
    notes: opts.notes || '',
    tags: opts.tags || [],
    mapX: opts.mapX ?? null,
    mapY: opts.mapY ?? null,
    isManual: opts.isManual ?? true,
    evidenceIds: opts.evidenceIds || []
  };
}

/** Create a Relationship record */
export function createRelationship(opts = {}) {
  return {
    id: opts.id || uuid(),
    sourceDeviceId: opts.sourceDeviceId,
    destDeviceId: opts.destDeviceId,
    type: opts.type || 'Unknown relationship',
    confidence: opts.confidence || CONFIDENCE.UNKNOWN,
    evidence: opts.evidence || '',
    discoverySource: opts.discoverySource || 'manual',
    lastObserved: opts.lastObserved || nowISO(),
    notes: opts.notes || ''
  };
}

/** Create an Observation (immutable evidence) */
export function createObservation(opts = {}) {
  return {
    id: opts.id || uuid(),
    deviceId: opts.deviceId || null,
    type: opts.type || 'generic',
    source: opts.source || '',
    data: opts.data || {},
    timestamp: opts.timestamp || nowISO(),
    adapterId: opts.adapterId || null
  };
}

/** Create an Alert */
export function createAlert(opts = {}) {
  return {
    id: opts.id || uuid(),
    severity: opts.severity || 'info',
    title: opts.title || '',
    message: opts.message || '',
    deviceId: opts.deviceId || null,
    relatedEvidence: opts.relatedEvidence || null,
    acknowledged: false,
    resolved: false,
    notes: '',
    createdAt: nowISO(),
    updatedAt: nowISO()
  };
}

/** Create a Subnet */
export function createSubnet(opts = {}) {
  return {
    id: opts.id || uuid(),
    network: opts.network || '',
    cidr: opts.cidr || 24,
    gateway: opts.gateway || '',
    vlanId: opts.vlanId || null,
    dhcpRange: opts.dhcpRange || '',
    notes: opts.notes || ''
  };
}

/** Create a VLAN */
export function createVlan(opts = {}) {
  return {
    id: opts.id || uuid(),
    vlanId: opts.vlanId ?? 1,
    name: opts.name || '',
    network: opts.network || '',
    notes: opts.notes || ''
  };
}

/** Normalize MAC to AA:BB:CC:DD:EE:FF */
export function normalizeMac(mac) {
  if (!mac) return '';
  const cleaned = mac.replace(/[^0-9A-Fa-f]/g, '').toUpperCase();
  if (cleaned.length !== 12) return mac;
  return cleaned.match(/.{1,2}/g).join(':');
}

/** Basic IPv4 validation */
export function isValidIPv4(ip) {
  if (!ip) return false;
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => {
    const n = Number(p);
    return Number.isInteger(n) && n >= 0 && n <= 255 && String(n) === p.trim();
  });
}

/** Basic MAC validation */
export function isValidMac(mac) {
  if (!mac) return false;
  const cleaned = mac.replace(/[^0-9A-Fa-f]/g, '');
  return cleaned.length === 12;
}
