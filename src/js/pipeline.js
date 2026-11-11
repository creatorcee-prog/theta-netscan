/**
 * Discovery Result Pipeline
 */

import {
  createDevice, createObservation, createAlert, createRelationship,
  normalizeMac, isValidIPv4, uuid, nowISO, CONFIDENCE
} from './models.js';
import { createDiscoveryRun } from './adapters/base.js';

export function processDiscoveryResults(session, adapterResults, options = {}) {
  const startedAt = options.startedAt || nowISO();
  const observations = [];
  const allErrors = [];
  const adapterSummaries = [];

  for (const result of adapterResults) {
    const meta = result.meta || {};
    const adapterId = meta.adapterId || 'unknown';
    observations.push(...(result.observations || []));
    if (result.errors?.length) allErrors.push(...result.errors.map(e => `[${adapterId}] ${e}`));
    adapterSummaries.push({
      adapterId,
      status: result.errors?.length && result.observations?.length
        ? 'partial'
        : result.errors?.length
          ? 'failed'
          : meta.skipped
            ? 'unavailable'
            : 'success',
      resultCount: (result.observations || []).length,
      error: result.errors?.[0] || null
    });
  }

  session.devices = session.devices || [];
  session.observations = session.observations || [];
  session.relationships = session.relationships || [];
  session.alerts = session.alerts || [];
  session.discoveryRuns = session.discoveryRuns || [];

  const beforeCount = session.devices.length;
  const newDeviceIds = [];
  const updatedDeviceIds = [];

  for (const raw of observations) {
    const obs = normalizeObservation(raw);
    if (!obs) continue;

    const observation = createObservation({
      type: obs.type || 'generic',
      source: obs.source || obs.adapterId || 'adapter',
      data: obs.data || obs,
      adapterId: obs.adapterId || null,
      timestamp: obs.timestamp || nowISO()
    });
    session.observations.push(observation);

    const match = findMatchingDevice(session.devices, obs);
    if (match) {
      mergeObservationIntoDevice(match, obs, observation.id);
      updatedDeviceIds.push(match.id);
      observation.deviceId = match.id;
    } else if (obs.ipAddress || obs.macAddress || obs.hostname) {
      const device = createDeviceFromObservation(obs, observation.id);
      session.devices.push(device);
      newDeviceIds.push(device.id);
      observation.deviceId = device.id;

      session.alerts.push(createAlert({
        severity: 'info',
        title: 'New device discovered',
        message: `${device.hostname || device.ipAddress || device.macAddress || 'Device'} via ${obs.source || obs.adapterId || 'discovery'}`,
        deviceId: device.id
      }));
    }

    if (obs.relationship && (obs.relationship.sourceMac || obs.relationship?.sourceIp)) {
      tryIngestRelationship(session, obs);
    }
  }

  const run = createDiscoveryRun({
    startedAt,
    finishedAt: nowISO(),
    adapters: adapterSummaries,
    observationCount: observations.length,
    deviceCountDelta: session.devices.length - beforeCount,
    errors: allErrors,
    backend: options.backend || 'browser',
    trigger: options.trigger || 'manual'
  });
  session.discoveryRuns.unshift(run);
  if (session.discoveryRuns.length > 50) session.discoveryRuns.length = 50;
  session.updatedAt = nowISO();

  return {
    session,
    run,
    summary: {
      observations: observations.length,
      newDevices: newDeviceIds.length,
      updatedDevices: [...new Set(updatedDeviceIds)].length,
      errors: allErrors.length,
      adaptersRun: adapterSummaries.length
    }
  };
}

function normalizeObservation(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const obs = { ...raw };
  if (obs.macAddress) obs.macAddress = normalizeMac(obs.macAddress);
  obs.timestamp = obs.timestamp || nowISO();
  return obs;
}

function findMatchingDevice(devices, obs) {
  if (obs.macAddress) {
    const byMac = devices.find(d => d.macAddress && d.macAddress === obs.macAddress);
    if (byMac) return byMac;
  }
  if (obs.ipAddress) {
    const byIp = devices.find(d => d.ipAddress && d.ipAddress === obs.ipAddress);
    if (byIp) return byIp;
  }
  if (obs.hostname) {
    const host = obs.hostname.toLowerCase();
    const byHost = devices.find(d => d.hostname && d.hostname.toLowerCase() === host);
    if (byHost) return byHost;
  }
  return null;
}

function mergeObservationIntoDevice(device, obs, observationId) {
  if (obs.hostname && !device.hostname) device.hostname = obs.hostname;
  if (obs.ipAddress && !device.ipAddress) device.ipAddress = obs.ipAddress;
  if (obs.macAddress && !device.macAddress) device.macAddress = obs.macAddress;
  if (obs.manufacturer && !device.manufacturer) device.manufacturer = obs.manufacturer;
  if (obs.model && !device.model) device.model = obs.model;
  if (obs.category && device.category === 'Unknown Device') device.category = obs.category;
  if (obs.os && !device.os) device.os = obs.os;
  if (obs.status) device.status = obs.status;
  device.lastObserved = nowISO();
  if (observationId) {
    device.evidenceIds = device.evidenceIds || [];
    if (!device.evidenceIds.includes(observationId)) device.evidenceIds.push(observationId);
  }
  if (obs.confidence === CONFIDENCE.VERIFIED) device.confidence = CONFIDENCE.VERIFIED;
  else if (obs.confidence === CONFIDENCE.OBSERVED && device.confidence !== CONFIDENCE.VERIFIED) {
    device.confidence = CONFIDENCE.OBSERVED;
  }
  if (obs.source) device.discoverySource = obs.source;
  device.isManual = false;
}

function createDeviceFromObservation(obs, observationId) {
  return createDevice({
    hostname: obs.hostname || '',
    ipAddress: obs.ipAddress || '',
    macAddress: obs.macAddress || '',
    manufacturer: obs.manufacturer || '',
    model: obs.model || '',
    category: obs.category || 'Unknown Device',
    os: obs.os || '',
    status: obs.status || 'unknown',
    vlan: obs.vlan ?? null,
    subnet: obs.subnet || '',
    gateway: obs.gateway || '',
    discoverySource: obs.source || obs.adapterId || 'discovery',
    confidence: obs.confidence || CONFIDENCE.OBSERVED,
    isManual: false,
    evidenceIds: observationId ? [observationId] : []
  });
}

function tryIngestRelationship(session, obs) {
  const rel = obs.relationship;
  if (!rel) return;
  const src = session.devices.find(d =>
    (rel.sourceMac && d.macAddress === normalizeMac(rel.sourceMac)) ||
    (rel.sourceIp && d.ipAddress === rel.sourceIp)
  );
  const dst = session.devices.find(d =>
    (rel.destMac && d.macAddress === normalizeMac(rel.destMac)) ||
    (rel.destIp && d.ipAddress === rel.destIp)
  );
  if (!src || !dst || src.id === dst.id) return;
  const exists = session.relationships.some(r =>
    (r.sourceDeviceId === src.id && r.destDeviceId === dst.id) ||
    (r.sourceDeviceId === dst.id && r.destDeviceId === src.id)
  );
  if (exists) return;
  session.relationships.push(createRelationship({
    sourceDeviceId: src.id,
    destDeviceId: dst.id,
    type: rel.type || 'Unknown relationship',
    confidence: rel.confidence || CONFIDENCE.OBSERVED,
    evidence: rel.evidence || `From ${obs.source || 'discovery'}`,
    discoverySource: obs.source || obs.adapterId || 'discovery'
  }));
}
