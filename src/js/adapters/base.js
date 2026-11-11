/**
 * Discovery Adapter Interface
 *
 * Every discovery method is an independent adapter that:
 * - Declares its capabilities and requirements
 * - Reports availability for the current backend
 * - Emits normalized observations into the pipeline
 * - Never invents data; failures are explicit
 */

import { uuid, nowISO } from '../models.js';

export const ADAPTER_STATUS = {
  IDLE: 'idle',
  RUNNING: 'running',
  SUCCESS: 'success',
  PARTIAL: 'partial',
  FAILED: 'failed',
  UNAVAILABLE: 'unavailable'
};

export class DiscoveryAdapter {
  constructor(config = {}) {
    this.id = config.id || 'unknown';
    this.name = config.name || 'Unknown Adapter';
    this.protocol = config.protocol || '';
    this.backend = config.backend || 'browser';
    this.requiredPermissions = config.requiredPermissions || [];
    this.supportedDeviceTypes = config.supportedDeviceTypes || [];
    this.supportedOps = config.supportedOps || [];
    this.description = config.description || '';
    this.reasonUnavailable = config.reasonUnavailable || '';
    this.status = ADAPTER_STATUS.IDLE;
    this.lastRunAt = null;
    this.lastError = null;
    this.lastResultCount = 0;
    this.available = config.available ?? false;
  }

  getCapability() {
    return {
      id: this.id,
      name: this.name,
      protocol: this.protocol,
      backend: this.backend,
      available: this.available,
      description: this.available ? this.description : (this.reasonUnavailable || this.description),
      requiredPermissions: this.requiredPermissions,
      supportedOps: this.supportedOps,
      status: this.status,
      lastRunAt: this.lastRunAt,
      lastError: this.lastError,
      lastResultCount: this.lastResultCount
    };
  }

  async checkAvailability() {
    return this.available;
  }

  async run(context = {}) {
    const available = await this.checkAvailability();
    if (!available) {
      this.status = ADAPTER_STATUS.UNAVAILABLE;
      this.lastError = this.reasonUnavailable || 'Adapter not available on this backend';
      return {
        observations: [],
        errors: [this.lastError],
        meta: { adapterId: this.id, skipped: true }
      };
    }

    this.status = ADAPTER_STATUS.RUNNING;
    this.lastError = null;
    const started = nowISO();

    try {
      const result = await this._execute(context);
      const observations = result.observations || [];
      const errors = result.errors || [];

      this.lastRunAt = nowISO();
      this.lastResultCount = observations.length;
      this.status = errors.length && observations.length
        ? ADAPTER_STATUS.PARTIAL
        : errors.length
          ? ADAPTER_STATUS.FAILED
          : ADAPTER_STATUS.SUCCESS;
      if (errors.length) this.lastError = errors[0];

      return {
        observations,
        errors,
        meta: {
          adapterId: this.id,
          started,
          finished: this.lastRunAt,
          ...(result.meta || {})
        }
      };
    } catch (err) {
      this.status = ADAPTER_STATUS.FAILED;
      this.lastError = err.message || String(err);
      this.lastRunAt = nowISO();
      this.lastResultCount = 0;
      return {
        observations: [],
        errors: [this.lastError],
        meta: { adapterId: this.id, started, finished: this.lastRunAt, exception: true }
      };
    }
  }

  async _execute(_context) {
    throw new Error(`Adapter ${this.id} does not implement _execute()`);
  }
}

export function createDiscoveryRun(opts = {}) {
  return {
    id: opts.id || uuid(),
    startedAt: opts.startedAt || nowISO(),
    finishedAt: opts.finishedAt || null,
    adapters: opts.adapters || [],
    observationCount: opts.observationCount || 0,
    deviceCountDelta: opts.deviceCountDelta || 0,
    errors: opts.errors || [],
    backend: opts.backend || 'browser',
    trigger: opts.trigger || 'manual'
  };
}
