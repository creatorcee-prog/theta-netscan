/**
 * Adapter Registry
 */

import { DiscoveryAdapter, ADAPTER_STATUS } from './base.js';
import { EXECUTION_BACKENDS } from '../capabilities.js';
import { nowISO, CONFIDENCE } from '../models.js';

class ManualAdapter extends DiscoveryAdapter {
  constructor() {
    super({
      id: 'manual',
      name: 'Manual Registration',
      protocol: 'User input',
      backend: EXECUTION_BACKENDS.BROWSER,
      available: true,
      description: 'Add devices by hand. Always available.',
      supportedOps: ['create', 'edit']
    });
  }
  async _execute() {
    return { observations: [], errors: [], meta: { note: 'Use Devices → Add for manual entry' } };
  }
}

class CsvImportAdapter extends DiscoveryAdapter {
  constructor() {
    super({
      id: 'csv-import',
      name: 'CSV Import',
      protocol: 'File',
      backend: EXECUTION_BACKENDS.BROWSER,
      available: true,
      description: 'Import device lists from router or scanner exports.',
      supportedOps: ['import']
    });
  }
  async _execute() {
    return { observations: [], errors: [], meta: { note: 'Use Devices → Import CSV' } };
  }
}

class ArpAdapter extends DiscoveryAdapter {
  constructor() {
    super({
      id: 'arp-neighbor',
      name: 'ARP / Neighbor Discovery',
      protocol: 'ARP',
      backend: EXECUTION_BACKENDS.BROWSER,
      available: false,
      reasonUnavailable: 'Browsers cannot read ARP or neighbor tables. Requires Windows/Linux agent or native iOS companion.',
      requiredPermissions: ['raw-socket', 'local-network'],
      supportedOps: ['mac-ip-mapping'],
      supportedDeviceTypes: ['*']
    });
  }
}

class IcmpAdapter extends DiscoveryAdapter {
  constructor() {
    super({
      id: 'icmp-ping',
      name: 'ICMP Ping',
      protocol: 'ICMP',
      backend: EXECUTION_BACKENDS.BROWSER,
      available: false,
      reasonUnavailable: 'ICMP is not available from JavaScript.',
      requiredPermissions: ['raw-socket'],
      supportedOps: ['reachability', 'latency']
    });
  }
}

class MdnsAdapter extends DiscoveryAdapter {
  constructor() {
    super({
      id: 'mdns',
      name: 'mDNS / Bonjour',
      protocol: 'mDNS',
      backend: EXECUTION_BACKENDS.BROWSER,
      available: false,
      reasonUnavailable: 'Safari does not expose unrestricted mDNS to web pages. Requires native iOS companion.',
      requiredPermissions: ['local-network'],
      supportedOps: ['service-discovery', 'hostname'],
      supportedDeviceTypes: ['Printer', 'NAS', 'Smart Television', 'Desktop', 'Laptop', 'IoT Device']
    });
  }
}

class SsdpAdapter extends DiscoveryAdapter {
  constructor() {
    super({
      id: 'ssdp',
      name: 'SSDP / UPnP',
      protocol: 'SSDP',
      backend: EXECUTION_BACKENDS.BROWSER,
      available: false,
      reasonUnavailable: 'Multicast discovery is restricted in browsers.',
      requiredPermissions: ['multicast'],
      supportedOps: ['device-discovery']
    });
  }
}

class SnmpAdapter extends DiscoveryAdapter {
  constructor() {
    super({
      id: 'snmp',
      name: 'SNMP Polling',
      protocol: 'SNMP',
      backend: EXECUTION_BACKENDS.BROWSER,
      available: false,
      reasonUnavailable: 'SNMP requires UDP and credentials; not available in browser for arbitrary local targets.',
      requiredPermissions: ['udp', 'credentials'],
      supportedOps: ['sysDescr', 'interfaces', 'counters', 'bridge-table'],
      supportedDeviceTypes: ['Router', 'Managed Switch', 'Access Point', 'Firewall', 'Server']
    });
  }
}

class LldpAdapter extends DiscoveryAdapter {
  constructor() {
    super({
      id: 'lldp-cdp',
      name: 'LLDP / CDP',
      protocol: 'LLDP/CDP',
      backend: EXECUTION_BACKENDS.BROWSER,
      available: false,
      reasonUnavailable: 'Requires packet capture or switch/agent access.',
      requiredPermissions: ['packet-capture', 'snmp'],
      supportedOps: ['topology', 'port-mapping']
    });
  }
}

class DemoSampleAdapter extends DiscoveryAdapter {
  constructor() {
    super({
      id: 'demo-sample',
      name: 'Demo Sample Discovery',
      protocol: 'Synthetic',
      backend: EXECUTION_BACKENDS.BROWSER,
      available: true,
      description: 'Injects sample observations so you can exercise the pipeline. Not real network data.',
      supportedOps: ['demo']
    });
  }

  async _execute(context = {}) {
    const suffix = Date.now().toString(36).slice(-4);
    const observations = [
      {
        adapterId: this.id,
        source: 'demo-sample',
        type: 'synthetic',
        hostname: `demo-host-${suffix}`,
        ipAddress: `192.168.1.${100 + (Date.now() % 50)}`,
        macAddress: `02:00:00:00:${(Date.now() % 256).toString(16).padStart(2, '0')}:${(Date.now() % 99).toString(16).padStart(2, '0')}`,
        category: 'Laptop',
        status: 'online',
        confidence: CONFIDENCE.OBSERVED,
        manufacturer: 'Demo',
        timestamp: nowISO()
      }
    ];
    if (context.skipDemo) return { observations: [], errors: [], meta: { skipped: true } };
    return { observations, errors: [], meta: { demo: true } };
  }
}

const adapters = [
  new ManualAdapter(),
  new CsvImportAdapter(),
  new DemoSampleAdapter(),
  new ArpAdapter(),
  new IcmpAdapter(),
  new MdnsAdapter(),
  new SsdpAdapter(),
  new SnmpAdapter(),
  new LldpAdapter()
];

export function getAllAdapters() {
  return adapters;
}

export function getAdapter(id) {
  return adapters.find(a => a.id === id) || null;
}

export function getAvailableAdapters() {
  return adapters.filter(a => a.available);
}

export function getUnavailableAdapters() {
  return adapters.filter(a => !a.available);
}

export function getAdapterCapabilities() {
  return adapters.map(a => a.getCapability());
}

export async function runAdapters(adapterIds, context = {}) {
  const ids = adapterIds || adapters.filter(a => a.available).map(a => a.id);
  const results = [];
  for (const id of ids) {
    const adapter = getAdapter(id);
    if (!adapter) {
      results.push({
        observations: [],
        errors: [`Unknown adapter: ${id}`],
        meta: { adapterId: id }
      });
      continue;
    }
    results.push(await adapter.run(context));
  }
  return results;
}
