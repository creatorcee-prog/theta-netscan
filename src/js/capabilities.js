/**
 * Discovery capability detection for current execution environment.
 * Browser (Safari on iPhone) has severe restrictions.
 */

export const EXECUTION_BACKENDS = {
  BROWSER: 'browser',
  IOS_NATIVE: 'ios-native',
  WINDOWS_AGENT: 'windows-agent',
  LINUX_AGENT: 'linux-agent'
};

export const BROWSER_CAPABILITIES = [
  {
    id: 'manual-registration',
    name: 'Manual Device Registration',
    protocol: 'User input',
    backend: EXECUTION_BACKENDS.BROWSER,
    available: true,
    description: 'Add devices by hand with hostname, IP, MAC, category, notes.',
    requiredPermissions: [],
    supportedOps: ['create', 'edit', 'tag']
  },
  {
    id: 'json-import',
    name: 'JSON Session Import / Export',
    protocol: 'File',
    backend: EXECUTION_BACKENDS.BROWSER,
    available: true,
    description: 'Full session backup and restore. Device inventory, relationships, alerts.',
    requiredPermissions: [],
    supportedOps: ['import', 'export']
  },
  {
    id: 'csv-import',
    name: 'CSV Device Import / Export',
    protocol: 'File',
    backend: EXECUTION_BACKENDS.BROWSER,
    available: true,
    description: 'Import device lists from router exports or spreadsheets. Validated with error reporting.',
    requiredPermissions: [],
    supportedOps: ['import', 'export']
  },
  {
    id: 'mdns-browser',
    name: 'mDNS / Bonjour Discovery',
    protocol: 'mDNS',
    backend: EXECUTION_BACKENDS.BROWSER,
    available: false,
    reason: 'Safari and Chromium do not expose unrestricted mDNS to web pages. Requires native iOS companion or agent.',
    requiredPermissions: ['local-network'],
    supportedOps: ['service-discovery', 'hostname']
  },
  {
    id: 'arp-neighbor',
    name: 'ARP / Neighbor Table',
    protocol: 'ARP',
    backend: EXECUTION_BACKENDS.BROWSER,
    available: false,
    reason: 'Browsers cannot send or receive raw ARP packets or read the system neighbor table.',
    requiredPermissions: ['raw-socket', 'local-network'],
    supportedOps: ['mac-ip-mapping']
  },
  {
    id: 'icmp-ping',
    name: 'ICMP Ping / Reachability',
    protocol: 'ICMP',
    backend: EXECUTION_BACKENDS.BROWSER,
    available: false,
    reason: 'ICMP is not available from JavaScript. Some limited HTTP-based reachability checks are possible for public hosts only.',
    requiredPermissions: ['raw-socket'],
    supportedOps: ['reachability', 'latency']
  },
  {
    id: 'snmp',
    name: 'SNMP Polling (v1/v2c/v3)',
    protocol: 'SNMP',
    backend: EXECUTION_BACKENDS.BROWSER,
    available: false,
    reason: 'SNMP requires UDP sockets and community/credentials that browsers cannot use for arbitrary local targets.',
    requiredPermissions: ['udp', 'credentials'],
    supportedOps: ['sysDescr', 'interfaces', 'counters', 'bridge-table']
  },
  {
    id: 'lldp-cdp',
    name: 'LLDP / CDP Neighbor Discovery',
    protocol: 'LLDP/CDP',
    backend: EXECUTION_BACKENDS.BROWSER,
    available: false,
    reason: 'Requires packet capture or switch/agent access. Not possible in browser.',
    requiredPermissions: ['packet-capture', 'snmp'],
    supportedOps: ['topology', 'port-mapping']
  },
  {
    id: 'ssdp-upnp',
    name: 'SSDP / UPnP Discovery',
    protocol: 'SSDP',
    backend: EXECUTION_BACKENDS.BROWSER,
    available: false,
    reason: 'Multicast discovery is restricted in browsers.',
    requiredPermissions: ['multicast'],
    supportedOps: ['device-discovery', 'service-advertisement']
  },
  {
    id: 'tcp-service',
    name: 'TCP Service Probes',
    protocol: 'TCP',
    backend: EXECUTION_BACKENDS.BROWSER,
    available: 'partial',
    reason: 'Browser can attempt fetch()/WebSocket to same-origin or CORS-enabled targets only. Arbitrary local TCP ports are blocked.',
    requiredPermissions: [],
    supportedOps: ['http-check', 'limited']
  },
  {
    id: 'dns-lookup',
    name: 'DNS Resolution',
    protocol: 'DNS',
    backend: EXECUTION_BACKENDS.BROWSER,
    available: 'partial',
    reason: 'Can resolve hostnames via the browser resolver for public names. Cannot choose DNS server or perform arbitrary record queries against local resolvers.',
    requiredPermissions: [],
    supportedOps: ['A/AAAA via browser']
  },
  {
    id: 'traffic-counters',
    name: 'Interface Traffic Counters',
    protocol: 'SNMP / Agent',
    backend: EXECUTION_BACKENDS.BROWSER,
    available: false,
    reason: 'Requires SNMP or native interface statistics. Not available in browser.',
    requiredPermissions: ['snmp', 'agent'],
    supportedOps: ['bytes-in-out', 'errors', 'utilization']
  },
  {
    id: 'packet-capture',
    name: 'Packet Capture',
    protocol: 'pcap',
    backend: EXECUTION_BACKENDS.BROWSER,
    available: false,
    reason: 'Raw packet capture is impossible from a web page.',
    requiredPermissions: ['pcap', 'root-or-capability'],
    supportedOps: ['capture', 'analysis']
  }
];

export function detectBackend() {
  return {
    id: EXECUTION_BACKENDS.BROWSER,
    name: 'Browser (Safari / PWA)',
    description: 'Running inside a mobile or desktop browser. Local network discovery is severely limited by browser security policies.',
    capabilities: BROWSER_CAPABILITIES
  };
}

export function getAvailableAdapters() {
  return BROWSER_CAPABILITIES.filter(c => c.available === true);
}

export function getUnavailableAdapters() {
  return BROWSER_CAPABILITIES.filter(c => c.available === false || c.available === 'partial');
}
