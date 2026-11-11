# NetScan Local Agent

Real network discovery for field use. Runs on a laptop/desktop on the same LAN, then feeds the NetScan PWA on your iPhone.

## Why an agent?

Safari cannot read ARP tables, send ICMP, or scan the local network. The agent does that on a real OS and exports results the phone already knows how to import.

## Quick start

```bash
cd agent
python3 netscan_agent.py
```

Writes `netscan-agent-export.json`.

**On the iPhone:** NetScan → Reports → Import Session → choose that file.

### Live pull over Wi‑Fi

```bash
python3 netscan_agent.py --serve
```

Note the computer’s LAN IP. On the phone (same Wi‑Fi):

NetScan → Reports → **Pull from agent** → `http://<pc-ip>:8765`

### Options

| Flag | Meaning |
|------|---------|
| `--ping` | Ping-sweep the /24 |
| `--cidr 10.0.0.0/24` | Subnet for ping sweep |
| `--mdns` | mDNS browse (`pip install zeroconf`) |
| `--serve` | HTTP API for the phone |
| `--port 8765` | HTTP port |

## What it discovers

- ARP / neighbor table (IP ↔ MAC)
- Optional ping sweep
- Optional mDNS hostnames
- Reverse DNS, OUI vendor hints
- Map positions + inferred gateway links (confidence INFERRED)

Physical switch-port / LLDP still needs SNMP or switch export.
