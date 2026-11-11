#!/usr/bin/env python3
"""
NetScan Local Agent — real network discovery for field use.

Runs on Windows, macOS, or Linux on the same LAN.
Discovers neighbors via ARP/neighbor table, optional ping sweep, optional mDNS.
Outputs NetScan-compatible JSON or serves over HTTP for the phone.

  python3 netscan_agent.py
  python3 netscan_agent.py --serve
  python3 netscan_agent.py --cidr 192.168.1.0/24 --ping
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import platform
import re
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

VERSION = "0.3.0"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_id() -> str:
    return str(uuid.uuid4())


def normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(cleaned) != 12:
        return mac.upper()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def get_local_ipv4s() -> list:
    results = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                results.append((ip, ""))
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127.") and ip not in [r[0] for r in results]:
            results.append((ip, ""))
    except Exception:
        pass
    return results or [("192.168.1.100", "")]


def guess_cidr(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "192.168.1.0/24"


def read_neighbor_table() -> list:
    system = platform.system().lower()
    if system == "windows":
        entries = _arp_windows()
    elif system == "darwin":
        entries = _arp_macos()
    else:
        entries = _arp_linux()
    by_ip = {}
    for e in entries:
        ip = e.get("ip")
        if not ip or ip.startswith("224.") or ip.startswith("239."):
            continue
        mac = normalize_mac(e.get("mac", ""))
        if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", ""):
            continue
        by_ip[ip] = {
            "ipAddress": ip,
            "macAddress": mac,
            "status": e.get("status", "unknown"),
            "source": "arp-neighbor",
        }
    return list(by_ip.values())


def _arp_windows() -> list:
    out = []
    try:
        raw = subprocess.check_output(["arp", "-a"], text=True, errors="replace", timeout=15)
    except Exception:
        return out
    for line in raw.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})\s+(\w+)", line)
        if m:
            out.append({
                "ip": m.group(1),
                "mac": m.group(2).replace("-", ":"),
                "status": "online" if m.group(3).lower() == "dynamic" else "unknown",
            })
    return out


def _arp_macos() -> list:
    out = []
    try:
        raw = subprocess.check_output(["arp", "-an"], text=True, errors="replace", timeout=15)
    except Exception:
        return out
    for line in raw.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line)
        if m and "incomplete" not in line.lower():
            out.append({"ip": m.group(1), "mac": m.group(2), "status": "online"})
    return out


def _arp_linux() -> list:
    out = []
    try:
        raw = subprocess.check_output(["ip", "neigh", "show"], text=True, errors="replace", timeout=15)
        for line in raw.splitlines():
            m = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-fA-F:]+)\s+(\w+)", line)
            if m:
                st = m.group(3).upper()
                status = "online" if st in ("REACHABLE", "STALE", "DELAY", "PROBE") else "unknown"
                out.append({"ip": m.group(1), "mac": m.group(2), "status": status})
        if out:
            return out
    except Exception:
        pass
    try:
        raw = subprocess.check_output(["arp", "-an"], text=True, errors="replace", timeout=15)
        for line in raw.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line)
            if m and "incomplete" not in line.lower():
                out.append({"ip": m.group(1), "mac": m.group(2), "status": "online"})
    except Exception:
        pass
    return out


def ping_host(ip: str, timeout_ms: int = 500) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        return r.returncode == 0
    except Exception:
        return False


def ping_sweep(cidr: str, max_hosts: int = 254) -> list:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    hosts = list(net.hosts())[:max_hosts]
    alive = []
    workers = min(32, len(hosts))
    lock = threading.Lock()

    def worker(batch):
        for ip in batch:
            if ping_host(str(ip)):
                with lock:
                    alive.append(str(ip))

    chunks = [hosts[i::workers] for i in range(workers)]
    threads = [threading.Thread(target=worker, args=(ch,)) for ch in chunks if ch]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return alive


def mdns_discover(timeout: float = 3.0) -> list:
    try:
        from zeroconf import ServiceBrowser, Zeroconf, ServiceListener
    except ImportError:
        return []
    found = []

    class Listener(ServiceListener):
        def add_service(self, zc, type_, name):
            info = zc.get_service_info(type_, name, timeout=1000)
            if not info:
                return
            addrs = []
            for a in info.addresses or []:
                try:
                    addrs.append(socket.inet_ntoa(a))
                except Exception:
                    pass
            host = (info.server or name).rstrip(".")
            found.append({
                "hostname": host.split(".")[0] if host else name,
                "ipAddress": addrs[0] if addrs else "",
                "macAddress": "",
                "category": _guess_category_from_service(type_),
                "status": "online",
                "source": "mdns",
            })

        def remove_service(self, *a):
            pass

        def update_service(self, *a):
            pass

    zc = Zeroconf()
    types = [
        "_http._tcp.local.", "_https._tcp.local.", "_ssh._tcp.local.",
        "_printer._tcp.local.", "_ipp._tcp.local.", "_airplay._tcp.local.",
        "_googlecast._tcp.local.", "_smb._tcp.local.", "_device-info._tcp.local.",
    ]
    browsers = [ServiceBrowser(zc, t, Listener()) for t in types]
    time.sleep(timeout)
    zc.close()
    return found


def _guess_category_from_service(stype: str) -> str:
    s = stype.lower()
    if "printer" in s or "ipp" in s:
        return "Printer"
    if "airplay" in s or "googlecast" in s:
        return "Smart Television"
    if "smb" in s:
        return "NAS"
    if "ssh" in s:
        return "Server"
    return "Unknown Device"


OUI_HINTS = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi", "00:1A:11": "Google",
    "AC:DE:48": "Apple", "F0:18:98": "Apple", "3C:22:FB": "Apple",
    "F4:F5:E8": "Ubiquiti", "24:5A:4C": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    "B0:E4:35": "Cisco", "00:17:88": "Philips Hue", "00:0D:4B": "Roku",
}


def manufacturer_from_mac(mac: str) -> str:
    if not mac or len(mac) < 8:
        return ""
    return OUI_HINTS.get(mac.upper()[:8], "")


def guess_category(hostname: str, manufacturer: str) -> str:
    h = (hostname or "").lower()
    m = (manufacturer or "").lower()
    if any(x in h for x in ("router", "gateway", "gw-", "core-")):
        return "Router"
    if "switch" in h:
        return "Managed Switch"
    if any(x in h for x in ("ap-", "access", "unifi", "uap")):
        return "Access Point"
    if any(x in h for x in ("iphone", "android", "pixel", "galaxy")):
        return "Smartphone"
    if any(x in h for x in ("macbook", "laptop", "nb-")):
        return "Laptop"
    if any(x in h for x in ("nas", "synology", "qnap")):
        return "NAS"
    if "printer" in h:
        return "Printer"
    if "roku" in h or "appletv" in h:
        return "Smart Television"
    if "ubiquiti" in m or "cisco" in m:
        return "Network Appliance"
    return "Unknown Device"


def build_session(devices_raw: list, site_name: str = "Agent Scan") -> dict:
    devices = []
    for i, raw in enumerate(devices_raw):
        mac = normalize_mac(raw.get("macAddress") or raw.get("mac") or "")
        ip = raw.get("ipAddress") or raw.get("ip") or ""
        host = raw.get("hostname") or ""
        mfr = raw.get("manufacturer") or manufacturer_from_mac(mac)
        cat = raw.get("category") or guess_category(host, mfr)
        status = raw.get("status") or "online"
        source = raw.get("source") or "agent"
        n = max(len(devices_raw), 1)
        angle = (i / n) * 2 * math.pi - math.pi / 2
        radius = 120 + (i % 3) * 40
        map_x = 200 + radius * math.cos(angle)
        map_y = 220 + radius * math.sin(angle)
        devices.append({
            "id": new_id(),
            "hostname": host,
            "ipAddress": ip,
            "macAddress": mac,
            "manufacturer": mfr,
            "model": "",
            "category": cat,
            "os": "",
            "vlan": None,
            "subnet": "",
            "gateway": "",
            "connectionMethod": "",
            "status": status,
            "firstDiscovered": now_iso(),
            "lastObserved": now_iso(),
            "discoverySource": source,
            "confidence": "OBSERVED",
            "notes": "",
            "tags": ["agent-scan"],
            "mapX": round(map_x, 1),
            "mapY": round(map_y, 1),
            "isManual": False,
            "evidenceIds": [],
        })

    gw_id = None
    for d in devices:
        if d["ipAddress"].endswith(".1") or d["category"] == "Router":
            if d["category"] == "Unknown Device":
                d["category"] = "Router"
            gw_id = d["id"]
            break

    relationships = []
    if gw_id:
        for d in devices:
            if d["id"] == gw_id:
                continue
            relationships.append({
                "id": new_id(),
                "sourceDeviceId": gw_id,
                "destDeviceId": d["id"],
                "type": "Logical network membership",
                "confidence": "INFERRED",
                "evidence": "Same L2 neighborhood via ARP; physical path not verified",
                "discoverySource": "agent",
                "lastObserved": now_iso(),
                "notes": "",
            })

    return {
        "id": new_id(),
        "siteName": site_name,
        "clientName": "",
        "location": platform.node(),
        "notes": f"Scanned by NetScan agent v{VERSION} on {platform.system()}",
        "createdAt": now_iso(),
        "updatedAt": now_iso(),
        "devices": devices,
        "interfaces": [],
        "subnets": [],
        "vlans": [],
        "relationships": relationships,
        "observations": [],
        "discoveryRuns": [{
            "id": new_id(),
            "startedAt": now_iso(),
            "finishedAt": now_iso(),
            "adapters": [{"adapterId": "agent-arp", "status": "success", "resultCount": len(devices)}],
            "observationCount": len(devices),
            "deviceCountDelta": len(devices),
            "errors": [],
            "backend": "agent",
            "trigger": "manual",
        }],
        "diagnosticRuns": [],
        "trafficSamples": [],
        "alerts": [{
            "id": new_id(),
            "severity": "info",
            "title": "Agent scan imported",
            "message": f"{len(devices)} devices from local agent",
            "deviceId": None,
            "acknowledged": False,
            "resolved": False,
            "notes": "",
            "createdAt": now_iso(),
            "updatedAt": now_iso(),
        }],
        "notesList": [],
        "schemaVersion": 1,
    }


def run_scan(cidr: str | None = None, do_ping: bool = False, do_mdns: bool = False) -> dict:
    print("[agent] Reading neighbor / ARP table…")
    neighbors = read_neighbor_table()
    print(f"[agent] ARP/neighbor entries: {len(neighbors)}")
    by_ip = {n["ipAddress"]: n for n in neighbors}

    if do_ping:
        if not cidr:
            local = get_local_ipv4s()
            cidr = guess_cidr(local[0][0]) if local else "192.168.1.0/24"
        print(f"[agent] Ping sweep {cidr}…")
        alive = ping_sweep(cidr)
        print(f"[agent] Ping responses: {len(alive)}")
        for ip in alive:
            if ip not in by_ip:
                by_ip[ip] = {"ipAddress": ip, "macAddress": "", "status": "online", "source": "icmp"}

    if do_mdns:
        print("[agent] mDNS browse (3s)…")
        for m in mdns_discover(3.0):
            ip = m.get("ipAddress") or ""
            if ip and ip in by_ip:
                if m.get("hostname") and not by_ip[ip].get("hostname"):
                    by_ip[ip]["hostname"] = m["hostname"]
                if m.get("category"):
                    by_ip[ip]["category"] = m["category"]
            elif ip or m.get("hostname"):
                key = ip or m.get("hostname")
                by_ip[key] = m

    for ip, entry in list(by_ip.items()):
        if entry.get("hostname"):
            continue
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            entry["hostname"] = host.split(".")[0]
        except Exception:
            pass

    devices = list(by_ip.values())
    site = f"Scan {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    return build_session(devices, site_name=site)


_latest_session = None
_scan_lock = threading.Lock()


class AgentHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[http] {args[0]}")

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        global _latest_session
        path = urlparse(self.path).path
        if path in ("/", "/status"):
            body = json.dumps({
                "service": "netscan-agent",
                "version": VERSION,
                "platform": platform.system(),
                "host": platform.node(),
                "devices": len((_latest_session or {}).get("devices") or []),
                "scannedAt": (_latest_session or {}).get("updatedAt"),
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path in ("/session", "/export", "/scan"):
            if path == "/scan":
                with _scan_lock:
                    _latest_session = run_scan(
                        cidr=getattr(self.server, "cidr", None),
                        do_ping=getattr(self.server, "do_ping", False),
                        do_mdns=getattr(self.server, "do_mdns", False),
                    )
            session = _latest_session or {"error": "No scan yet", "devices": []}
            body = json.dumps(session).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self._cors()
        self.end_headers()


def serve(port: int, cidr, do_ping: bool, do_mdns: bool):
    global _latest_session
    print("[agent] Initial scan…")
    _latest_session = run_scan(cidr=cidr, do_ping=do_ping, do_mdns=do_mdns)
    out = "netscan-agent-export.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(_latest_session, f, indent=2)
    print(f"[agent] Wrote {out} ({len(_latest_session.get('devices', []))} devices)")
    server = HTTPServer(("0.0.0.0", port), AgentHandler)
    server.cidr = cidr
    server.do_ping = do_ping
    server.do_mdns = do_mdns
    print(f"[agent] Serving on http://0.0.0.0:{port}")
    print("        Phone: NetScan → Reports → Pull from agent")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[agent] Stopped")


def main():
    p = argparse.ArgumentParser(description="NetScan local discovery agent")
    p.add_argument("--cidr", help="Subnet for ping sweep")
    p.add_argument("--ping", action="store_true", help="Ping-sweep subnet")
    p.add_argument("--mdns", action="store_true", help="mDNS browse")
    p.add_argument("--serve", action="store_true", help="HTTP server for phone")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("-o", "--output", default="netscan-agent-export.json")
    args = p.parse_args()
    print(f"NetScan Agent v{VERSION} · {platform.system()} · {platform.node()}")
    if args.serve:
        serve(args.port, args.cidr, args.ping, args.mdns)
        return
    session = run_scan(cidr=args.cidr, do_ping=args.ping, do_mdns=args.mdns)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(session, f, indent=2)
    n = len(session.get("devices", []))
    print(f"[agent] Wrote {args.output} with {n} devices")
    for d in session.get("devices", [])[:20]:
        print(f"  {d.get('ipAddress', ''):15}  {d.get('macAddress', ''):17}  {d.get('hostname') or d.get('category')}")


if __name__ == "__main__":
    main()
