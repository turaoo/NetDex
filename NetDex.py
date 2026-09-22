#!/usr/bin/env python3
"""
NetDex - Arthur Lima
==================================================
A lightweight network scanner for learning host discovery, port scanning,
and service/banner detection concepts. Built for use on Kali Linux.

INTENDED USE: Only scan networks and hosts you own or have explicit
written authorization to test. Unauthorized scanning of systems you do
not control may be illegal in your jurisdiction.

Usage examples:
    sudo python3 netdex.py discover 192.168.1.0/24
    python3 netdex.py scan 192.168.1.10 -p 1-1024
    python3 netdex.py scan 192.168.1.10 -p 22,80,443 --banners
"""

import argparse
import ipaddress
import socket
import sys
import threading
import queue
import time
from datetime import datetime

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
}

BANNER = r"""
 _   _      _   ____             
| \ | | ___| |_|  _ \  _____  __
|  \| |/ _ \ __| | | |/ _ \ \/ /
| |\  |  __/ |_| |_| |  __/>  < 
|_| \_|\___|\__|____/ \___/_/\_\

  NetDex :: Gotta catch 'em all ports
"""


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------

def arp_discover(cidr, timeout=2):
    """Discover live hosts on a local subnet using ARP requests (requires scapy + root)."""
    if not SCAPY_AVAILABLE:
        log("scapy not available, falling back to ICMP/TCP ping sweep.")
        return ping_sweep(cidr)

    log(f"Starting ARP discovery on {cidr} (requires root)...")
    try:
        arp = ARP(pdst=cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=timeout, verbose=0)[0]
        hosts = []
        for sent, received in result:
            hosts.append((received.psrc, received.hwsrc))
        return hosts
    except PermissionError:
        log("Permission denied. Run with sudo for ARP discovery.")
        return []
    except Exception as e:
        log(f"ARP discovery failed ({e}), falling back to ping sweep.")
        return ping_sweep(cidr)


def ping_sweep(cidr, timeout=0.5, max_threads=100):
    """Fallback host discovery using a TCP connect probe on common ports (no root required)."""
    net = ipaddress.ip_network(cidr, strict=False)
    q = queue.Queue()
    alive = []
    lock = threading.Lock()

    for ip in net.hosts():
        q.put(str(ip))

    def worker():
        while not q.empty():
            try:
                ip = q.get_nowait()
            except queue.Empty:
                return
            if _is_host_alive(ip, timeout):
                with lock:
                    alive.append((ip, None))
            q.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return alive


def _is_host_alive(ip, timeout):
    for port in (80, 443, 22, 445, 139):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except (socket.error, OSError):
            continue
    return False


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------

def parse_ports(port_spec):
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)


def grab_banner(ip, port, timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in (80, 8080, 8443, 443):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(256)
            return data.decode(errors="ignore").strip().split("\n")[0]
    except Exception:
        return None


def scan_port(ip, port, timeout, results, lock, grab=False):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                service = COMMON_PORTS.get(port, "unknown")
                banner = grab_banner(ip, port) if grab else None
                with lock:
                    results.append((port, service, banner))
    except (socket.error, OSError):
        pass


def scan_host(ip, ports, timeout=1.0, max_threads=200, grab=False):
    q = queue.Queue()
    results = []
    lock = threading.Lock()

    for p in ports:
        q.put(p)

    def worker():
        while not q.empty():
            try:
                port = q.get_nowait()
            except queue.Empty:
                return
            scan_port(ip, port, timeout, results, lock, grab)
            q.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(min(max_threads, len(ports)) or 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return sorted(results, key=lambda r: r[0])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_discover(args):
    print(BANNER)
    start = time.time()
    if args.arp:
        hosts = arp_discover(args.target)
    else:
        log(f"Starting ping sweep on {args.target}...")
        hosts = ping_sweep(args.target)

    elapsed = time.time() - start
    print()
    if not hosts:
        log("No live hosts found.")
    else:
        log(f"Found {len(hosts)} live host(s):")
        for ip, mac in hosts:
            if mac:
                print(f"  {ip:<16} {mac}")
            else:
                print(f"  {ip}")
    log(f"Discovery completed in {elapsed:.2f}s")


def cmd_scan(args):
    print(BANNER)
    ports = parse_ports(args.ports)
    log(f"Scanning {args.target} — {len(ports)} port(s)...")
    start = time.time()

    try:
        socket.gethostbyname(args.target)
    except socket.gaierror:
        log(f"Could not resolve target: {args.target}")
        sys.exit(1)

    results = scan_host(args.target, ports, timeout=args.timeout,
                         max_threads=args.threads, grab=args.banners)
    elapsed = time.time() - start

    print()
    if not results:
        log("No open ports found.")
    else:
        log(f"Open ports on {args.target}:")
        print(f"  {'PORT':<8}{'SERVICE':<16}{'BANNER'}")
        print(f"  {'-'*8}{'-'*16}{'-'*30}")
        for port, service, banner in results:
            banner_str = banner if banner else ""
            print(f"  {port:<8}{service:<16}{banner_str}")
    log(f"Scan completed in {elapsed:.2f}s ({len(ports)} ports, {len(results)} open)")


def main():
    parser = argparse.ArgumentParser(
        prog="netdex",
        description="NetDex - Educational network scanner for authorized testing only."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    d = sub.add_parser("discover", help="Discover live hosts on a subnet (CIDR notation)")
    d.add_argument("target", help="Target subnet, e.g. 192.168.1.0/24")
    d.add_argument("--arp", action="store_true", help="Use ARP-based discovery (requires root + scapy)")
    d.set_defaults(func=cmd_discover)

    s = sub.add_parser("scan", help="Scan ports on a single host")
    s.add_argument("target", help="Target IP or hostname")
    s.add_argument("-p", "--ports", default="1-1024", help="Ports, e.g. 22,80,443 or 1-1024")
    s.add_argument("-t", "--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    s.add_argument("--threads", type=int, default=200, help="Max concurrent threads")
    s.add_argument("--banners", action="store_true", help="Attempt banner grabbing on open ports")
    s.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
