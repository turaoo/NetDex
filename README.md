# NetDex

A lightweight, educational network reconnaissance tool for Kali Linux. Built with pure Python (standard library), with optional `scapy` support for ARP-based host discovery.

**Only scan networks and hosts you own or are explicitly authorized to test.**

## Requirements

Kali Linux ships with Python 3 and scapy by default, so no setup should be needed. If scapy is missing:

```bash
pip install scapy --break-system-packages
```

## Usage

### Discover live hosts on a subnet

Fast, no-root ping sweep (TCP probe on common ports):
```bash
python3 netdex.py discover 192.168.1.0/24
```

ARP-based discovery (more accurate on your local LAN, requires root):
```bash
sudo python3 netdex.py discover 192.168.1.0/24 --arp
```

### Scan ports on a host

Default scan (ports 1-1024):
```bash
python3 netdex.py scan 192.168.1.10
```

Specific ports, with banner grabbing:
```bash
python3 netdex.py scan 192.168.1.10 -p 22,80,443,8080 --banners
```

Custom range, timeout, and thread count:
```bash
python3 netdex.py scan 192.168.1.10 -p 1-65535 -t 0.5 --threads 500
```

## How it works

- **Host discovery**: either ARP requests (via scapy, needs root/local subnet) or a TCP connect probe against a handful of commonly-open ports as a no-root fallback.
- **Port scanning**: threaded TCP connect scan (`connect()` to each port) — this is the same fundamental technique nmap's `-sT` scan uses, no raw sockets required.
- **Service/banner detection**: matches well-known ports against a small lookup table, and optionally grabs the first line a service sends back (or issues a basic `HEAD /` for HTTP ports).

## Notes for further learning

This is intentionally simple so the code is easy to read end-to-end. Ideas to extend it yourself:
- Add a SYN scan mode using raw sockets/scapy (needs root)
- Add UDP scanning
- Add OS fingerprinting via TTL/window-size heuristics
- Add output formats (JSON, CSV)
- Add a `--timing` profile system like nmap's `-T0` through `-T5`
