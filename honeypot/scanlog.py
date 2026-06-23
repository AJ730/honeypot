"""Passive port-scan logger.

A raw-socket sniffer that captures inbound TCP SYN packets (connection attempts)
to ports the honeypot does NOT serve, and records them as port scans. The
honeypot container runs with host networking + CAP_NET_RAW so this sees the
VM's real interfaces. If the raw socket can't be opened (no capability, not
Linux), it silently does nothing — port-scan logging is best-effort and must
never break the honeypot.
"""
from __future__ import annotations

import socket
import struct
import threading
import time


def parse_syn(pkt: bytes):
    """Return (src_ip, dest_port) if pkt is a TCP SYN (without ACK), else None.

    Expects a link-layer frame starting with a 14-byte Ethernet header.
    """
    if len(pkt) < 14 + 20:
        return None
    if struct.unpack("!H", pkt[12:14])[0] != 0x0800:  # not IPv4
        return None
    ip = pkt[14:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 6:  # not TCP
        return None
    src = socket.inet_ntoa(ip[12:16])
    tcp = ip[ihl:]
    if len(tcp) < 14:
        return None
    dport = struct.unpack("!H", tcp[2:4])[0]
    flags = tcp[13]
    if (flags & 0x02) and not (flags & 0x10):  # SYN set, ACK clear
        return src, dport
    return None


def _ignored(src: str) -> bool:
    # Skip loopback and docker bridge chatter — we care about external probes.
    return (src.startswith("127.") or src.startswith("172.17.")
            or src.startswith("172.18.") or src == "0.0.0.0")


def run_sniffer(on_scan, served_ports, stop) -> None:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.settimeout(1.0)
    except Exception:
        return  # no permission / not Linux — port-scan logging disabled
    seen: dict = {}  # (src, port) -> last seen ts, for dedupe
    while not stop():
        try:
            pkt = s.recv(65535)
        except socket.timeout:
            continue
        except Exception:
            continue
        parsed = parse_syn(pkt)
        if not parsed:
            continue
        src, port = parsed
        if port in served_ports or _ignored(src):
            continue
        now = time.time()
        key = (src, port)
        if seen.get(key, 0) > now - 5:  # collapse retransmits within 5s
            continue
        seen[key] = now
        if len(seen) > 8192:  # bound memory
            seen.clear()
        try:
            on_scan(src, port)
        except Exception:
            pass


def start_sniffer(store, served_ports=(11434,)) -> threading.Event:
    """Start the sniffer in a daemon thread. Returns a stop Event."""
    stop_event = threading.Event()
    served = set(served_ports)

    def on_scan(src, port):
        store.log_scan(src, port)

    t = threading.Thread(
        target=run_sniffer,
        args=(on_scan, served, stop_event.is_set),
        daemon=True,
    )
    t.start()
    return stop_event
