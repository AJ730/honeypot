import socket
import struct

from honeypot.scanlog import parse_syn
from honeypot.logging_store import LoggingStore


def make_frame(src_ip, dport, flags):
    eth = b"\x00" * 6 + b"\x00" * 6 + struct.pack("!H", 0x0800)
    ip = bytes([0x45, 0, 0, 40]) + b"\x00\x00" + b"\x00\x00" + bytes([64, 6]) \
        + b"\x00\x00" + socket.inet_aton(src_ip) + socket.inet_aton("10.0.0.1")
    tcp = struct.pack("!HH", 40000, dport) + b"\x00" * 4 + b"\x00" * 4 \
        + bytes([0x50, flags]) + b"\x00" * 6
    return eth + ip + tcp


def test_parse_syn_detects_connection_attempt():
    assert parse_syn(make_frame("8.8.8.8", 22, 0x02)) == ("8.8.8.8", 22)


def test_parse_syn_ignores_syn_ack():
    assert parse_syn(make_frame("8.8.8.8", 22, 0x12)) is None  # SYN+ACK = reply


def test_parse_syn_ignores_non_tcp_and_short():
    assert parse_syn(b"\x00" * 10) is None


def test_store_scans_roundtrip(tmp_path):
    s = LoggingStore(str(tmp_path / "store.db"), str(tmp_path / "events.jsonl"))
    s.log_scan("1.2.3.4", 22)
    s.log_scan("1.2.3.4", 8080)
    rows = s.recent_scans(10)
    assert len(rows) == 2
    assert rows[0]["dest_port"] == 8080      # newest first
    assert rows[0]["source_ip"] == "1.2.3.4"
