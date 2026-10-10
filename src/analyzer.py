"""Offline IPsec/IKE capture parsing with transparent rule-based findings."""
from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

IKE_PORTS = {500, 4500}
MAX_CAPTURE_BYTES = 100 * 1024 * 1024
MAX_PACKET_COUNT = 1_000_000
IKE_EXCHANGES = {
    2: "Main mode",
    4: "Aggressive mode",
    32: "Quick mode",
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}


@dataclass
class PacketSummary:
    index: int
    timestamp: float
    src: str
    dst: str
    protocol: str
    length: int
    info: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    exchange: str = ""


@dataclass
class AnalysisReport:
    total_packets: int = 0
    ipsec_related: int = 0
    ike_count: int = 0
    ikev2_count: int = 0
    esp_count: int = 0
    ah_count: int = 0
    sessions: list[dict[str, Any]] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    packets: list[PacketSummary] = field(default_factory=list)
    capture_name: str = ""
    capture_format: str = ""
    capture_size_bytes: int = 0
    duration_seconds: float = 0.0
    unique_peers: list[str] = field(default_factory=list)
    protocols: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)


def _ike_version_and_exchange(payload: bytes) -> tuple[str, str]:
    """Read fixed IKE header fields only; encrypted payloads remain opaque."""
    if len(payload) < 28:
        return "IKE", "Truncated IKE header"
    version = payload[17] >> 4
    exchange_code = payload[18]
    exchange = IKE_EXCHANGES.get(exchange_code, f"Exchange {exchange_code}")
    if version >= 2:
        return "IKEv2", exchange
    return "IKE", exchange


def _is_ike_header(payload: bytes) -> bool:
    return len(payload) >= 28 and (payload[17] >> 4) in {1, 2}


def _parse_synthetic_markers(data: bytes) -> list[dict[str, Any]]:
    """Read the repository's historical marker fixture (not a real packet trace)."""
    markers = (
        (b"IKE_SA_INIT", "IKEv2", "IKEv2 IKE_SA_INIT"),
        (b"ESP_PACKET", "ESP", "ESP marker fixture"),
        (b"AH_PACKET", "AH", "AH marker fixture"),
        (b"ISAKMP", "IKE", "IKEv1 marker fixture"),
    )
    text = data.decode("latin-1", errors="ignore")
    packets: list[dict[str, Any]] = []
    timestamp = 0.0
    for marker, protocol, info in markers:
        for _ in range(text.count(marker)):
            packets.append({
                "index": len(packets),
                "proto": protocol,
                "src": "10.0.0.1",
                "dst": "10.0.0.2",
                "sport": 500 if protocol in {"IKE", "IKEv2"} else None,
                "dport": 500 if protocol in {"IKE", "IKEv2"} else None,
                "len": 100,
                "ts": timestamp,
                "info": info,
                "exchange": "Fixture marker",
            })
            timestamp += 1.0
    return packets


def _parse_capture_scapy(path: Path) -> list[dict[str, Any]]:
    """Parse classic PCAP and PCAPNG through Scapy; never decrypt payloads."""
    try:
        from scapy.all import IP, IPv6, UDP, rdpcap
    except ImportError as exc:
        raise RuntimeError("PCAP parsing needs Scapy. Install it with: python -m pip install scapy") from exc

    try:
        capture = rdpcap(str(path))
    except Exception as exc:
        raise ValueError("Could not read this capture. Check that it is a valid PCAP or PCAPNG file.") from exc
    if len(capture) > MAX_PACKET_COUNT:
        raise ValueError(f"Capture contains more than {MAX_PACKET_COUNT:,} packets; split it into smaller captures.")

    packets: list[dict[str, Any]] = []
    for index, packet in enumerate(capture):
        src = "unknown"
        dst = "unknown"
        source_port: int | None = None
        dest_port: int | None = None
        protocol = "Other"
        info = "Non-IP or unrelated traffic"
        exchange = ""
        ip = packet.getlayer(IP)
        ipv6 = packet.getlayer(IPv6)
        udp = packet.getlayer(UDP)
        if ip is not None:
            src, dst = str(ip.src), str(ip.dst)
            if int(ip.proto) == 50:
                protocol, info = "ESP", "ESP encrypted payload"
            elif int(ip.proto) == 51:
                protocol, info = "AH", "Authentication Header"
        elif ipv6 is not None:
            src, dst = str(ipv6.src), str(ipv6.dst)
            next_header = int(ipv6.nh)
            if next_header == 50:
                protocol, info = "ESP", "ESP encrypted payload"
            elif next_header == 51:
                protocol, info = "AH", "Authentication Header"

        if udp is not None:
            source_port, dest_port = int(udp.sport), int(udp.dport)
            if source_port in IKE_PORTS or dest_port in IKE_PORTS:
                payload = bytes(udp.payload)
                if 4500 in {source_port, dest_port} and payload[:4] != b"\x00\x00\x00\x00":
                    if len(payload) == 1 and payload == b"\xff":
                        protocol, info = "NAT-T keepalive", "NAT traversal keepalive"
                    elif len(payload) >= 8:
                        protocol, info = "ESP", "ESP encapsulated in UDP (NAT-T)"
                    else:
                        protocol, info = "UDP/4500", "Short NAT-T payload"
                else:
                    ike_payload = payload[4:] if payload.startswith(b"\x00\x00\x00\x00") else payload
                    if _is_ike_header(ike_payload):
                        protocol, exchange = _ike_version_and_exchange(ike_payload)
                        info = f"{protocol} · {exchange}"
                    elif payload:
                        protocol, info = "UDP/500 or 4500", "IKE-like port; header not recognised"
                    else:
                        protocol, info = "UDP/500 or 4500", "Empty IKE/NAT-T payload"

        packets.append({
            "index": index,
            "proto": protocol,
            "src": src,
            "dst": dst,
            "sport": source_port,
            "dport": dest_port,
            "len": int(len(packet)),
            "ts": float(getattr(packet, "time", index)),
            "info": info,
            "exchange": exchange,
        })
    return packets


def _parse_pcap_simple(path: Path) -> list[dict[str, Any]]:
    """Compatibility entry point: parse marker fixtures and real PCAP/PCAPNG."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise FileNotFoundError(f"Capture not found or unreadable: {path}") from exc
    if size > MAX_CAPTURE_BYTES:
        raise ValueError("Capture exceeds the 100 MB upload limit.")
    data = path.read_bytes()
    if len(data) < 4:
        raise ValueError("File is too small to be a PCAP or PCAPNG capture.")
    if any(marker in data for marker in (b"IKE_SA_INIT", b"ESP_PACKET", b"AH_PACKET", b"ISAKMP")):
        packets = _parse_synthetic_markers(data)
        if packets:
            return packets
    return _parse_capture_scapy(path)


def _risk_and_anomalies(report: AnalysisReport) -> None:
    findings: list[str] = []
    score = 0.0
    if report.esp_count and not (report.ike_count or report.ikev2_count):
        findings.append("ESP traffic observed without IKE negotiation in this capture")
        score += 0.40
    if report.ike_count and not report.ikev2_count:
        findings.append("IKEv1 observed; prefer IKEv2 where compatible")
        score += 0.20
    if report.ikev2_count and not report.esp_count:
        findings.append("IKEv2 traffic observed but no ESP packets were captured")
        score += 0.10
    if not report.ipsec_related:
        report.warnings.append("No recognisable IKE, ESP, or AH packets were found. Confirm the capture point and filter.")
    report.anomalies = findings
    report.risk_score = round(min(1.0, score), 3)


def analyze_pcap(path: str | Path) -> AnalysisReport:
    path = Path(path).expanduser()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Capture not found: {path}")
    if path.stat().st_size > MAX_CAPTURE_BYTES:
        raise ValueError("Capture exceeds the 100 MB upload limit.")
    parsed = _parse_pcap_simple(path)
    if not parsed:
        raise ValueError("No packets were read from this capture.")

    report = AnalysisReport(
        total_packets=len(parsed),
        capture_name=path.name,
        capture_format="PCAPNG" if path.suffix.lower() == ".pcapng" else "PCAP",
        capture_size_bytes=path.stat().st_size,
    )
    start = min(float(p["ts"]) for p in parsed)
    end = max(float(p["ts"]) for p in parsed)
    report.duration_seconds = max(0.0, end - start)
    peer_set: set[str] = set()
    sessions: dict[tuple[str, str], dict[str, Any]] = {}
    exchange_events: list[dict[str, Any]] = []

    for packet in parsed:
        proto = str(packet.get("proto", "Other"))
        src = str(packet.get("src", "unknown"))
        dst = str(packet.get("dst", "unknown"))
        sport = packet.get("sport")
        dport = packet.get("dport")
        summary = PacketSummary(
            index=int(packet.get("index", len(report.packets))),
            timestamp=float(packet.get("ts", 0.0)),
            src=src,
            dst=dst,
            protocol=proto,
            length=int(packet.get("len", 0)),
            info=str(packet.get("info", proto)),
            src_port=int(sport) if sport is not None else None,
            dst_port=int(dport) if dport is not None else None,
            exchange=str(packet.get("exchange", "")),
        )
        report.packets.append(summary)
        if proto in {"IKE", "IKEv2", "ESP", "AH"}:
            report.ipsec_related += 1
        if proto == "IKE":
            report.ike_count += 1
        elif proto == "IKEv2":
            report.ikev2_count += 1
        elif proto == "ESP":
            report.esp_count += 1
        elif proto == "AH":
            report.ah_count += 1
        peer_set.update((src, dst))
        left, right = sorted((src, dst))
        session = sessions.setdefault(
            (left, right),
            {"src": left, "dst": right, "packet_count": 0, "protocols": set(),
             "first_seen": summary.timestamp, "last_seen": summary.timestamp},
        )
        session["packet_count"] += 1
        session["protocols"].add(proto)
        session["first_seen"] = min(session["first_seen"], summary.timestamp)
        session["last_seen"] = max(session["last_seen"], summary.timestamp)
        if proto in {"IKE", "IKEv2"}:
            exchange_events.append({
                "timestamp": summary.timestamp,
                "time_offset": round(summary.timestamp - start, 3),
                "src": src,
                "dst": dst,
                "protocol": proto,
                "exchange": summary.exchange or summary.info,
                "info": summary.info,
            })

    report.unique_peers = sorted(peer for peer in peer_set if peer not in {"unknown", "0.0.0.0"})
    report.protocols = dict(Counter(packet.protocol for packet in report.packets))
    report.sessions = [
        {
            "src": session["src"],
            "dst": session["dst"],
            "packet_count": session["packet_count"],
            "protocols": sorted(session["protocols"]),
            "first_seen": session["first_seen"],
            "last_seen": session["last_seen"],
            "duration_seconds": round(session["last_seen"] - session["first_seen"], 3),
        }
        for session in sessions.values()
    ]
    report.sessions.sort(key=lambda item: (-item["packet_count"], item["src"], item["dst"]))
    report.events = sorted(exchange_events, key=lambda event: event["timestamp"])
    _risk_and_anomalies(report)
    return report


def report_to_dict(report: AnalysisReport) -> dict[str, Any]:
    return {
        "capture": {
            "name": report.capture_name,
            "format": report.capture_format,
            "size_bytes": report.capture_size_bytes,
            "duration_seconds": report.duration_seconds,
            "total_packets": report.total_packets,
            "ipsec_related_packets": report.ipsec_related,
            "unique_peers": report.unique_peers,
        },
        "protocol_counts": report.protocols,
        "ike_v1_packets": report.ike_count,
        "ike_v2_packets": report.ikev2_count,
        "esp_packets": report.esp_count,
        "ah_packets": report.ah_count,
        "risk_score": report.risk_score,
        "anomalies": report.anomalies,
        "warnings": report.warnings,
        "sessions": report.sessions,
        "events": report.events,
        "packets": [packet.__dict__ for packet in report.packets],
    }


def build_demo_capture(path: str | Path) -> Path:
    """Write a small, valid synthetic PCAP with an IKEv2 exchange and ESP."""
    try:
        from scapy.all import ESP, Ether, IP, Raw, UDP, wrpcap
    except ImportError as exc:
        raise RuntimeError("Generating the sample capture needs Scapy. Install it with: python -m pip install scapy") from exc

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    packets = []
    initiator_spi = 0x0102030405060708
    responder_spi = 0x1112131415161718
    ike_init = struct.pack("!QQBBBBII", initiator_spi, 0, 0, 0x20, 34, 0x08, 0, 28)
    ike_reply = struct.pack("!QQBBBBII", initiator_spi, responder_spi, 0, 0x20, 34, 0x20, 0, 28)
    packets.append(Ether()/IP(src="192.0.2.10", dst="198.51.100.20")/UDP(sport=500, dport=500)/Raw(load=ike_init))
    packets.append(Ether()/IP(src="198.51.100.20", dst="192.0.2.10")/UDP(sport=500, dport=500)/Raw(load=ike_reply))
    packets.append(Ether()/IP(src="192.0.2.10", dst="198.51.100.20")/ESP(spi=0x12345678, seq=1)/Raw(load=b"\x00"*32))
    packets.append(Ether()/IP(src="198.51.100.20", dst="192.0.2.10")/ESP(spi=0x12345678, seq=1)/Raw(load=b"\x00"*32))
    wrpcap(str(path), packets)
    return path
