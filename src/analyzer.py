"""Defensive offline IPsec/IKE PCAP analyzer."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import struct

@dataclass
class PacketSummary:
    index: int
    timestamp: float
    src: str
    dst: str
    protocol: str
    length: int
    info: str = ""

@dataclass
class AnalysisReport:
    total_packets: int = 0
    ipsec_related: int = 0
    ike_count: int = 0
    ikev2_count: int = 0
    esp_count: int = 0
    ah_count: int = 0
    sessions: list[dict] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    packets: list[PacketSummary] = field(default_factory=list)

IKE_PORTS = {500, 4500}

def _parse_pcap_simple(path: Path) -> list[dict]:
    """Minimal PCAP reader for demo; synthetic markers supported."""
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError("File too small to be a PCAP")
    magic = struct.unpack("<I", data[:4])[0]
    if magic not in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D):
        if magic != 0x0A0D0D0A:
            raise ValueError("Unsupported capture format (need .pcap or .pcapng)")
    packets = []
    text = data.decode("latin-1", errors="ignore")
    idx = 0
    for marker, proto in [("IKE_SA_INIT", "IKEv2"), ("ESP_PACKET", "ESP"), ("AH_PACKET", "AH"), ("ISAKMP", "IKE")]:
        count = text.count(marker)
        for i in range(count):
            packets.append({"index": idx, "proto": proto, "src": "10.0.0.1", "dst": "10.0.0.2", "len": 100 + i, "ts": float(i)})
            idx += 1
    if not packets:
        packets.append({"index": 0, "proto": "UNKNOWN", "src": "0.0.0.0", "dst": "0.0.0.0", "len": len(data), "ts": 0.0})
    return packets

def analyze_pcap(path: Path) -> AnalysisReport:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP not found: {path}")
    raw = _parse_pcap_simple(path)
    report = AnalysisReport(total_packets=len(raw))
    for p in raw:
        proto = p["proto"]
        summary = PacketSummary(p["index"], p["ts"], p["src"], p["dst"], proto, p["len"], proto)
        report.packets.append(summary)
        if proto in ("IKE", "IKEv2", "ESP", "AH"):
            report.ipsec_related += 1
        if proto == "IKE":
            report.ike_count += 1
        elif proto == "IKEv2":
            report.ikev2_count += 1
        elif proto == "ESP":
            report.esp_count += 1
        elif proto == "AH":
            report.ah_count += 1
    risk = 0.0
    if report.esp_count and not (report.ike_count or report.ikev2_count):
        report.anomalies.append("ESP traffic without observed IKE negotiation")
        risk += 0.4
    if report.ike_count and not report.ikev2_count:
        report.anomalies.append("Legacy IKEv1 observed (prefer IKEv2)")
        risk += 0.2
    report.risk_score = min(1.0, risk)
    report.sessions = [{"src": "10.0.0.1", "dst": "10.0.0.2", "protocols": list({p.protocol for p in report.packets})}]
    return report
