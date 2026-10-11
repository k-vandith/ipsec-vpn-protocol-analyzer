"""Regression tests for real capture parsing and IPsec heuristics."""
from __future__ import annotations

from pathlib import Path
import struct

import pytest

from src.analyzer import AnalysisReport, analyze_pcap, build_demo_capture, report_to_dict, _ike_version_and_exchange
from src.ipsec_features import handshake_anomaly_score


def test_real_pcap_decodes_ikev2_and_esp(tmp_path: Path) -> None:
    capture = build_demo_capture(tmp_path / "sample.pcap")
    report = analyze_pcap(capture)

    assert report.total_packets == 4
    assert report.ipsec_related == 4
    assert report.ikev2_count == 2
    assert report.esp_count == 2
    assert report.ike_count == 0
    assert len(report.unique_peers) == 2
    assert len(report.events) == 2
    assert report.sessions[0]["packet_count"] == 4
    assert report.duration_seconds >= 0
    assert report.risk_score == 0.0


def test_json_summary_keeps_capture_metadata(tmp_path: Path) -> None:
    capture = build_demo_capture(tmp_path / "review.pcap")
    payload = report_to_dict(analyze_pcap(capture))

    assert payload["capture"]["name"] == "review.pcap"
    assert payload["protocol_counts"]["IKEv2"] == 2
    assert payload["esp_packets"] == 2
    assert "packets" in payload


def test_capture_missing_and_invalid_files_fail_clearly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        analyze_pcap(tmp_path / "missing.pcap")
    invalid = tmp_path / "not-a-capture.pcap"
    invalid.write_bytes(b"this is not a packet capture")
    with pytest.raises(ValueError, match="PCAP"):
        analyze_pcap(invalid)


def test_marker_fixture_compatibility(tmp_path: Path) -> None:
    # Preserve support for the original repository's legacy synthetic marker fixture.
    capture = tmp_path / "legacy-demo.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20 + b"IKE_SA_INIT ESP_PACKET ISAKMP AH_PACKET")
    report = analyze_pcap(capture)
    assert report.total_packets >= 4
    assert report.ikev2_count >= 1
    assert report.esp_count >= 1
    assert report.ah_count >= 1
    assert report.ike_count >= 1


def test_large_capture_is_rejected_before_parsing(tmp_path: Path) -> None:
    capture = tmp_path / "large.pcap"
    with capture.open("wb") as handle:
        handle.truncate(100 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="100 MB"):
        analyze_pcap(capture)


def test_heuristic_indicator_has_an_explanation() -> None:
    report = AnalysisReport(total_packets=2, esp_count=2, risk_score=0.4)
    result = handshake_anomaly_score(report)
    assert 0 <= result["anomaly_score"] <= 1
    assert result["method"] == "heuristic_rules"
    assert "not a probability" in result["explanation"]



def _ike_payload(version: int, exchange: int, declared_length: int = 28) -> bytes:
    payload = bytearray(28)
    payload[17] = version << 4
    payload[18] = exchange
    payload[24:28] = struct.pack("!I", declared_length)
    return bytes(payload)


def test_ike_exchange_names_are_version_specific() -> None:
    assert _ike_version_and_exchange(_ike_payload(1, 2)) == ("IKE", "Main mode")
    assert _ike_version_and_exchange(_ike_payload(1, 34)) == ("IKE", "Exchange 34")
    assert _ike_version_and_exchange(_ike_payload(2, 34)) == ("IKEv2", "IKE_SA_INIT")
    assert _ike_version_and_exchange(_ike_payload(2, 2)) == ("IKEv2", "Exchange 2")


def test_malformed_ike_header_length_is_not_classified_as_ike(tmp_path: Path) -> None:
    from scapy.all import Ether, IP, Raw, UDP, wrpcap

    capture = tmp_path / "malformed-ike.pcap"
    malformed = _ike_payload(2, 34, declared_length=0)
    wrpcap(str(capture), [Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=500, dport=500) / Raw(load=malformed)])

    report = analyze_pcap(capture)
    assert report.ikev2_count == 0
    assert report.ike_count == 0
    assert report.protocols.get("UDP/500 or 4500") == 1


def test_packet_count_limit_is_checked_while_reading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import src.analyzer as analyzer_module

    capture = build_demo_capture(tmp_path / "many-packets.pcap")
    monkeypatch.setattr(analyzer_module, "MAX_PACKET_COUNT", 2)

    with pytest.raises(ValueError, match="more than 2 packets"):
        analyze_pcap(capture)


def test_nat_t_keepalive_is_counted_as_ipsec_related(tmp_path: Path) -> None:
    from scapy.all import Ether, IP, Raw, UDP, wrpcap

    capture = tmp_path / "natt-keepalive.pcap"
    packet = Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=4500, dport=4500) / Raw(load=b"\xff")
    wrpcap(str(capture), [packet])

    report = analyze_pcap(capture)
    assert report.protocols.get("NAT-T keepalive") == 1
    assert report.ipsec_related == 1
