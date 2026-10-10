"""Regression tests for real capture parsing and IPsec heuristics."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from src.analyzer import AnalysisReport, analyze_pcap, build_demo_capture, report_to_dict
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
