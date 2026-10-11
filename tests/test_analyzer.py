"""Regression tests for real capture parsing and IPsec heuristics."""
from __future__ import annotations

from pathlib import Path

import pytest

from src.analyzer import (
    AnalysisReport,
    _capture_format,
    _is_ike_header,
    analyze_pcap,
    build_demo_capture,
    report_to_dict,
)
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



def test_ike_header_requires_sane_declared_message_length() -> None:
    import struct

    header = bytearray(28)
    header[17] = 0x20
    struct.pack_into("!I", header, 24, 28)
    assert _is_ike_header(bytes(header))

    struct.pack_into("!I", header, 24, 0)
    assert not _is_ike_header(bytes(header))

    struct.pack_into("!I", header, 24, 29)
    assert not _is_ike_header(bytes(header))


def test_capture_packet_limit_is_enforced_while_streaming(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import scapy.all

    capture_file = tmp_path / "capture.pcap"
    capture_file.write_bytes(bytes.fromhex("d4c3b2a102000400" + "00" * 16))
    monkeypatch.setattr("src.analyzer.MAX_PACKET_COUNT", 2)

    class Packet:
        time = 1.0

        def getlayer(self, _layer):
            return None

        def haslayer(self, _layer):
            return False

        def __len__(self):
            return 42

    class Reader:
        def __init__(self, _path: str) -> None:
            self.yielded = 0
            self.closed = False

        def __iter__(self):
            for _ in range(5):
                self.yielded += 1
                yield Packet()

        def close(self):
            self.closed = True

    reader = Reader(str(capture_file))
    monkeypatch.setattr(scapy.all, "PcapReader", lambda _path: reader)

    with pytest.raises(ValueError, match="more than 2 packets"):
        analyze_pcap(capture_file)

    assert reader.yielded == 3
    assert reader.closed


def test_capture_format_uses_file_signature_not_suffix(tmp_path: Path) -> None:
    path = tmp_path / "misleading.pcap"
    path.write_bytes(bytes.fromhex("0a0d0d0a" + "00" * 20))
    assert _capture_format(path) == "PCAPNG"
