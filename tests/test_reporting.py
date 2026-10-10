"""Tests for safe and useful report exports."""
from __future__ import annotations

import json

from src.analyzer import AnalysisReport, PacketSummary
from src.ipsec_features import ConfigFinding
from src.reporting import build_html_report, build_packets_csv, build_report_json


def test_html_report_escapes_uploaded_finding_text() -> None:
    finding = ConfigFinding(
        source="<vpn>.cfg",
        issue="weak_cipher",
        severity="critical",
        detail="<script>alert('x')</script>",
        remediation="Use a modern cipher.",
        line=7,
        category="encryption",
    )
    html = build_html_report([], [finding])

    assert "&lt;script&gt;" in html
    assert "<script>alert('x')</script>" not in html
    assert "TunnelScope" in html


def test_json_and_csv_include_capture_metadata() -> None:
    report = AnalysisReport(
        total_packets=1,
        ipsec_related=1,
        ikev2_count=1,
        capture_name="sample.pcap",
        capture_format="PCAP",
        protocols={"IKEv2": 1},
        packets=[PacketSummary(
            index=0, timestamp=1.25, src="192.0.2.10", dst="198.51.100.20",
            protocol="IKEv2", length=80, info="IKEv2 IKE_SA_INIT",
            src_port=500, dst_port=500, exchange="IKE_SA_INIT",
        )],
    )
    payload = json.loads(build_report_json([report], []))
    csv_text = build_packets_csv([report])

    assert payload["captures"][0]["capture"]["name"] == "sample.pcap"
    assert payload["captures"][0]["protocol_counts"]["IKEv2"] == 1
    assert "sample.pcap" in csv_text
    assert "IKE_SA_INIT" in csv_text


def test_pdf_report_is_available_only_with_optional_extra() -> None:
    try:
        import reportlab  # noqa: F401
    except ImportError:
        return
    from src.reporting import build_pdf_report

    result = build_pdf_report([], [])
    assert result.startswith(b"%PDF")
