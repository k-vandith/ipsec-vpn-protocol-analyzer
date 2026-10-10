"""Regression tests for vendor-style VPN configuration checks."""
from __future__ import annotations

from src.analyzer import AnalysisReport
from src.ipsec_features import (
    analyze_config_text,
    parse_cisco_style,
    parse_strongswan_config,
    remediation_report,
)


def test_strongswan_weak_proposal_has_line_and_plain_english() -> None:
    text = """# commented reference should be ignored
conn sample
    keyexchange=ikev2
    ike=aes128-sha1-modp1024
    aggressive=yes
    authby=psk
"""
    findings = parse_strongswan_config(text, "sample.conf")
    by_issue = {item.issue: item for item in findings}

    assert {"weak_hash", "weak_dh", "aggressive_mode", "psk_auth"} <= set(by_issue)
    assert by_issue["weak_hash"].line == 4
    assert "SHA-256" in by_issue["weak_hash"].remediation
    assert by_issue["weak_dh"].severity == "high"


def test_strongswan_strong_proposal_does_not_match_weak_dh_tokens() -> None:
    text = "conn good\n ike=aes256gcm16-prfsha384-ecp384\n esp=aes256gcm16\n"
    findings = parse_strongswan_config(text, "good.conf")

    assert not any(item.issue in {"weak_cipher", "weak_hash", "weak_dh"} for item in findings)


def test_cisco_legacy_crypto_lines_are_flagged() -> None:
    text = """crypto isakmp policy 10
 encryption 3des
 hash md5
 authentication pre-share
 group 2
crypto isakmp aggressive-mode
crypto ipsec transform-set LEGACY esp-3des esp-sha-hmac
"""
    findings = parse_cisco_style(text, "legacy.cfg")
    issues = {item.issue for item in findings}

    assert {"weak_cipher", "weak_hash", "weak_dh", "aggressive_mode", "psk_auth"} <= issues
    assert all(item.line > 0 for item in findings)


def test_cisco_modern_values_are_not_false_positive_for_dh_and_cipher() -> None:
    text = """crypto isakmp policy 20
 encryption aes 256
 hash sha256
 authentication pre-share
 group 14
"""
    findings = parse_cisco_style(text, "modern.cfg")

    assert not any(item.issue in {"weak_cipher", "weak_hash", "weak_dh", "aggressive_mode"} for item in findings)
    assert any(item.issue == "psk_auth" for item in findings)


def test_vendor_detection_and_remediation_report() -> None:
    config = analyze_config_text("conn example\n ike=aes128-sha1-modp1024\n", "strongswan.conf")
    report = AnalysisReport(total_packets=3, ikev2_count=1, esp_count=2, ipsec_related=3)
    text = remediation_report(report, config)

    assert "TunnelScope IPsec Review" in text
    assert "Configuration findings" in text
    assert "strongswan.conf:2" in text
    assert "not a probability" in text
