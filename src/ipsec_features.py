"""Explainable IPsec configuration checks and remediation guidance."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.analyzer import AnalysisReport


@dataclass
class ConfigFinding:
    source: str
    issue: str
    severity: str
    detail: str
    remediation: str
    line: int = 0
    category: str = "proposal"


WEAK_DH = {"modp768", "modp1024", "modp1536", "group1", "group2", "dh1", "dh2"}
WEAK_ENC = {"des", "3des", "null", "rc4", "esp-des", "esp-3des", "esp-null", "esp-rc4"}
WEAK_HASH = {"md5", "sha1", "sha-1"}
IKEV2_FRIENDLY = "Prefer IKEv2 with AES-GCM, a modern DH/ECDH group, and certificate or managed identity authentication."


def _clean_lines(text: str) -> list[tuple[int, str]]:
    return [
        (number, line.strip())
        for number, line in enumerate(text.splitlines(), start=1)
        if line.strip() and not line.lstrip().startswith(("#", "!", "//", ";"))
    ]


def _append_once(
    findings: list[ConfigFinding],
    source: str,
    issue: str,
    severity: str,
    detail: str,
    remediation: str,
    line: int,
    category: str,
) -> None:
    key = (issue, line, detail)
    if not any((item.issue, item.line, item.detail) == key for item in findings):
        findings.append(ConfigFinding(source, issue, severity, detail, remediation, line, category))


def parse_strongswan_config(text: str, source: str = "strongswan.conf") -> list[ConfigFinding]:
    findings: list[ConfigFinding] = []
    for line_number, line in _clean_lines(text):
        if re.search(r"\baggressive\s*=\s*(?:yes|true|1)\b", line, re.I):
            _append_once(
                findings, source, "aggressive_mode", "high", "IKEv1 aggressive mode is enabled",
                "Prefer IKEv2. If IKEv1 is required for compatibility, disable aggressive mode and review identity exposure.",
                line_number, "exchange",
            )
        if re.search(r"\b(?:authby|leftauth|rightauth)\s*=\s*psk\b|\bsecret\s*=", line, re.I):
            _append_once(
                findings, source, "psk_auth", "medium", "Pre-shared-key authentication is configured",
                "Confirm that the shared secret is high-entropy, unique, rotated, and stored with restricted permissions; consider certificate-based authentication.",
                line_number, "authentication",
            )
        if re.search(r"\b(?:ike|esp|phase2alg)\s*=", line, re.I):
            key, value = re.split(r"=", line, maxsplit=1)
            suites = [part.strip() for part in value.split(",") if part.strip()]
            for suite in suites:
                tokens = {
                    token.lower()
                    for token in re.split(r"[-_/+\s!:]+", suite)
                    if token
                }
                enc_tokens = tokens & {"des", "3des", "null", "rc4", "desede", "3des-cbc"}
                hash_tokens = tokens & {"md5", "sha1", "sha-1"}
                dh_tokens = tokens & WEAK_DH
                normalized = suite.strip()
                if enc_tokens:
                    _append_once(
                        findings, source, "weak_cipher", "critical",
                        f"Legacy or null encryption referenced in {key.strip()} proposal: {normalized}",
                        "Remove DES/3DES/RC4/null-encryption proposals. Choose a supported modern authenticated-encryption suite, then verify both peers.",
                        line_number, "encryption",
                    )
                if hash_tokens:
                    _append_once(
                        findings, source, "weak_hash", "high",
                        f"Legacy hash referenced in {key.strip()} proposal: {normalized}",
                        "Prefer a modern hash (for example SHA-256 or stronger) where the protocol and implementation support it.",
                        line_number, "integrity",
                    )
                if dh_tokens:
                    _append_once(
                        findings, source, "weak_dh", "high",
                        f"Legacy Diffie–Hellman group referenced in {key.strip()} proposal: {normalized}",
                        "Choose a current DH/ECDH group supported by your VPN peers and validate interoperability before deployment.",
                        line_number, "key exchange",
                    )
    return findings


def parse_cisco_style(text: str, source: str = "cisco.cfg") -> list[ConfigFinding]:
    findings: list[ConfigFinding] = []
    for line_number, line in _clean_lines(text):
        lower = line.lower()
        if re.search(r"\bhash\s+md5\b|\besp-sha-hmac\b", lower):
            _append_once(
                findings, source, "weak_hash", "high",
                "MD5 or a legacy SHA-1 HMAC transform is referenced",
                "Use a modern integrity/authentication transform supported by both peers; review the full Phase 1 and Phase 2 policy.",
                line_number, "integrity",
            )
        if re.search(r"\bencryption\s+(?:des|3des)\b|\besp-(?:des|3des)\b|\bencryption\s+null\b|\besp-null\b|\bcrypto\s+isakmp\s+key\b", lower):
            detail = "Legacy encryption or a pre-shared key declaration is present"
            is_weak_enc = bool(re.search(r"\bencryption\s+(?:des|3des|null)\b|\besp-(?:des|3des|null)\b", lower))
            if is_weak_enc:
                _append_once(
                    findings, source, "weak_cipher", "critical",
                    "Legacy DES/3DES/null encryption referenced",
                    "Remove legacy or null encryption transforms and confirm the approved AES-based policy on both VPN peers.",
                    line_number, "encryption",
                )
        if re.search(r"\bgroup\s+[12]\b", lower):
            _append_once(
                findings, source, "weak_dh", "high", "Diffie–Hellman group 1 or 2 is referenced",
                "Use a modern DH/ECDH group agreed with the remote peer; avoid legacy group 1/2 settings.",
                line_number, "key exchange",
            )
        if re.search(r"\bauthentication\s+pre-share\b|\bcrypto\s+isakmp\s+key\b", lower):
            _append_once(
                findings, source, "psk_auth", "medium", "Pre-shared-key authentication is configured",
                "Check shared-secret entropy, uniqueness, rotation, and secret storage; consider certificate-based authentication.",
                line_number, "authentication",
            )
        if re.search(r"\baggressive(?:-mode)?\b", lower):
            _append_once(
                findings, source, "aggressive_mode", "high", "IKEv1 aggressive mode is referenced",
                "Prefer IKEv2 or disable aggressive mode after checking compatibility and identity exposure.",
                line_number, "exchange",
            )
        if re.search(r"\bcrypto\s+isakmp\s+policy\b", lower):
            _append_once(
                findings, source, "ikev1_policy", "info", "Cisco ISAKMP (IKEv1) policy configured",
                "Confirm whether IKEv1 is still needed; prefer IKEv2 for new deployments.",
                line_number, "exchange",
            )
    return findings


def analyze_config_text(text: str, source: str = "vpn.conf") -> list[ConfigFinding]:
    name = source.lower()
    lower = text.lower()
    if "strongswan" in name or "conn " in lower or re.search(r"^\s*(?:ike|esp|leftauth|rightauth)\s*=", text, re.I | re.M):
        return parse_strongswan_config(text, source)
    return parse_cisco_style(text, source)


def analyze_config_file(path: str | Path) -> list[ConfigFinding]:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"Could not read VPN configuration file: {path.name}") from exc
    return analyze_config_text(text, path.name)


def handshake_anomaly_score(report: AnalysisReport) -> dict[str, Any]:
    """Return a transparent rule score; not a probability or exploitability model."""
    features = {
        "ike_ratio": report.ike_count / max(1, report.total_packets),
        "esp_without_ike": 1.0 if report.esp_count and not (report.ike_count or report.ikev2_count) else 0.0,
        "anomaly_count": float(len(report.anomalies)),
        "risk_score": report.risk_score,
    }
    score = min(
        1.0,
        0.4 * features["esp_without_ike"]
        + 0.3 * min(1.0, features["anomaly_count"] / 5)
        + 0.3 * features["risk_score"],
    )
    return {
        "anomaly_score": round(score, 4),
        "features": features,
        "method": "heuristic_rules",
        "explanation": "A rule-based triage indicator based on visible capture patterns. It is not a probability of compromise.",
    }


def remediation_report(
    report: AnalysisReport,
    config_findings: list[ConfigFinding] | None = None,
) -> str:
    lines = [
        "# TunnelScope IPsec Review",
        "",
        "## Capture summary",
        f"- Packets read: {report.total_packets}",
        f"- IPsec-related packets recognised: {report.ipsec_related}",
        f"- IKEv1: {report.ike_count} · IKEv2: {report.ikev2_count} · ESP: {report.esp_count} · AH: {report.ah_count}",
        f"- Rule-based risk indicator: {report.risk_score:.2f} (not a probability or a formal security rating)",
        "",
        "## Capture findings",
    ]
    if report.anomalies:
        lines.extend(f"- {item}" for item in report.anomalies)
    else:
        lines.append("- No configured capture anomaly rule matched the recognised packets.")
    lines.extend(["", "## Configuration findings"])
    configs = config_findings or []
    if configs:
        for item in sorted(configs, key=lambda finding: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(finding.severity, 9), finding.source, finding.line)):
            location = f"{item.source}:{item.line}" if item.line else item.source
            lines.append(f"- [{item.severity.upper()}] {location} — {item.detail}. Next step: {item.remediation}")
    else:
        lines.append("- No configuration findings were supplied to the report.")
    lines.extend([
        "",
        "## Recommended review order",
        "1. Verify critical encryption and weak-key-exchange findings against the active policy.",
        "2. Check IKE version, proposal compatibility, authentication method, and secret-handling practices.",
        "3. Review packet capture scope; missing negotiation packets may reflect the capture point or filter.",
        "4. Repeat the analysis after a configuration change and compare results.",
        "",
        "## Method and limits",
        "TunnelScope uses packet headers and configuration text patterns. It does not decrypt ESP traffic, "
        "prove that a VPN is exploitable, or establish that every negotiation packet was captured.",
    ])
    return "\n".join(lines)
