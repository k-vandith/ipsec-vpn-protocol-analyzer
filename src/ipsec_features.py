"""IPsec extras: config parsing, weak-crypto detection, remediation report."""
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

WEAK_DH = {"modp768", "modp1024", "group1", "group2", "dh1", "dh2", "1", "2"}
WEAK_ENC = {"des", "3des", "null", "rc4"}
WEAK_HASH = {"md5", "sha1"}

def parse_strongswan_config(text: str, source: str = "strongswan.conf") -> list[ConfigFinding]:
    findings = []
    if re.search(r"aggressive\s*=\s*yes", text, re.I):
        findings.append(ConfigFinding(source, "aggressive_mode", "high", "Aggressive mode enabled", "Use main mode / IKEv2 only."))
    if re.search(r"authby\s*=\s*psk|secret\s*=", text, re.I):
        findings.append(ConfigFinding(source, "psk_auth", "medium", "PSK authentication referenced", "Prefer certificate authentication."))
    for m in re.finditer(r"ike\s*=\s*([^\n#]+)", text, re.I):
        suite = m.group(1).lower()
        for w in WEAK_ENC:
            if w in suite:
                findings.append(ConfigFinding(source, "weak_cipher", "critical", f"Weak encryption: {suite.strip()}", "Use AES-GCM or AES-CBC-256."))
        for w in WEAK_HASH:
            if w in suite:
                findings.append(ConfigFinding(source, "weak_hash", "high", f"Weak hash: {suite.strip()}", "Use SHA-256+."))
        for w in WEAK_DH:
            if w in suite.replace(" ", ""):
                findings.append(ConfigFinding(source, "weak_dh", "high", f"Weak DH: {suite.strip()}", "Use DH14+ or ECDH."))
    return findings

def parse_cisco_style(text: str, source: str = "cisco.cfg") -> list[ConfigFinding]:
    findings = []
    if re.search(r"hash\s+md5", text, re.I):
        findings.append(ConfigFinding(source, "weak_hash", "high", "ISAKMP hash md5", "Use SHA-256+."))
    if re.search(r"encryption\s+des\b", text, re.I):
        findings.append(ConfigFinding(source, "weak_cipher", "critical", "ISAKMP encryption des", "Use AES."))
    if re.search(r"group\s+[12]\b", text, re.I):
        findings.append(ConfigFinding(source, "weak_dh", "high", "DH group 1/2", "Use group 14+."))
    if re.search(r"aggressive", text, re.I):
        findings.append(ConfigFinding(source, "aggressive_mode", "high", "Aggressive mode", "Disable."))
    return findings

def analyze_config_file(path: Path) -> list[ConfigFinding]:
    text = path.read_text(encoding="utf-8", errors="replace")
    low = text.lower()
    if "conn " in low or "ike=" in low:
        return parse_strongswan_config(text, path.name)
    return parse_cisco_style(text, path.name)

def handshake_anomaly_score(report: AnalysisReport) -> dict[str, Any]:
    features = {
        "ike_ratio": report.ike_count / max(1, report.total_packets),
        "esp_without_ike": 1.0 if report.esp_count and not (report.ike_count or report.ikev2_count) else 0.0,
        "anomaly_count": float(len(report.anomalies)),
        "risk_score": report.risk_score,
    }
    score = min(1.0, 0.4 * features["esp_without_ike"] + 0.3 * min(1.0, features["anomaly_count"] / 5) + 0.3 * features["risk_score"])
    return {"anomaly_score": round(score, 4), "features": features, "method": "heuristic_rules"}

def remediation_report(report: AnalysisReport, config_findings: list[ConfigFinding] | None = None) -> str:
    lines = ["# IPsec Remediation Report", f"Risk score: {report.risk_score:.2f}", ""]
    for a in report.anomalies:
        lines.append(f"- PCAP anomaly: {a}")
    for f in config_findings or []:
        lines.append(f"- [{f.severity}] {f.issue}: {f.detail} → {f.remediation}")
    lines.append("Recommendations: prefer IKEv2, AES-GCM, strong DH/ECDH, cert auth.")
    return "\n".join(lines)
