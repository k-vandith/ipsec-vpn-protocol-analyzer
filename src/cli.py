"""Typer command-line interface for local TunnelScope reviews."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from src.analyzer import analyze_pcap, report_to_dict
from src.ipsec_features import analyze_config_file

app = typer.Typer(
    name="tunnelscope",
    help="Review IPsec/IKE packet captures and VPN configuration files locally.",
    no_args_is_help=True,
    add_completion=False,
)


@app.command()
def scan(
    capture: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False, readable=True, help="Path to a PCAP or PCAPNG file."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON results to this path instead of stdout."),
    format: str = typer.Option("summary", "--format", help="Output format: summary or json."),
) -> None:
    """Analyse a PCAP/PCAPNG capture without decrypting payloads."""
    if capture.suffix.lower() not in {".pcap", ".pcapng"}:
        raise typer.BadParameter("Choose a .pcap or .pcapng capture.", param_hint="capture")
    if format not in {"summary", "json"}:
        raise typer.BadParameter("Use 'summary' or 'json'.", param_hint="--format")
    report = analyze_pcap(capture)
    if format == "json":
        text = json.dumps(report_to_dict(report), indent=2)
    else:
        lines = [
            f"TunnelScope — {report.capture_name}",
            f"Packets: {report.total_packets} · IPsec-related: {report.ipsec_related}",
            f"IKEv1: {report.ike_count} · IKEv2: {report.ikev2_count} · ESP: {report.esp_count} · AH: {report.ah_count}",
            f"Review indicator: {report.risk_score:.2f} (heuristic, not probability)",
            "",
            "Observations:",
        ]
        lines.extend(f"- {item}" for item in report.anomalies or ["No configured capture anomaly rule matched."])
        lines.extend(f"Warning: {item}" for item in report.warnings)
        text = "\n".join(lines)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        typer.echo(f"Saved {format} report to {output}")
    else:
        typer.echo(text)


@app.command("check-config")
def check_config(
    files: list[Path] = typer.Argument(..., exists=True, file_okay=True, dir_okay=False, readable=True, help="VPN configuration file(s)."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON configuration findings to this path."),
) -> None:
    """Check strongSwan or Cisco-style VPN configuration text."""
    findings = []
    for path in files:
        findings.extend(analyze_config_file(path))
    payload = [
        {
            "source": item.source,
            "line": item.line,
            "issue": item.issue,
            "severity": item.severity,
            "category": item.category,
            "detail": item.detail,
            "remediation": item.remediation,
        }
        for item in findings
    ]
    text = json.dumps(payload, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        typer.echo(f"Saved configuration findings to {output}")
    else:
        if not payload:
            typer.echo("No configured text-pattern rule matched these files.")
        else:
            for item in findings:
                typer.echo(f"[{item.severity.upper()}] {item.source}:{item.line} — {item.detail}")
                typer.echo(f"  Next step: {item.remediation}")
    typer.echo(f"{len(findings)} configuration finding(s)")


if __name__ == "__main__":
    app()
