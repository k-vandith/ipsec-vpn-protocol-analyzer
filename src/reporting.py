"""Local HTML, JSON, CSV, and optional PDF reporting for TunnelScope."""
from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone
from typing import Any, Iterable

from src.analyzer import AnalysisReport, report_to_dict
from src.ipsec_features import ConfigFinding


def build_report_json(
    reports: Iterable[AnalysisReport],
    config_findings: Iterable[ConfigFinding],
) -> str:
    return json.dumps({
        "product": "TunnelScope",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "captures": [report_to_dict(report) for report in reports],
        "configuration_findings": [
            {
                "source": finding.source,
                "line": finding.line,
                "issue": finding.issue,
                "severity": finding.severity,
                "category": finding.category,
                "detail": finding.detail,
                "remediation": finding.remediation,
            }
            for finding in config_findings
        ],
        "limitations": [
            "Protocol detection is based on visible packet headers and heuristics.",
            "ESP payloads are not decrypted.",
            "A missing packet or negotiation can reflect capture placement or filtering.",
            "Scores are review indicators, not probabilities or formal security ratings.",
        ],
    }, indent=2)


def build_packets_csv(reports: Iterable[AnalysisReport]) -> str:
    output = io.StringIO()
    fields = [
        "capture", "packet_index", "timestamp", "source", "source_port",
        "destination", "destination_port", "protocol", "exchange", "length", "info",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for report in reports:
        for packet in report.packets:
            writer.writerow({
                "capture": report.capture_name,
                "packet_index": packet.index,
                "timestamp": packet.timestamp,
                "source": packet.src,
                "source_port": packet.src_port or "",
                "destination": packet.dst,
                "destination_port": packet.dst_port or "",
                "protocol": packet.protocol,
                "exchange": packet.exchange,
                "length": packet.length,
                "info": packet.info,
            })
    return output.getvalue()


def build_html_report(
    reports: Iterable[AnalysisReport],
    config_findings: Iterable[ConfigFinding],
) -> str:
    reports = list(reports)
    config_findings = list(config_findings)
    total_packets = sum(report.total_packets for report in reports)
    ipsec_packets = sum(report.ipsec_related for report in reports)
    capture_anomalies = [(report.capture_name, item) for report in reports for item in report.anomalies]
    risk = max((report.risk_score for report in reports), default=0.0)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    config_findings.sort(key=lambda item: (sev_order.get(item.severity.lower(), 9), item.source, item.line))
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    capture_rows = []
    for report in reports:
        capture_rows.append(
            "<tr>"
            f"<td>{html.escape(report.capture_name)}</td>"
            f"<td>{report.capture_format}</td><td>{report.total_packets:,}</td>"
            f"<td>{report.ike_count:,}</td><td>{report.ikev2_count:,}</td>"
            f"<td>{report.esp_count:,}</td><td>{report.ah_count:,}</td>"
            f"<td>{report.risk_score:.2f}</td></tr>"
        )
    config_rows = []
    for finding in config_findings:
        location = f"{finding.source}:{finding.line}" if finding.line else finding.source
        config_rows.append(
            "<tr>"
            f"<td><span class='severity {html.escape(finding.severity.lower())}'>{html.escape(finding.severity.upper())}</span></td>"
            f"<td>{html.escape(location)}</td><td>{html.escape(finding.detail)}</td>"
            f"<td>{html.escape(finding.remediation)}</td></tr>"
        )
    anomaly_rows = [
        f"<li><b>{html.escape(name)}</b> — {html.escape(item)}</li>"
        for name, item in capture_anomalies
    ]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TunnelScope · IPsec Review</title><style>
:root{{--ink:#152333;--muted:#526477;--line:#dbe4ec;--surface:#f5f8fb;--accent:#147c8d}}
*{{box-sizing:border-box}}body{{margin:0;font:15px/1.55 Inter,Segoe UI,Arial,sans-serif;color:var(--ink);background:var(--surface)}}
main{{max-width:1200px;margin:30px auto;padding:0 24px}}header{{padding:26px 30px;border-radius:18px;background:#0b0d14;color:#f4f5fb}}
header small{{color:#70d4e2;letter-spacing:.16em;text-transform:uppercase;font-weight:800}}h1{{font-size:2.05rem;margin:.3rem 0}}.muted{{color:var(--muted)}}
.grid{{display:grid;grid-template-columns:repeat(4,minmax(130px,1fr));gap:12px;margin:18px 0}}
.card{{border:1px solid var(--line);background:#fff;border-radius:14px;padding:16px}}.card b{{font-size:1.55rem;display:block}}
h2{{font-size:1.15rem;margin:26px 0 8px}}table{{width:100%;border-collapse:collapse;background:#fff;font-size:.88rem}}
th,td{{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}}th{{background:#eaf0f5}}
.severity{{font-size:.72rem;font-weight:750}}.critical{{color:#b42332}}.high{{color:#b54708}}.medium{{color:#9a6700}}.info{{color:#526477}}
.notice{{border-left:3px solid var(--accent);background:#e8f6f8;padding:12px 14px;margin:16px 0}}
@media(max-width:760px){{main{{padding:0 12px}}.grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}}}
</style></head><body><main>
<header><small>Local-first network security review</small><h1>TunnelScope</h1>
<p>IPsec and IKE capture analysis with configuration review.</p><p class="muted">Generated {html.escape(generated)} · Heuristic triage, not a formal security rating.</p></header>
<div class="grid">
<div class="card"><span class="muted">Captures</span><b>{len(reports)}</b></div>
<div class="card"><span class="muted">Packets read</span><b>{total_packets:,}</b></div>
<div class="card"><span class="muted">IPsec-related</span><b>{ipsec_packets:,}</b></div>
<div class="card"><span class="muted">Highest capture indicator</span><b>{risk:.2f}</b></div>
</div>
<div class="notice">Interpretation: visible packet metadata and configuration text are reviewed locally. ESP remains encrypted. Missing negotiation packets can reflect where or how the capture was taken.</div>
<h2>Capture summary</h2><table><thead><tr><th>Capture</th><th>Format</th><th>Packets</th><th>IKEv1</th><th>IKEv2</th><th>ESP</th><th>AH</th><th>Indicator</th></tr></thead>
<tbody>{''.join(capture_rows) if capture_rows else '<tr><td colspan="8">No capture was included in this review.</td></tr>'}</tbody></table>
<h2>Capture observations</h2><ul>{''.join(anomaly_rows) if anomaly_rows else '<li>No configured capture anomaly rule matched the recognised packets.</li>'}</ul>
<h2>Configuration review</h2><table><thead><tr><th>Priority</th><th>Location</th><th>Finding</th><th>Suggested action</th></tr></thead>
<tbody>{''.join(config_rows) if config_rows else '<tr><td colspan="4">No configuration findings were supplied.</td></tr>'}</tbody></table>
<h2>Limits</h2><p class="muted">TunnelScope is a defensive review aid, not an IKE state-machine validator, a decryption tool, a complete configuration proof, or a probability of compromise. Validate recommendations with the organisation's VPN requirements.</p>
</main></body></html>"""


def build_pdf_report(
    reports: Iterable[AnalysisReport],
    config_findings: Iterable[ConfigFinding],
) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import landscape, letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError("PDF export is optional. Install it with: python -m pip install -e .[reports]") from exc

    reports = list(reports)
    config_findings = list(config_findings)
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=landscape(letter), leftMargin=0.45*inch, rightMargin=0.45*inch,
                            topMargin=0.45*inch, bottomMargin=0.45*inch, title="TunnelScope IPsec Review")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TSCell", parent=styles["Normal"], fontSize=7.5, leading=9, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="TSMuted", parent=styles["Normal"], textColor=colors.HexColor("#526477"), fontSize=8, leading=11))
    story = [
        Paragraph("TunnelScope", styles["Title"]),
        Paragraph("IPsec &amp; IKE capture review · locally generated", styles["TSMuted"]),
        Paragraph("Scores are heuristic review indicators, not probabilities or formal security ratings.", styles["TSMuted"]),
        Spacer(1, 10),
    ]
    captures = [["Capture", "Packets", "IKEv1", "IKEv2", "ESP", "AH", "Indicator"]]
    for report in reports:
        captures.append([
            report.capture_name, str(report.total_packets), str(report.ike_count),
            str(report.ikev2_count), str(report.esp_count), str(report.ah_count),
            f"{report.risk_score:.2f}",
        ])
    if len(captures) == 1:
        captures.append(["No capture included", "0", "0", "0", "0", "0", "—"])
    def make_table(rows: list[list[str]], widths: list[float]) -> Table:
        wrapped = [[Paragraph(html.escape(str(cell)), styles["TSCell"]) for cell in row] for row in rows]
        table = Table(wrapped, colWidths=widths, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b0d14")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#dbe4ec")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f8fb")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        return table
    story.extend([Paragraph("Capture summary", styles["Heading2"]), make_table(captures, [2.5*inch, .8*inch, .7*inch, .7*inch, .7*inch, .7*inch, .85*inch]), Spacer(1, 12)])
    story.append(Paragraph("Observations", styles["Heading2"]))
    anomalies = [(report.capture_name, anomaly) for report in reports for anomaly in report.anomalies]
    story.append(Paragraph("<br/>".join(f"• {html.escape(name)} — {html.escape(message)}" for name, message in anomalies) or "No configured capture anomaly rule matched the recognised packets.", styles["Normal"]))
    story.extend([Spacer(1, 10), Paragraph("Configuration findings", styles["Heading2"])])
    rows = [["Priority", "Location", "Finding", "Suggested action"]]
    for finding in config_findings:
        loc = f"{finding.source}:{finding.line}" if finding.line else finding.source
        rows.append([finding.severity.upper(), loc, finding.detail, finding.remediation])
    if len(rows) == 1:
        rows.append(["—", "—", "No configuration findings supplied", "Upload a VPN configuration to review it."])
    story.extend([make_table(rows, [.75*inch, 1.3*inch, 2.7*inch, 3.7*inch]), Spacer(1, 12),
                  Paragraph("Limits: packet headers and text patterns only. ESP payloads are not decrypted. Capture position and filters affect what is observed.", styles["TSMuted"])])
    doc.build(story)
    return output.getvalue()
