"""TunnelScope: upload-first, local IPsec/IKE review workspace."""
from __future__ import annotations

import base64
import html
import re
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import plotly.express as px
import streamlit as st

from src.analyzer import AnalysisReport, analyze_pcap, build_demo_capture
from src.ipsec_features import (
    ConfigFinding,
    analyze_config_file,
    handshake_anomaly_score,
    remediation_report,
)
from src.reporting import (
    build_html_report,
    build_packets_csv,
    build_pdf_report,
    build_report_json,
)
from src.sample_data import SAMPLE_CISCO, SAMPLE_STRONGSWAN, write_sample_case
from src.ui_theme import theme_css
from src.upload_io import (
    CAPTURE_EXTENSIONS,
    CONFIG_EXTENSIONS,
    stage_captures,
    stage_configs,
    validate_upload_batch,
)

ACCENT = "#70d4e2"
NAVIGATION = [
    "Overview",
    "Upload & Configure",
    "Negotiation Timeline",
    "Configuration Review",
    "Packet Explorer",
    "Reports",
    "Glossary",
]
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLORS = {
    "critical": "#e06b75",
    "high": "#ee9864",
    "medium": "#e2b15a",
    "low": "#7eb6ff",
    "info": "#8d9ab1",
}
RULE_HELP = {
    "aggressive_mode": "IKEv1 aggressive mode trades away some negotiation privacy and deserves a compatibility review.",
    "psk_auth": "A pre-shared key is not automatically weak. Review uniqueness, entropy, rotation, and storage.",
    "weak_cipher": "DES, 3DES, RC4, or null encryption is a legacy or unsafe proposal signal. Confirm the active proposal.",
    "weak_hash": "MD5 and SHA-1 references may be legacy integrity or authentication choices. Validate the exact protocol use.",
    "weak_dh": "Legacy Diffie–Hellman groups can provide insufficient security margin. Confirm supported replacement groups.",
    "ikev1_policy": "IKEv1 may be required for compatibility, but new deployments should prefer a supported IKEv2 policy.",
}


def _init_state() -> None:
    defaults = {
        "current_page": "Overview",
        "theme_mode": "Dark",
        "capture_reports": [],
        "config_findings": [],
        "analysis_complete": False,
        "source_label": "",
        "files_checked": 0,
        "checked_at": "",
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def _preview_config(payload: bytes) -> str:
    """Show a short config preview without exposing common inline secret assignments."""
    text = payload[:2000].decode("utf-8", errors="replace")
    text = re.sub(
        r"""(?im)(\b(?:secret|password|psk|pre-shared-key|private[_-]?key|preshared[_-]?key)\b\s*(?:=|:)\s*)(?:"[^"]*"|'[^']*'|[^\s#;]+)""",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(r"(?im)(crypto\s+isakmp\s+key\s+)\S+", r"\1[REDACTED]", text)
    return text.strip()[:500].replace("\n", " ⏎ ")


def _go_to(page: str) -> None:
    st.session_state["current_page"] = page


def _reset_session() -> None:
    defaults = {
        "current_page": "Overview",
        "capture_reports": [],
        "config_findings": [],
        "analysis_complete": False,
        "source_label": "",
        "files_checked": 0,
        "checked_at": "",
    }
    for key, value in defaults.items():
        st.session_state[key] = value


def _logo_data_uri() -> str:
    try:
        encoded = base64.b64encode((ROOT / "assets" / "tunnelscope-mark.svg").read_bytes()).decode("ascii")
        return f"data:image/svg+xml;base64,{encoded}"
    except OSError:
        return ""


def _reports() -> list[AnalysisReport]:
    value = st.session_state.get("capture_reports", [])
    return value if isinstance(value, list) else []


def _config_findings() -> list[ConfigFinding]:
    value = st.session_state.get("config_findings", [])
    return value if isinstance(value, list) else []


def _severity_counts(findings: list[ConfigFinding]) -> dict[str, int]:
    return {
        level: sum(1 for item in findings if item.severity.lower() == level)
        for level in SEVERITY_ORDER
    }


def _store_results(
    reports: list[AnalysisReport],
    findings: list[ConfigFinding],
    source_label: str,
    files_checked: int,
) -> None:
    st.session_state["capture_reports"] = reports
    st.session_state["config_findings"] = findings
    st.session_state["analysis_complete"] = True
    st.session_state["source_label"] = source_label
    st.session_state["files_checked"] = files_checked
    st.session_state["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _analyse_staged_files(capture_uploads: list[object], config_uploads: list[object]) -> None:
    validate_upload_batch(capture_uploads, config_uploads)
    with tempfile.TemporaryDirectory(prefix="tunnelscope-") as temp_dir:
        root = Path(temp_dir)
        captures = stage_captures(capture_uploads, root / "captures") if capture_uploads else []
        configs = stage_configs(config_uploads, root / "configs") if config_uploads else []
        reports: list[AnalysisReport] = []
        findings: list[ConfigFinding] = []
        for capture in captures:
            reports.append(analyze_pcap(capture))
        for config in configs:
            findings.extend(analyze_config_file(config))
        names = [str(getattr(item, "name", "file")) for item in capture_uploads + config_uploads]
        _store_results(reports, findings, ", ".join(names[:3]) + (" …" if len(names) > 3 else ""), len(captures) + len(configs))


def _load_sample_case() -> None:
    st.session_state["action_error"] = ""
    try:
        with tempfile.TemporaryDirectory(prefix="tunnelscope-sample-") as temp_dir:
            capture, configs = write_sample_case(temp_dir)
            report = analyze_pcap(capture)
            findings = []
            for config in configs:
                findings.extend(analyze_config_file(config))
            _store_results([report], findings, "Synthetic training case", 1 + len(configs))
    except (ValueError, RuntimeError, OSError) as exc:
        st.session_state["action_error"] = f"Could not load the sample case: {exc}"
    except Exception:
        st.session_state["action_error"] = "The sample case could not be loaded. Check that app dependencies are installed."


def _sample_capture_bytes() -> bytes:
    with tempfile.TemporaryDirectory(prefix="tunnelscope-template-") as temp_dir:
        capture = build_demo_capture(Path(temp_dir) / "tunnelscope-sample.pcap")
        return capture.read_bytes()


def _page_intro(title: str, purpose: str, how_to_read: str) -> None:
    st.markdown(
        f"<div class='ts-section'><div class='ts-eyebrow'>{html.escape(title)}</div></div>",
        unsafe_allow_html=True,
    )
    st.caption(purpose)
    with st.expander("How to read this page"):
        st.write(how_to_read)


def _metric_card(label: str, value: object, detail: str) -> None:
    st.markdown(
        f"<div class='ts-card'><div class='ts-label'>{html.escape(str(label))}</div>"
        f"<div class='ts-value'>{html.escape(str(value))}</div>"
        f"<div class='ts-help'>{html.escape(str(detail))}</div></div>",
        unsafe_allow_html=True,
    )


def _aggregate_protocols(reports: list[AnalysisReport]) -> dict[str, int]:
    combined: Counter[str] = Counter()
    for report in reports:
        combined.update(report.protocols)
    return dict(combined)


def _all_packets(reports: list[AnalysisReport]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for report in reports:
        for packet in report.packets:
            rows.append({
                "Capture": report.capture_name,
                "Packet": packet.index + 1,
                "Time (epoch)": packet.timestamp,
                "Time": datetime.fromtimestamp(packet.timestamp, timezone.utc).strftime("%H:%M:%S.%f")[:-3]
                    if packet.timestamp > 0 else "—",
                "Source": packet.src,
                "Source port": packet.src_port if packet.src_port is not None else "—",
                "Destination": packet.dst,
                "Destination port": packet.dst_port if packet.dst_port is not None else "—",
                "Protocol": packet.protocol,
                "Exchange": packet.exchange or "—",
                "Length (bytes)": packet.length,
                "Details": packet.info,
            })
    return pd.DataFrame(rows)


def _all_events(reports: list[AnalysisReport]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for report in reports:
        for event in report.events:
            stamp = float(event.get("timestamp", 0))
            rows.append({
                "Capture": report.capture_name,
                "UTC time": datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                    if stamp > 0 else "—",
                "Offset (s)": event.get("time_offset", 0),
                "Source": event.get("src", ""),
                "Destination": event.get("dst", ""),
                "Protocol": event.get("protocol", ""),
                "Exchange": event.get("exchange", ""),
            })
    return pd.DataFrame(rows)


def _config_frame(findings: list[ConfigFinding]) -> pd.DataFrame:
    rows = []
    for item in findings:
        rows.append({
            "Priority": item.severity.title(),
            "Category": item.category.title(),
            "File": item.source,
            "Line": item.line or "—",
            "Finding": item.detail,
            "Issue code": item.issue,
            "Why it matters": RULE_HELP.get(item.issue, "This pattern warrants a context check."),
            "Suggested action": item.remediation,
        })
    return pd.DataFrame(rows)


def _render_summary(reports: list[AnalysisReport], findings: list[ConfigFinding]) -> None:
    if not st.session_state.get("analysis_complete"):
        st.info("No review has run yet. Load the fictional case or upload a capture and/or VPN configuration.")
        return
    counts = _severity_counts(findings)
    packets = sum(report.total_packets for report in reports)
    ipsec_packets = sum(report.ipsec_related for report in reports)
    critical_high = counts["critical"] + counts["high"]
    review_score = max((report.risk_score for report in reports), default=0.0)
    cols = st.columns(4)
    with cols[0]:
        _metric_card("Files reviewed", f"{st.session_state.get('files_checked', 0):,}", "Capture and config files")
    with cols[1]:
        _metric_card("Packets decoded", f"{packets:,}", "All packets in included captures")
    with cols[2]:
        _metric_card("IPsec packets", f"{ipsec_packets:,}", "Recognised IKE, ESP and AH")
    with cols[3]:
        _metric_card("Config priorities", f"{critical_high:,}", "Critical/high text-pattern matches")
    st.markdown(
        f"<div class='ts-note'><b>Key takeaway</b><br>"
        f"{html.escape(_summary_sentence(reports, findings))}</div>",
        unsafe_allow_html=True,
    )
    st.caption(
        f"Source: {st.session_state.get('source_label') or 'Not recorded'} · "
        f"Reviewed {st.session_state.get('checked_at') or '—'} · "
        f"Highest capture review indicator {review_score:.2f} (heuristic, not a probability)."
    )


def _summary_sentence(reports: list[AnalysisReport], findings: list[ConfigFinding]) -> str:
    critical_high = [item for item in findings if item.severity.lower() in {"critical", "high"}]
    messages = [anomaly for report in reports for anomaly in report.anomalies]
    if critical_high:
        first = sorted(critical_high, key=lambda item: ({"critical": 0, "high": 1}.get(item.severity.lower(), 9), item.line))[0]
        return (
            f"{len(critical_high)} configuration finding(s) are marked critical or high priority for review. "
            f"Start with {first.detail} in {first.source}"
            f"{':' + str(first.line) if first.line else ''}; validate the effective VPN policy before changing it."
        )
    if messages:
        return f"{len(messages)} capture observation(s) need context review. First: {messages[0]}. "
        "A missing handshake can reflect capture filters or where the traffic was observed."
    if findings:
        return f"{len(findings)} configuration pattern(s) were found, none labelled critical/high. Validate them against your security baseline."
    if reports:
        return "No configured capture anomaly rule matched the decoded packets. This is not proof that the VPN is secure."
    return "Only configuration text was reviewed; add a capture to analyse negotiation and ESP/AH packet visibility."


def _plotly_theme() -> dict[str, Any]:
    text = "#152333" if st.session_state.get("theme_mode") == "Light" else "#d9e2f0"
    grid = "rgba(50,70,90,.16)" if st.session_state.get("theme_mode") == "Light" else "rgba(150,170,195,.15)"
    return {
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "font": {"color": text},
        "margin": {"l": 8, "r": 8, "t": 48, "b": 8},
        "xaxis": {"gridcolor": grid},
        "yaxis": {"gridcolor": grid},
    }


def _protocol_chart(reports: list[AnalysisReport], compact: bool = False) -> None:
    protocol_counts = _aggregate_protocols(reports)
    protocol_counts = {key: value for key, value in protocol_counts.items() if value}
    if not protocol_counts:
        st.markdown("<div class='ts-card'><b>No capture packet data</b><p class='ts-muted'>Upload a PCAP/PCAPNG to see protocol counts. Configuration-only scans still provide config findings.</p></div>", unsafe_allow_html=True)
        return
    order = ["IKEv2", "IKE", "ESP", "AH", "NAT-T keepalive", "UDP/500 or 4500", "Other"]
    rows = [{"Protocol": key, "Packets": value} for key, value in protocol_counts.items()]
    df = pd.DataFrame(rows)
    df["sort"] = df["Protocol"].apply(lambda value: order.index(value) if value in order else len(order))
    df = df.sort_values(["sort", "Packets"], ascending=[True, False]).drop(columns="sort")
    fig = px.bar(
        df, x="Protocol", y="Packets", color="Protocol",
        title="Recognised protocol packets",
        color_discrete_map={
            "IKEv2": ACCENT, "IKE": "#9b8cff", "ESP": "#6fbfa0", "AH": "#e2b15a",
            "NAT-T keepalive": "#7eb6ff", "UDP/500 or 4500": "#b79bff", "Other": "#8d9ab1",
        },
    )
    fig.update_layout(height=310 if compact else 360, showlegend=False, **_plotly_theme())
    fig.update_xaxes(title=None, showgrid=False)
    fig.update_yaxes(title="Packet count", rangemode="tozero")
    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
    most_common = max(protocol_counts.items(), key=lambda item: item[1])
    st.caption(
        f"Key takeaway: {most_common[0]} is the most common recognised category ({most_common[1]} packet(s)). "
        "Non-IP and unrelated packets may also be present in the capture."
    )


def _render_top_config_findings(findings: list[ConfigFinding], limit: int = 5) -> None:
    if not findings:
        st.success("No configured VPN text-pattern rule matched the uploaded config. Confirm that the correct file and full connection policy were included.")
        return
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    items = sorted(findings, key=lambda item: (order.get(item.severity.lower(), 9), item.source, item.line))
    for item in items[:limit]:
        css = "danger" if item.severity.lower() in {"critical", "high"} else ("warn" if item.severity.lower() == "medium" else "")
        location = f"{item.source}:{item.line}" if item.line else item.source
        st.markdown(
            f"<div class='ts-note {css}'><span class='ts-badge'>{html.escape(item.severity.upper())}</span>"
            f"<b>{html.escape(item.detail)}</b><div class='ts-muted'>{html.escape(location)} · {html.escape(item.issue)}</div>"
            f"<p>{html.escape(RULE_HELP.get(item.issue, 'Review the pattern in context.'))}</p>"
            f"<div class='ts-muted'><b>Suggested next step:</b> {html.escape(item.remediation)}</div></div>",
            unsafe_allow_html=True,
        )


def _overview(reports: list[AnalysisReport], findings: list[ConfigFinding]) -> None:
    st.markdown(
        "<div class='ts-hero'><div class='ts-eyebrow'>VPN security review · local-first</div>"
        "<h1>TunnelScope</h1><p>See what your IPsec capture actually shows, review IKE negotiation patterns, "
        "and surface legacy settings in strongSwan or Cisco-style VPN configurations — without uploading evidence to a service.</p>"
        "<span class='ts-chip'>PCAP / PCAPNG</span><span class='ts-chip'>No paid key</span>"
        "<span class='ts-chip'>ESP stays encrypted</span></div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<div class='ts-flow'><span>1 · Upload<small>Capture and config files</small></span>"
        "<span>2 · Validate<small>Format and size checks</small></span>"
        "<span>3 · Review<small>Negotiation and config signals</small></span>"
        "<span>4 · Report<small>Evidence and next steps</small></span></div>",
        unsafe_allow_html=True,
    )
    left, right = st.columns([1.15, 1])
    with left:
        st.markdown("### Start a review")
        st.write("Load a fictional training case or choose your own PCAP and VPN configuration.")
        c1, c2 = st.columns(2)
        with c1:
            if st.button(
                "Load sample case", type="primary", use_container_width=True,
                help="Analyse a generated four-packet IKEv2/ESP trace and fictional weak VPN configurations.",
            ):
                try:
                    with st.spinner("Generating and analysing the fictional case…"):
                        _load_sample_case()
                    st.success("Sample review complete.")
                except (ValueError, RuntimeError, OSError) as exc:
                    st.error(f"Could not load the sample case: {exc}")
                except Exception:
                    st.error("The sample case could not be loaded. Check that the app dependencies are installed.")

        with c2:
            st.button(
                "Upload my files", use_container_width=True,
                help="Open capture and configuration upload.",
                on_click=_go_to, args=("Upload & Configure",),
            )
        st.download_button(
            "Download sample PCAP", _sample_capture_bytes(),
            file_name="tunnelscope-sample.pcap", mime="application/vnd.tcpdump.pcap",
            use_container_width=True,
            help="A valid small PCAP built with fictional documentation-only IP addresses.",
        )
        config_col1, config_col2 = st.columns(2)
        with config_col1:
            st.download_button("Download strongSwan config", SAMPLE_STRONGSWAN,
                               file_name="strongswan-sample.conf", mime="text/plain", use_container_width=True)
        with config_col2:
            st.download_button("Download Cisco config", SAMPLE_CISCO,
                               file_name="cisco-sample.cfg", mime="text/plain", use_container_width=True)
    with right:
        st.markdown("### Designed for")
        st.markdown(
            "<div class='ts-card'><b>VPN administrators</b><p class='ts-muted'>Check negotiation visibility and legacy proposals.</p>"
            "<b>Network defenders</b><p class='ts-muted'>Review authorised packet captures without sending them to a cloud analyzer.</p>"
            "<b>Students and trainers</b><p class='ts-muted'>Learn how IKE, ESP, and configuration findings relate to a review.</p></div>",
            unsafe_allow_html=True,
        )
    st.markdown("<div class='ts-section'><h3>Latest review</h3></div>", unsafe_allow_html=True)
    if st.session_state.get("analysis_complete"):
        _render_summary(reports, findings)
        c1, c2 = st.columns([1, 1])
        with c1:
            _protocol_chart(reports, compact=True)
        with c2:
            st.markdown("#### Configuration review priorities")
            _render_top_config_findings(findings, 4)
    else:
        st.markdown(
            "<div class='ts-card'><div class='ts-label'>Ready for input</div>"
            "<div class='ts-value'>No files analysed yet</div>"
            "<div class='ts-help'>The sample uses fictional data. Your captures and configs are staged in a temporary folder only while analysis runs.</div></div>",
            unsafe_allow_html=True,
        )
    st.caption("Anomaly indicators are transparent rules for review, not exploitability probabilities or formal compliance results.")


def _upload_page() -> None:
    _page_intro(
        "Upload & configure",
        "Add one or more PCAP/PCAPNG captures and/or VPN configuration files. The files are processed locally and the temporary copies are removed after analysis.",
        "Upload a complete capture for the best view of negotiation order. Capture packet filters and collection points affect which packets are present. Add strongSwan or Cisco-style configuration text to check proposals and settings. A configuration-only review is allowed.",
    )
    st.markdown("#### 1. Upload packet captures")
    captures = st.file_uploader(
        "Capture files",
        type=["pcap", "pcapng"],
        accept_multiple_files=True,
        key="capture_uploads",
        help="PCAP and PCAPNG are supported. Each capture is limited to 100 MB; total selected uploads are limited to 100 MB.",
    )
    st.markdown("#### 2. Upload VPN configurations (optional)")
    configs = st.file_uploader(
        "Configuration files",
        type=[item.lstrip(".") for item in sorted(CONFIG_EXTENSIONS)],
        accept_multiple_files=True,
        key="config_uploads",
        help="Add strongSwan (.conf/.ini) or Cisco-style (.cfg/.txt) text config. Each config is limited to 5 MB.",
    )
    selected = list(captures or []) + list(configs or [])
    if selected:
        preview = []
        for item in selected:
            payload = item.getvalue()
            preview.append({
                "Type": "Capture" if Path(item.name).suffix.lower() in CAPTURE_EXTENSIONS else "VPN config",
                "File": item.name,
                "Size": f"{len(payload) / 1024:.1f} KB",
                "Preview": "Binary capture — contents not rendered" if Path(item.name).suffix.lower() in CAPTURE_EXTENSIONS
                    else _preview_config(payload),
            })
        st.dataframe(pd.DataFrame(preview), hide_index=True, width="stretch")
    else:
        st.info("No files selected. Use the template buttons below or load the sample case.")
    a, b, c = st.columns([1.2, 1, 1])
    with a:
        analyse_clicked = st.button(
            "Analyse selected files", type="primary", use_container_width=True, disabled=not selected,
            help="Parse selected captures and check selected VPN config lines.",
        )
        if analyse_clicked:
            try:
                with st.spinner("Validating uploads and analysing packet/configuration data…"):
                    _analyse_staged_files(list(captures or []), list(configs or []))
                st.success("Review complete. Temporary uploaded copies have been removed.")
            except (ValueError, FileNotFoundError, RuntimeError, OSError) as exc:
                st.error(f"Could not analyse these files: {exc}")
            except Exception:
                st.error("The review could not be completed. Try a smaller capture or verify the file format.")

    with b:
        st.button("Load sample case", use_container_width=True, on_click=_load_sample_case,
                  help="Loads a four-packet synthetic IKEv2/ESP capture plus fictional strongSwan and Cisco configs.")
    with c:
        st.download_button(
            "Download sample PCAP", _sample_capture_bytes(), file_name="tunnelscope-sample.pcap",
            mime="application/vnd.tcpdump.pcap", use_container_width=True,
        )
    with st.expander("Download config templates"):
        c1, c2 = st.columns(2)
        with c1:
            st.download_button("strongSwan template", SAMPLE_STRONGSWAN, "strongswan-sample.conf", "text/plain", use_container_width=True)
        with c2:
            st.download_button("Cisco-style template", SAMPLE_CISCO, "cisco-sample.cfg", "text/plain", use_container_width=True)
    if st.session_state.get("analysis_complete"):
        st.markdown("<div class='ts-section'><h3>Most recent analysis</h3></div>", unsafe_allow_html=True)
        reports = _reports()
        findings = _config_findings()
        _render_summary(reports, findings)
        if reports:
            _protocol_chart(reports, compact=True)
        _render_top_config_findings(findings, 3)
        st.button("Review results", on_click=_go_to, args=("Packet Explorer",), help="Open packet rows and metadata filters.")


def _timeline_page(reports: list[AnalysisReport]) -> None:
    _page_intro(
        "Negotiation timeline",
        "Follow visible IKE exchange messages in capture time order and compare activity across captures.",
        "The timeline includes only packets where the fixed IKE header was recognised. It cannot see encrypted ESP contents or infer negotiation messages that were not captured. Relative offsets are useful for sequence; timestamps depend on the capture clock.",
    )
    events = _all_events(reports)
    if events.empty:
        st.info("No recognised IKE exchange headers are in the current review. Load the sample case or analyse a capture containing IKE traffic.")
        st.button("Upload a capture", on_click=_go_to, args=("Upload & Configure",), type="primary")
        return
    left, right = st.columns([1, 1])
    with left:
        choices = sorted(events["Protocol"].dropna().unique().tolist())
        selected_protocols = st.multiselect("Protocol", choices, default=choices,
                                            help="Filter visible negotiation events.")
    with right:
        max_offset = max(1.0, float(events["Offset (s)"].max()))
        lower, upper = st.slider(
            "Capture-relative seconds",
            min_value=0.0, max_value=max_offset,
            value=(0.0, max_offset), step=max(0.1, max_offset / 100),
            help="The slider filters the events shown by their offset from the start of each capture.",
        )
    view = events[
        events["Protocol"].isin(selected_protocols)
        & (events["Offset (s)"] >= lower)
        & (events["Offset (s)"] <= upper)
    ]
    figure = px.scatter(
        view, x="Offset (s)", y="Capture", color="Protocol", symbol="Exchange",
        hover_data=["UTC time", "Source", "Destination", "Exchange"],
        title="Recognised IKE messages over capture time",
        color_discrete_map={"IKEv2": ACCENT, "IKE": "#9b8cff"},
    )
    figure.update_layout(height=360, **_plotly_theme())
    figure.update_xaxes(title="Seconds after capture start")
    figure.update_yaxes(title=None)
    st.plotly_chart(figure, width="stretch", config={"displayModeBar": False})
    st.caption(
        f"Key takeaway: {len(view)} of {len(events)} recognised IKE event(s) are visible in this time window. "
        "This describes captured messages, not a complete VPN state-machine reconstruction."
    )
    st.dataframe(view, hide_index=True, width="stretch")
    if view.empty:
        st.info("No events match the current timeline filters.")


def _configuration_page(findings: list[ConfigFinding]) -> None:
    _page_intro(
        "Configuration review",
        "Review line-aware VPN configuration signals for legacy encryption, hashes, DH groups, authentication choices, and IKEv1 aggressive mode.",
        "The checks are text-pattern rules, not a complete parser for every strongSwan version or Cisco platform. Confirm that the configuration is active and review all peers and inherited policies before changing it.",
    )
    if not st.session_state.get("analysis_complete"):
        st.info("Run a review to see configuration signals.")
        st.button("Load sample case", type="primary", on_click=_load_sample_case)
        return
    if not findings:
        st.success("No configured VPN text-pattern rule matched the uploaded configuration.")
        st.caption("This does not prove the VPN policy is secure. Confirm the complete configuration and platform-specific settings.")
        return
    counts = _severity_counts(findings)
    top_cols = st.columns(4)
    for i, level in enumerate(("critical", "high", "medium", "info")):
        with top_cols[i]:
            _metric_card(level.title(), counts[level], "Matched configuration lines")
    chart_df = pd.DataFrame([{"Priority": level.title(), "Findings": counts[level]} for level in SEVERITY_ORDER])
    fig = px.bar(
        chart_df, x="Priority", y="Findings", color="Priority", title="Configuration review signals by priority",
        color_discrete_map={key.title(): value for key, value in SEVERITY_COLORS.items()},
        category_orders={"Priority": [key.title() for key in SEVERITY_ORDER]},
    )
    fig.update_layout(height=320, showlegend=False, **_plotly_theme())
    fig.update_xaxes(title=None, showgrid=False)
    fig.update_yaxes(title="Matched lines", rangemode="tozero")
    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
    dominant = max(counts.items(), key=lambda item: item[1])
    st.caption(f"Key takeaway: {dominant[1]} finding(s) are labelled {dominant[0]} in this configuration review; severity is a triage label, not exploitability.")
    df = _config_frame(findings)
    c1, c2 = st.columns([1, 1.4])
    with c1:
        selected = st.multiselect("Priority filter", [item.title() for item in SEVERITY_ORDER],
                                  default=[item.title() for item in SEVERITY_ORDER],
                                  help="Show only selected review priority levels.")
    with c2:
        query = st.text_input("Search config findings", placeholder="Try modp1024, AES, cisco-sample.cfg…",
                              help="Search file, finding, category, or suggested action.")
    view = df[df["Priority"].isin(selected)]
    if query:
        mask = view.astype(str).apply(lambda column: column.str.contains(query, case=False, regex=False)).any(axis=1)
        view = view[mask]
    st.dataframe(view, hide_index=True, width="stretch")
    st.download_button(
        "Download filtered config CSV", view.to_csv(index=False).encode("utf-8"),
        file_name="tunnelscope-config-findings.csv", mime="text/csv",
        help="Exports the current filtered configuration finding list.",
    )
    _render_top_config_findings(
        [item for item in findings if not query or query.lower() in " ".join((item.detail, item.source, item.remediation)).lower()],
        10,
    )


def _packet_page(reports: list[AnalysisReport]) -> None:
    _page_intro(
        "Packet explorer",
        "Search decoded packet metadata, filter by protocol, and inspect endpoints, ports, sizes and exchange names.",
        "Packet rows describe visible headers and protocol classifications only. ESP payloads stay encrypted and are not shown. A row classified as an IKE-like port without a recognised header is deliberately kept separate from confirmed IKE.",
    )
    df = _all_packets(reports)
    if df.empty:
        st.info("No capture packet rows are available. Upload a PCAP/PCAPNG or load the sample case.")
        st.button("Upload a capture", type="primary", on_click=_go_to, args=("Upload & Configure",))
        return
    c1, c2 = st.columns([1, 1.3])
    protocols = sorted(df["Protocol"].unique().tolist())
    with c1:
        selected = st.multiselect("Protocols", protocols, default=protocols, help="Filter the packet table.")
    with c2:
        query = st.text_input("Search packets", placeholder="192.0.2.10, IKE_SA_INIT, ESP…",
                              help="Search visible endpoint, protocol, exchange and details fields.")
    view = df[df["Protocol"].isin(selected)]
    if query:
        mask = view.astype(str).apply(lambda column: column.str.contains(query, case=False, regex=False)).any(axis=1)
        view = view[mask]
    st.caption(f"{len(view):,} packet(s) shown out of {len(df):,}. Displayed rows are header metadata; the app does not decrypt payloads.")
    st.dataframe(
        view.head(5_000), hide_index=True, width="stretch",
        column_config={
            "Time (epoch)": st.column_config.NumberColumn("Packet timestamp (epoch seconds)", format="%.3f"),
            "Length (bytes)": st.column_config.NumberColumn("Length", format="%d"),
        },
    )
    st.download_button(
        "Download visible packets CSV",
        build_packets_csv(reports).encode("utf-8") if len(view) == len(df) else view.drop(columns=["Time (epoch)", "Time"]).to_csv(index=False).encode("utf-8"),
        file_name="tunnelscope-packets.csv", mime="text/csv",
        help="Exports packet header metadata, not raw packet bytes or decrypted content.",
    )
    if not view.empty:
        summary = view["Protocol"].value_counts()
        first = summary.index[0]
        st.markdown(
            f"<div class='ts-note'><b>Key takeaway</b><br>{html.escape(str(summary[first]))} packet(s) in the current view are classified as {html.escape(str(first))}. "
            "Classifications are based on the visible protocol headers and selected IKE fields.</div>",
            unsafe_allow_html=True,
        )


def _reports_page(reports: list[AnalysisReport], findings: list[ConfigFinding]) -> None:
    _page_intro(
        "Reports",
        "Export findings for a ticket, peer review, or offline audit trail.",
        "The report includes capture summary metrics and configuration findings. It does not include raw PCAP payload bytes. Review endpoint addresses and filenames before sending the output outside your team.",
    )
    if not st.session_state.get("analysis_complete"):
        st.info("Run a review before exporting. Load the synthetic sample to see the full report workflow.")
        st.button("Load sample case", type="primary", on_click=_load_sample_case)
        return
    _render_summary(reports, findings)
    json_text = build_report_json(reports, findings)
    html_text = build_html_report(reports, findings)
    md_text = "\n".join([
        "# TunnelScope Review",
        "",
        f"Source: {st.session_state.get('source_label', 'Uploaded files')}",
        f"Reviewed: {st.session_state.get('checked_at', '')}",
        "",
        remediation_report(reports[0], findings) if reports else "# Configuration Review\n\n" + "\n".join(
            f"- [{item.severity.upper()}] {item.source}:{item.line} {item.detail} — {item.remediation}"
            for item in findings
        ),
    ])
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button("Download HTML review", html_text.encode("utf-8"),
                           file_name="tunnelscope-review.html", mime="text/html", use_container_width=True)
        st.caption("Styled capture and config review with recommended next steps.")
    with c2:
        st.download_button("Download JSON", json_text.encode("utf-8"),
                           file_name="tunnelscope-review.json", mime="application/json", use_container_width=True)
        st.caption("Structured results for archival or scripting.")
    with c3:
        st.download_button("Download packet CSV", build_packets_csv(reports).encode("utf-8"),
                           file_name="tunnelscope-packets.csv", mime="text/csv", use_container_width=True)
        st.caption("Header-level packet table; no raw payloads.")
    c4, c5 = st.columns(2)
    with c4:
        pdf_available = _reportlab_available()
        if pdf_available:
            pdf_bytes = build_pdf_report(reports, findings)
            st.download_button("Download PDF review", pdf_bytes, file_name="tunnelscope-review.pdf",
                               mime="application/pdf", use_container_width=True)
        else:
            st.button("PDF export unavailable", disabled=True, use_container_width=True,
                      help="Enable optional PDF support with python -m pip install -e .[reports].")
            st.caption("PDF export is optional. Enable it with python -m pip install -e .[reports].")
    with c5:
        st.download_button("Download remediation notes", md_text.encode("utf-8"),
                           file_name="tunnelscope-remediation.md", mime="text/markdown", use_container_width=True)
        st.caption("Prioritised observations and the suggested review order.")
    st.markdown("<div class='ts-section'><h3>What to do next</h3></div>", unsafe_allow_html=True)
    priorities = []
    critical_high = [item for item in findings if item.severity.lower() in {"critical", "high"}]
    if critical_high:
        priorities.append("Verify the critical/high configuration lines against the active policy and both tunnel peers.")
    if any(report.anomalies for report in reports):
        priorities.append("Check capture placement, filters, and whether negotiation packets are missing from the trace.")
    if any(item.issue == "psk_auth" for item in findings):
        priorities.append("Review shared-secret entropy, uniqueness, storage and rotation; this signal does not by itself mean the secret is weak.")
    priorities.append("Apply one change at a time, collect a fresh authorised capture, and compare the review.")
    for idx, item in enumerate(priorities, start=1):
        st.markdown(f"<div class='ts-note'><b>{idx}.</b> {html.escape(item)}</div>", unsafe_allow_html=True)


def _reportlab_available() -> bool:
    try:
        import reportlab  # noqa: F401
        return True
    except ImportError:
        return False


def _glossary_page() -> None:
    _page_intro(
        "Glossary",
        "Simple definitions for terms used in TunnelScope.",
        "This glossary explains packet and VPN configuration terminology in everyday language. The analyzer uses heuristic rules and cannot confirm whether a configured option was negotiated or used by live traffic.",
    )
    entries = [
        ("AH", "Authentication Header: IPsec protocol providing packet integrity and data-origin authentication, without encrypting the payload."),
        ("ESP", "Encapsulating Security Payload: IPsec protocol commonly used to protect packet confidentiality and integrity. TunnelScope does not decrypt it."),
        ("IKE", "Internet Key Exchange: protocol used by VPN peers to negotiate security associations and key material."),
        ("IKEv1", "The first major IKE version. Some legacy modes and configurations have privacy or security drawbacks."),
        ("IKEv2", "A later IKE version with a more structured exchange flow and modern configuration options."),
        ("NAT-T", "NAT Traversal: encapsulation that carries IPsec traffic through devices performing network address translation, usually over UDP 4500."),
        ("PCAP / PCAPNG", "Common packet capture file formats used by network analysis tools."),
        ("Pre-shared key (PSK)", "A secret known to both VPN peers. It should be unique, high-entropy, rotated and protected."),
        ("Diffie–Hellman (DH) group", "A set of parameters used by peers to establish shared key material. Legacy groups may offer insufficient security."),
        ("Proposal", "The set of encryption, integrity, key-exchange and related settings that a VPN peer offers during negotiation."),
        ("Review indicator", "A rule-based score that helps prioritise review; it is not a probability, formal rating, or proof of compromise."),
    ]
    for term, definition in entries:
        st.markdown(
            f"<div class='ts-card' style='margin-bottom:9px'><b>{html.escape(term)}</b>"
            f"<p class='ts-muted'>{html.escape(definition)}</p></div>",
            unsafe_allow_html=True,
        )
    st.markdown("<div class='ts-section'><h3>What this tool cannot prove</h3></div>", unsafe_allow_html=True)
    st.write(
        "TunnelScope reads visible packet headers and text configuration patterns. It does not decrypt ESP, "
        "reconstruct every IKE state transition, guarantee capture completeness, validate every vendor-specific setting, "
        "or determine that a VPN is compromised. Confirm important findings against the active system policy."
    )


def main() -> None:
    st.set_page_config(page_title="TunnelScope · IPsec Review", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    _init_state()
    logo = _logo_data_uri()
    with st.sidebar:
        if logo:
            st.markdown(
                f"<div style='display:flex;align-items:center;gap:11px;margin:4px 0 8px'>"
                f"<img src='{logo}' alt='TunnelScope logo' width='54' height='54'>"
                f"<div><div class='ts-brand'>TUNNELSCOPE</div>"
                f"<div class='ts-muted'>IPSEC REVIEW WORKSPACE</div></div></div>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown("### 🛡️ TunnelScope")
        st.caption("Local-first IPsec/IKE review")
        st.radio("Workspace", NAVIGATION, key="current_page", label_visibility="collapsed",
                 help="Open the overview, upload files, review negotiation time, configuration findings, packets, reports or the glossary.")
        st.divider()
        st.radio("Appearance", ["Dark", "Light"], key="theme_mode", horizontal=True,
                 help="Switch between the shared dark and light visual themes.")
        status = "REVIEW COMPLETE" if st.session_state.get("analysis_complete") else "AWAITING INPUT"
        st.markdown(f"<span class='ts-badge'>{status}</span>", unsafe_allow_html=True)
        st.caption("CPU-only · no API key · local analysis")
        if st.session_state.get("analysis_complete"):
            st.caption(f"{sum(report.total_packets for report in _reports()):,} packets · {len(_config_findings())} config findings")
        st.button("Reset this review", on_click=_reset_session,
                  help="Clear results in this Streamlit session. Original files on disk are not changed.")

    st.markdown(theme_css(ACCENT, st.session_state["theme_mode"]), unsafe_allow_html=True)
    st.markdown(
        "<div class='ts-topbar'><div class='ts-brand'>TUNNELSCOPE</div>"
        "<div class='ts-topnote'>IPsec &amp; IKE protocol review</div>"
        "<div class='ts-local'>● LOCAL-FIRST</div></div>",
        unsafe_allow_html=True,
    )
    if st.session_state.get("action_error"):
        st.error(st.session_state["action_error"])
        st.session_state["action_error"] = ""

    page = st.session_state["current_page"]
    reports = _reports()
    findings = _config_findings()
    if page == "Overview":
        _overview(reports, findings)
    elif page == "Upload & Configure":
        _upload_page()
    elif page == "Negotiation Timeline":
        _timeline_page(reports)
    elif page == "Configuration Review":
        _configuration_page(findings)
    elif page == "Packet Explorer":
        _packet_page(reports)
    elif page == "Reports":
        _reports_page(reports, findings)
    else:
        _glossary_page()
    st.markdown(
        "<div class='ts-muted' style='margin-top:24px'>TunnelScope reports captured metadata and text-pattern signals only. "
        "Keep live captures and VPN configuration files access-controlled; they may contain sensitive infrastructure information.</div>",
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
