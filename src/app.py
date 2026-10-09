"""IPsec inspection console."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import pandas as pd
import plotly.express as px
import streamlit as st
from src.analyzer import analyze_pcap
from src.ipsec_features import handshake_anomaly_score, remediation_report
from src.ui_theme import theme_css

def main() -> None:
    st.set_page_config(page_title="IPsec Analyzer", layout="wide")
    st.markdown(theme_css("#5aa6c8"), unsafe_allow_html=True)
    st.markdown('<div class="top"><div><div class="kicker">Network security</div><p class="title">IPsec protocol analyzer</p></div><div class="pill">Local capture · no live attack</div></div>', unsafe_allow_html=True)
    sample = ROOT / "data" / "sample" / "demo_ipsec.pcap"
    upload = st.sidebar.file_uploader("PCAP", type=["pcap", "pcapng"])
    target = sample
    if upload is not None:
        target = ROOT / "data" / "uploads" / Path(upload.name).name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(upload.getvalue())
    if not target.exists():
        st.markdown('<div class="panel"><p class="muted">No capture loaded. Run <code>python scripts/generate_demo_data.py</code> or upload a .pcap.</p></div>', unsafe_allow_html=True)
        return
    try:
        report = analyze_pcap(target)
    except Exception as exc:
        st.markdown('<div class="panel"><p class="title">Analysis failed</p><p class="muted">The file could not be parsed. Use a classic pcap or the sample capture.</p></div>', unsafe_allow_html=True)
        st.caption(str(exc))
        return
    score = handshake_anomaly_score(report)
    st.markdown(f'<div class="panel"><div class="kicker">Capture</div><p class="title">{report.total_packets} packets · risk {report.risk_score:.2f}</p><p class="muted">IKE {report.ike_count} · IKEv2 {report.ikev2_count} · ESP {report.esp_count} · AH {report.ah_count}</p></div>', unsafe_allow_html=True)
    if report.packets:
        df = pd.DataFrame([p.__dict__ for p in report.packets])
        fig = px.bar(df.groupby("protocol").size().reset_index(name="count"), x="protocol", y="count", title="Protocols in capture")
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e7ecf3", height=320)
        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(df, use_container_width=True, hide_index=True)
    if report.anomalies:
        for a in report.anomalies:
            st.warning(a)
    st.markdown("### Remediation")
    st.code(remediation_report(report))
    st.caption(str(score))

if __name__ == "__main__":
    main()
