from pathlib import Path
from src.analyzer import analyze_pcap

def test_analyze_demo():
    p = Path(__file__).resolve().parents[1] / "data" / "sample" / "demo_ipsec.pcap"
    if not p.exists():
        import subprocess, sys
        subprocess.check_call([sys.executable, str(p.parents[2] / "scripts" / "generate_demo_data.py")])
    r = analyze_pcap(p)
    assert r.total_packets >= 1
    assert r.ipsec_related >= 1
