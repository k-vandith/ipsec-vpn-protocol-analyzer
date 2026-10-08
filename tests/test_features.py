from src.ipsec_features import parse_strongswan_config, remediation_report
from src.analyzer import AnalysisReport

def test_config_parse():
    text = "conn %default\nike=aes128-sha1-modp1024\naggressive=yes\n"
    f = parse_strongswan_config(text)
    assert any(x.issue=="aggressive_mode" for x in f)

def test_remediation():
    r = AnalysisReport(total_packets=1, risk_score=0.2)
    assert "Remediation" in remediation_report(r, [])
