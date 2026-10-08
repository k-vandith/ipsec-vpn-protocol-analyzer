# IPsec VPN Protocol Analyzer

Defensive offline PCAP analysis platform for IPsec / IKE / ESP / AH detection, session analysis, anomaly detection and risk scoring.

## Installation

### Linux / macOS
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Windows PowerShell
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Demo
```bash
python scripts/generate_demo_data.py
python -c "from src.analyzer import analyze_pcap; r=analyze_pcap('data/sample/demo_ipsec.pcap'); print(r)"
```

## Testing
```bash
pytest -v
```

## Limitations
Demo uses synthetic marker-based captures. For real PCAPs install scapy and extend parsing. Offensive features are intentionally excluded.

## License
MIT
