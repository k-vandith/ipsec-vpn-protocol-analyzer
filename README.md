# IPsec VPN Protocol Analyzer

Offline analyzer for IPsec-related traffic captures: detects IKE/ISAKMP and ESP patterns, summarizes proposals, and flags anomalous configuration indicators for defensive review.

## Problem Statement

VPN misconfiguration and weak IKE proposals remain a common enterprise risk. Teams need a portable tool to inspect PCAPs for IPsec negotiation behaviour without shipping captures to cloud analyzers.

## Overview

Load a PCAP (or demo capture), detect IKE and ESP-related packets, summarise exchange patterns, and present findings in a Streamlit UI or CLI-friendly report.

## Features

- **PCAP loading** via Scapy
- **IKE / ISAKMP heuristics** – exchange detection
- **ESP presence** – encrypted payload indicators
- **Summary reports** – counts, peers, proposal hints
- **Streamlit dashboard** – interactive review
- **Demo PCAP generator** – no live network required

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Streamlit  │────▶│   Analyzer   │────▶│    Scapy    │
│     UI      │     │              │     │  PCAP parse │
└─────────────┘     └──────┬───────┘     └─────────────┘
                           │
                    ┌──────▼───────┐
                    │  Report JSON │
                    └──────────────┘
```

## Tech Stack

- Python 3.11+
- Scapy
- Streamlit + Plotly
- Pandas
- pytest

## Repository Structure

```
ipsec-vpn-protocol-analyzer/
├── README.md
├── requirements.txt
├── src/
│   └── analyzer.py
├── tests/
│   └── test_analyzer.py
├── data/
├── scripts/
│   ├── setup_env.py
│   ├── setup.sh
│   ├── setup.ps1
│   └── generate_demo_data.py
└── docs/
```

## System Requirements

| Mode | CPU | RAM | Disk | GPU |
|------|-----|-----|------|-----|
| Demo | Any | 2 GB | 1 GB | Not needed |

## Installation

### Recommended (all platforms) — automated bootstrap

Handles missing `ensurepip`, symlink restrictions, and installs dependencies into `.venv`:

```bash
git clone https://github.com/k-vandith/ipsec-vpn-protocol-analyzer.git
cd ipsec-vpn-protocol-analyzer
python3 scripts/setup_env.py    # or:  python scripts/setup_env.py
```

Then activate:

```bash
# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

### Manual setup

#### Windows (PowerShell)

```powershell
git clone https://github.com/k-vandith/ipsec-vpn-protocol-analyzer.git
cd ipsec-vpn-protocol-analyzer
python -m venv .venv --copies
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### Linux / macOS

```bash
git clone https://github.com/k-vandith/ipsec-vpn-protocol-analyzer.git
cd ipsec-vpn-protocol-analyzer
# If venv fails with ensurepip errors:
#   sudo apt install python3-venv python3-pip
python3 -m venv .venv --copies
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Why `--copies`?

Some environments cannot create symlinks inside a venv (`Operation not permitted` on `lib64 → lib`). Using `--copies` avoids that. `scripts/setup_env.py` tries `--copies` first automatically.

## Environment Variables

None required.

## Dataset / Demo Mode

```bash
python scripts/generate_demo_data.py
```

Writes a synthetic capture under `data/` for offline analysis.

## Running the Application

```bash
streamlit run src/analyzer.py
# or programmatic:
python -c "from src.analyzer import analyze; print(analyze('data/demo.pcap'))"
```

## API Usage

```python
from src.analyzer import analyze_pcap
report = analyze_pcap("data/demo.pcap")
print(report)
```

## Testing

```bash
pytest -v
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `ModuleNotFoundError: src` | Run from project root; ensure `PYTHONPATH=.` |
| `venv` / ensurepip fails | Run `python3 scripts/setup_env.py` or install `python3-venv` |
| `Operation not permitted` on lib64 | Use `python3 -m venv .venv --copies` |
| Missing dependency | Activate `.venv` and re-run `pip install -r requirements.txt` |

## Limitations

- Heuristic protocol detection; not a full IKEv2 state machine.
- Encrypted payloads are not decrypted (by design).
- Large PCAPs may need more memory.

## Security / Privacy

- Defensive analysis only — do not use to attack VPN endpoints.
- Keep real customer captures offline and access-controlled.

## Future Improvements

- Deeper IKEv2 proposal parsing
- Timeline visualisation of negotiations
- Integration with Zeek/Suricata logs

## License

MIT
