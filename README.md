<p align="center">
  <img src="assets/tunnelscope-mark.svg" alt="TunnelScope logo" width="92" />
</p>

<h1 align="center">TunnelScope</h1>
<p align="center">
  <strong>See the negotiation. Find the weak settings. Know what to review first.</strong><br />
  Local-first IPsec and IKE packet-capture analysis for VPN administrators, defenders, and students.
</p>

<p align="center">
  <a href="https://github.com/k-vandith/ipsec-vpn-protocol-analyzer/actions/workflows/tests.yml"><img src="https://github.com/k-vandith/ipsec-vpn-protocol-analyzer/actions/workflows/tests.yml/badge.svg?branch=main" alt="Tests" /></a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/Streamlit-workspace-FF4B4B?logo=streamlit&logoColor=white" alt="Streamlit" />
  <img src="https://img.shields.io/badge/analysis-local--first-70d4e2?labelColor=0b0d14" alt="Local-first" />
  <img src="https://img.shields.io/badge/license-MIT-64748b" alt="MIT License" />
</p>

---

## What is TunnelScope?

TunnelScope is the guided workspace for **IPsec VPN Protocol Analyzer**. It reads PCAP/PCAPNG captures with Scapy, identifies visible IKEv1/IKEv2, ESP, AH, and NAT-T patterns, and checks strongSwan or Cisco-style configuration text for legacy proposals and settings.

- **Understand the capture:** protocol counts, peer pairs, packet metadata, and an IKE exchange timeline.
- **Review VPN configuration:** findings with file/line references, priority labels, plain-English context, and suggested actions.
- **Export your review:** HTML and JSON reports, CSV packet details, remediation notes, plus optional PDF.

TunnelScope is a local, rule-based review aid. It is not a full IKE state-machine validator, a decryption tool, a probability of compromise, or a formal security rating.

## Quick start

Python 3.11 or newer is recommended. No paid API key, cloud service, or GPU is required.

~~~bash
git clone https://github.com/k-vandith/ipsec-vpn-protocol-analyzer.git
cd ipsec-vpn-protocol-analyzer
python scripts/setup_env.py
~~~

Activate the environment and run the workspace:

**Windows · PowerShell**
~~~powershell
.venv\Scripts\Activate.ps1
python run.py
~~~

**macOS · Linux**
~~~bash
source .venv/bin/activate
python run.py
~~~

Open **http://127.0.0.1:8501**.

## Try it in five steps

1. Open **Overview** and choose **Load sample case**. It creates a small, valid synthetic capture and fictional strongSwan/Cisco configs.
2. Check the summary: packets decoded, recognisable IPsec traffic, and configuration findings.
3. Open **Negotiation Timeline** to see the IKE exchange headers that were actually captured.
4. Open **Configuration Review** to filter findings by priority and read the suggested next action.
5. Open **Reports** and download HTML, JSON, CSV, or remediation notes. Enable the optional reports extra for PDF output.

The sample uses documentation-only IP addresses. It is training data, not real VPN traffic.

## Supported inputs

| Input | Formats | What TunnelScope does |
|---|---|---|
| Packet capture | .pcap, .pcapng | Parses packets with Scapy; classifies visible IKEv1/IKEv2 headers, ESP, AH, IKE/NAT-T UDP ports, and exchange types when the fixed IKE header is readable. |
| strongSwan config | .conf, .ini, .txt | Checks IKE/ESP proposal text, legacy encryption/hash/DH group patterns, aggressive-mode references, and PSK configuration. |
| Cisco-style config | .cfg, .conf, .txt, .vpn, .config, .properties | Checks common ISAKMP/IPsec policy lines for DES/3DES, MD5/legacy HMACs, DH group 1/2, aggressive mode, and PSK references. |
| Synthetic case | Built in | Writes a small valid PCAP plus fictional strongSwan/Cisco config examples to a temporary folder for the sample workflow. |

Upload limits are **100 MB per capture**, **5 MB per config**, and **100 MB combined per analysis batch**. Capture uploads must have a recognised PCAP/PCAPNG header. Unsupported file extensions, empty files, and malformed captures show a friendly error. Uploads are processed in a temporary directory that is removed after analysis.

## Architecture

~~~mermaid
flowchart TD
    User[User] --> UI[Streamlit workspace]
    UI --> Upload[Validate upload and size]
    Upload --> Temp[Temporary local staging]
    Temp --> Capture[Scapy PCAP / PCAPNG parser]
    Temp --> Config[strongSwan / Cisco text rules]
    Capture --> Packets[Packet metadata]
    Packets --> IKE[IKE and NAT-T classification]
    Packets --> IPsec[ESP and AH classification]
    IKE --> Findings[Capture observations and timeline]
    IPsec --> Findings
    Config --> Findings
    Findings --> Summary[Plain-English review summary]
    Summary --> Export[HTML / JSON / CSV / optional PDF]
~~~

## How to read the results

- **IKEv1 / IKEv2:** packets whose visible fixed header can be recognised as an IKE exchange. Exchange names may include IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, and INFORMATIONAL.
- **ESP / AH:** IPsec encapsulation or authentication headers observed in the capture. ESP contents remain encrypted.
- **NAT-T:** traffic using UDP port 4500. The app distinguishes recognised IKE headers, ESP-in-UDP patterns, keepalives, and unknown short payloads.
- **Configuration priority:** a rule-defined critical/high/medium/info label for review. A text match can occur in a comment, inactive profile, legacy fallback, or example.
- **Capture review indicator:** a simple heuristic from selected packet observations. It is neither an exploitability probability nor a formal security rating.

### Configuration finding examples

| Pattern | Why it matters | Suggested next step |
|---|---|---|
| DES / 3DES / null encryption | Legacy or unsafe proposal signal | Verify the negotiated policy and remove unsupported legacy transforms. |
| MD5 / SHA-1 reference | Potentially legacy integrity/authentication use | Confirm protocol context and migrate where required by the security baseline. |
| Legacy DH group | May provide an insufficient security margin | Select a modern DH/ECDH group supported by both peers. |
| Aggressive-mode reference | Legacy IKEv1 mode can expose more identity information | Prefer a supported IKEv2 policy, or disable aggressive mode if IKEv1 is necessary. |
| PSK authentication | Not automatically weak, but secret handling matters | Check entropy, uniqueness, restricted storage, and rotation. |

These are pattern checks, not an exhaustive parser for every VPN appliance, strongSwan release, or inherited policy. Verify the effective configuration before changing production systems.

## Negotiation timeline and packet explorer

The timeline charts recognised IKE exchange messages in capture-relative time and lists source/destination endpoints. The packet explorer filters decoded metadata by protocol and search text.

A capture that lacks the IKE handshake can still include ESP because the capture may start after negotiation or use a filter that excludes IKE packets. TunnelScope surfaces this as context to check—not automatic proof of misconfiguration.

## CLI

The Typer CLI is available for repeatable local reviews:

~~~bash
# Capture summary
python -m src.cli scan ./capture.pcap

# Machine-readable capture results
python -m src.cli scan ./capture.pcap --format json --output ./report.json

# Review multiple strongSwan/Cisco configuration files
python -m src.cli check-config ./strongswan.conf ./router.cfg --output ./config-findings.json
~~~

## Tests and development

~~~bash
python -m pip install -r requirements-dev.txt
ruff check src/app.py src/ui_theme.py run.py tests/test_ui_smoke.py
bandit -q -r src/app.py run.py -ll
pip-audit -r requirements.txt --progress-spinner off
pytest -q
~~~

The tests cover real synthetic PCAP decoding, protocol classification, configuration rules, upload validation, export safety, and Streamlit AppTest smoke checks for every page.

## Capture real page screenshots

An optional headless Playwright helper opens the app, loads the synthetic case, and saves real page screenshots under docs/screenshots/.

~~~bash
python -m pip install playwright
python -m playwright install chromium
python scripts/capture_screenshots.py
~~~

The helper has to be run in a working local checkout with the app dependencies and Chromium installed. Screenshots have **not** been generated by this change environment, so no static mockup is presented as a real app screenshot.

## Optional PDF reports

PDF export is optional and does not affect packet analysis.

~~~bash
python -m pip install -e ".[reports]"
~~~

The Reports page explains how to enable it if ReportLab is missing.

## Troubleshooting

| Issue | What to check |
|---|---|
| Could not read this capture | Confirm the file is a genuine PCAP/PCAPNG, try opening it in Wireshark, and export it again if necessary. |
| No IKE packets found | Check capture filters and the capture point; IKE may have completed before capture started. |
| ESP without observed IKE | The handshake may not be included in the trace. Confirm the capture scope before escalating the observation. |
| No configuration finding | Confirm the correct active config and proposal lines were included. The rules are pattern-based and may not recognise vendor-specific syntax. |
| PDF button disabled | Install the optional reports extra. HTML and JSON export work without ReportLab. |
| Virtual environment activation blocked on Windows | Use PowerShell for .venv\Scripts\Activate.ps1 or run .venv\Scripts\python.exe run.py directly. |

## Privacy and limitations

- Capture and configuration analysis runs locally; no source or packet data is sent to an external analysis API.
- The app does not decrypt ESP or reveal encrypted payloads.
- PCAPs and VPN configurations can contain sensitive network and identity metadata. Protect the originals and review exported reports before sharing them.
- Live traffic is not generated or scanned. The tool reads uploaded evidence only.
- Results can be incomplete or incorrect. Validate key decisions against your actual VPN platform and security baseline.

## Project map

~~~text
assets/tunnelscope-mark.svg        Product logo
.streamlit/config.toml             Theme and upload limits
src/analyzer.py                    Scapy packet parsing and capture indicators
src/ipsec_features.py              strongSwan/Cisco text checks and remediation notes
src/upload_io.py                   Upload validation and temporary staging
src/sample_data.py                 Fictional sample PCAP and config text
src/reporting.py                   HTML, JSON, CSV, and optional PDF reports
src/cli.py                         Typer CLI
src/ui_theme.py                    Shared LinkLens tokens and theme modes
tests/                             Core, upload, report, and page smoke tests
scripts/capture_screenshots.py     Optional real browser screenshots
~~~

## License

MIT. See [LICENSE](LICENSE).
