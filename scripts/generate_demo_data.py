from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data" / "sample"
SAMPLE.mkdir(parents=True, exist_ok=True)
content = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20
content += b"ISAKMP IKE_SA_INIT ESP_PACKET ESP_PACKET AH_PACKET IKEv2 "
(SAMPLE / "demo_ipsec.pcap").write_bytes(content)
print("Wrote", SAMPLE / "demo_ipsec.pcap")
