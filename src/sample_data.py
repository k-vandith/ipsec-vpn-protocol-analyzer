"""Safe fictional inputs used by the TunnelScope sample workflow."""
from __future__ import annotations

from pathlib import Path

from src.analyzer import build_demo_capture

SAMPLE_STRONGSWAN = """# Fictional training config; not a production VPN policy
conn sample-vpn
    keyexchange=ikev2
    authby=psk
    aggressive=yes
    ike=aes128-sha1-modp1024,aes256gcm16-prfsha384-ecp384
    esp=aes128-sha1
"""

SAMPLE_CISCO = """! Fictional training snippet; not a complete deployable configuration
crypto isakmp policy 10
 encryption 3des
 hash md5
 authentication pre-share
 group 2
crypto isakmp aggressive-mode
crypto ipsec transform-set LEGACY esp-3des esp-sha-hmac
"""


def write_sample_case(destination: str | Path) -> tuple[Path, list[Path]]:
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    capture = build_demo_capture(root / "sample-ikev2.pcap")
    strongswan = root / "strongswan-sample.conf"
    cisco = root / "cisco-sample.cfg"
    strongswan.write_text(SAMPLE_STRONGSWAN, encoding="utf-8")
    cisco.write_text(SAMPLE_CISCO, encoding="utf-8")
    return capture, [strongswan, cisco]
