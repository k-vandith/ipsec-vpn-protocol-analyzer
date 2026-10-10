#!/usr/bin/env python3
"""Generate a small, fictional IPsec capture and VPN config examples for TunnelScope."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.sample_data import write_sample_case

SAMPLE = ROOT / "data" / "sample"


def main() -> None:
    capture, configs = write_sample_case(SAMPLE)
    print(f"Wrote synthetic PCAP: {capture.relative_to(ROOT)}")
    for config in configs:
        print(f"Wrote fictional config: {config.relative_to(ROOT)}")
    print("The addresses use documentation-only ranges; this sample is not production traffic.")


if __name__ == "__main__":
    main()
