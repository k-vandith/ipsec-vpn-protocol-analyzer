"""Tests for capture and configuration upload validation."""
from __future__ import annotations

from pathlib import Path

import pytest

from src.analyzer import build_demo_capture
from src.upload_io import stage_captures, stage_configs, validate_upload_batch


class FakeUpload:
    def __init__(self, name: str, payload: bytes) -> None:
        self.name = name
        self._payload = payload

    def getvalue(self) -> bytes:
        return self._payload


def test_capture_upload_requires_real_pcap_header(tmp_path: Path) -> None:
    capture = build_demo_capture(tmp_path / "valid.pcap")
    valid = FakeUpload("trace.pcap", capture.read_bytes())
    staged = stage_captures([valid], tmp_path / "staged")
    assert len(staged) == 1
    assert staged[0].name == "trace.pcap"

    invalid = FakeUpload("broken.pcap", b"not a pcap file")
    with pytest.raises(ValueError, match="header"):
        stage_captures([invalid], tmp_path / "bad")


def test_config_upload_restricts_extensions_and_stages_safely(tmp_path: Path) -> None:
    config = FakeUpload("../vpn.conf", b"conn sample\nike=aes128-sha1-modp1024\n")
    staged = stage_configs([config], tmp_path / "configs")
    assert staged[0].name == "vpn.conf"
    assert staged[0].read_text(encoding="utf-8").startswith("conn sample")

    with pytest.raises(ValueError, match="unsupported"):
        stage_configs([FakeUpload("image.png", b"not a config")], tmp_path / "unsupported")


def test_empty_upload_batch_explains_what_is_needed() -> None:
    with pytest.raises(ValueError, match="Choose a capture"):
        validate_upload_batch([], [])


def test_duplicate_filenames_are_not_overwritten(tmp_path: Path) -> None:
    items = [
        FakeUpload("vpn.conf", b"conn first\n"),
        FakeUpload("vpn.conf", b"conn second\n"),
    ]
    staged = stage_configs(items, tmp_path / "duplicate")
    assert [path.name for path in staged] == ["vpn.conf", "vpn-2.conf"]
    assert staged[0].read_text(encoding="utf-8") == "conn first\n"
    assert staged[1].read_text(encoding="utf-8") == "conn second\n"
