"""Validated, temporary staging for capture and VPN configuration uploads."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from src.analyzer import MAX_CAPTURE_BYTES

MAX_CONFIG_BYTES = 5 * 1024 * 1024
MAX_BATCH_BYTES = 100 * 1024 * 1024
CAPTURE_EXTENSIONS = {".pcap", ".pcapng"}
CONFIG_EXTENSIONS = {".conf", ".cfg", ".ini", ".txt", ".vpn", ".config", ".properties"}


def _payload(upload: object) -> bytes:
    getvalue = getattr(upload, "getvalue", None)
    if callable(getvalue):
        value = getvalue()
    else:
        read = getattr(upload, "read", None)
        if not callable(read):
            raise ValueError("An uploaded item could not be read.")
        value = read()
    if not isinstance(value, (bytes, bytearray)):
        raise ValueError("Uploaded data must be a file.")
    return bytes(value)


def _safe_name(value: str) -> str:
    name = Path(value.replace("\\", "/")).name
    if name in {"", ".", ".."} or "\x00" in name:
        raise ValueError("One of the uploaded filenames is invalid.")
    return name


def _stage_many(
    uploads: Iterable[object],
    destination: str | Path,
    allowed: set[str],
    limit: int,
    type_label: str,
) -> list[Path]:
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    items = list(uploads)
    staged: list[Path] = []
    batch_bytes = 0
    reserved: set[str] = set()

    for upload in items:
        name = _safe_name(str(getattr(upload, "name", "")))
        suffix = Path(name).suffix.lower()
        if suffix not in allowed:
            expected = ", ".join(sorted(allowed))
            raise ValueError(f"{name}: unsupported {type_label} file. Choose {expected}.")
        payload = _payload(upload)
        if not payload:
            raise ValueError(f"{name} is empty.")
        if len(payload) > limit:
            raise ValueError(f"{name} exceeds the {limit // (1024 * 1024)} MB per-file limit.")
        batch_bytes += len(payload)
        if batch_bytes > MAX_BATCH_BYTES:
            raise ValueError("The combined uploads exceed the 100 MB batch limit.")
        if suffix in CAPTURE_EXTENSIONS:
            if suffix == ".pcapng" and not payload.startswith(b"\x0a\x0d\x0d\x0a"):
                raise ValueError(f"{name} does not have a recognised PCAPNG file header.")
            if suffix == ".pcap" and payload[:4] not in {
                b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
            }:
                raise ValueError(f"{name} does not have a recognised classic PCAP header.")
        target_name = name
        counter = 2
        while target_name.lower() in reserved or (root / target_name).exists():
            stem, extension = Path(name).stem, Path(name).suffix
            target_name = f"{stem}-{counter}{extension}"
            counter += 1
        reserved.add(target_name.lower())
        target = (root / target_name).resolve()
        if root not in target.parents:
            raise ValueError("An uploaded filename resolves outside the temporary folder.")
        target.write_bytes(payload)
        staged.append(target)
    return staged


def stage_captures(uploads: Iterable[object], destination: str | Path) -> list[Path]:
    return _stage_many(uploads, destination, CAPTURE_EXTENSIONS, MAX_CAPTURE_BYTES, "capture")


def stage_configs(uploads: Iterable[object], destination: str | Path) -> list[Path]:
    return _stage_many(uploads, destination, CONFIG_EXTENSIONS, MAX_CONFIG_BYTES, "configuration")


def validate_upload_batch(captures: Iterable[object], configs: Iterable[object]) -> None:
    capture_items = list(captures)
    config_items = list(configs)
    if not capture_items and not config_items:
        raise ValueError("Choose a capture or VPN configuration file before running the review.")
    total = sum(len(_payload(item)) for item in capture_items + config_items)
    if total > MAX_BATCH_BYTES:
        raise ValueError("The combined uploads exceed the 100 MB batch limit.")
