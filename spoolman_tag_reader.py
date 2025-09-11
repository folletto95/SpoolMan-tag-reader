"""Simple reader for BambuLab spool NFC tags.

This script uses a PN532 reader to read BambuLab spool tags and posts
decoded information to a SpoolMan instance. The reader interface and
SpoolMan URL can be configured from the command line to work across
different Linux distributions.
"""
from __future__ import annotations

import argparse
import binascii
import json
import os
import sys
from dataclasses import dataclass
from typing import Optional

import nfc
import requests


def load_env(path: str = ".env") -> None:
    """Load environment variables from a .env file if present."""
    if not os.path.exists(path):
        return
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key, value)


load_env()

@dataclass
class SpoolInfo:
    """Metadata decoded from a BambuLab spool tag."""

    spool_id: str
    material: Optional[str] = None
    color: Optional[str] = None
    weight_grams: Optional[int] = None
    raw_hex: Optional[str] = None


SPOOLMAN_URL = os.environ.get("SPOOLMAN_URL", "http://localhost:8000/api/spools")
PN532_DEVICE = os.environ.get("PN532_DEVICE", "auto")


def read_tag(device: str) -> nfc.tag.Tag:
    """Wait for a tag and return the nfcpy tag object."""
    with nfc.ContactlessFrontend(device) as clf:
        print("Place a BambuLab spool tag near the reader...")
        tag = clf.connect(rdwr={"on-connect": lambda tag: False})
        return tag


def auto_detect_device() -> str:
    """Try to locate a connected PN532 reader automatically."""
    candidates = [
        "usb",
        "tty:USB0:pn532",
        "tty:S0:pn532",
    ]
    for dev in candidates:
        try:
            with nfc.ContactlessFrontend(dev):
                return dev
        except Exception:
            continue
    raise RuntimeError("PN532 reader not found; specify device in .env or via --device")


def decode_bambu_tag(tag: nfc.tag.Tag) -> SpoolInfo:
    """Decode raw memory from the tag into :class:`SpoolInfo`.

    BambuLab tags store spool information as JSON in the user memory
    of the tag. If decoding fails the raw hex is returned.
    """
    try:
        # Read entire user memory
        data = tag.dump()
    except AttributeError:
        # Fallback for non-dump capable tags
        data = bytes()
        if hasattr(tag, "read_bytes"):
            size = getattr(tag, "memory_size", 0)
            data = tag.read_bytes(0, size)

    text = bytes(b for b in data if 32 <= b <= 126).decode("ascii", "ignore")
    info: dict[str, object]
    try:
        info = json.loads(text)
    except json.JSONDecodeError:
        return SpoolInfo(
            spool_id="unknown",
            raw_hex=binascii.hexlify(data).decode("ascii"),
        )

    return SpoolInfo(
        spool_id=str(info.get("spool_id", "unknown")),
        material=info.get("material"),
        color=info.get("color"),
        weight_grams=info.get("weight_grams"),
        raw_hex=binascii.hexlify(data).decode("ascii"),
    )


def post_to_spoolman(info: SpoolInfo, url: str) -> None:
    """Post decoded info to SpoolMan."""
    payload = {
        "spool_id": info.spool_id,
        "material": info.material,
        "color": info.color,
        "weight_grams": info.weight_grams,
    }
    # Remove None values to keep payload compact
    payload = {k: v for k, v in payload.items() if v is not None}
    try:
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"Failed to post to SpoolMan: {exc}", file=sys.stderr)
    else:
        print("Spool posted to SpoolMan")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--device",
        default=PN532_DEVICE,
        help="nfcpy device string, e.g. 'usb', 'tty:USB0', or 'auto'",
    )
    parser.add_argument(
        "--url",
        default=SPOOLMAN_URL,
        help="SpoolMan API endpoint",
    )
    args = parser.parse_args()

    device = args.device
    if device in ("auto", ""):
        device = auto_detect_device()

    tag_obj = read_tag(device)
    info = decode_bambu_tag(tag_obj)
    print(info)
    post_to_spoolman(info, args.url)


if __name__ == "__main__":
    main()
