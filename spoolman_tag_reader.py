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


@dataclass
class SpoolInfo:
    """Metadata decoded from a BambuLab spool tag."""

    spool_id: str
    material: Optional[str] = None
    color: Optional[str] = None
    weight_grams: Optional[int] = None
    raw_hex: Optional[str] = None


SPOOLMAN_URL = os.environ.get("SPOOLMAN_URL", "http://localhost:8000/api/spools")


def read_tag(device: str) -> nfc.tag.Tag:
    """Wait for a tag and return the nfcpy tag object."""
    with nfc.ContactlessFrontend(device) as clf:
        print("Place a BambuLab spool tag near the reader...")
        tag = clf.connect(rdwr={"on-connect": lambda tag: False})
        return tag


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
        default="usb",
        help="nfcpy device string, e.g. 'usb' or 'tty:USB0'",
    )
    parser.add_argument(
        "--url",
        default=SPOOLMAN_URL,
        help="SpoolMan API endpoint",
    )
    args = parser.parse_args()

    tag_obj = read_tag(args.device)
    info = decode_bambu_tag(tag_obj)
    print(info)
    post_to_spoolman(info, args.url)


if __name__ == "__main__":
    main()
