#!/usr/bin/env python3
"""
pn532_bambu2spoolman.py
-----------------------

This script continuously listens for NFC tags using a PN532 reader and, for
each tag detected, performs the following steps:

* Reads all data from the tag (attempting MIFARE Classic 1 K authentication
  when appropriate).
* Saves the raw tag contents to a ``.bin`` file and a human‑readable JSON
  document containing per‑block hex dumps.
* Parses the tag using ``bambutag_parse.py`` from this repository to
  extract information about filament type, colour, spool weight, length,
  diameters and other metadata.
* Converts the parsed data into two JSON payloads compatible with
  SpoolMan's REST API: one for creating a ``Filament`` entity and one for
  creating a ``Spool`` entity.

The script is designed to be robust against typical issues encountered when
working with PN532 readers:

* **Multiple tags detected** – If the PN532 reports that more than one
  card is present (``RuntimeError: More than one card detected!``), the
  script simply waits a short moment and retries instead of crashing.
* **No tag present** – The ``wait_for_tag`` function will wait
  indefinitely (or up to an optional timeout) until a tag is detected,
  rather than raising an exception when no card is in range.
* **Authentication failures** – If the tag refuses authentication on a
  given sector, the script reports the problem and resumes the wait loop.
  You can extend the ``KEYS`` list below to add additional MIFARE Classic
  keys if your tags use non‑standard keys.  See the ``README.md`` for
  further information.

Because some Bambu tags are **not** MIFARE Classic but rather NTAG21x
variants, authentication may legitimately fail.  In such cases, you
should instead use the simpler ``pn532_dump.py`` example shipped with
``adafruit_pn532`` to read Ultralight/NTAG tags.

Usage examples::

    # Scan tags using a PN532 connected via USB serial (HSU/UART)
    python3 src/pn532_bambu2spoolman.py --uart /dev/ttyUSB0

    # Or using a Raspberry Pi via I²C
    python3 src/pn532_bambu2spoolman.py --i2c

    # Limit to a single tag then exit
    python3 src/pn532_bambu2spoolman.py --uart /dev/ttyUSB0 --oneshot

The generated files will be written into an ``export`` directory in
the repository root.

Note: this script does *not* perform any HTTP requests.  To actually
populate SpoolMan you must send the JSON files using SpoolMan's REST
API once you know the ``filament_id`` assigned by your SpoolMan
instance.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
import datetime
import re
from pathlib import Path

try:
    # Adafruit PN532 drivers.  These must be installed in your virtual
    # environment: pip install adafruit-circuitpython-pn532 pyserial
    from adafruit_pn532.adafruit_pn532 import (
        MIFARE_CMD_AUTH_A,
        MIFARE_CMD_AUTH_B,
    )
    from adafruit_pn532.uart import PN532_UART
    from adafruit_pn532.i2c import PN532_I2C
except ImportError as exc:
    raise SystemExit(
        "Required dependency missing. Install with 'pip install adafruit-circuitpython-pn532 pyserial'"
    ) from exc

try:
    import serial  # type: ignore
except ImportError:
    serial = None

try:
    import board, busio  # type: ignore
    HAVE_BOARD = True
except Exception:
    HAVE_BOARD = False

# Import the Bambu tag parser from this repository.  The script must reside
# in the same directory (src) or the PYTHONPATH must include the repo root.
try:
    from . import bambutag_parse  # type: ignore
except Exception:
    # Fallback to relative import if executed as a script from repo root
    import importlib
    bambutag_parse = importlib.import_module("bambutag_parse")


###############################################################################
# MIFARE keys
###############################################################################

# Default set of well‑known MIFARE Classic keys.  You can extend this
# list if your tags use a different key.  Keys are provided in
# hexadecimal (12 hex characters = 6 bytes).  Note that many Bambu tags
# are not MIFARE Classic at all; in such cases no key will work and
# authentication will always fail.
KEYS_HEX: list[str] = [
    "FFFFFFFFFFFF",  # default transport key
    "A0A1A2A3A4A5",  # Chinese backdoor key A
    "D3F7D3F7D3F7",  # Chinese backdoor key B
    "000000000000",  # all zeros
    "B0B1B2B3B4B5",  # alternate
    "4D3A99C351DD",  # NXP test key
    "1A982C7E459A",  # NXP test key
    "AABBCCDDEEFF",  # test key
    # Extra keys occasionally used on consumer products
    "A1B2C3D4E5F6",
    "010203040506",
    "9876543210FF",
]

KEYS: list[bytes] = [bytes.fromhex(k) for k in KEYS_HEX]

BYTES_PER_BLOCK = 16
TOTAL_BLOCKS = 64
TOTAL_BYTES = BYTES_PER_BLOCK * TOTAL_BLOCKS


###############################################################################
# Utility functions
###############################################################################

def open_pn532(args: argparse.Namespace):
    """Initialize a PN532 instance based on the provided CLI arguments.

    :param args: Parsed command‑line arguments.
    :return: Configured PN532 instance.
    """
    if args.uart:
        if serial is None:
            raise SystemExit(
                "pyserial not installed. Install with 'pip install pyserial'"
            )
        ser = serial.Serial(args.uart, baudrate=args.baud, timeout=1)
        pn = PN532_UART(ser, debug=args.debug)
    elif args.i2c:
        if not HAVE_BOARD:
            raise SystemExit(
                "I2C mode requested but board/busio not available."
            )
        i2c = busio.I2C(board.SCL, board.SDA)
        pn = PN532_I2C(i2c, debug=args.debug)
    else:
        raise SystemExit("Specify either --uart or --i2c")
    pn.SAM_configuration()
    return pn


def wait_for_tag(pn, timeout: float | None = None) -> bytes | None:
    """Wait for a single NFC tag to be present and return its UID.

    This function polls the PN532 using ``read_passive_target`` with a
    short timeout.  If no tag is present, it continues polling.  If the
    PN532 reports that more than one card is detected, the error is
    ignored and the function continues polling.  A user‑provided
    timeout may be specified to give up after a certain duration.

    :param pn: PN532 instance
    :param timeout: Optional maximum time in seconds to wait for a tag
    :return: UID bytes or ``None`` on timeout
    """
    start = time.monotonic()
    while True:
        try:
            uid = pn.read_passive_target(timeout=0.5)
        except RuntimeError as e:
            # Known error when multiple tags are present
            if "More than one card detected" in str(e):
                # Simply ignore and retry
                time.sleep(0.2)
                continue
            # Unexpected errors are reported and then ignored
            print(f"read_passive_target error: {e}")
            time.sleep(0.2)
            continue
        except Exception as e:
            # Catch any other exception to prevent crash
            print(f"Unexpected exception while polling for tag: {e}")
            time.sleep(0.5)
            continue

        if uid:
            return bytes(uid)

        if timeout is not None and (time.monotonic() - start) > timeout:
            return None


def try_auth_sector(pn, uid: bytes, sector: int) -> tuple[str | None, bytes | None]:
    """Attempt to authenticate the first block of a sector using known keys.

    :param pn: PN532 instance
    :param uid: UID of the card
    :param sector: Sector number (0–15)
    :returns: Tuple of (mode, key) on success; (None, None) on failure
    """
    first_block = sector * 4
    for key in KEYS:
        # Try with Key A
        try:
            if pn.mifare_classic_authenticate_block(
                uid, first_block, MIFARE_CMD_AUTH_A, key
            ):
                return ("A", key)
        except Exception:
            # Many drivers throw exceptions on authentication failure; ignore
            pass
        # Try with Key B
        try:
            if pn.mifare_classic_authenticate_block(
                uid, first_block, MIFARE_CMD_AUTH_B, key
            ):
                return ("B", key)
        except Exception:
            pass
    return (None, None)


def read_full_tag(pn, uid: bytes) -> tuple[bytes, list[dict[str, object]]]:
    """Read all 64 blocks from a MIFARE Classic 1 K tag.

    :param pn: PN532 instance
    :param uid: UID of the card
    :returns: Tuple of (raw_bytes, block_json_list)
    :raises RuntimeError: if authentication fails for any sector
    """
    dump = bytearray()
    blocks_json = []
    for sector in range(16):
        mode, key = try_auth_sector(pn, uid, sector)
        if mode is None:
            raise RuntimeError(
                f"Authentication failed on sector {sector}. Try repositioning the tag or extending the key list."
            )
        for block in range(sector * 4, sector * 4 + 4):
            data = pn.mifare_classic_read_block(block)
            if not data or len(data) != 16:
                raise RuntimeError(f"Failed to read block {block}.")
            dump.extend(data)
            blocks_json.append({"index": block, "data": data.hex().upper()})
    return bytes(dump), blocks_json


def extract_number(u) -> float | None:
    """Extract numeric value from various types used by bambutag_parse.Unit.

    The parser returns units such as grams, metres and millimetres.  This
    helper function attempts to pull the underlying numeric value.  If a
    string is passed, any floating point number within the string is
    extracted.
    """
    try:
        # Some Unit objects have a .value attribute
        return getattr(u, "value")
    except Exception:
        pass
    if isinstance(u, (int, float)):
        return float(u)
    if isinstance(u, str):
        m = re.search(r"[-+]?[0-9]*\.?[0-9]+", u)
        return float(m.group(0)) if m else None
    return None


def colour_hexes(color_field: str | None) -> tuple[str | None, list[str] | None]:
    """Parse a colour field (e.g. '#RRGGBB' or '#RRRRGGGGBBBB / #RRGGBB').

    Returns a tuple ``(single, multi)`` where ``single`` is a six‑digit
    hex code if a single colour is present, and ``multi`` is a list of
    hex strings if multiple colours are present.
    """
    if not color_field:
        return (None, None)
    parts = [p.strip() for p in color_field.split("/") if p.strip()]
    hexes: list[str] = []
    for p in parts:
        h = p.lstrip("#").strip()
        if re.fullmatch(r"[0-9A-Fa-f]{6,8}", h):
            hexes.append(h.upper())
    if not hexes:
        return (None, None)
    if len(hexes) == 1:
        return (hexes[0], None)
    return (None, hexes)


def guess_material(text: str | None) -> str | None:
    """Attempt to infer the material (PLA, PETG, ABS, etc.) from text."""
    if not text:
        return None
    t = text.upper()
    for m in DENSITY_BY_MATERIAL.keys():
        if m in t:
            return m
    m = re.search(r"[A-Z]{2,4}", t)
    return m.group(0) if m else None


def compute_net_weight(d_mm: float | None, length_m: float | None, density: float | None) -> float | None:
    """Estimate net weight of filament (g) from diameter (mm), length (m) and density (g/cm³)."""
    if not (d_mm and length_m and density):
        return None
    # Convert mm -> cm, m -> cm
    d_cm = d_mm / 10.0
    length_cm = length_m * 100.0
    # Cylinder volume formula: π·r²·h; r = d/2
    volume_cm3 = math.pi * ((d_cm / 2.0) ** 2) * (length_cm)
    return density * volume_cm3


def build_spoolman_payloads(tag_obj: bambutag_parse.Tag, uid_hex: str) -> tuple[dict[str, object], dict[str, object]]:
    """Convert parsed Bambu tag into SpoolMan JSON payloads.

    :param tag_obj: Tag instance returned by bambutag_parse.Tag
    :param uid_hex: UID of the tag (uppercase hex string)
    :returns: Tuple of (filament_params, spool_params)
    """
    data = tag_obj.data
    filament_type = data.get("filament_type") or ""
    detailed_type = data.get("detailed_filament_type") or ""
    color_field = data.get("filament_color") or ""
    spool_weight = extract_number(data.get("spool_weight"))
    length_m = extract_number(data.get("filament_length"))
    diameter_mm = extract_number(data.get("filament_diameter"))
    temps = data.get("temperatures") or {}
    bed_temp = extract_number(temps.get("bed_temp"))
    min_hotend = extract_number(temps.get("min_hotend"))
    max_hotend = extract_number(temps.get("max_hotend"))
    prod_date = data.get("production_date")
    material_id = data.get("material_id")
    variant_id = data.get("variant_id")

    # Normalise production date to ISO string
    if hasattr(prod_date, "isoformat"):
        prod_date_str = prod_date.isoformat()
    else:
        prod_date_str = str(prod_date) if prod_date else None

    material = guess_material(f"{filament_type} {detailed_type}")
    density = DENSITY_BY_MATERIAL.get(material)

    # Colour handling
    color_hex, multi = colour_hexes(color_field if isinstance(color_field, str) else None)

    # Build a descriptive name
    name_parts = []
    if detailed_type:
        name_parts.append(str(detailed_type).strip())
    elif filament_type:
        name_parts.append(str(filament_type).strip())
    else:
        name_parts.append("Bambu Filament")
    if color_hex and len(color_hex) == 6 and color_hex.upper() != "FFFFFF":
        name_parts.append(f"#{color_hex.upper()}")
    name = " ".join(name_parts)

    init_weight = compute_net_weight(diameter_mm, length_m, density)
    if init_weight is not None:
        init_weight = round(init_weight, 1)

    filament_params: dict[str, object] = {
        "name": name,
        "material": material,
        "diameter": round(diameter_mm, 3) if diameter_mm else None,
        "density": round(density, 3) if density else None,
        "weight": init_weight,
        "spool_weight": round(spool_weight, 1) if spool_weight else None,
        "color_hex": color_hex,
        "multi_color_hexes": ",".join(multi) if multi else None,
        "settings_extruder_temp": int(max_hotend) if max_hotend else None,
        "settings_bed_temp": int(bed_temp) if bed_temp else None,
        "external_id": f"bambu:material_id={material_id}|variant_id={variant_id}",
    }
    # Remove None entries
    filament_params = {k: v for k, v in filament_params.items() if v is not None}

    spool_params: dict[str, object] = {
        "filament_id": "<REPLACE_ME>",
        "spool_weight": round(spool_weight, 1) if spool_weight else None,
        "initial_weight": init_weight,
        "lot_nr": prod_date_str,
        "comment": f"Import from Bambu tag | UID={uid_hex} | variant_id={variant_id}",
    }
    spool_params = {k: v for k, v in spool_params.items() if v is not None}
    return filament_params, spool_params


###############################################################################
# Material densities (g/cm³)
###############################################################################

DENSITY_BY_MATERIAL: dict[str, float] = {
    "PLA": 1.24,
    "PETG": 1.27,
    "ABS": 1.04,
    "ASA": 1.07,
    "TPU": 1.21,
    "PA": 1.14,
    "PC": 1.20,
    "PVA": 1.30,
}


def ensure_export_dir(base: Path) -> Path:
    """Ensure that an export directory exists and return its path."""
    export_path = base / "export"
    export_path.mkdir(parents=True, exist_ok=True)
    return export_path


def main() -> None:
    ap = argparse.ArgumentParser(description="PN532 -> Dump + Parse + SpoolMan JSON")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--uart", help="PN532 serial device path for HSU/UART mode")
    group.add_argument("--i2c", action="store_true", help="Use I²C bus (on Raspberry Pi)")
    ap.add_argument("--baud", type=int, default=115200, help="Baudrate for UART mode (default 115200)")
    ap.add_argument("--debug", action="store_true", help="Enable PN532 debug output")
    ap.add_argument(
        "--oneshot",
        action="store_true",
        help="Read a single tag then exit instead of looping forever",
    )
    args = ap.parse_args()

    # Determine our base directory (repo root) and prepare export directory
    here = Path(__file__).resolve().parent
    export_dir = ensure_export_dir(here.parent)

    pn = open_pn532(args)
    print("Ready. Hold a Bambu tag near the PN532 reader...")

    while True:
        uid = wait_for_tag(pn)
        if uid is None:
            # Timeout occurred (only if a timeout parameter was passed)
            print("No tag detected within timeout.")
            break

        uid_hex = uid.hex().upper()
        print(f"\nTag detected. UID={uid_hex}")

        # Attempt to dump all sectors
        try:
            dump_bytes, blocks = read_full_tag(pn, uid)
        except RuntimeError as e:
            # Authentication or read error: report and continue scanning
            print(f"ERROR reading tag: {e}")
            if args.oneshot:
                # In oneshot mode we terminate on error
                sys.exit(1)
            else:
                time.sleep(0.5)
                continue
        except Exception as e:
            # Unexpected error: print and continue
            print(f"Unexpected error: {e}")
            if args.oneshot:
                sys.exit(1)
            else:
                time.sleep(0.5)
                continue

        # Save raw dump and JSON
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"bambu_tag_{timestamp}_{uid_hex}"
        bin_path = export_dir / f"{base_name}.bin"
        dump_path = export_dir / f"{base_name}.dump.json"
        with open(bin_path, "wb") as f:
            f.write(dump_bytes)
        with open(dump_path, "w") as f:
            json.dump({"uid": uid_hex, "blocks": blocks}, f, indent=2)
        print(f"Saved raw dump to {bin_path}")
        print(f"Saved block JSON to {dump_path}")

        # Parse the tag using bambutag_parse
        try:
            tag = bambutag_parse.Tag(bin_path, dump_bytes)
        except Exception as e:
            print(f"ERROR parsing tag: {e}")
            if args.oneshot:
                sys.exit(1)
            else:
                time.sleep(0.5)
                continue

        filament_params, spool_params = build_spoolman_payloads(tag, uid_hex)

        # Write SpoolMan JSON files
        filament_json_path = export_dir / f"{base_name}.spoolman.filament.json"
        spool_json_path = export_dir / f"{base_name}.spoolman.spool.json"
        with open(filament_json_path, "w") as f:
            json.dump(filament_params, f, indent=2)
        with open(spool_json_path, "w") as f:
            json.dump(spool_params, f, indent=2)
        print("Generated SpoolMan payloads:")
        print(f"  - {filament_json_path}")
        print(f"  - {spool_json_path}")

        # Display a quick summary for the operator
        summary = {
            "filament_preview": filament_params,
            "spool_preview": spool_params,
        }
        print("\nSummary:")
        print(json.dumps(summary, indent=2))

        if args.oneshot:
            break
        # Short delay before scanning again to avoid duplicate triggers
        time.sleep(1.0)


if __name__ == "__main__":
    main()
