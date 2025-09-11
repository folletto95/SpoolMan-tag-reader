"""Funzioni per interpretare i dati dei blocchi Bambu."""

from __future__ import annotations

import binascii
import struct
from typing import Any, Dict, List


def _to_ascii(data: bytes) -> str:
    return data.decode("ascii", errors="ignore").replace("\x00", "").strip()


def _le16(data: bytes) -> int:
    return int.from_bytes(data, "little")


def _lefloat(data: bytes) -> float:
    return struct.unpack("<f", data)[0]


def parse_blocks(blocks: List[Dict[str, str]]) -> Dict[str, Any]:
    """Decodifica alcuni campi noti dai blocchi della tag Bambu."""

    block_bytes = {b["index"]: binascii.unhexlify(b["data"]) for b in blocks}
    raw_hex = "".join(b["data"] for b in blocks).lower()
    parsed: Dict[str, Any] = {"raw_hex": raw_hex}

    try:
        b = block_bytes
        parsed.update(
            {
                "variant_id": _to_ascii(b[1][0:8]),
                "material_id": _to_ascii(b[1][8:16]),
                "filament_type": _to_ascii(b[2]),
                "detailed_filament_type": _to_ascii(b[4]),
                "color": "#" + binascii.hexlify(b[5][0:4]).decode().upper(),
                "spool_weight_g": _le16(b[5][4:6]),
                "filament_diameter_mm": round(_lefloat(b[5][8:12]), 2),
                "spool_width_mm": _le16(b[10][4:6]) / 100,
                "production_date": _to_ascii(b[12]),
                "filament_length_m": _le16(b[14][4:6]),
            }
        )
    except KeyError:
        # Mancano blocchi necessari per il parsing completo
        pass

    return parsed


__all__ = ["parse_blocks"]
