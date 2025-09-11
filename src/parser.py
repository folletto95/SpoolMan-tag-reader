"""Funzioni per interpretare i dati dei blocchi Bambu."""

from __future__ import annotations

import binascii
import struct
from typing import Any, Dict, List


def parse_blocks(blocks: List[Dict[str, str]]) -> Dict[str, Any]:
    """Decodifica i blocchi Mifare delle bobine Bambu in un dizionario."""

    raw_blocks: List[bytes] = [binascii.unhexlify(b["data"]) for b in blocks]
    result: Dict[str, Any] = {}

    def b_to_string(data: bytes) -> str:
        return data.decode("ascii", errors="ignore").replace("\x00", " ").strip()

    def b_to_int(data: bytes) -> int:
        return int.from_bytes(data, "little")

    def b_to_float(data: bytes) -> float:
        return struct.unpack("<f", data)[0]

    def b_to_hex(data: bytes) -> str:
        return data.hex().upper()

    def parse_date(data: bytes) -> str:
        s = b_to_string(data)
        parts = s.split("_")
        if len(parts) >= 5:
            try:
                return f"{parts[0]}-{parts[1]}-{parts[2]} {parts[3]}:{parts[4]}"
            except Exception:
                pass
        return s

    # UID block 0, primi 4 byte
    if len(raw_blocks) > 0 and len(raw_blocks[0]) >= 4:
        result["uid"] = b_to_hex(raw_blocks[0][0:4])

    # Blocchi 2 e 4: tipo filamento
    if len(raw_blocks) > 4:
        result["filament_type"] = b_to_string(raw_blocks[2])
        result["detailed_filament_type"] = b_to_string(raw_blocks[4])

    # Blocco 1: variant_id e material_id
    if len(raw_blocks) > 1:
        b1 = raw_blocks[1]
        result["variant_id"] = b_to_string(b1[0:8])
        result["material_id"] = b_to_string(b1[8:16])

    # Blocco 5: colore, peso, diametro
    if len(raw_blocks) > 5:
        b5 = raw_blocks[5]
        result["filament_color"] = "#" + b_to_hex(b5[0:4])
        result["weight_grams"] = b_to_int(b5[4:6])
        result["filament_diameter_mm"] = round(b_to_float(b5[8:12]), 3)

    # Blocco 10: larghezza bobina (1/100 mm)
    if len(raw_blocks) > 10:
        width_raw = b_to_int(raw_blocks[10][4:6])
        result["spool_width_mm"] = width_raw / 100.0

    # Blocco 14: lunghezza filamento (m)
    if len(raw_blocks) > 14:
        result["filament_length_m"] = b_to_int(raw_blocks[14][4:6])

    # Blocco 8: diametro ugello e info camera
    if len(raw_blocks) > 8:
        result["nozzle_diameter_mm"] = round(b_to_float(raw_blocks[8][12:16]), 1)
        result["x_cam_info_hex"] = b_to_hex(raw_blocks[8][0:12])

    # Blocco 9: tray UID
    if len(raw_blocks) > 9:
        result["tray_uid_hex"] = b_to_hex(raw_blocks[9])

    # Blocco 6: temperature e tempi di asciugatura
    if len(raw_blocks) > 6:
        tb = raw_blocks[6]
        temps = {
            "drying_temp_C": b_to_int(tb[0:2]),
            "drying_time_h": b_to_int(tb[2:4]),
            "bed_temp_type": b_to_int(tb[4:6]),
            "bed_temp_C": b_to_int(tb[6:8]),
            "max_hotend_C": b_to_int(tb[8:10]),
            "min_hotend_C": b_to_int(tb[10:12]),
        }
        result["temperatures"] = temps

    # Blocchi 12 e 13: date
    if len(raw_blocks) > 12:
        result["production_date"] = parse_date(raw_blocks[12])
    if len(raw_blocks) > 13:
        result["unknown_date_1"] = b_to_string(raw_blocks[13])

    # Blocco 16: numero di colori e secondo colore
    if len(raw_blocks) > 16:
        b16 = raw_blocks[16]
        has_extra = len(b16) >= 2 and b16[0:2] == b"\x02\x00"
        color_count = b_to_int(b16[2:4]) if has_extra else 1
        result["filament_color_count"] = color_count
        if color_count == 2 and len(raw_blocks) > 5:
            second = b16[4:8][::-1]
            result["filament_color"] = (
                result.get("filament_color", "#" + b_to_hex(raw_blocks[5][0:4]))
                + " / #" + b_to_hex(second)
            )

    return result


__all__ = ["parse_blocks"]
