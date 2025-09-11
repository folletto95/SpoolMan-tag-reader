"""
Implementation of parse_blocks for BambuLab NFC tags.

This module provides a standalone parse_blocks function that decodes
BambuLab Mifare Classic tag memory into a structured dictionary of
filament spool information. It is based on reverse engineering
documentation from the Bambu Research Group’s RFID-Tag-Guide and
mirrors the fields extracted in their reference parser【275912188313276†L160-L176】.

Use this function to replace the existing parse_blocks in
your SpoolMan-tag-reader project if you wish to extract
filament data (material, color, weight, diameter, etc.) from
genuine Bambu spools.
"""

import binascii
import struct
from typing import Any, Dict, List


def parse_blocks(blocks: List[Dict[str, str]]) -> Dict[str, Any]:
    """Parse Mifare tag blocks into filament data.

    Args:
        blocks: A list of dictionaries, each containing an "index" and
            "data" key. The data field must be a hex string representing
            16 bytes of tag memory (e.g. from a PN532 dump).

    Returns:
        A dictionary with decoded filament information, including
        fields such as uid, filament_type, filament_color, weight_grams,
        filament_diameter_mm, filament_length_m, spool_width_mm,
        nozzle_diameter_mm, variant_id, material_id, temperatures,
        production_date, and filament_color_count. Unknown or unused
        bytes are not returned.
    """
    # Reassemble raw blocks from the provided hex strings
    raw_blocks: List[bytes] = [binascii.unhexlify(b["data"]) for b in blocks]
    result: Dict[str, Any] = {}

    # Helper conversion functions
    def b_to_string(data: bytes) -> str:
        return data.decode("ascii", errors="ignore").replace("\x00", " ").strip()

    def b_to_int(data: bytes) -> int:
        return int.from_bytes(data, byteorder="little")

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

    # Ensure we have enough blocks to read the required fields
    # UID is in block 0 (first 4 bytes)
    if len(raw_blocks) > 0 and len(raw_blocks[0]) >= 4:
        result["uid"] = b_to_hex(raw_blocks[0][0:4])

    # Block 2 and 4: filament types
    if len(raw_blocks) > 4:
        result["filament_type"] = b_to_string(raw_blocks[2])
        result["detailed_filament_type"] = b_to_string(raw_blocks[4])

    # Block 1: variant_id and material_id
    if len(raw_blocks) > 1:
        b1 = raw_blocks[1]
        result["variant_id"] = b_to_string(b1[0:8])
        result["material_id"] = b_to_string(b1[8:16])

    # Block 5: color, weight, diameter
    if len(raw_blocks) > 5:
        b5 = raw_blocks[5]
        result["filament_color"] = "#" + b_to_hex(b5[0:4])
        result["weight_grams"] = b_to_int(b5[4:6])
        # filament diameter as float (mm)
        result["filament_diameter_mm"] = round(b_to_float(b5[8:12]), 3)

    # Block 10: spool width stored in 1/100 mm
    if len(raw_blocks) > 10:
        width_raw = b_to_int(raw_blocks[10][4:6])
        result["spool_width_mm"] = width_raw / 100.0

    # Block 14: filament length (meters)
    if len(raw_blocks) > 14:
        result["filament_length_m"] = b_to_int(raw_blocks[14][4:6])

    # Block 8: nozzle diameter (last 4 bytes, float) and camera info (first 12)
    if len(raw_blocks) > 8:
        result["nozzle_diameter_mm"] = round(b_to_float(raw_blocks[8][12:16]), 1)
        result["x_cam_info_hex"] = b_to_hex(raw_blocks[8][0:12])

    # Block 9: tray UID
    if len(raw_blocks) > 9:
        result["tray_uid_hex"] = b_to_hex(raw_blocks[9])

    # Block 6: temperatures and drying data【275912188313276†L178-L188】
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

    # Block 12 and 13: dates【275912188313276†L160-L176】
    if len(raw_blocks) > 12:
        result["production_date"] = parse_date(raw_blocks[12])
    if len(raw_blocks) > 13:
        result["unknown_date_1"] = b_to_string(raw_blocks[13])

    # Block 16: color count and possible second color【275912188313276†L160-L176】
    if len(raw_blocks) > 16:
        b16 = raw_blocks[16]
        has_extra = len(b16) >= 2 and b16[0:2] == b"\x02\x00"
        color_count = b_to_int(b16[2:4]) if has_extra else 1
        result["filament_color_count"] = color_count
        if color_count == 2:
            # The second color is stored in bytes 4-7 of block 16 in reverse order
            second = b16[4:8][::-1]
            result["filament_color"] = result.get("filament_color", "#" + b_to_hex(b5[0:4])) + " / #" + b_to_hex(second)

    return result