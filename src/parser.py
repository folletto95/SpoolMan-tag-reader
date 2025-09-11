import struct
from typing import List, Dict, Any

def _hex_to_bytes(h: str) -> bytes:
    h = h.strip().lower()
    return bytes.fromhex(h)

def _le_u16(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=False)

def _le_u32(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=False)

def _le_f32(b: bytes) -> float:
    # float IEEE754 little-endian
    return struct.unpack("<f", b)[0]

def _safe_slice(b: bytes, start: int, end: int) -> bytes:
    if start < 0 or end > len(b) or start >= end:
        return b""
    return b[start:end]

def parse_blocks(blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Decodifica tag Bambu (Mifare Classic 1K) secondo le evidenze pubbliche (RFID-Tag-Guide).
    Richiede l'array 'blocks' con elementi: {"index": int, "data": "<hex>"}
    """
    by_idx: Dict[int, bytes] = {}
    for blk in blocks:
        by_idx[int(blk["index"])] = _hex_to_bytes(blk["data"])

    out: Dict[str, Any] = {}

    # UID (bloc 0, primi 4 byte)
    if 0 in by_idx and len(by_idx[0]) >= 4:
        out["uid_hex"] = by_idx[0][:4].hex()

    # Blocchi chiave (vedi Bambu parse.py)
    # material/variant ids (bloc 1)
    if 1 in by_idx:
        b1 = by_idx[1]
        if len(b1) >= 16:
            out["variant_id_hex"]  = _safe_slice(b1, 0, 8).hex()
            out["material_id_hex"] = _safe_slice(b1, 8, 16).hex()

    # descrizioni (bloc 2 e 4) – stringhe ASCII "soft"
    def _ascii_soft(b: bytes) -> str:
        try:
            return b.decode("utf-8", errors="ignore").strip("\x00").strip()
        except Exception:
            return ""

    if 2 in by_idx: out["filament_type"] = _ascii_soft(by_idx[2])
    if 4 in by_idx: out["detail"]        = _ascii_soft(by_idx[4])

    # bloc 5: colore, peso (g), diametro (float)
    if 5 in by_idx:
        b5 = by_idx[5]
        if len(b5) >= 12:
            out["filament_color_rgba_hex"] = _safe_slice(b5, 0, 4).hex()
            out["weight_grams"] = _le_u16(_safe_slice(b5, 4, 6))
            out["filament_diameter_mm"] = round(
                _le_f32(_safe_slice(b5, 8, 12)), 3
            )

    # bloc 6: temperature, dry times, ecc.
    if 6 in by_idx:
        b6 = by_idx[6]
        if len(b6) >= 12:
            out.update(
                {
                    "dry_temp_c": _le_u16(_safe_slice(b6, 0, 2)),
                    "dry_time_h": _le_u16(_safe_slice(b6, 2, 4)),
                    "bed_temp_type": _le_u16(_safe_slice(b6, 4, 6)),
                    "bed_temp_c": _le_u16(_safe_slice(b6, 6, 8)),
                    "hotend_temp_max_c": _le_u16(_safe_slice(b6, 8, 10)),
                    "hotend_temp_min_c": _le_u16(_safe_slice(b6, 10, 12)),
                }
            )

    # bloc 8: nozzle diameter (float)
    if 8 in by_idx and len(by_idx[8]) >= 16:
        out["nozzle_diameter_mm"] = round(_le_f32(_safe_slice(by_idx[8], 12, 16)), 3)

    # bloc 9: tray UID
    if 9 in by_idx:
        out["tray_uid_hex"] = by_idx[9].hex()

    # bloc 10: spool width (mm/100)
    if 10 in by_idx and len(by_idx[10]) >= 6:
        out["spool_width_mm"] = round(_le_u16(_safe_slice(by_idx[10], 4, 6)) / 100.0, 2)

    # bloc 14: filament length (m)
    if 14 in by_idx and len(by_idx[14]) >= 6:
        out["filament_length_m"] = _le_u16(_safe_slice(by_idx[14], 4, 6))

    # bloc 12 e 13: date di produzione
    if 12 in by_idx:
        out["production_datetime"] = _ascii_soft(by_idx[12])
    if 13 in by_idx:
        out["production_datetime_short"] = _ascii_soft(by_idx[13])

    # bloc 16: multi-colore (se presente)
    if 16 in by_idx:
        b16 = by_idx[16]
        if len(b16) >= 8 and b16[0:2] == b"\x02\x00":
            color_count = _le_u16(_safe_slice(b16, 2, 4))
            out["filament_color_count"] = color_count
            if len(b16) >= 8:
                out["second_color_rgb_hex"] = _safe_slice(b16, 4, 8)[::-1].hex()

    return out

