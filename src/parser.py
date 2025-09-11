"""Funzioni per interpretare i dati dei blocchi Bambu."""

from __future__ import annotations

import binascii
import json
from typing import Any, Dict, List


def parse_blocks(blocks: List[Dict[str, str]]) -> Dict[str, Any]:
    """Decodifica le informazioni della bobina da un dump di blocchi.

    I tag delle bobine BambuLab salvano un payload JSON nella memoria
    utente. Questa funzione ricostruisce i byte grezzi, estrae il testo
    ASCII e prova a interpretarlo come JSON. In caso di successo vengono
    restituiti i campi principali; altrimenti viene ritornato l'esadecimale
    originale.
    """

    raw_bytes = b"".join(binascii.unhexlify(b["data"]) for b in blocks)
    text = bytes(b for b in raw_bytes if 32 <= b <= 126)

    parsed: Dict[str, Any] = {"raw_hex": binascii.hexlify(raw_bytes).decode("ascii")}
    try:
        info = json.loads(text.decode("ascii"))
    except Exception:
        return parsed

    parsed.update(
        {
            "spool_id": str(info.get("spool_id", "unknown")),
            "material": info.get("material"),
            "color": info.get("color"),
            "weight_grams": info.get("weight_grams"),
        }
    )
    return parsed


__all__ = ["parse_blocks"]
