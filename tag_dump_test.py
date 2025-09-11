#!/usr/bin/env python3
import nfc
import binascii
import json
import time
import re
import sys

HEX2 = re.compile(r'(?i)\b[0-9a-f]{2}\b')

def robust_dump(tag):
    """Ritorna (blocks, raw_bytes) da qualunque tipo di tag"""
    blocks = []
    raw = bytearray()

    # Tentativo con Type2 (NTAG21x)
    if hasattr(tag, "read_pages"):
        page = 0
        idx = 0
        while True:
            try:
                data = tag.read_pages(page)  # 16B = 4 pagine
            except Exception:
                break
            if not data or len(data) != 16:
                break
            raw.extend(data)
            blocks.append({"index": idx, "data": data.hex().upper()})
            idx += 1
            page += 4
        if blocks:
            return blocks, bytes(raw)

    # Fallback: usa tag.dump() e raccoglie tutte le coppie hex
    try:
        lines = tag.dump()
    except Exception:
        lines = []

    bytes_seq = []
    for ln in lines:
        for m in HEX2.finditer(str(ln)):
            bytes_seq.append(int(m.group(0), 16))

    raw = bytes(bytes_seq)

    blocks = []
    for i in range(0, len(raw), 16):
        chunk = raw[i:i+16]
        if len(chunk) < 16:
            break
        blocks.append({"index": i // 16, "data": chunk.hex().upper()})

    return blocks, raw


def on_connect(tag):
    uid = getattr(tag, "identifier", b"")
    print(f"[INFO] UID: {uid.hex() if uid else 'n/a'}")

    blocks, raw_bytes = robust_dump(tag)
    print(f"[INFO] Blocchi letti: {len(blocks)} | Bytes totali: {len(raw_bytes)}")

    ts = time.strftime("%Y%m%d_%H%M%S")
    base = f"tagdump_{ts}"

    # Salva bin grezzo
    with open(base + ".bin", "wb") as f:
        f.write(raw_bytes)
    print(f"[INFO] Salvato dump binario in {base}.bin")

    # Salva json con i blocchi
    with open(base + ".json", "w") as f:
        json.dump({"uid": uid.hex(), "blocks": blocks}, f, indent=2)
    print(f"[INFO] Salvato dump JSON in {base}.json")

    return True


def main():
    device = None
    if len(sys.argv) > 1 and sys.argv[1] == "--device" and len(sys.argv) > 2:
        device = sys.argv[2]

    if not device:
        # default PN532 su ttyUSB0
        device = "tty:USB0:pn532"

    print(f"[INFO] Avvio lettore NFC su '{device}'…")
    with nfc.ContactlessFrontend(device) as clf:
        clf.connect(rdwr={"on-connect": on_connect})


if __name__ == "__main__":
    main()
