import argparse
import glob
import os
import nfc
import json
import binascii
from datetime import datetime

from parser import parse_blocks

OUTPUT_FILE = f"bambu_tag_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

def detect_device():
    """Try to auto-detect an NFC reader.

    Attempts USB first, then common serial interfaces like /dev/ttyUSB* or
    /dev/ttyACM*. Returns a device string understood by nfcpy or None if no
    reader is found.
    """
    candidates = ["usb"]
    serial_globs = ("/dev/ttyUSB*", "/dev/ttyACM*")
    for pattern in serial_globs:
        for dev in glob.glob(pattern):
            name = os.path.basename(dev)
            if name.startswith("tty"):
                name = name[3:]
            candidates.append(f"tty:{name}:pn532")

    for dev in candidates:
        try:
            with nfc.ContactlessFrontend(dev):
                return dev
        except Exception:
            continue
    return None

def on_connect(tag):
    print(f"[INFO] Tag trovato: {tag}")
    dump_data = {}

    # UID
    dump_data["uid"] = binascii.hexlify(tag.identifier).decode()

    blocks = []
    # Prova prima a leggere i blocchi grezzi
    if hasattr(tag, "read"):
        page = 0
        while True:
            try:
                data = tag.read(page)
            except Exception:
                break
            if not data:
                break
            for offset in range(0, len(data), 4):
                block = data[offset : offset + 4]
                block_hex = binascii.hexlify(block).decode()
                blocks.append({"index": page + offset // 4, "data": block_hex})
            page += 4

    # Se la lettura diretta fallisce, ripiega su dump() e filtra le righe utili
    if not blocks and hasattr(tag, "dump"):
        for line in tag.dump():
            if isinstance(line, bytes):
                block = line[:4]
                block_hex = binascii.hexlify(block).decode()
                index = len(blocks)
                blocks.append({"index": index, "data": block_hex})
                continue

            # Per le stringhe estrai solo i caratteri esadecimali e ignora altro
            hex_chars = "".join(ch for ch in line if ch in "0123456789abcdefABCDEF")
            if len(hex_chars) < 8:
                continue
            block_hex = hex_chars[:8]
            blocks.append({"index": len(blocks), "data": block_hex})

    dump_data["blocks"] = blocks
    dump_data["parsed"] = parse_blocks(blocks)
    print(f"[INFO] Decodificato: {dump_data['parsed']}")

    # Salva su file JSON
    with open(OUTPUT_FILE, "w") as f:
        json.dump(dump_data, f, indent=2)

    print(f"[INFO] Dump salvato in {OUTPUT_FILE}")
    return True

def main():
    parser = argparse.ArgumentParser(description="Legge le tag NFC delle bobine BambuLab")
    parser.add_argument(
        "--device",
        help="stringa dispositivo nfcpy (es. 'usb' o 'tty:USB0:pn532')",
    )
    args = parser.parse_args()

    device = args.device or os.environ.get("NFC_DEVICE") or detect_device()
    if device is None:
        print("[ERROR] Nessun lettore NFC trovato. Specifica --device o variabile NFC_DEVICE.")
        return

    print(f"[INFO] Avvio lettore NFC su '{device}'...")
    with nfc.ContactlessFrontend(device) as clf:
        clf.connect(rdwr={'on-connect': on_connect})

if __name__ == "__main__":
    main()
