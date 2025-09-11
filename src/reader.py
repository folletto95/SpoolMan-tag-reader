import argparse
import os
import nfc
import json
import binascii
from datetime import datetime

from parser import parse_blocks

OUTPUT_FILE = f"bambu_tag_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

def on_connect(tag):
    print(f"[INFO] Tag trovato: {tag}")
    dump_data = {}

    # UID
    dump_data["uid"] = binascii.hexlify(tag.identifier).decode()

    # Prova a leggere tutti i blocchi possibili
    if hasattr(tag, 'dump'):
        blocks = []
        for i, block in enumerate(tag.dump()):
            block_hex = binascii.hexlify(block).decode()
            blocks.append({"index": i, "data": block_hex})
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
        default=os.environ.get("NFC_DEVICE", "usb"),
        help="stringa dispositivo nfcpy (es. 'usb' o 'tty:USB0:pn532')",
    )
    args = parser.parse_args()

    print("[INFO] Avvio lettore NFC...")
    with nfc.ContactlessFrontend(args.device) as clf:
        clf.connect(rdwr={'on-connect': on_connect})

if __name__ == "__main__":
    main()
