import argparse
import glob
import os
import nfc
import json
import binascii
import string
import errno
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
    # Usa tag.dump() per ottenere blocchi da 16 byte e convertirli in esadecimale
    if hasattr(tag, "dump"):
        hexdigits = set(string.hexdigits)
        for idx, line in enumerate(tag.dump()):
            if isinstance(line, bytes):
                block_hex = binascii.hexlify(line).decode().upper()
            else:
                hex_chars = "".join(ch for ch in line if ch in hexdigits)
                if len(hex_chars) < 32:
                    continue
                block_hex = hex_chars[:32].upper()
            blocks.append({"index": idx, "data": block_hex})

    # Se dump() non è disponibile, prova la lettura grezza pagina per pagina
    if not blocks and hasattr(tag, "read"):
        page = 0
        while True:
            try:
                data = tag.read(page)
            except Exception:
                break
            if not data:
                break
            for offset in range(0, len(data), 16):
                block = data[offset : offset + 16]
                if len(block) < 16:
                    break
                block_hex = binascii.hexlify(block).decode().upper()
                blocks.append({"index": page + offset // 16, "data": block_hex})
            page += 4

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
    try:
        with nfc.ContactlessFrontend(device) as clf:
            clf.connect(rdwr={'on-connect': on_connect})
    except OSError as e:
        print(f"[ERROR] Impossibile aprire il lettore NFC: {e}")
        if e.errno == errno.ETIMEDOUT:
            print("[HINT] Nessuna risposta dal PN532. Controlla cablaggio e parametro --device.")
        elif e.errno == errno.ENOENT:
            print("[HINT] Il device specificato non esiste. Verifica il nome (es. /dev/ttyUSB0).")
        elif e.errno == errno.EACCES:
            print("[HINT] Permessi insufficienti per accedere al device. Usa sudo o aggiungi l'utente al gruppo dialout.")
    except Exception as e:
        print(f"[ERROR] Impossibile aprire il lettore NFC: {e}")

if __name__ == "__main__":
    main()
