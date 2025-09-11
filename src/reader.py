import argparse
import glob
import os
import nfc
import json
import binascii
import string
from datetime import datetime

from parser import parse_blocks

OUTPUT_FILE = f"bambu_tag_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
RAW_FILE = OUTPUT_FILE.replace(".json", ".bin")
DUMP_FILE = OUTPUT_FILE.replace(".json", ".dump.txt")


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
    # Leggi la memoria del tag 16 byte per volta usando read()
    if hasattr(tag, "read"):
        page = 0
        while True:
            try:
                data = tag.read(page)
            except Exception:
                break
            if not data:
                break
            block_hex = binascii.hexlify(data).decode().upper()
            blocks.append({"index": page // 4, "data": block_hex})
            page += 4
    # In mancanza di read(), prova con dump() raggruppando ogni 16 byte
    elif hasattr(tag, "dump"):
        hexdigits = set(string.hexdigits)
        buffer = ""
        idx = 0
        for line in tag.dump():
            hex_chars = "".join(ch for ch in line if ch in hexdigits)
            buffer += hex_chars.upper()
            while len(buffer) >= 32:
                blocks.append({"index": idx, "data": buffer[:32]})
                buffer = buffer[32:]
                idx += 1

    # Se la lettura diretta non ha prodotto dati, prova con dump()
    if not blocks and hasattr(tag, "dump"):
        print("[WARN] Lettura diretta fallita, uso dump()")
        hexdigits = set(string.hexdigits)
        buffer = ""
        idx = 0
        for line in tag.dump():
            hex_chars = "".join(ch for ch in line if ch in hexdigits)
            buffer += hex_chars.upper()
            while len(buffer) >= 32:
                blocks.append({"index": idx, "data": buffer[:32]})
                buffer = buffer[32:]
                idx += 1

    # Prova comunque a catturare l'output di dump() per eventuali blocchi mancanti
    dump_lines = []
    seen = {b["index"] for b in blocks}
    if hasattr(tag, "dump"):
        hexdigits = set(string.hexdigits)
        buffer = ""
        idx = 0
        for line in tag.dump():
            dump_lines.append(line.rstrip())
            hex_chars = "".join(ch for ch in line if ch in hexdigits)
            buffer += hex_chars.upper()
            while len(buffer) >= 32:
                if idx not in seen:
                    blocks.append({"index": idx, "data": buffer[:32]})
                    seen.add(idx)
                buffer = buffer[32:]
                idx += 1
    if dump_lines:
        with open(DUMP_FILE, "w") as df:
            df.write("\n".join(dump_lines))

    dump_data["blocks"] = sorted(blocks, key=lambda b: b["index"])

    # Salva anche i dati grezzi concatenati per analisi successive
    raw_bytes = b"".join(
        binascii.unhexlify(b["data"]) for b in blocks if len(b["data"]) % 2 == 0
    )
    with open(RAW_FILE, "wb") as rf:
        rf.write(raw_bytes)
    if raw_bytes:
        print(f"[INFO] Dati grezzi salvati in {RAW_FILE}")
    else:
        print(f"[WARN] Nessun dato grezzo ottenuto, file vuoto {RAW_FILE}")

    parsed = parse_blocks(dump_data["blocks"])

    dump_data["parsed"] = parsed
    if parsed:
        print(f"[INFO] Decodificato: {parsed}")
    else:
        print("[WARN] Nessun dato decodificato. Controlla il file grezzo per analisi.")

    # Avvisa se il primo blocco non contiene il UID atteso
    if dump_data["blocks"]:
        first_block = dump_data["blocks"][0]["data"].upper()
        if not first_block.startswith(dump_data["uid"].upper()):
            print(
                "[WARN] Il primo blocco non coincide con l'UID: possibile lettura errata."
            )


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

    attempts = [device]
    if device and not device.startswith("usb"):
        attempts.append("usb")  # fallback CCID/PCSC

    last_err = None
    for dev in attempts:
        print(f"[INFO] Provo ad aprire NFC device '{dev}'...")
        try:
            with nfc.ContactlessFrontend(dev) as clf:
                clf.connect(rdwr={'on-connect': on_connect})
                return
        except Exception as e:
            print(f"[WARN] Apertura fallita su '{dev}': {e}")
            last_err = e

    raise SystemExit(f"[ERROR] Nessun lettore NFC utilizzabile. Ultimo errore: {last_err}")

if __name__ == "__main__":
    main()
