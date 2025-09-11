import argparse
import glob
import os
import re
import time

import nfc
import json
import binascii

from parser import parse_blocks

HEX2 = re.compile(r"(?i)\b[0-9a-f]{2}\b")


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
    dump_data = {
        "uid": binascii.hexlify(tag.identifier).decode()
    }



    Tries to read Type2 tags via ``read_pages`` when available, otherwise
    falls back to parsing the generic ``dump()`` output. ``blocks`` is a list
    of ``{"index": int, "data": HEX16}`` dictionaries, where ``HEX16`` is
    a 32-character uppercase hex string. ``raw_bytes`` contains all bytes
    concatenated in the order read. ``dump_lines`` contains the raw lines from
    ``tag.dump()`` for troubleshooting.
    """
    blocks = []
    # Leggi la memoria del tag usando read() suddividendo ogni 16 byte
    if hasattr(tag, "read"):
        blk = 0
        while True:
            try:
                data = tag.read(blk)
            except Exception:
                break
            if not data:
                break
            # tag.read potrebbe restituire più blocchi alla volta (es. 64 byte)
            for off in range(0, len(data), 16):
                chunk = data[off : off + 16]
                if len(chunk) < 16:
                    continue
                block_hex = binascii.hexlify(chunk).decode().upper()
                blocks.append({"index": blk + off // 16, "data": block_hex})
            step = max(1, len(data) // 16)
            blk += step
    # Se read() non ha restituito dati, prova con dump()
    if not blocks and hasattr(tag, "dump"):
        hexdigits = set(string.hexdigits)
        for idx, line in enumerate(tag.dump()):
            hex_chars = "".join(ch for ch in line if ch in hexdigits)
            block_hex = hex_chars.upper().ljust(32, "0")[:32]
            blocks.append({"index": idx, "data": block_hex})

    print(f"[DEBUG] Numero di blocchi letti: {len(blocks)}")
    dump_data["blocks"] = blocks

    # Salva anche i dati grezzi concatenati per analisi successive
    raw_bytes = b"".join(
        binascii.unhexlify(b["data"]) for b in blocks if len(b["data"]) % 2 == 0
    )
    print(f"[DEBUG] Dim. raw bytes: {len(raw_bytes)}")
    if raw_bytes:
        with open(RAW_FILE, "wb") as rf:
            rf.write(raw_bytes)
        print(f"[INFO] Dati grezzi salvati in {RAW_FILE}")
    else:
        print("[WARN] Nessun dato da scrivere nel file binario")


    blocks, raw_bytes, dump_lines = robust_dump(tag)
    print(f"[INFO] Blocchi estratti: {len(blocks)}  Bytes totali: {len(raw_bytes)}")

    ts = time.strftime("%Y%m%d_%H%M%S")
    base = f"bambu_tag_{ts}"
    raw_file = base + ".bin"
    dump_file = base + ".dump.txt"

    if raw_bytes:
        with open(raw_file, "wb") as rf:
            rf.write(raw_bytes)
        print(f"[INFO] Dati grezzi salvati in {raw_file}")
    else:
        print(f"[WARN] Nessun dato grezzo salvato (dump vuoto)")

    if dump_lines:
        with open(dump_file, "w") as df:
            df.write("\n".join(dump_lines))
        print(f"[INFO] Dump testuale salvato in {dump_file}")


    out_json = {
        "uid": getattr(tag, "identifier", b"").hex(),
        "blocks": blocks,
    }

    try:
        out_json["parsed"] = parse_blocks(blocks)
    except Exception as e:
        print(f"[WARN] parse_blocks fallito: {e}")

    json_file = base + ".json"
    with open(json_file, "w") as f:
        json.dump(out_json, f, indent=2)
    print(f"[INFO] JSON salvato in {json_file}")

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
