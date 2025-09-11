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


def robust_dump(tag):
    """Return (blocks, raw_bytes) from an NFC tag.

    Tries to read Type2 tags via ``read_pages`` when available, otherwise
    falls back to parsing the generic ``dump()`` output. ``blocks`` is a list
    of ``{"index": int, "data": HEX16}`` dictionaries, where ``HEX16`` is
    a 32-character uppercase hex string. ``raw_bytes`` contains all bytes
    concatenated in the order read.
    """
    blocks = []
    raw = bytearray()

    # 1) Prefer Type2 tags with read_pages (16 bytes per call)
    try:
        if hasattr(tag, "read_pages"):
            idx = 0
            page = 0
            while True:
                try:
                    data = tag.read_pages(page)
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
    except Exception:
        pass

    # 2) Fallback: parse output of dump()
    try:
        lines = tag.dump()
    except Exception:
        lines = []

    bytes_seq = []
    for ln in lines:
        for m in HEX2.finditer(str(ln)):
            bytes_seq.append(int(m.group(0), 16))

    if not bytes_seq:
        return [], b""

    raw = bytes(bytes_seq)
    for i in range(0, len(raw), 16):
        chunk = raw[i : i + 16]
        if len(chunk) < 16:
            break
        blocks.append({"index": i // 16, "data": chunk.hex().upper()})

    return blocks, raw


def on_connect(tag):
    print(f"[INFO] Tag: {tag}  UID: {getattr(tag, 'identifier', b'').hex() if hasattr(tag, 'identifier') else 'n/a'}")

    blocks, raw_bytes = robust_dump(tag)
    print(f"[INFO] Blocchi estratti: {len(blocks)}  Bytes totali: {len(raw_bytes)}")

    ts = time.strftime("%Y%m%d_%H%M%S")
    base = f"bambu_tag_{ts}"
    raw_file = base + ".bin"

    if raw_bytes:
        with open(raw_file, "wb") as rf:
            rf.write(raw_bytes)
        print(f"[INFO] Dati grezzi salvati in {raw_file}")
    else:
        print(f"[WARN] Nessun dato grezzo salvato (dump vuoto)")

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
