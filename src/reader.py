import argparse
import glob
import os
import time
import binascii
import json
import string

import nfc

from parser import parse_blocks


def detect_device():
    """Try to auto-detect an NFC reader.

    Attempts USB first, then common serial interfaces like /dev/ttyUSB* or
    /dev/ttyACM*. Returns a device string understood by nfcpy or ``None`` if no
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
    """Dump tag memory with extensive debug output.

    The function prints every line returned by ``tag.dump()`` and, when
    possible, reads the tag memory in 16-byte chunks using ``read_pages``.
    A tuple ``(blocks, raw_bytes, dump_lines)`` is returned where ``blocks`` is
    a list of ``{"index": int, "data": HEXSTR}`` dictionaries, ``raw_bytes``
    contains the concatenated bytes of all blocks and ``dump_lines`` keeps the
    raw text from ``tag.dump()`` for troubleshooting.
    """

    dump_lines = []
    if hasattr(tag, "dump"):
        lines = tag.dump()
        for i, ln in enumerate(lines):
            print(f"[DBG] {i}: {ln}")
            dump_lines.append(ln)

    blocks = []
    raw_bytes = b""

    if hasattr(tag, "read_pages"):
        idx = 0
        page = 0
        while True:
            try:
                data = tag.read_pages(page)  # 16B = 4 pagine
            except Exception:
                break
            if not data:
                break
            print(f"[DBG] page {page}-{page+3}: {data.hex()}")
            hex_data = data.hex().upper()
            blocks.append({"index": idx, "data": hex_data})
            raw_bytes += data
            idx += 1
            page += 4
    elif dump_lines:
        hexdigits = set(string.hexdigits)
        for idx, line in enumerate(dump_lines):
            hex_chars = "".join(ch for ch in line if ch in hexdigits)
            block_hex = hex_chars.upper().ljust(32, "0")[:32]
            if not block_hex:
                continue
            blocks.append({"index": idx, "data": block_hex})
            try:
                raw_bytes += bytes.fromhex(block_hex)
            except ValueError:
                pass

    return blocks, raw_bytes, dump_lines


    if not bytes_seq:
        return [], b"", dump_lines

    raw = bytes(bytes_seq)
    for i in range(0, len(raw), 16):
        chunk = raw[i : i + 16]
        if len(chunk) < 16:
            break
        blocks.append({"index": i // 16, "data": chunk.hex().upper()})

    return blocks, raw, dump_lines


def on_connect(tag):
    print(
        f"[INFO] Tag: {tag}  UID: {getattr(tag, 'identifier', b'').hex() if hasattr(tag, 'identifier') else 'n/a'}"
    )

def on_connect(tag):
    print(f"[INFO] Tag trovato: {tag}")
    blocks, raw_bytes, dump_lines = robust_dump(tag)
    print(f"[INFO] Blocchi estratti: {len(blocks)}  Bytes totali: {len(raw_bytes)}")

    ts = time.strftime("%Y%m%d_%H%M%S")
    base = f"bambu_tag_{ts}"
    bin_file = base + ".bin"
    dump_file = base + ".dump.txt"
    json_file = base + ".json"

    if raw_bytes:
        with open(bin_file, "wb") as rf:
            rf.write(raw_bytes)
        print(f"[INFO] Dati grezzi salvati in {bin_file}")
    else:
        print("[WARN] Nessun dato grezzo salvato (dump vuoto)")

    if dump_lines:
        with open(dump_file, "w") as df:
            df.write("\n".join(dump_lines))
        print(f"[INFO] Dump testuale salvato in {dump_file}")

    out_json = {"uid": getattr(tag, "identifier", b"").hex(), "blocks": blocks}

    try:
        out_json["parsed"] = parse_blocks(blocks)
    except Exception as e:
        print(f"[WARN] parse_blocks fallito: {e}")

    with open(json_file, "w") as f:
        json.dump(out_json, f, indent=2)
    print(f"[INFO] JSON salvato in {json_file}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Legge le tag NFC delle bobine BambuLab"
    )
    parser.add_argument(
        "--device",
        help="stringa dispositivo nfcpy (es. 'usb' o 'tty:USB0:pn532')",
    )
    args = parser.parse_args()

    device = args.device or os.environ.get("NFC_DEVICE") or detect_device()
    if device is None:
        print(
            "[ERROR] Nessun lettore NFC trovato. Specifica --device o variabile NFC_DEVICE."
        )
        return

    attempts = [device]
    if device and not device.startswith("usb"):
        attempts.append("usb")  # fallback CCID/PCSC

    last_err = None
    for dev in attempts:
        print(f"[INFO] Provo ad aprire NFC device '{dev}'...")
        try:
            with nfc.ContactlessFrontend(dev) as clf:
                clf.connect(rdwr={"on-connect": on_connect})
                return
        except Exception as e:
            print(f"[WARN] Apertura fallita su '{dev}': {e}")
            last_err = e

    raise SystemExit(
        f"[ERROR] Nessun lettore NFC utilizzabile. Ultimo errore: {last_err}"
    )


if __name__ == "__main__":
    main()

