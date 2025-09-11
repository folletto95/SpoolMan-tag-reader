import argparse
import glob
import os
import time
import json
import string

import nfc

from parser import parse_blocks
from bambu_read_pn532 import keylist_from_uid, read_mfc_with_keys
from bambutag_parse import Tag as BambuTag
from spoolman_formatter import tag_to_spoolman_payload


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


def on_connect(tag):
    uid_hex = getattr(tag, "identifier", b"").hex().upper()
    print(f"[INFO] Tag trovato: {tag}")

    blocks: list[dict] = []
    raw_bytes = b""
    dump_lines: list[str] = []

    # prova prima la lettura autenticata MIFARE Classic
    try:
        keys = keylist_from_uid(uid_hex)
        blocks, raw_bytes = read_mfc_with_keys(tag, keys)
    except Exception as e:
        print(f"[DBG] Lettura MIFARE autenticata fallita: {e}")

    # se la lettura autenticata non produce dati, usa il fallback generico
    if not raw_bytes:
        blocks, raw_bytes, dump_lines = robust_dump(tag)
    else:
        for blk in blocks:
            dump_lines.append(f"{blk['index']:03}: {blk['data']}")

    print(f"[INFO] Blocchi estratti: {len(blocks)}  Bytes totali: {len(raw_bytes)}")

    ts = time.strftime("%Y%m%d_%H%M%S")
    base = f"bambu_tag_{ts}"
    bin_file = base + ".bin"
    dump_file = base + ".dump.txt"
    json_file = base + ".json"
    spool_file = base + ".spoolman.json"

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

    out_json = {"uid": uid_hex, "blocks": blocks}

    try:
        tag_obj = BambuTag(bin_file, raw_bytes)
        spool_data = tag_to_spoolman_payload(tag_obj)
        out_json["spoolman"] = spool_data
        with open(spool_file, "w") as sf:
            json.dump(spool_data, sf, indent=2)
        print(f"[INFO] Dati Spoolman salvati in {spool_file}")
    except Exception as e:
        print(f"[WARN] Impossibile estrarre dati Spoolman: {e}")

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

