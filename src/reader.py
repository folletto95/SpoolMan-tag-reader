import argparse
import glob
import os
import time
import json
import string
import subprocess
import tempfile
import shutil

import nfc

from parser import parse_blocks
from bambu_read_pn532 import keylist_from_uid
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


def dump_with_libnfc(uid_hex: str, outfile: str):
    """Use libnfc's ``nfc-mfclassic`` to dump a MIFARE Classic tag.

    ``uid_hex`` is the tag UID as hex string, ``outfile`` is the path where the
    binary dump will be written. Returns ``(blocks, raw_bytes)``.
    """

    keys = keylist_from_uid(uid_hex)
    with tempfile.NamedTemporaryFile("w", delete=False) as kf:
        for k in keys:
            line = k.hex().upper() if isinstance(k, bytes) else bytes(k).hex().upper()
            kf.write(line + "\n")
        keyfile = kf.name
    try:
        subprocess.run(
            ["nfc-mfclassic", "r", "a", outfile, keyfile],
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        os.unlink(keyfile)

    with open(outfile, "rb") as f:
        raw = f.read()

    blocks = []
    for i in range(0, len(raw), 16):
        chunk = raw[i : i + 16]
        if len(chunk) < 16:
            break
        blocks.append({"index": i // 16, "data": chunk.hex().upper()})

    return blocks, raw


def on_connect(tag):
    uid_hex = getattr(tag, "identifier", b"").hex().upper()
    print(f"[INFO] Tag trovato: {tag}")

    ts = time.strftime("%Y%m%d_%H%M%S")
    base = f"bambu_tag_{ts}"
    bin_file = base + ".bin"
    dump_file = base + ".dump.txt"
    json_file = base + ".json"
    spool_file = base + ".spoolman.json"

    # primo tentativo: dump generico con nfcpy
    blocks, raw_bytes, dump_lines = robust_dump(tag)

    # se sembra una MIFARE Classic ma abbiamo letto solo 4 blocchi, prova libnfc
    is_classic = getattr(tag, "sak", 0) in (0x08, 0x18)
    if (is_classic or len(raw_bytes) <= 64) and shutil.which("nfc-mfclassic"):
        try:
            blocks, raw_bytes = dump_with_libnfc(uid_hex, bin_file)
            dump_lines = [f"{b['index']:03}: {b['data']}" for b in blocks]
            print("[DBG] Dump ottenuto tramite nfc-mfclassic")
        except Exception as e:
            print(f"[WARN] Lettura con nfc-mfclassic fallita: {e}")

    print(f"[INFO] Blocchi estratti: {len(blocks)}  Bytes totali: {len(raw_bytes)}")

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

