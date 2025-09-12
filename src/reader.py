#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import re
import subprocess
import sys
import time
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_GUIDE = (HERE.parent / "RFID-Tag-Guide")  # cambia se l'hai altrove


def sh(cmd, check=True):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(
            f"Command failed ({p.returncode}): {' '.join(cmd)}\n--- STDOUT ---\n{p.stdout}\n--- STDERR ---\n{p.stderr}"
        )
    return p


def find_file(candidates):
    for p in candidates:
        if p and Path(p).exists():
            return str(Path(p))
    return None


def timestamp():
    return time.strftime("%Y%m%d_%H%M%S")


UID_PATTERNS = [
    re.compile(r"UID\s*\(NFCID1\)\s*:\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2}){3,10})"),
    re.compile(r"NFCID1\s*:\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2}){3,10})"),
]


def get_uid_and_info():
    """
    Esegue `nfc-list -v` e prova ad estrarre:
      - UID/NFCID1
      - indicazione di tipo MIFARE Classic 1K (se presente)
      - ATQA/SAK (per diagnosi)
    """
    p = sh(["nfc-list", "-v"], check=False)  # non fallire, vogliamo vedere output
    out = (p.stdout or "") + (p.stderr or "")

    uid_hex = None
    for pat in UID_PATTERNS:
        m = pat.search(out)
        if m:
            uid_hex = m.group(1).replace(" ", "").upper()
            break

    atqa = None
    sak = None
    m1k = False

    m = re.search(r"ATQA\s*:\s*(0x[0-9A-Fa-f]+)", out)
    if m:
        atqa = m.group(1).upper()
    m = re.search(r"SAK\s*:\s*(0x[0-9A-Fa-f]+)", out)
    if m:
        sak = m.group(1).upper()

    if re.search(r"MIFARE\s+Classic\s+1K", out, re.IGNORECASE):
        m1k = True
    else:
        # euristica comune: 1K spesso ATQA=0x0004, SAK=0x08
        if atqa == "0x0004" and sak in {"0x08", "0x09"}:
            m1k = True

    return uid_hex, m1k, atqa, sak, out


def derive_keys(uid_hex, derive_py):
    p = sh(["python3", derive_py, uid_hex], check=True)
    tmp = tempfile.NamedTemporaryFile(prefix="keys_", suffix=".dic", delete=False)
    tmp.write(p.stdout.encode("utf-8"))
    tmp.close()
    return tmp.name


def nfclassic_dump(out_mfd, keys_dic):
    # nfc-mfclassic r a <dumpfile> <keysfile>
    sh(["nfc-mfclassic", "r", "a", out_mfd, keys_dic], check=True)


def parse_mfd(mfd_path, parse_py):
    p = sh(["python3", parse_py, mfd_path], check=True)
    return p.stdout


def main():
    ap = argparse.ArgumentParser(description="Bambu MIFARE Classic 1K reader (solo libnfc)")
    ap.add_argument("--guide", default=str(DEFAULT_GUIDE), help="Percorso alla cartella RFID-Tag-Guide (deriveKeys.py/parse.py)")
    ap.add_argument("--derive", default=None, help="Path a deriveKeys.py (se diverso da --guide)")
    ap.add_argument("--parse", default=None, help="Path a parse.py (se diverso da --guide)")
    ap.add_argument("--keys", default=None, help="Usa questo keys.dic (salta deriveKeys.py)")
    ap.add_argument("--keep-keys", action="store_true", help="Non cancellare il file keys.dic temporaneo")
    ap.add_argument("--no-parse", action="store_true", help="Non eseguire parse.py (lascia solo .mfd)")
    ap.add_argument("--only-parse", default=None, help="Salta la lettura: esegue solo parse.py su questo .mfd")
    ap.add_argument("--outstem", default=None, help="Prefisso output (default: bambu_tag_<timestamp>)")
    args = ap.parse_args()

    # Risolvi derive/parse
    guide = Path(args.guide)
    derive_py = args.derive or str(guide / "deriveKeys.py")
    parse_py = args.parse or str(guide / "parse.py")

    if args.only-parse:
        mfd = Path(args.only-parse)
        if not mfd.exists():
            print(f"[ERR] MFD non trovato: {mfd}", file=sys.stderr)
            sys.exit(2)
        if args.no-parse:
            print("[ERR] --only-parse e --no-parse sono incompatibili.", file=sys.stderr)
            sys.exit(2)
        if not Path(parse_py).exists():
            print(f"[ERR] parse.py non trovato in {parse_py}", file=sys.stderr)
            sys.exit(2)

        outstem = args.outstem or f"bambu_tag_{timestamp()}"
        json_path = Path(f"{outstem}.json")
        print(f"[INFO] Parsing {mfd} → {json_path}")
        try:
            js = parse_mfd(str(mfd), parse_py)
            json_path.write_text(js, encoding="utf-8")
            print(f"[INFO] JSON salvato in {json_path}")
            sys.exit(0)
        except Exception as e:
            print(f"[ERR] parse.py fallito: {e}", file=sys.stderr)
            sys.exit(1)

    # Lettura live
    print("[INFO] Interrogo il reader con nfc-list -v…")
    uid_hex, m1k, atqa, sak, raw = get_uid_and_info()

    if uid_hex:
        print(f"[INFO] UID: {uid_hex}")
    else:
        print("[ERR] Impossibile estrarre UID. Output nfc-list:\n" + raw, file=sys.stderr)
        sys.exit(1)

    if not m1k:
        print(f"[WARN] Il tag non appare come MIFARE Classic 1K (ATQA={atqa}, SAK={sak}).")
        print("[WARN] Se è un NTAG (Type-2), questo script non lo legge. (Qui gestiamo SOLO MIFARE Classic.)")

    outstem = args.outstem or f"bambu_tag_{timestamp()}"
    mfd_path = Path(f"{outstem}.mfd")

    # keys.dic
    keys_path = args.keys
    temp_keys = None
    if not keys_path:
        derive_path = find_file([derive_py])
        if not derive_path:
            print(f"[ERR] deriveKeys.py non trovato (cerca in {derive_py}).", file=sys.stderr)
            sys.exit(2)
        print("[INFO] Derivo chiavi dall'UID…")
        try:
            keys_path = derive_keys(uid_hex, derive_path)
            temp_keys = keys_path
        except Exception as e:
            print(f"[ERR] deriveKeys.py fallito: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        if not Path(keys_path).exists():
            print(f"[ERR] keys.dic non trovato: {keys_path}", file=sys.stderr)
            sys.exit(2)

    # Dump
    print(f"[INFO] Dump MIFARE → {mfd_path}")
    try:
        nfclassic_dump(str(mfd_path), keys_path)
        print(f"[INFO] Dump salvato: {mfd_path}")
    except Exception as e:
        print(f"[ERR] nfc-mfclassic fallito: {e}", file=sys.stderr)
        if "no compatible devices found" in str(e):
            print("[HINT] Controlla /etc/nfc/libnfc.conf e che il device non sia occupato.", file=sys.stderr)
        if "No valid key found" in str(e) or "AUTH" in str(e).upper():
            print("[HINT] Verifica le chiavi derivate. UID corretto? Tag compatibile/famiglia FM11RF08S?", file=sys.stderr)
        sys.exit(1)
    finally:
        if temp_keys and not args.keep-keys:
            try:
                os.remove(temp_keys)
            except Exception:
                pass

    # Parse (opzionale)
    if args.no-parse:
        print("[INFO] parse.py disabilitato (--no-parse). Fine.")
        sys.exit(0)

    parse_path = find_file([parse_py])
    if not parse_path:
        print(f"[WARN] parse.py non trovato ({parse_py}). Salto conversione JSON.")
        sys.exit(0)

    json_path = Path(f"{outstem}.json")
    print(f"[INFO] Parsing → {json_path}")
    try:
        js = parse_mfd(str(mfd_path), parse_path)
        json_path.write_text(js, encoding="utf-8")
        print(f"[INFO] JSON salvato: {json_path}")
    except Exception as e:
        print(f"[ERR] parse.py fallito: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Interrotto dall'utente.")
        sys.exit(130)
