#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BambuLab spool tag reader using libnfc utilities.

This script reads BambuLab filament spool tags (MIFARE Classic 1K) using
libnfc command-line tools. It can automatically fetch the RFID-Tag-Guide
repository when missing to obtain ``deriveKeys.py`` and ``parse.py``.

Workflow:
1. Repeatedly call ``nfc-list -v`` until a tag UID is found.
2. Derive sector keys via ``deriveKeys.py`` using the UID.
3. Dump the tag with ``nfc-mfclassic``.
4. Optionally parse the dump with ``parse.py`` to produce JSON.

All intermediate paths are resolved to absolute paths to avoid issues with
scripts that change their working directory.
"""

import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_GUIDE = HERE.parent / "RFID-Tag-Guide"
GUIDE_GIT = "https://github.com/Bambu-Research-Group/RFID-Tag-Guide"
GUIDE_ZIP = (
    "https://github.com/Bambu-Research-Group/RFID-Tag-Guide/archive/refs/heads/main.zip"
)

def sh(cmd, check: bool = True) -> subprocess.CompletedProcess:
    """Run *cmd* returning the CompletedProcess.

    Raises ``RuntimeError`` on non-zero exit code when ``check`` is True.
    ``stdout`` and ``stderr`` are captured for diagnostics.
    """

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"--- STDOUT ---\n{proc.stdout}\n--- STDERR ---\n{proc.stderr}"
        )
    return proc


def timestamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


UID_PATTERNS = [
    re.compile(
        r"UID\s*\(NFCID1\)\s*:\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2}){3,10})"
    ),
    re.compile(r"NFCID1\s*:\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2}){3,10})"),
]


def get_uid_once() -> tuple[str | None, bool, str | None, str | None, str]:
    """Run ``nfc-list -v`` once and try to extract UID and tag info."""

    proc = sh(["nfc-list", "-v"], check=False)
    out = (proc.stdout or "") + (proc.stderr or "")

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
    elif atqa == "0x0004" and sak in {"0x08", "0x09"}:
        m1k = True

    return uid_hex, m1k, atqa, sak, out


def scan_uid_until(timeout_s: float = 8.0, interval_s: float = 0.3) -> tuple[str, bool, str | None, str | None]:
    """Repeatedly call ``nfc-list`` until UID found or timeout."""

    start = time.time()
    last_out = ""
    while time.time() - start < timeout_s:
        uid, m1k, atqa, sak, out = get_uid_once()
        last_out = out
        if uid:
            return uid, m1k, atqa, sak
        time.sleep(interval_s)
    raise RuntimeError(
        "Impossibile estrarre UID: nessun tag rilevato.\n"
        f"Output finale nfc-list:\n{last_out}"
    )


def ensure_guide_repo(guide_dir: Path, auto_fetch: bool = True) -> tuple[str, str]:
    """Return absolute paths to deriveKeys.py and parse.py.

    If missing and ``auto_fetch`` is True, clone or download the repository.
    """

    derive_py = guide_dir / "deriveKeys.py"
    parse_py = guide_dir / "parse.py"
    if derive_py.exists() and parse_py.exists():
        return str(derive_py.resolve()), str(parse_py.resolve())

    if not auto_fetch:
        raise FileNotFoundError(f"RFID-Tag-Guide non trovato in {guide_dir}")

    guide_dir = guide_dir.resolve()
    guide_dir.parent.mkdir(parents=True, exist_ok=True)

    # Attempt git clone first
    if shutil.which("git"):
        try:
            print(f"[INFO] Clono {GUIDE_GIT} in {guide_dir}…")
            sh(["git", "clone", "--depth", "1", GUIDE_GIT, str(guide_dir)])
        except Exception as e:
            print(f"[WARN] git clone fallito: {e}. Provo download zip…")

    # If still missing, download ZIP
    if not (derive_py.exists() and parse_py.exists()):
        with tempfile.TemporaryDirectory() as td:
            zip_path = Path(td) / "guide.zip"
            print(f"[INFO] Scarico ZIP {GUIDE_ZIP} …")
            urllib.request.urlretrieve(GUIDE_ZIP, zip_path)
            print("[INFO] Estraggo ZIP…")
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(Path(td))
            roots = [p for p in Path(td).iterdir() if p.is_dir()]
            if not roots:
                raise RuntimeError("ZIP estratto ma cartella non trovata")
            extracted = max(roots, key=lambda p: len(list(p.rglob("*"))))
            guide_dir.mkdir(parents=True, exist_ok=True)
            for item in extracted.iterdir():
                dest = guide_dir / item.name
                if item.is_dir():
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(item, dest)
                else:
                    shutil.copy2(item, dest)

    if not (derive_py.exists() and parse_py.exists()):
        raise FileNotFoundError(
            f"Impossibile preparare RFID-Tag-Guide in {guide_dir}"
        )

    return str(derive_py.resolve()), str(parse_py.resolve())


def derive_keys(
    uid_hex: str,
    derive_py_abs: str,
    master_key: str | None = None,
    show: bool = False,
) -> str:
    """Run ``deriveKeys.py`` and write keys to a temporary file.

    When ``show`` is True, the derived keys are printed to stdout for debug.
    ``master_key`` allows overriding the default master secret used by
    ``deriveKeys.py``.
    """

    cmd = ["python3", derive_py_abs, uid_hex]
    if master_key:
        cmd.extend(["--master-key", master_key])

    proc = sh(cmd, check=True)

    if show:
        print("[DBG] Chiavi derivate:\n" + proc.stdout.strip())

    tmp = tempfile.NamedTemporaryFile(
        prefix="keys_", suffix=".dic", delete=False, mode="w"
    )
    tmp.write(proc.stdout)
    tmp.close()
    logging.debug("Chiavi derivate salvate in %s:\n%s", tmp.name, proc.stdout.strip())
    return tmp.name


def nfclassic_dump(out_mfd_abs: str, keys_dic_path: str) -> subprocess.CompletedProcess:
    """Dump the tag with ``nfc-mfclassic`` and return the process.

    ``nfc-mfclassic`` may report "authentication failed" while still exiting
    with status 0. Detect this case to provide a clearer error message and, when
    possible, indicate the failing block/sector.
    """

    proc = sh(["nfc-mfclassic", "r", "a", out_mfd_abs, keys_dic_path], check=False)
    out_combined = proc.stdout + proc.stderr

    if proc.returncode != 0 or "authentication failed" in out_combined.lower():
        m_block = re.search(r"block\s+(0x[0-9A-Fa-f]+|\d+)", out_combined, re.IGNORECASE)
        m_sector = re.search(r"sector\s+(0x[0-9A-Fa-f]+|\d+)", out_combined, re.IGNORECASE)

        if m_block:
            block_val = int(m_block.group(1), 0)
            sector_val = block_val // 4
            where = f"block {block_val} (0x{block_val:02X}, sector {sector_val})"
        elif m_sector:
            sector_val = int(m_sector.group(1), 0)
            where = f"sector {sector_val}"
        else:
            where = "sconosciuto"

    out_combined = proc.stdout + proc.stderr
    if "authentication failed" in out_combined.lower():
        m = re.search(r"authentication failed for block 0x([0-9a-fA-F]+)", out_combined)
        if m:
            blk = int(m.group(1), 16)
            sector = blk // 4
            msg = (
                f"Autenticazione al tag fallita (blocco 0x{blk:02X}, settore {sector}).\n"
            )
        else:
            msg = "Autenticazione al tag fallita (chiavi errate?).\n"
        raise RuntimeError(
            msg + f"--- STDOUT ---\n{proc.stdout}\n--- STDERR ---\n{proc.stderr}"
        )

    return proc


def parse_mfd(mfd_abs: str, parse_py_abs: str) -> str:
    """Parse an ``.mfd`` dump via ``parse.py``."""

    proc = sh(["python3", parse_py_abs, mfd_abs], check=True)
    return proc.stdout


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Bambu MIFARE Classic 1K reader (solo libnfc, auto-fetch guida)"
    )
    ap.add_argument(
        "--guide",
        default=str(DEFAULT_GUIDE),
        help="Percorso della cartella RFID-Tag-Guide (verrà creata se manca)",
    )
    ap.add_argument("--derive", default=None, help="Path a deriveKeys.py (opzionale)")
    ap.add_argument("--parse", default=None, help="Path a parse.py (opzionale)")
    ap.add_argument("--keys", default=None, help="Usa questo keys.dic e salta deriveKeys.py")

    ap.add_argument(
        "--master-key",
        dest="master_key",
        default=None,
        help="Master key esadecimale (32 hex) per deriveKeys.py",
    )
    ap.add_argument(
        "--show-keys",
        dest="show_keys",
        action="store_true",
        help="Stampa a video le chiavi derivate (debug)",
    )

    ap.add_argument(
        "--no-parse",
        dest="no_parse",
        action="store_true",
        help="Non eseguire parse.py (lascia solo .mfd)",
    )
    ap.add_argument(
        "--only-parse",
        dest="only_parse",
        default=None,
        help="Salta la lettura: esegue solo parse.py su questo .mfd (consigliato path assoluto)",
    )
    ap.add_argument(
        "--outstem",
        default=None,
        help="Prefisso output (default: bambu_tag_<timestamp>)",
    )
    ap.add_argument(
        "--no-auto-fetch",
        dest="auto_fetch",
        action="store_false",
        help="Non scaricare automaticamente RFID-Tag-Guide se manca",
    )
    ap.set_defaults(auto_fetch=True)
    ap.add_argument(
        "--scan-timeout",
        type=float,
        default=8.0,
        help="Secondi massimi per trovare l'UID con nfc-list (default: 8.0)",
    )
    ap.add_argument("--debug", action="store_true", help="Abilita messaggi di debug")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    guide_path = Path(args.guide)
    derive_py_abs: str | None = None
    parse_py_abs: str | None = None

    # Determine paths for deriveKeys.py and parse.py upfront
    if args.only_parse:
        if args.parse:
            parse_py_abs = str(Path(args.parse).resolve())
        else:
            _, parse_py_abs = ensure_guide_repo(guide_path, auto_fetch=args.auto_fetch)
    else:
        if args.keys:
            if args.parse:
                parse_py_abs = str(Path(args.parse).resolve())
            elif not args.no_parse:
                _, parse_py_abs = ensure_guide_repo(guide_path, auto_fetch=args.auto_fetch)
        else:
            if args.derive:
                derive_py_abs = str(Path(args.derive).resolve())
            if args.parse:
                parse_py_abs = str(Path(args.parse).resolve())
            if not derive_py_abs or (not parse_py_abs and not args.no_parse):
                d, p = ensure_guide_repo(guide_path, auto_fetch=args.auto_fetch)
                if not derive_py_abs:
                    derive_py_abs = d
                if not parse_py_abs and not args.no_parse:
                    parse_py_abs = p

    # Validate existence
    for path, name in [(derive_py_abs, "deriveKeys.py"), (parse_py_abs, "parse.py")]:
        if path and not Path(path).exists():
            print(f"[ERR] {name} non trovato: {path}", file=sys.stderr)
            sys.exit(2)

    if derive_py_abs:
        print(f"[INFO] deriveKeys.py: {derive_py_abs}")
    if parse_py_abs:
        print(f"[INFO] parse.py: {parse_py_abs}")

    # Parse existing dump only
    if args.only_parse:
        mfd = Path(args.only_parse).resolve()
        if not mfd.exists():
            print(f"[ERR] MFD non trovato: {mfd}", file=sys.stderr)
            sys.exit(2)

        if args.no_parse:
            print("[ERR] --only-parse e --no-parse sono incompatibili.", file=sys.stderr)
            sys.exit(2)

        outstem = args.outstem or f"bambu_tag_{timestamp()}"
        json_path = Path(f"{outstem}.json").resolve()
        print(f"[INFO] Parsing {mfd} → {json_path}")
        try:
            js = parse_mfd(str(mfd), parse_py_abs)  # type: ignore[arg-type]
            json_path.write_text(js, encoding="utf-8")
            print(f"[INFO] JSON salvato in {json_path}")
            sys.exit(0)
        except Exception as e:
            print(f"[ERR] parse.py fallito: {e}", file=sys.stderr)
            sys.exit(1)

    # Live reading
    print("[INFO] Interrogo il reader (scan UID)…")
    try:
        uid_hex, m1k, atqa, sak = scan_uid_until(timeout_s=args.scan_timeout)
    except Exception as e:
        print(f"[ERR] {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] UID: {uid_hex}")
    if not m1k:
        print(
            f"[WARN] Il tag non appare come MIFARE Classic 1K (ATQA={atqa}, SAK={sak}). Procedo comunque."
        )

    outstem = args.outstem or f"bambu_tag_{timestamp()}"
    mfd_path = Path(f"{outstem}.mfd").resolve()

    if args.keys:
        keys_path = Path(args.keys).resolve()
        if not keys_path.exists():
            print(f"[ERR] keys.dic non trovato: {keys_path}", file=sys.stderr)
            sys.exit(2)
        keys_dic_abs = str(keys_path)
    else:
        print("[INFO] Derivo chiavi dall'UID…")
        keys_dic_abs = derive_keys(uid_hex, derive_py_abs)  # type: ignore[arg-type]
        print(f"[INFO] keys.dic salvato: {keys_dic_abs}")

    try:
        if args.keys:
            keys_dic_abs = str(keys_path)
        else:
            print("[INFO] Derivo chiavi dall'UID…")
            keys_dic_abs = derive_keys(
                uid_hex,
                derive_py_abs,  # type: ignore[arg-type]
                master_key=args.master_key,
                show=args.show_keys,
            )
            temp_keys = keys_dic_abs
            
        print(f"[INFO] Dump MIFARE → {mfd_path.name}")
        proc = nfclassic_dump(str(mfd_path), keys_dic_abs)
        if not mfd_path.exists():
            raise RuntimeError(
                f"nfc-mfclassic non ha creato il dump {mfd_path}\n"
                f"--- STDOUT ---\n{proc.stdout}\n--- STDERR ---\n{proc.stderr}"
            )
        print(f"[INFO] Dump salvato: {mfd_path}")

        if args.no_parse:
            print("[INFO] parse.py disabilitato (--no-parse). Fine.")
            return

        json_path = Path(f"{outstem}.json").resolve()
        print(f"[INFO] Parsing → {json_path.name}")
        js = parse_mfd(str(mfd_path), parse_py_abs)  # type: ignore[arg-type]
        json_path.write_text(js, encoding="utf-8")
        print(f"[INFO] JSON salvato: {json_path}")

    except Exception as e:
        print(f"[ERR] Operazione fallita: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Interrotto dall'utente.")
        sys.exit(130)
