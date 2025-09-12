import argparse
import binascii
import glob
import json
import os
import subprocess
import tempfile
import time

import nfc

from bambutag_parse import Tag as BambuTag
from spoolman_formatter import tag_to_spoolman_payload


def detect_device() -> str | None:
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


def get_uid_and_release(device_str: str) -> str:
    """Apre PN532, legge UID via nfcpy e RILASCIA SUBITO il reader."""

    uid_hex: str | None = None

    def on_connect(tag):
        nonlocal uid_hex
        try:
            uid_hex = binascii.hexlify(tag.identifier).decode().upper()
        finally:
            # Restituisci True per chiudere immediatamente la sessione sul reader
            return True

    with nfc.ContactlessFrontend(device_str) as clf:
        clf.connect(rdwr={"on-connect": on_connect, "beep-on-connect": False})

    if not uid_hex:
        raise RuntimeError("Impossibile leggere l'UID dal tag")
    return uid_hex


def derive_keys_to_tmp(uid_hex: str) -> str:
    """Prova a derivare le chiavi con deriveKeys.py; se non presente, solleva."""

    candidates = [
        "./RFID-Tag-Guide/deriveKeys.py",
        "../RFID-Tag-Guide/deriveKeys.py",
        "/opt/RFID-Tag-Guide/deriveKeys.py",
    ]
    derive = next((p for p in candidates if os.path.exists(p)), None)
    if derive is None:
        raise FileNotFoundError("deriveKeys.py non trovato. Clona RFID-Tag-Guide e riprova.")

    with tempfile.NamedTemporaryFile(prefix="keys_", suffix=".dic", delete=False, mode="w") as f:
        tmp_keys = f.name

    res = subprocess.run(
        ["python3", derive, uid_hex],
        check=True,
        capture_output=True,
        text=True,
    )
    with open(tmp_keys, "w") as f:
        f.write(res.stdout)
    return tmp_keys


def dump_mifare_with_libnfc(out_path: str, keys_dic_path: str) -> None:
    """Esegue nfc-mfclassic DOPO che il reader è stato rilasciato da nfcpy."""

    cmd = ["nfc-mfclassic", "r", "a", out_path, keys_dic_path]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(
            f"nfc-mfclassic exit {res.returncode}\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )


def handle_bambu_spool(device_str: str, out_stem: str) -> None:
    # 1) UID e rilascio del PN532
    uid = get_uid_and_release(device_str)
    print(f"[INFO] UID: {uid}")

    # 2) Deriva chiavi in file temporaneo
    keys_dic = derive_keys_to_tmp(uid)

    try:
        # 3) Dump completo (ora libnfc può aprire il lettore)
        mfd_path = f"{out_stem}.mfd"
        dump_mifare_with_libnfc(mfd_path, keys_dic)
        print(f"[INFO] Dump MIFARE salvato: {mfd_path}")

        with open(mfd_path, "rb") as f:
            raw = f.read()
        blocks = [
            {"index": i // 16, "data": raw[i : i + 16].hex().upper()}
            for i in range(0, len(raw), 16)
            if len(raw[i : i + 16]) == 16
        ]
        dump_lines = [f"{b['index']:03}: {b['data']}" for b in blocks]
        dump_file = f"{out_stem}.dump.txt"
        with open(dump_file, "w") as df:
            df.write("\n".join(dump_lines))
        print(f"[INFO] Dump testuale salvato in {dump_file}")

        out_json = {"uid": uid, "blocks": blocks}

        try:
            tag_obj = BambuTag(mfd_path, raw)
            spool_data = tag_to_spoolman_payload(tag_obj)
            out_json["spoolman"] = spool_data
            spool_file = f"{out_stem}.spoolman.json"
            with open(spool_file, "w") as sf:
                json.dump(spool_data, sf, indent=2)
            print(f"[INFO] Dati Spoolman salvati in {spool_file}")
        except Exception as e:
            print(f"[WARN] Impossibile estrarre dati Spoolman: {e}")

        parse_candidates = [
            "./RFID-Tag-Guide/parse.py",
            "../RFID-Tag-Guide/parse.py",
            "/opt/RFID-Tag-Guide/parse.py",
        ]
        parse = next((p for p in parse_candidates if os.path.exists(p)), None)
        json_path = f"{out_stem}.json"
        if parse:
            res = subprocess.run(
                ["python3", parse, mfd_path],
                check=True,
                capture_output=True,
                text=True,
            )
            with open(json_path, "w") as f:
                f.write(res.stdout)
            print(f"[INFO] JSON salvato: {json_path}")
        else:
            with open(json_path, "w") as f:
                json.dump(out_json, f, indent=2)
            print(f"[WARN] parse.py non trovato: salvato dump base in {json_path}")

    finally:
        try:
            os.remove(keys_dic)
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Legge le tag NFC delle bobine BambuLab",
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

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    stem = f"bambu_tag_{timestamp}"
    handle_bambu_spool(device, stem)


if __name__ == "__main__":
    main()

