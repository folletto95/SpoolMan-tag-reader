#!/usr/bin/env python3
import sys, time, json, binascii
import nfc


# importa il KDF ufficiale
from src.thirdparty.deriveKeys import kdf
from src.bambutag_parse import Tag as BambuTag
from src.spoolman_formatter import tag_to_spoolman_payload


def keylist_from_uid(uid_hex: str):
    """
    Restituisce una lista di 16 chiavi A (6 byte ciascuna) per i settori 0..15,
    usando il KDF della repo Bambu (deriveKeys.py).
    """
    # kdf restituisce 16 chiavi in formato bytes
    keys = kdf(bytes.fromhex(uid_hex))
    out = []
    for k in keys:
        if isinstance(k, str):
            out.append(binascii.unhexlify(k.replace(" ", "")))
        else:
            out.append(k)
    if len(out) != 16:
        raise RuntimeError(f"Attese 16 chiavi, ottenute {len(out)}")
    return out

def read_mfc_with_keys(tag, keysA):
    """
    Legge MIFARE Classic 1K: 16 settori, 4 blocchi/settore (0..3), blocco 3 = trailer.
    Autentica su ciascun settore con Key A, legge i 3 blocchi dati.
    Ritorna: blocks(list[{'index': int, 'data': HEX32}]), raw_bytes
    """
    blocks = []
    raw = bytearray()

    # Alcuni lettori consentono il blocco 0 (manufacturer) senza auth:
    try:
        b0 = tag.read(0) if hasattr(tag, "read") else tag.read_block(0)
        blocks.append({"index": 0, "data": b0.hex().upper()})
        raw.extend(b0)
    except Exception:
        pass

    for sector in range(16):
        base = sector * 4
        keyA = keysA[sector] if sector < len(keysA) else None
        if keyA is None:
            continue

        # nfcpy espone metodi leggermente diversi a seconda della versione/driver:
        auth_ok = False
        # tentativo 1: authenticate(blocco, key, 0x60=KeyA)
        if hasattr(tag, "authenticate"):
            try:
                auth_ok = bool(tag.authenticate(base, keyA, 0x60))
            except Exception:
                auth_ok = False

        # tentativo 2: classic_auth_a(blocco, key) (alcune build/porting)
        if not auth_ok and hasattr(tag, "classic_auth_a"):
            try:
                auth_ok = bool(tag.classic_auth_a(base, keyA))
            except Exception:
                auth_ok = False

        if not auth_ok:
            # niente panico: proseguiamo con i settori che si autenticano
            continue

        # leggi i blocchi dati 0..2 del settore (salta trailer 3)
        for off in (0, 1, 2):
            blk = base + off
            try:
                data = tag.read(blk) if hasattr(tag, "read") else tag.read_block(blk)
                if len(data) == 16:
                    blocks.append({"index": blk, "data": data.hex().upper()})
                    raw.extend(data)
            except Exception:
                pass

    return blocks, bytes(raw)

def on_connect(tag):
    # stampa UID
    uid = getattr(tag, "identifier", b"")
    uid_hex = uid.hex().upper()
    print(f"[INFO] UID: {uid_hex}")

    # ottieni chiavi con il KDF ufficiale
    keysA = keylist_from_uid(uid_hex)
    print(f"[INFO] Derivate {len(keysA)} chiavi per settore")

    # esegui lettura autenticata
    blocks, raw = read_mfc_with_keys(tag, keysA)
    print(f"[INFO] Blocchi letti: {len(blocks)}  Bytes: {len(raw)}")

    ts = time.strftime("%Y%m%d_%H%M%S")
    base = f"bambu_{uid_hex}_{ts}"

    # salva dump bin
    with open(base + ".bin", "wb") as f:
        f.write(raw)
    # salva json grezzo
    with open(base + ".json", "w") as f:
        json.dump({"uid": uid_hex, "blocks": blocks}, f, indent=2)

    # estrai i dati con il parser ufficiale e prepara il payload per Spoolman
    try:
        tag_obj = BambuTag(base + ".bin", raw)
        spoolman_data = tag_to_spoolman_payload(tag_obj)
        with open(base + ".spoolman.json", "w") as f:
            json.dump(spoolman_data, f, indent=2)
        print(f"[OK] Dati Spoolman salvati in {base}.spoolman.json")
    except Exception as e:
        print(f"[WARN] Impossibile estrarre dati Spoolman: {e}")

    # se vuoi leggere più tag nella stessa sessione, ritorna True
    return True

def main():
    # device da CLI, es: --device tty:USB0:pn532
    device = None
    if len(sys.argv) > 2 and sys.argv[1] == "--device":
        device = sys.argv[2]
    if not device:
        device = "tty:USB0:pn532"

    print(f"[INFO] Apertura PN532 su '{device}' ...")
    with nfc.ContactlessFrontend(device) as clf:
        clf.connect(rdwr={"on-connect": on_connect})

if __name__ == "__main__":
    main()
