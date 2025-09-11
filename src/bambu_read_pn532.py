#!/usr/bin/env python3
import sys, time, json, binascii
import nfc


# importa il KDF ufficiale
try:
    from thirdparty.deriveKeys import kdf
except ModuleNotFoundError:  # support execution as package
    from .thirdparty.deriveKeys import kdf

try:
    from bambutag_parse import Tag as BambuTag
except ModuleNotFoundError:
    from .bambutag_parse import Tag as BambuTag

try:
    from spoolman_formatter import tag_to_spoolman_payload
except ModuleNotFoundError:
    from .spoolman_formatter import tag_to_spoolman_payload


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
    Legge MIFARE Classic 1K (64 blocchi da 16 byte).
    Per ogni blocco autentica con la Key A del settore di appartenenza e
    tenta la lettura. Restituisce la lista dei blocchi letti e i byte grezzi.
    """
    blocks = []
    raw = bytearray()

    for blk in range(64):
        sector = blk // 4
        keyA = keysA[sector] if sector < len(keysA) else None
        if keyA is None:
            continue

        # autenticazione per il blocco corrente
        auth_ok = False
        if hasattr(tag, "authenticate"):
            try:
                auth_ok = bool(tag.authenticate(blk, keyA, 0x60))
            except Exception:
                pass
        if not auth_ok and hasattr(tag, "classic_auth_a"):
            try:
                auth_ok = bool(tag.classic_auth_a(blk, keyA))
            except Exception:
                pass
        if not auth_ok:
            continue

        # lettura del blocco
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
