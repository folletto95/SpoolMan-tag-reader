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

    # l'oggetto tag potrebbe non esporre le API MIFARE Classic; in quel caso
    # usiamo direttamente l'interfaccia del frontend (clf.exchange)
    clf = getattr(tag, "clf", getattr(tag, "_clf", None))
    uid = getattr(tag, "identifier", b"")

    for blk in range(64):
        sector = blk // 4
        keyA = keysA[sector] if sector < len(keysA) else None
        if keyA is None:
            continue

        auth_ok = False

        # 1) API alte se disponibili
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

        # 2) fallback a scambio raw via PN532
        if not auth_ok and clf is not None and uid:
            try:
                cmd = bytearray([0x60, blk]) + keyA + uid[:4]
                rsp = clf.exchange(cmd)
                auth_ok = bool(rsp and rsp[0] == 0x00)
            except Exception:
                pass
        if not auth_ok:
            continue

        data = None
        if hasattr(tag, "read"):
            try:
                data = tag.read(blk)
            except Exception:
                data = None
        if data is None and hasattr(tag, "read_block"):
            try:
                data = tag.read_block(blk)
            except Exception:
                data = None
        if data is None and clf is not None:
            try:
                data = clf.exchange(bytearray([0x30, blk]))
            except Exception:
                data = None

        if isinstance(data, (bytes, bytearray)) and len(data) == 16:
            blocks.append({"index": blk, "data": data.hex().upper()})
            raw.extend(data)

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
