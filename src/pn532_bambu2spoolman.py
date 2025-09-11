#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Loop continuo: ad ogni tag NFC Bambu rilevata con PN532
- legge tutti i 64 blocchi (MIFARE Classic 1K)
- salva dump .bin (1024 B) e .dump.json (blocchi grezzi)
- usa il parser interno (bambutag_parse.py) per estrarre i campi
- prepara due file JSON per SpoolMan:
    * <base>.spoolman.filament.json (FilamentParameters)
    * <base>.spoolman.spool.json    (SpoolParameters, senza invio)
Nessuna chiamata HTTP viene effettuata.

Uso (UART consigliato):
    python3 src/pn532_bambu2spoolman.py --uart /dev/ttyUSB0

Uso (I2C su Raspberry):
    python3 src/pn532_bambu2spoolman.py --i2c
"""

import argparse, json, math, os, sys, time, datetime, re
from pathlib import Path

# ---- PN532 drivers ----
from adafruit_pn532.adafruit_pn532 import MIFARE_CMD_AUTH_A, MIFARE_CMD_AUTH_B
from adafruit_pn532.uart import PN532_UART
from adafruit_pn532.i2c import PN532_I2C

try:
    import serial
except Exception:
    serial = None

try:
    import board, busio
    HAVE_BOARD = True
except Exception:
    HAVE_BOARD = False

# ---- Import parser interno della repo ----
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

try:
    import bambutag_parse  # deve essere presente in src/
except Exception as e:
    print("ERRORE: non riesco ad importare bambutag_parse.py dalla cartella src/.\n"
          "Assicurati che il file esista (src/bambutag_parse.py) e riprova.\n"
          f"Dettaglio: {e}")
    sys.exit(2)

# ---- Costanti e utility ----
KEYS_HEX = [
    'FFFFFFFFFFFF', 'A0A1A2A3A4A5', 'D3F7D3F7D3F7', '000000000000',
    'B0B1B2B3B4B5', '4D3A99C351DD', '1A982C7E459A', 'AABBCCDDEEFF'
]
KEYS = [bytes.fromhex(k) for k in KEYS_HEX]

BYTES_PER_BLOCK = 16
TOTAL_BLOCKS = 64
TOTAL_BYTES = BYTES_PER_BLOCK * TOTAL_BLOCKS

EXPORT_DIR = HERE.parent / "export"
EXPORT_DIR.mkdir(exist_ok=True)

def open_pn532(args):
    if args.uart:
        if serial is None:
            print("pyserial non disponibile. Installa con: pip install pyserial")
            sys.exit(2)
        ser = serial.Serial(args.uart, baudrate=args.baud, timeout=1)
        pn = PN532_UART(ser, debug=args.debug)
    elif args.i2c:
        if not HAVE_BOARD:
            print("I2C richiesto ma board/busio non disponibili.")
            sys.exit(2)
        i2c = busio.I2C(board.SCL, board.SDA)
        pn = PN532_I2C(i2c, debug=args.debug)
    else:
        print("Specifica --uart /dev/ttyUSB0 oppure --i2c")
        sys.exit(2)
    pn.SAM_configuration()
    return pn

def wait_for_tag(pn, timeout=None):
    t0 = time.time()
    while True:
        uid = pn.read_passive_target(timeout=0.5)
        if uid is not None:
            return bytes(uid)
        if timeout and (time.time() - t0 > timeout):
            return None

def try_auth_sector(pn, uid, sector):
    first_block = sector * 4
    if pn.mifare_classic_authenticate_block(uid, first_block, MIFARE_CMD_AUTH_A, KEYS[0]):
        return ('A', KEYS[0])
    # proverà tutte le chiavi se la prima non va
    for key in KEYS:
        if pn.mifare_classic_authenticate_block(uid, first_block, MIFARE_CMD_AUTH_A, key):
            return ('A', key)
        if pn.mifare_classic_authenticate_block(uid, first_block, MIFARE_CMD_AUTH_B, key):
            return ('B', key)
    return (None, None)

def read_full_tag(pn, uid):
    dump = bytearray()
    blocks_json = []
    for sector in range(16):
        mode, key = try_auth_sector(pn, uid, sector)
        if mode is None:
            raise RuntimeError(f"Autenticazione fallita sul settore {sector}. Prova a riposizionare la tag o ampliare le chiavi.")
        for block in range(sector*4, sector*4 + 4):
            data = pn.mifare_classic_read_block(block)
            if data is None or len(data) != 16:
                raise RuntimeError(f"Lettura fallita al blocco {block}.")
            dump.extend(data)
            blocks_json.append({'index': block, 'data': data.hex().upper()})
    return bytes(dump), blocks_json

# ---- Mapping/materiali -> densità (g/cm^3) ----
DENSITY_BY_MATERIAL = {
    'PLA': 1.24, 'PETG': 1.27, 'ABS': 1.04, 'ASA': 1.07,
    'TPU': 1.21, 'PA': 1.14, 'PC': 1.20, 'PVA': 1.30,
}

def guess_material(text: str) -> str | None:
    if not text:
        return None
    t = text.upper()
    for m in DENSITY_BY_MATERIAL.keys():
        if m in t:
            return m
    m = re.search(r'[A-Z]{2,4}', t)
    return m.group(0) if m else None

def extract_color_hex(color_field: str) -> tuple[str | None, list[str] | None]:
    """Ritorna (color_hex singolo, lista_multi) senza '#'."""
    if not color_field:
        return None, None
    parts = [p.strip() for p in color_field.split('/') if p.strip()]
    hexes = []
    for p in parts:
        h = p.replace('#', '').strip()
        if re.fullmatch(r'[0-9A-Fa-f]{6,8}', h):
            hexes.append(h.upper())
    if not hexes:
        return None, None
    if len(hexes) == 1:
        return hexes[0], None
    return None, hexes

def unit_value(u):
    """Estrae il valore numerico da bambutag_parse.Unit o lascia int/float."""
    try:
        return getattr(u, 'value')
    except Exception:
        pass
    if isinstance(u, (int, float)):
        return u
    if isinstance(u, str):
        m = re.search(r'[-+]?[0-9]*\.?[0-9]+', u)
        return float(m.group(0)) if m else None
    return None

def compute_net_weight_grams(d_mm: float, length_m: float, density_g_cm3: float) -> float | None:
    """grammi = densità * (pi/4) * d_mm^2 * lunghezza_m"""
    if not (d_mm and length_m and density_g_cm3):
        return None
    return density_g_cm3 * (math.pi/4.0) * (d_mm**2) * (length_m)

def build_spoolman_payloads(tag_obj, uid_hex: str):
    d = tag_obj.data
    filament_type = d.get('filament_type')
    detailed_type = d.get('detailed_filament_type')
    color_field   = d.get('filament_color')
    spool_weight  = unit_value(d.get('spool_weight'))
    length_m      = unit_value(d.get('filament_length'))
    diameter_mm   = unit_value(d.get('filament_diameter'))
    temps         = d.get('temperatures') or {}
    bed_temp      = unit_value(temps.get('bed_temp'))
    min_hotend    = unit_value(temps.get('min_hotend'))
    max_hotend    = unit_value(temps.get('max_hotend'))
    prod_date     = d.get('production_date')
    material_id   = d.get('material_id')
    variant_id    = d.get('variant_id')

    prod_date_str = prod_date.isoformat() if hasattr(prod_date, 'isoformat') else (str(prod_date) if prod_date else None)
    material = guess_material(f"{filament_type} {detailed_type}")
    density  = DENSITY_BY_MATERIAL.get(material) if material else None
    color_hex, multi_hexes = extract_color_hex(color_field if isinstance(color_field, str) else None)

    name = None
    if detailed_type and isinstance(detailed_type, str) and detailed_type.strip():
        name = f"{detailed_type}".strip()
    elif filament_type and isinstance(filament_type, str) and filament_type.strip():
        name = f"{filament_type}".strip()
    else:
        name = f"Bambu Filament"
    if color_hex and len(color_hex) == 6 and color_hex.upper() != "FFFFFF":
        name += f" #{color_hex.upper()}"

    init_weight = compute_net_weight_grams(diameter_mm, length_m, density) if (diameter_mm and length_m and density) else None
    if init_weight is not None:
        init_weight = round(init_weight, 1)

    filament_params = {
        "name": name,
        "material": material,
        "diameter": round(diameter_mm, 3) if diameter_mm else None,
        "density": round(density, 3) if density else None,
        "weight": init_weight,
        "spool_weight": round(spool_weight, 1) if spool_weight else None,
        "color_hex": color_hex,
        "multi_color_hexes": ",".join(multi_hexes) if multi_hexes else None,
        "settings_extruder_temp": int(max_hotend) if max_hotend else None,
        "settings_bed_temp": int(bed_temp) if bed_temp else None,
        "external_id": f"bambu:material_id={material_id}|variant_id={variant_id}"
    }
    filament_params = {k:v for k,v in filament_params.items() if v is not None}

    spool_params = {
        "filament_id": "<REPLACE_ME>",
        "spool_weight": round(spool_weight, 1) if spool_weight else None,
        "initial_weight": init_weight,
        "lot_nr": prod_date_str,
        "comment": f"Import da tag Bambu | UID={uid_hex.upper()} | variant_id={variant_id}"
    }
    spool_params = {k:v for k,v in spool_params.items() if v is not None}

    return filament_params, spool_params

def main():
    ap = argparse.ArgumentParser(description="PN532 -> Dump completo + Parse + JSON per SpoolMan (no chiamate API)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--uart", help="es. /dev/ttyUSB0 (PN532 in HSU/UART)")
    g.add_argument("--i2c", action="store_true", help="usa I2C (Raspberry)")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--oneshot", action="store_true", help="legge una sola tag e termina")
    args = ap.parse_args()

    pn = open_pn532(args)

    print("Pronto. Avvicina una tag Bambu alla testina PN532...")
    while True:
        uid = wait_for_tag(pn)
        uid_hex = uid.hex().upper()
        print(f"\nTag rilevata. UID={uid_hex}")

        try:
            dump, blocks_json = read_full_tag(pn, uid)
        except Exception as e:
            print(f"ERRORE lettura tag: {e}")
            if args.oneshot:
                sys.exit(1)
            else:
                continue

        if len(dump) != TOTAL_BYTES:
            print(f"Dump incompleto ({len(dump)} bytes). Attesi {TOTAL_BYTES}.")
            if args.oneshot:
                sys.exit(1)
            else:
                continue

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"bambu_tag_{ts}_{uid_hex}"
        bin_path  = EXPORT_DIR / f"{base}.bin"
        json_path = EXPORT_DIR / f"{base}.dump.json"

        with open(bin_path, "wb") as f:
            f.write(dump)
        with open(json_path, "w") as f:
            json.dump({"uid": uid_hex, "blocks": blocks_json}, f, indent=2)

        print(f"Salvati:\n  - {bin_path}\n  - {json_path}")

        try:
            tag_obj = bambutag_parse.Tag(bin_path, dump)
        except Exception as e:
            print(f"ERRORE parser: {e}")
            if args.oneshot:
                sys.exit(1)
            else:
                continue

        filament_params, spool_params = build_spoolman_payloads(tag_obj, uid_hex)

        filament_json = EXPORT_DIR / f"{base}.spoolman.filament.json"
        spool_json    = EXPORT_DIR / f"{base}.spoolman.spool.json"

        with open(filament_json, "w") as f:
            json.dump(filament_params, f, indent=2)
        with open(spool_json, "w") as f:
            json.dump(spool_params, f, indent=2)

        print("Creati payload SpoolMan:")
        print(f"  - {filament_json}")
        print(f"  - {spool_json}")
        print("\nRiepilogo rapido:")
        print(json.dumps({
            "filament_preview": filament_params,
            "spool_preview": spool_params
        }, indent=2))

        if args.oneshot:
            break

        print("\nPronto per una nuova tag... (Ctrl+C per uscire)")
        time.sleep(1.0)

if __name__ == "__main__":
    main()
