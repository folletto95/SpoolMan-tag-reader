#!/usr/bin/env python3
"""
pn532_bambu2spoolman.py
-----------------------

Questo script ascolta continuamente le tag NFC usando PN532 e, per ogni tag
Bambu rilevata, esegue il dump completo (64 blocchi), salva i dati grezzi,
parsa la tag con bambutag_parse.py e genera due JSON pronti per le API di
SpoolMan (FilamentParameters e SpoolParameters).
Gestisce correttamente l’eccezione “More than one card detected!” e gli
eventuali errori di autenticazione.
"""

from __future__ import annotations
import argparse, json, math, os, sys, time, datetime, re
from pathlib import Path

# PN532 drivers (richiedono adafruit-circuitpython-pn532 e pyserial)
from adafruit_pn532.adafruit_pn532 import MIFARE_CMD_AUTH_A, MIFARE_CMD_AUTH_B
from adafruit_pn532.uart import PN532_UART
from adafruit_pn532.i2c import PN532_I2C
import serial
import board, busio

# Import parser bambu
from . import bambutag_parse  # se lanciate dalla cartella src

# Chiavi MIFARE note (si possono estendere)
KEYS_HEX = [
    "FFFFFFFFFFFF", "A0A1A2A3A4A5", "D3F7D3F7D3F7",
    "000000000000", "B0B1B2B3B4B5", "4D3A99C351DD",
    "1A982C7E459A", "AABBCCDDEEFF", "A1B2C3D4E5F6",
    "010203040506", "9876543210FF",
]
KEYS = [bytes.fromhex(k) for k in KEYS_HEX]
BYTES_PER_BLOCK = 16
TOTAL_BLOCKS = 64

# Densità di alcuni materiali (g/cm³)
DENSITY_BY_MATERIAL = {
    "PLA": 1.24, "PETG": 1.27, "ABS": 1.04,
    "ASA": 1.07, "TPU": 1.21, "PA": 1.14,
    "PC": 1.20, "PVA": 1.30,
}

def open_pn532(args):
    if args.uart:
        ser = serial.Serial(args.uart, baudrate=args.baud, timeout=1)
        pn = PN532_UART(ser, debug=args.debug)
    elif args.i2c:
        i2c = busio.I2C(board.SCL, board.SDA)
        pn = PN532_I2C(i2c, debug=args.debug)
    else:
        raise SystemExit("--uart o --i2c è obbligatorio")
    pn.SAM_configuration()
    return pn

def wait_for_tag(pn, timeout=None):
    """Poll incessante per una sola tag; ignora l’errore 'More than one card detected!'."""
    start = time.monotonic()
    while True:
        try:
            uid = pn.read_passive_target(timeout=0.5)
        except RuntimeError as e:
            if "More than one card detected" in str(e):
                time.sleep(0.2)
                continue
            print(f"read_passive_target error: {e}")
            time.sleep(0.2)
            continue
        if uid:
            return bytes(uid)
        if timeout and (time.monotonic() - start) > timeout:
            return None

def try_auth_sector(pn, uid, sector):
    """Autentica il primo blocco del settore con le chiavi note."""
    first = sector * 4
    for key in KEYS:
        try:
            if pn.mifare_classic_authenticate_block(uid, first, MIFARE_CMD_AUTH_A, key):
                return ("A", key)
        except Exception:
            pass
        try:
            if pn.mifare_classic_authenticate_block(uid, first, MIFARE_CMD_AUTH_B, key):
                return ("B", key)
        except Exception:
            pass
    return (None, None)

def read_full_tag(pn, uid):
    """Legge tutti i 64 blocchi di una MIFARE Classic 1K; solleva RuntimeError se un settore non si autentica."""
    dump = bytearray()
    blocks_json = []
    for sector in range(16):
        mode, key = try_auth_sector(pn, uid, sector)
        if mode is None:
            raise RuntimeError(f"Autenticazione fallita sul settore {sector}.")
        for block in range(sector*4, sector*4+4):
            data = pn.mifare_classic_read_block(block)
            if not data or len(data) != 16:
                raise RuntimeError(f"Lettura fallita al blocco {block}.")
            dump.extend(data)
            blocks_json.append({"index": block, "data": data.hex().upper()})
    return bytes(dump), blocks_json

# Funzioni di utilità (estrazione numeri, parsing colori, ecc.) qui...

# Funzione build_spoolman_payloads che costruisce FilamentParameters e SpoolParameters.

# Funzione main con ciclo: attende tag, effettua dump, salva .bin e .json,
# parsifica con bambutag_parse.Tag, genera JSON per SpoolMan e li salva in export/.

if __name__ == "__main__":
    main()
