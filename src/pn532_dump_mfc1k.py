#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, time, sys, json
from binascii import hexlify

# PN532 CircuitPython
from adafruit_pn532.adafruit_pn532 import MIFARE_CMD_AUTH_A, MIFARE_CMD_AUTH_B
from adafruit_pn532.uart import PN532_UART
from adafruit_pn532.i2c import PN532_I2C

# UART/I2C su Linux/Raspberry
import serial
try:
    import board, busio
    HAVE_BOARD = True
except Exception:
    HAVE_BOARD = False

# Set di chiavi note per MIFARE Classic
KEYS = [bytes.fromhex(k) for k in [
    'FFFFFFFFFFFF', 'A0A1A2A3A4A5', 'D3F7D3F7D3F7', '000000000000',
    'B0B1B2B3B4B5', '4D3A99C351DD', '1A982C7E459A', 'AABBCCDDEEFF'
]]

def open_pn532(args):
    if args.uart:
        ser = serial.Serial(args.uart, baudrate=args.baud, timeout=1)
        pn = PN532_UART(ser, debug=args.debug)
    elif args.i2c:
        if not HAVE_BOARD:
            print('I2C richiesto ma board/busio non disponibili.', file=sys.stderr); sys.exit(2)
        i2c = busio.I2C(board.SCL, board.SDA)
        pn = PN532_I2C(i2c, debug=args.debug)
    else:
        print('Specifica --uart /dev/ttyUSB0 oppure --i2c', file=sys.stderr); sys.exit(2)
    pn.SAM_configuration()
    return pn

def wait_for_tag(pn, timeout=60):
    t0 = time.time()
    while True:
        uid = pn.read_passive_target(timeout=0.5)
        if uid is not None:
            return bytes(uid)
        if time.time() - t0 > timeout:
            return None

def try_auth_sector(pn, uid, sector):
    first_block = sector * 4
    for key in KEYS:
        if pn.mifare_classic_authenticate_block(uid, first_block, MIFARE_CMD_AUTH_A, key):
            return ('A', key)
        if pn.mifare_classic_authenticate_block(uid, first_block, MIFARE_CMD_AUTH_B, key):
            return ('B', key)
    return (None, None)

def read_full_tag(pn, uid):
    dump = bytearray()
    blocks_json = []
    for sector in range(16):  # 16 settori * 4 blocchi = 64 blocchi
        mode, key = try_auth_sector(pn, uid, sector)
        if mode is None:
            raise RuntimeError(f'Autenticazione fallita sul settore {sector}. Prova altre chiavi.')
        for block in range(sector*4, sector*4 + 4):
            data = pn.mifare_classic_read_block(block)
            if data is None or len(data) != 16:
                raise RuntimeError(f'Lettura fallita al blocco {block}.')
            dump.extend(data)
            blocks_json.append({'index': block, 'data': data.hex().upper()})
    return bytes(dump), blocks_json

def main():
    ap = argparse.ArgumentParser(description='Dump completo MIFARE Classic 1K con PN532')
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--uart', help='es. /dev/ttyUSB0 (PN532 in modalità HSU/UART)')
    g.add_argument('--i2c', action='store_true', help='usa I2C (Raspberry)')
    ap.add_argument('--baud', type=int, default=115200)
    ap.add_argument('--outfile', required=True, help='file .bin (1024 byte)')
    ap.add_argument('--json', help='(opzionale) salva anche JSON con blocchi')
    ap.add_argument('--debug', action='store_true')
    args = ap.parse_args()

    pn = open_pn532(args)
    print('Avvicina la tag...')
    uid = wait_for_tag(pn, timeout=60)
    if uid is None:
        print('Timeout: nessuna tag rilevata.', file=sys.stderr); sys.exit(1)

    print('UID:', uid.hex().upper())
    try:
        dump, blocks = read_full_tag(pn, uid)
    except Exception as e:
        print(f'ERRORE: {e}', file=sys.stderr); sys.exit(1)

    with open(args.outfile, 'wb') as f:
        f.write(dump)
    print(f'Scritto {len(dump)} byte in {args.outfile}')

    if args.json:
        obj = {'uid': uid.hex(), 'blocks': blocks}
        with open(args.json, 'w') as f:
            json.dump(obj, f, indent=2)
        print(f'Scritto JSON in {args.json}')

if __name__ == '__main__':
    main()
