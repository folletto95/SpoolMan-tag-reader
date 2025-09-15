# -*- coding: utf-8 -*-

"""Generate sector keys for BambuLab RFID tags.

This version adds an optional ``--master-key`` argument so alternative master
secrets can be tested without modifying the script. The output is identical to
the original implementation: 16 lines containing the 6‑byte keys in hexadecimal
format.
"""

import argparse
import sys
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256

DEFAULT_MASTER = bytes(
    [0x9A, 0x75, 0x9C, 0xF2, 0xC4, 0xF7, 0xCA, 0xFF,
     0x22, 0x2C, 0xB9, 0x76, 0x9B, 0x41, 0xBC, 0x96]
)


def kdf(uid: bytes, master: bytes) -> list[bytes]:
    """Derive 16 sector keys from *uid* and *master*."""

    return HKDF(uid, 6, master, SHA256, 16, context=b"RFID-A\0")


def main(argv: list[str]) -> int:
    if sys.version_info < (3, 6):
        print("Python 3.6 or higher is required!")
        return -1

    ap = argparse.ArgumentParser(description="Generate BambuLab tag keys")
    ap.add_argument("uid", help="UID of the tag in hex (without spaces)")
    ap.add_argument(
        "--master-key",
        dest="master_key",
        help="Override master key (32 hex chars)",
    )
    args = ap.parse_args(argv)

    uid = bytes.fromhex(args.uid)
    master = (
        bytes.fromhex(args.master_key)
        if args.master_key is not None
        else DEFAULT_MASTER
    )

    keys = kdf(uid, master)
    output = [a.hex().upper() for a in keys]
    print("\n".join(output))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
