#!/usr/bin/env python3
"""
hardcoded_key_decryptor.py

A generic symmetric decrypt/encrypt tool for recovering secrets from
applications that use DES or RC2 in CBC (or ECB) mode with PKCS7 padding
and hardcoded keys.

The cipher engine lives in this file; the key material lives in an external
JSON file (default: keys.json) so you can add new targets/profiles without
touching the code.

Educational / authorised security-research / CTF use only.
"""

import argparse
import base64
import json
import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers import algorithms as dec_algos
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 8  # DES and RC2 both use an 8-byte block


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------
def parse_hex(s: str) -> bytes:
    """Parse a hex string (spaces, commas, or 0x prefixes allowed) into bytes."""
    s = s.replace("0x", "").replace(",", " ").strip()
    parts = s.split()
    if len(parts) > 1:
        return bytes(int(p, 16) for p in parts)
    return bytes.fromhex(s)


def fix_b64(s: str) -> bytes:
    """Restore missing '=' padding and decode a Base64 string to raw bytes."""
    s = s.strip()
    missing = len(s) % 4
    if missing:
        s += "=" * (4 - missing)
    return base64.b64decode(s)


def load_profiles(path: str) -> dict:
    if not os.path.exists(path):
        sys.exit(f"Key file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("profiles", {})


# ---------------------------------------------------------------------------
# Cipher engine
# ---------------------------------------------------------------------------
def build_algorithm(method: str, key: bytes):
    method = method.lower()
    if method == "des":
        # single DES == 3DES with a repeated 8-byte key (mathematically identical)
        return dec_algos.TripleDES(key)
    if method == "rc2":
        return dec_algos.RC2(key)
    raise ValueError(f"Unknown method '{method}' (use 'des' or 'rc2').")


def build_mode(mode: str, iv: bytes):
    mode = mode.lower()
    if mode == "cbc":
        return modes.CBC(iv)
    if mode == "ecb":
        return modes.ECB()
    raise ValueError(f"Unknown mode '{mode}' (use 'cbc' or 'ecb').")


def strip_pkcs7(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= BLOCK_SIZE and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data


def add_pkcs7(data: bytes) -> bytes:
    pad = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad]) * pad


def decrypt(data: bytes, key: bytes, iv: bytes, method: str, mode: str) -> bytes:
    cipher = Cipher(build_algorithm(method, key), build_mode(mode, iv),
                    backend=default_backend())
    d = cipher.decryptor()
    return d.update(data) + d.finalize()


def encrypt(pt: bytes, key: bytes, iv: bytes, method: str, mode: str) -> bytes:
    cipher = Cipher(build_algorithm(method, key), build_mode(mode, iv),
                    backend=default_backend())
    e = cipher.encryptor()
    return e.update(add_pkcs7(pt)) + e.finalize()


# ---------------------------------------------------------------------------
# Resolve which (label, key, iv, method, mode) tuples to try
# ---------------------------------------------------------------------------
def resolve_targets(args, profiles):
    # 1) explicit raw key + iv on the command line
    if args.key and args.iv:
        return [("custom", parse_hex(args.key), parse_hex(args.iv),
                 args.method, args.mode)]

    # 2) a specific named profile
    if args.profile:
        if args.profile not in profiles:
            sys.exit(f"Profile '{args.profile}' not found in key file.")
        p = profiles[args.profile]
        return [(args.profile, parse_hex(p["key"]), parse_hex(p["iv"]),
                 p.get("method", "des"), p.get("mode", "cbc"))]

    # 3) default: try every profile in the key file
    out = []
    for name, p in profiles.items():
        out.append((name, parse_hex(p["key"]), parse_hex(p["iv"]),
                    p.get("method", "des"), p.get("mode", "cbc")))
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Generic DES/RC2 (CBC/PKCS7) decrypt/encrypt tool with an external key store.",
        epilog="Example: python3 hardcoded_key_decryptor.py -p my-profile '<base64-ciphertext>'",
    )
    ap.add_argument("value", nargs="?", help="Value to process (Base64 for decrypt, plain text for encrypt).")
    ap.add_argument("-d", "--decrypt", action="store_true", help="Decrypt mode (default).")
    ap.add_argument("-e", "--encrypt", action="store_true", help="Encrypt mode.")
    ap.add_argument("-k", "--keys", default="keys.json", help="Path to the key file (default: keys.json).")
    ap.add_argument("-p", "--profile", help="Use a specific named profile from the key file.")
    ap.add_argument("--list", action="store_true", help="List available profiles and exit.")
    ap.add_argument("-m", "--method", choices=["des", "rc2"], default="des",
                    help="Cipher for --key/--iv custom mode (default: des).")
    ap.add_argument("--mode", choices=["cbc", "ecb"], default="cbc",
                    help="Cipher mode for --key/--iv custom mode (default: cbc).")
    ap.add_argument("--key", help="Custom key as hex. Requires --iv.")
    ap.add_argument("--iv", help="Custom IV as hex. Requires --key.")
    args = ap.parse_args()

    if bool(args.key) != bool(args.iv):
        ap.error("--key and --iv must be used together.")

    profiles = load_profiles(args.keys)

    if args.list:
        print(f"Profiles in {args.keys}:")
        for name, p in profiles.items():
            print(f"  {name:24s} [{p.get('method','des')}/{p.get('mode','cbc')}] "
                  f"- {p.get('description','')}")
        return

    if args.value is None:
        ap.error("a value is required (or use --list to see profiles).")

    targets = resolve_targets(args, profiles)

    for label, key, iv, method, mode in targets:
        try:
            if args.encrypt:
                out = encrypt(args.value.encode("utf-8"), key, iv, method, mode)
                print(f"[{label}] encrypted (base64): {base64.b64encode(out).decode()}")
            else:
                pt = strip_pkcs7(decrypt(fix_b64(args.value), key, iv, method, mode))
                try:
                    print(f"[{label}] decrypted: {pt.decode('utf-8')}")
                except UnicodeDecodeError:
                    print(f"[{label}] (not UTF-8 -- wrong key/method) raw: {pt.hex()}")
        except Exception as ex:
            print(f"[{label}] error: {ex}", file=sys.stderr)


if __name__ == "__main__":
    main()
