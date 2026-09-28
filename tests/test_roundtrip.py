"""Round-trip and helper tests for hardcoded_key_decryptor.

Each cipher/mode should satisfy: strip_pkcs7(decrypt(encrypt(x))) == x.
"""
import base64

import pytest

import hardcoded_key_decryptor as hkd

# Example key material (not real recovered keys — just fixed test vectors).
DES_KEY = bytes.fromhex("B43F84D110B4E991")
DES_IV = bytes.fromhex("01D8AEE649AD9227")
# RC2 block size is 8 bytes (so the CBC IV is 8 bytes). Modern `cryptography`
# only accepts 128-bit (16-byte) RC2 keys, so use one here.
RC2_KEY = bytes.fromhex("0102030405060708090A0B0C0D0E0F10")
RC2_IV = bytes.fromhex("1112131415161718")

TEXTS = [
    "",                       # empty -> a full block of padding
    "a",
    "8bytes!!",               # exactly one block
    "RiverDragon#Storm25",
    "unicode: café ☕ 日本語",
    "x" * 100,                # spans many blocks
]


@pytest.mark.parametrize("text", TEXTS)
def test_des_cbc_roundtrip(text):
    ct = hkd.encrypt(text.encode("utf-8"), DES_KEY, DES_IV, "des", "cbc")
    pt = hkd.strip_pkcs7(hkd.decrypt(ct, DES_KEY, DES_IV, "des", "cbc"))
    assert pt.decode("utf-8") == text


@pytest.mark.parametrize("text", TEXTS)
def test_rc2_cbc_roundtrip(text):
    ct = hkd.encrypt(text.encode("utf-8"), RC2_KEY, RC2_IV, "rc2", "cbc")
    pt = hkd.strip_pkcs7(hkd.decrypt(ct, RC2_KEY, RC2_IV, "rc2", "cbc"))
    assert pt.decode("utf-8") == text


@pytest.mark.parametrize("text", TEXTS)
def test_des_ecb_roundtrip(text):
    # ECB ignores the IV, but the engine still accepts one.
    ct = hkd.encrypt(text.encode("utf-8"), DES_KEY, DES_IV, "des", "ecb")
    pt = hkd.strip_pkcs7(hkd.decrypt(ct, DES_KEY, DES_IV, "des", "ecb"))
    assert pt.decode("utf-8") == text


def test_ciphertext_is_base64_recoverable():
    """The base64 the tool prints must decode back through fix_b64 + decrypt."""
    text = "RiverDragon#Storm25"
    ct = hkd.encrypt(text.encode("utf-8"), DES_KEY, DES_IV, "des", "cbc")
    b64 = base64.b64encode(ct).decode()
    pt = hkd.strip_pkcs7(
        hkd.decrypt(hkd.fix_b64(b64), DES_KEY, DES_IV, "des", "cbc")
    )
    assert pt.decode("utf-8") == text


def test_pkcs7_add_then_strip_is_identity():
    for n in range(0, 33):
        data = b"A" * n
        padded = hkd.add_pkcs7(data)
        assert len(padded) % hkd.BLOCK_SIZE == 0
        assert 1 <= (padded[-1]) <= hkd.BLOCK_SIZE
        assert hkd.strip_pkcs7(padded) == data


def test_parse_hex_accepts_common_formats():
    expected = bytes([0xB4, 0x3F, 0x84, 0xD1])
    assert hkd.parse_hex("B4 3F 84 D1") == expected
    assert hkd.parse_hex("B4,3F,84,D1") == expected
    assert hkd.parse_hex("0xB4 0x3F 0x84 0xD1") == expected
    assert hkd.parse_hex("B43F84D1") == expected


def test_fix_b64_restores_missing_padding():
    raw = b"\x00\x01\x02\x03\x04"
    stripped = base64.b64encode(raw).decode().rstrip("=")
    assert hkd.fix_b64(stripped) == raw


def test_wrong_key_does_not_recover_plaintext():
    text = "RiverDragon#Storm25"
    ct = hkd.encrypt(text.encode("utf-8"), DES_KEY, DES_IV, "des", "cbc")
    wrong_key = bytes.fromhex("0000000000000000")
    pt = hkd.strip_pkcs7(hkd.decrypt(ct, wrong_key, DES_IV, "des", "cbc"))
    assert pt != text.encode("utf-8")


def test_unknown_method_and_mode_raise():
    with pytest.raises(ValueError):
        hkd.build_algorithm("aes", DES_KEY)
    with pytest.raises(ValueError):
        hkd.build_mode("ctr", DES_IV)
