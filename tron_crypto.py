"""TRON 主网地址：secp256k1 私钥 -> Base58Check (0x41) 地址。"""

from __future__ import annotations

import hashlib
import os

from coincurve import PrivateKey
from Crypto.Hash import keccak

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MAINNET_PREFIX = b"\x41"


def random_private_key_bytes() -> bytes:
    while True:
        n = int.from_bytes(os.urandom(32), "big")
        if 0 < n < SECP256K1_ORDER:
            return n.to_bytes(32, "big")


def public_key_uncompressed_to_address(public_key_64: bytes) -> str:
    if len(public_key_64) != 64:
        raise ValueError("public key must be 64 bytes (x||y, no 0x04 prefix)")
    digest = keccak.new(digest_bits=256, data=public_key_64).digest()
    payload = MAINNET_PREFIX + digest[-20:]
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _base58_encode(payload + checksum)


def private_key_to_address(private_key: bytes) -> str:
    if len(private_key) != 32:
        raise ValueError("private key must be 32 bytes")
    pub = PrivateKey(private_key).public_key.format(compressed=False)[1:]
    return public_key_uncompressed_to_address(pub)


def address_to_payload_hex(address: str) -> str:
    """Base58Check 地址 → 小写 hex（含 0x41 前缀，42 个 hex 字符）。"""
    raw = _base58_decode_check(address)
    return raw.hex()


_B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_decode_check(encoded: str) -> bytes:
    num = 0
    for ch in encoded:
        idx = _B58.find(ch.encode("ascii"))
        if idx < 0:
            raise ValueError("invalid base58 character")
        num = num * 58 + idx
    combined = num.to_bytes(25, "big")
    pad = 0
    for ch in encoded:
        if ch == "1":
            pad += 1
        else:
            break
    combined = b"\x00" * pad + combined.lstrip(b"\x00")
    if len(combined) < 25:
        combined = b"\x00" * (25 - len(combined)) + combined
    payload, checksum = combined[:-4], combined[-4:]
    expect = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expect:
        raise ValueError("base58 checksum mismatch")
    return payload


def _base58_encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    enc = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        enc.append(_B58[rem])
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    enc.extend(_B58[0:1] * pad)
    enc.reverse()
    return enc.decode("ascii")
