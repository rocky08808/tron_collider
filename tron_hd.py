"""BIP39 助记词 → BIP44(TRON coin 195) 私钥/地址（依赖 mnemonic + coincurve）。"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Iterable

from coincurve import PrivateKey
from mnemonic import Mnemonic

from tron_crypto import SECP256K1_ORDER
from tron_crypto import private_key_to_address

BIP39_ENGLISH = Mnemonic("english")
DEFAULT_TRON_PATH = "m/44'/195'/0'/0/0"


def _hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def _ser256(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _parse256(b: bytes) -> int:
    return int.from_bytes(b, "big")


def seed_from_mnemonic(mnemonic: str, passphrase: str = "") -> bytes:
    phrase = " ".join(mnemonic.strip().split())
    if not BIP39_ENGLISH.check(phrase):
        raise ValueError("助记词无效或校验失败")
    return BIP39_ENGLISH.to_seed(phrase, passphrase=passphrase or "")


def master_key_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    if len(seed) < 16:
        raise ValueError("seed 过短")
    digest = _hmac_sha512(b"Bitcoin seed", seed)
    return digest[:32], digest[32:]


def _ckd_priv(parent_key: bytes, parent_chain: bytes, index: int) -> tuple[bytes, bytes]:
    if index >= 0x80000000:
        data = b"\x00" + parent_key + struct.pack(">I", index)
    else:
        pub = PrivateKey(parent_key).public_key.format(compressed=True)
        data = pub + struct.pack(">I", index)
    digest = _hmac_sha512(parent_chain, data)
    il, ir = digest[:32], digest[32:]
    il_int = _parse256(il)
    if il_int >= SECP256K1_ORDER:
        raise ValueError("BIP32 派生无效 (IL >= n)")
    child_int = (il_int + _parse256(parent_key)) % SECP256K1_ORDER
    if child_int == 0:
        raise ValueError("BIP32 派生无效 (child = 0)")
    return _ser256(child_int), ir


def parse_bip32_path(path: str) -> list[int]:
    p = path.strip()
    if p.startswith("m/"):
        p = p[2:]
    elif p.startswith("M/"):
        p = p[2:]
    if not p:
        return []
    indices: list[int] = []
    for part in p.split("/"):
        part = part.strip()
        if not part:
            continue
        hardened = part.endswith("'") or part.endswith("h")
        if hardened:
            part = part.rstrip("'").rstrip("h")
        i = int(part)
        if hardened:
            i |= 0x80000000
        indices.append(i)
    return indices


def derive_private_key(seed: bytes, path: str = DEFAULT_TRON_PATH) -> bytes:
    key, chain = master_key_from_seed(seed)
    for index in parse_bip32_path(path):
        key, chain = _ckd_priv(key, chain, index)
    return key


def tron_address_from_mnemonic(
    mnemonic: str,
    *,
    passphrase: str = "",
    path: str = DEFAULT_TRON_PATH,
) -> tuple[str, str, bytes]:
    """返回 (address, path, private_key_bytes)。"""
    seed = seed_from_mnemonic(mnemonic, passphrase)
    pk = derive_private_key(seed, path)
    return private_key_to_address(pk), path, pk


def random_mnemonic(words: int = 12) -> str:
    strength = 128 if words == 12 else 256 if words == 24 else 128
    if words not in (12, 24):
        raise ValueError("仅支持 12 或 24 词")
    return BIP39_ENGLISH.generate(strength=strength)


def tron_path(account: int = 0, change: int = 0, index: int = 0) -> str:
    if change not in (0, 1):
        raise ValueError("change 只能是 0 或 1")
    return f"m/44'/195'/{account}'/{change}/{index}"
