"""随机或指定助记词 → TRON 地址 → Bloom/CSV（演示，非暴力穷举）。"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import requests

from bloom import BloomFilter, tron_address_key
from tron_hd import DEFAULT_TRON_PATH
from tron_hd import random_mnemonic
from tron_hd import tron_address_from_mnemonic
from tron_hd import tron_path
from verify_address import verify_candidate

ROOT = Path(__file__).resolve().parent


def load_exact_set(csv_path: Path) -> frozenset[str]:
    with csv_path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return frozenset(
            (row.get("address") or "").strip()
            for row in reader
            if (row.get("address") or "").strip()
        )


def run_mnemonic_attempt(
    *,
    bloom_path: Path,
    csv_path: Path,
    network: str = "off",
    mnemonic: str | None = None,
    passphrase: str = "",
    account: int = 0,
    address_index: int = 0,
    words: int = 12,
) -> dict[str, Any]:
    path = tron_path(account=account, change=0, index=address_index)
    if mnemonic:
        phrase = " ".join(mnemonic.strip().split())
    else:
        phrase = random_mnemonic(words)

    steps: list[dict[str, Any]] = []
    steps.append(
        {
            "step": 1,
            "name": "助记词",
            "detail": f"BIP39 {'随机' if not mnemonic else '指定'} · {len(phrase.split())} 词",
            "mnemonic": phrase,
            "passphrase_used": bool(passphrase),
        }
    )

    try:
        address, used_path, pk = tron_address_from_mnemonic(
            phrase, passphrase=passphrase, path=path
        )
    except ValueError as e:
        return {
            "outcome": "invalid_mnemonic",
            "error": str(e),
            "steps": steps,
            "mnemonic": phrase,
        }

    pk_hex = pk.hex()
    steps.append(
        {
            "step": 2,
            "name": "BIP44 派生",
            "detail": f"路径 {used_path} → 32 字节私钥",
            "derivation_path": used_path,
            "private_key_hex": pk_hex,
        }
    )
    steps.append(
        {
            "step": 3,
            "name": "TRON 地址",
            "detail": "与 collider 相同：Keccak + Base58Check",
            "address": address,
        }
    )

    if not bloom_path.is_file():
        raise FileNotFoundError(f"缺少 Bloom: {bloom_path}")
    bf = BloomFilter.load(bloom_path)
    in_bloom = tron_address_key(address) in bf
    steps.append(
        {
            "step": 4,
            "name": "布隆过滤器",
            "detail": "疑似在集合中" if in_bloom else "未命中 → 一定不在",
            "in_bloom": in_bloom,
        }
    )

    exact = load_exact_set(csv_path) if csv_path.is_file() else frozenset()
    in_exact = address in exact
    fp = in_bloom and not in_exact
    steps.append(
        {
            "step": 5,
            "name": "CSV 精确表",
            "detail": "在列表中" if in_exact else ("布隆假阳" if fp else "不在列表"),
            "in_exact": in_exact,
            "exact_set_size": len(exact),
        }
    )

    verify: dict[str, Any] | None = None
    if in_exact and network != "off":
        with requests.Session() as session:
            verify = verify_candidate(session, address, backend=network)

    if not in_bloom:
        outcome = "rejected_by_bloom"
    elif in_exact:
        outcome = "exact_hit"
    elif in_bloom:
        outcome = "bloom_false_positive"
    else:
        outcome = "not_in_set"

    return {
        "outcome": outcome,
        "mnemonic": phrase,
        "derivation_path": used_path,
        "private_key_hex": pk_hex,
        "address": address,
        "in_bloom": in_bloom,
        "in_exact": in_exact,
        "verify": verify,
        "steps": steps,
    }


def batch_random_mnemonics(
    *,
    bloom_path: Path,
    csv_path: Path,
    count: int,
    words: int = 12,
    account: int = 0,
    address_index: int = 0,
) -> dict[str, int]:
    bf = BloomFilter.load(bloom_path)
    exact = load_exact_set(csv_path) if csv_path.is_file() else frozenset()
    stats = {"tried": 0, "bloom_hits": 0, "exact_hits": 0, "invalid": 0}
    path = tron_path(account=account, change=0, index=address_index)
    for _ in range(max(0, int(count))):
        phrase = random_mnemonic(words)
        try:
            address, _, _ = tron_address_from_mnemonic(phrase, path=path)
        except ValueError:
            stats["invalid"] += 1
            continue
        stats["tried"] += 1
        if tron_address_key(address) not in bf:
            continue
        stats["bloom_hits"] += 1
        if address in exact:
            stats["exact_hits"] += 1
    return stats
