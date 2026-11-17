#!/usr/bin/env python3
"""单次密钥生成并走完整筛选流程（演示用）。"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

import requests

from bloom import BloomFilter, tron_address_key
from tron_crypto import private_key_to_address, random_private_key_bytes
from verify_address import verify_candidate

ROOT = Path(__file__).resolve().parent
DEFAULT_BLOOM = ROOT / "data" / "usdt_top200000.bloom"
DEFAULT_CSV = ROOT / "data" / "usdt_top200000.csv"


def load_exact_set(csv_path: Path) -> frozenset[str]:
    with csv_path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return frozenset(
            (row.get("address") or "").strip()
            for row in reader
            if (row.get("address") or "").strip()
        )


def run_single_attempt(
    *,
    bloom_path: Path = DEFAULT_BLOOM,
    csv_path: Path = DEFAULT_CSV,
    network: str = "off",
    private_key_hex: str | None = None,
) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []

    if private_key_hex:
        pk = bytes.fromhex(private_key_hex.replace("0x", ""))
        if len(pk) != 32:
            raise ValueError("private_key_hex 必须是 32 字节")
    else:
        pk = random_private_key_bytes()

    pk_hex = pk.hex()
    steps.append(
        {
            "step": 1,
            "name": "生成私钥",
            "detail": "随机 32 字节（secp256k1 合法范围）",
            "private_key_hex": pk_hex,
        }
    )

    address = private_key_to_address(pk)
    steps.append(
        {
            "step": 2,
            "name": "派生 TRON 地址",
            "detail": "secp256k1 公钥 → Keccak256 → 0x41 → Base58Check",
            "address": address,
        }
    )

    if not bloom_path.is_file():
        raise FileNotFoundError(f"缺少 Bloom: {bloom_path}")
    bf = BloomFilter.load(bloom_path)
    in_bloom = tron_address_key(address) in bf
    steps.append(
        {
            "step": 3,
            "name": "布隆过滤器",
            "detail": (
                "疑似在 Top1万 集合中（下一步需精确表或链上确认）"
                if in_bloom
                else "未命中 → 一定不在建 Bloom 时用的那批地址里"
            ),
            "in_bloom": in_bloom,
        }
    )

    exact: frozenset[str] = frozenset()
    in_exact = False
    if csv_path.is_file():
        exact = load_exact_set(csv_path)
        in_exact = address in exact
    fp_note = "；上一步布隆命中 → 此为布隆假阳" if in_bloom and not in_exact else ""
    steps.append(
        {
            "step": 4,
            "name": "CSV 精确表",
            "detail": (
                f"在 Top1万 列表中（共 {len(exact)} 个唯一地址）"
                if in_exact
                else f"不在 Top1万 CSV 中{fp_note}"
            ),
            "in_exact": in_exact,
            "exact_set_size": len(exact),
        }
    )

    network_skipped_reason: str | None = None
    verify: dict[str, Any] | None = None
    verify_error: str | None = None

    if not in_bloom:
        network_skipped_reason = "布隆未命中 → 扫描器试下一个，不联网"
    elif not in_exact:
        network_skipped_reason = (
            "布隆假阳 → 精确表否决 → 默认不联网"
            "（若开启「布隆疑似即联网」才会 HTTP）"
        )
    elif network == "off":
        network_skipped_reason = "精确命中但本次选择不联网（network=off）"
    else:
        network_skipped_reason = None

    if in_exact and network != "off":
        try:
            with requests.Session() as session:
                verify = verify_candidate(session, address, backend=network)
        except requests.RequestException as e:
            verify_error = str(e)
        steps.append(
            {
                "step": 5,
                "name": "链上验证",
                "detail": f"后端 {network}",
                "verify": verify,
                "verify_error": verify_error,
            }
        )
    else:
        steps.append(
            {
                "step": 5,
                "name": "链上验证",
                "detail": network_skipped_reason or "未触发",
                "skipped": True,
            }
        )

    outcome = "continue_scan"
    if in_exact:
        outcome = "exact_hit"
    elif in_bloom:
        outcome = "bloom_false_positive"
    else:
        outcome = "rejected_by_bloom"

    return {
        "address": address,
        "private_key_hex": pk_hex,
        "in_bloom": in_bloom,
        "in_exact": in_exact,
        "outcome": outcome,
        "steps": steps,
    }


def print_human(result: dict[str, Any]) -> None:
    for s in result["steps"]:
        print(f"\n[{s['step']}] {s['name']}")
        print(f"    {s['detail']}")
        for k, v in s.items():
            if k in ("step", "name", "detail"):
                continue
            if v is not None and v is not False:
                print(f"    {k}: {v}")
    print("\n--- 结论 ---")
    labels = {
        "rejected_by_bloom": "布隆未命中 → 扫描器直接试下一个",
        "bloom_false_positive": "布隆假阳 → 精确表否决 → 不联网（默认）",
        "exact_hit": "精确命中 → 应联网并记录 hits.jsonl",
    }
    print(labels.get(result["outcome"], result["outcome"]))


def main() -> None:
    parser = argparse.ArgumentParser(description="单次走通 私钥→地址→Bloom→CSV→联网")
    parser.add_argument("--bloom", type=Path, default=DEFAULT_BLOOM)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument(
        "--network",
        choices=("off", "tronscan", "trongrid"),
        default="off",
    )
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--private-key-hex", default=None)
    args = parser.parse_args()

    try:
        result = run_single_attempt(
            bloom_path=args.bloom,
            csv_path=args.csv,
            network=args.network,
            private_key_hex=args.private_key_hex,
        )
    except (OSError, ValueError) as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_human(result)


if __name__ == "__main__":
    main()
