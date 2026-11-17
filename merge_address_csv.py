#!/usr/bin/env python3
"""
合并多份地址 CSV / 纯文本地址列表，去重后输出统一 CSV。

用于在 TronScan Top1万 之外追加其它来源的地址，再 rebuild Bloom。
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

FIELDS = ("address", "balance_usdt", "balance_raw", "balance_usd", "address_tag", "source")


def load_csv(path: Path, source_label: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames and "address" in reader.fieldnames:
            for row in reader:
                addr = (row.get("address") or "").strip()
                if not addr:
                    continue
                out[addr] = {
                    "address": addr,
                    "balance_usdt": row.get("balance_usdt", "") or "",
                    "balance_raw": row.get("balance_raw", "") or "",
                    "balance_usd": row.get("balance_usd", "") or "",
                    "address_tag": row.get("address_tag", "") or "",
                    "source": row.get("source", "") or source_label,
                }
            return out
        f.seek(0)
        for line in f:
            addr = line.strip()
            if not addr or addr.startswith("#"):
                continue
            if addr.lower() == "address":
                continue
            out[addr] = {
                "address": addr,
                "balance_usdt": "",
                "balance_raw": "",
                "balance_usd": "",
                "address_tag": "",
                "source": source_label,
            }
    return out


def load_txt(path: Path, source_label: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        addr = line.strip()
        if not addr or addr.startswith("#"):
            continue
        out[addr] = {
            "address": addr,
            "balance_usdt": "",
            "balance_raw": "",
            "balance_usd": "",
            "address_tag": "",
            "source": source_label,
        }
    return out


def merge_rows(sources: list[dict[str, dict[str, str]]]) -> list[dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}
    for block in sources:
        for addr, row in block.items():
            if addr not in merged:
                merged[addr] = row
                continue
            old = merged[addr]
            try:
                new_bal = float(row.get("balance_usdt") or 0)
                old_bal = float(old.get("balance_usdt") or 0)
            except ValueError:
                new_bal = old_bal = 0
            if new_bal >= old_bal:
                merged[addr] = row
            else:
                merged[addr]["source"] = f"{old.get('source','')};{row.get('source','')}"
    return list(merged.values())


def main() -> None:
    parser = argparse.ArgumentParser(description="合并地址 CSV / txt，去重导出")
    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        action="append",
        required=True,
        help="输入文件，可多次指定（CSV 需含 address 列，或每行一个地址）",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("data/usdt_merged.csv"),
        help="输出 CSV",
    )
    args = parser.parse_args()

    blocks: list[dict[str, dict[str, str]]] = []
    for path in args.input:
        if not path.is_file():
            print(f"找不到: {path}", file=sys.stderr)
            sys.exit(1)
        label = path.name
        if path.suffix.lower() == ".txt":
            blocks.append(load_txt(path, label))
        else:
            blocks.append(load_csv(path, label))

    rows = merge_rows(blocks)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"合并 {len(rows)} 个唯一地址 -> {args.output}", file=sys.stderr)
    print(
        "下一步: python build_bloom_filter.py -i "
        f"{args.output} -o data/usdt_top10000.bloom",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
