#!/usr/bin/env python3
"""
本地批量生成 TRON 私钥/地址，用布隆过滤器预筛；仅对「疑似命中」做精确集合并可选链上验证。

流程：
  1. 随机私钥 -> 派生 Base58 地址
  2. 不在 Bloom -> 丢弃（无网络）
  3. Bloom 命中 -> 查内存精确地址表（Top1万 CSV）
  4. 精确表未命中 -> 布隆假阳，丢弃（无网络）
  5. 精确表命中 -> 触发 HTTP 验证并写入 hits 文件
"""

from __future__ import annotations

import argparse
import csv
import json
import multiprocessing as mp
import os
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

import requests

from bloom import BloomFilter, tron_address_key
from bloom_csv_match import validate_bloom_csv_pair
from scan_lifetime import bootstrap_lifetime_from_stats
from scan_lifetime import read_lifetime_total
from scan_lifetime import write_lifetime_total
from tron_crypto import private_key_to_address, random_private_key_bytes
from verify_address import verify_candidate

_worker_bloom: BloomFilter | None = None
_worker_exact: frozenset[str] | None = None


def load_address_set(csv_path: Path) -> frozenset[str]:
    with csv_path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return frozenset(
            (row.get("address") or "").strip()
            for row in reader
            if (row.get("address") or "").strip()
        )


def load_csv_usdt_balances(csv_path: Path) -> dict[str, float]:
    out: dict[str, float] = {}
    with csv_path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            addr = (row.get("address") or "").strip()
            if not addr:
                continue
            try:
                out[addr] = float(row.get("balance_usdt") or 0)
            except ValueError:
                out[addr] = 0.0
    return out


def _init_worker(bloom_path: str, csv_path: str) -> None:
    global _worker_bloom, _worker_exact
    _worker_bloom = BloomFilter.load(Path(bloom_path))
    _worker_exact = load_address_set(Path(csv_path))


def _scan_batch(
    batch_size: int, *, network_on_bloom: bool
) -> dict[str, int | list[tuple[str, str, str]]]:
    assert _worker_bloom is not None and _worker_exact is not None
    stats = {"tried": 0, "bloom_hits": 0, "exact_hits": 0}
    candidates: list[tuple[str, str, str]] = []

    for _ in range(batch_size):
        stats["tried"] += 1
        pk = random_private_key_bytes()
        addr = private_key_to_address(pk)
        if tron_address_key(addr) not in _worker_bloom:
            continue
        stats["bloom_hits"] += 1
        exact = addr in _worker_exact
        if exact:
            stats["exact_hits"] += 1
        if network_on_bloom or exact:
            kind = "exact" if exact else "bloom_fp"
            candidates.append((pk.hex(), addr, kind))

    return {**stats, "candidates": candidates}


def resolve_csv_path(bloom_path: Path, csv_arg: Path | None) -> Path:
    if csv_arg is not None:
        return csv_arg
    meta = bloom_path.with_suffix(bloom_path.suffix + ".meta.json")
    if meta.is_file():
        data = json.loads(meta.read_text(encoding="utf-8"))
        src = data.get("source_csv")
        if src:
            return Path(src)
    for default in (
        Path("data/usdt_top300000.csv"),
        Path("data/usdt_top200000.csv"),
        Path("data/usdt_top100000.csv"),
    ):
        if default.is_file():
            return default
    raise FileNotFoundError("请用 --address-csv 指定精确地址 CSV")


def main() -> None:
    parser = argparse.ArgumentParser(description="TRON 地址碰撞扫描（Bloom 预筛 + 按需联网）")
    parser.add_argument(
        "--bloom",
        type=Path,
        default=Path("data/usdt_top200000.bloom"),
        help="布隆过滤器文件",
    )
    parser.add_argument(
        "--address-csv",
        type=Path,
        default=None,
        help="精确地址表（默认从 .bloom.meta.json 读取）",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, (os.cpu_count() or 4) - 1),
        help="并行 worker 数",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=2000,
        help="每个 worker 每轮尝试的密钥数",
    )
    parser.add_argument(
        "--max-keys",
        type=int,
        default=0,
        help="最多尝试密钥数，0 表示不限制",
    )
    parser.add_argument(
        "--hits-file",
        type=Path,
        default=Path("data/hits.jsonl"),
        help="精确命中且联网验证后的记录",
    )
    parser.add_argument(
        "--network",
        choices=("tronscan", "trongrid", "off"),
        default="tronscan",
        help="联网验证后端；off 不发起 HTTP",
    )
    parser.add_argument(
        "--on-bloom-network",
        action="store_true",
        help="布隆命中即联网（会有约 0.1%% 假阳请求）；默认仅精确表命中后联网",
    )
    parser.add_argument(
        "--stats-interval",
        type=float,
        default=5.0,
        help="打印统计间隔（秒）",
    )
    parser.add_argument(
        "--stats-file",
        type=Path,
        default=None,
        help="周期性写入 JSON 运行状态（供 UI 读取）",
    )
    parser.add_argument(
        "--stop-file",
        type=Path,
        default=None,
        help="若该文件存在则优雅停止扫描",
    )
    args = parser.parse_args()

    if not args.bloom.is_file():
        print(f"找不到 Bloom 文件: {args.bloom}", file=sys.stderr)
        sys.exit(1)

    try:
        csv_path = resolve_csv_path(args.bloom, args.address_csv)
    except OSError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    project_root = Path(__file__).resolve().parent
    ok, err = validate_bloom_csv_pair(
        args.bloom.resolve(), csv_path.resolve(), project_root=project_root
    )
    if not ok:
        print(f"Bloom/CSV 校验失败: {err}", file=sys.stderr)
        sys.exit(1)

    exact_main = load_address_set(csv_path)
    csv_balances = load_csv_usdt_balances(csv_path)
    print(
        f"Bloom: {args.bloom} | 精确地址 {len(exact_main)} 条 | "
        f"workers={args.workers} batch={args.batch_size}",
        file=sys.stderr,
    )

    totals = {
        "tried": 0,
        "bloom_hits": 0,
        "exact_hits": 0,
        "network_ok": 0,
        "bloom_fp": 0,
    }
    session = requests.Session()
    args.hits_file.parent.mkdir(parents=True, exist_ok=True)
    args.hits_file.touch(exist_ok=True)
    last_stats = time.monotonic()
    start = time.monotonic()
    if args.stop_file and args.stop_file.is_file():
        args.stop_file.unlink(missing_ok=True)

    pid_file = (
        args.stats_file.with_name("scan.pid") if args.stats_file else None
    )
    lifetime_path = (
        args.stats_file.with_name("scan_lifetime.json")
        if args.stats_file
        else Path("data/scan_lifetime.json")
    )
    if args.stats_file and args.stats_file.is_file():
        bootstrap_lifetime_from_stats(lifetime_path, args.stats_file)
    session_base_tried = read_lifetime_total(lifetime_path)

    def publish_stats(status: str) -> None:
        if not args.stats_file:
            return
        elapsed = time.monotonic() - start
        rate = totals["tried"] / elapsed if elapsed > 0 else 0.0
        total_tried = session_base_tried + int(totals["tried"])
        write_lifetime_total(lifetime_path, total_tried)
        payload = {
            "status": status,
            "updated_at": time.time(),
            "pid": os.getpid(),
            "elapsed_sec": round(elapsed, 2),
            "rate_per_sec": round(rate, 1),
            "total_tried": total_tried,
            "session_base_tried": session_base_tried,
            **totals,
            "workers": args.workers,
            "batch_size": args.batch_size,
            "max_keys": args.max_keys,
        }
        args.stats_file.parent.mkdir(parents=True, exist_ok=True)
        args.stats_file.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        if pid_file is None:
            return
        if status == "running":
            pid_file.write_text(str(os.getpid()), encoding="utf-8")
        else:
            with suppress(OSError):
                pid_file.unlink(missing_ok=True)

    publish_stats("running")

    ctx = mp.get_context("spawn")
    with ctx.Pool(
        processes=args.workers,
        initializer=_init_worker,
        initargs=(str(args.bloom.resolve()), str(csv_path.resolve())),
    ) as pool:
        pending = []
        while True:
            if args.stop_file and args.stop_file.is_file():
                publish_stats("stopped")
                print("收到停止信号", file=sys.stderr)
                break
            if args.max_keys and totals["tried"] >= args.max_keys:
                break
            need = args.workers
            if args.max_keys:
                remaining = args.max_keys - totals["tried"]
                if remaining <= 0:
                    break
                need = min(need, max(1, remaining // args.batch_size + 1))

            round_remaining = (
                args.max_keys - totals["tried"] if args.max_keys else None
            )
            for _ in range(need):
                bs = args.batch_size
                if round_remaining is not None:
                    if round_remaining <= 0:
                        break
                    bs = min(bs, round_remaining)
                    round_remaining -= bs
                pending.append(
                    pool.apply_async(
                        _scan_batch,
                        (bs,),
                        {"network_on_bloom": args.on_bloom_network},
                    )
                )
            if not pending:
                break

            for job in pending:
                result = job.get()
                totals["tried"] += int(result["tried"])
                totals["bloom_hits"] += int(result["bloom_hits"])
                exact_n = int(result["exact_hits"])
                totals["exact_hits"] += exact_n
                totals["bloom_fp"] += int(result["bloom_hits"]) - exact_n

                for pk_hex, addr, kind in result["candidates"]:
                    record: dict[str, Any] = {
                        "address": addr,
                        "private_key_hex": pk_hex,
                        "match_kind": kind,
                        "ts": time.time(),
                    }
                    if addr in csv_balances:
                        record["csv_balance_usdt"] = csv_balances[addr]
                    if args.network != "off":
                        try:
                            v = verify_candidate(session, addr, backend=args.network)
                            record["verify"] = v
                            if v.get("usdt_balance") is not None:
                                record["usdt_balance"] = v["usdt_balance"]
                            totals["network_ok"] += 1
                        except requests.RequestException as e:
                            record["verify_error"] = str(e)
                    if kind == "exact" or args.on_bloom_network:
                        with args.hits_file.open("a", encoding="utf-8") as hf:
                            hf.write(json.dumps(record, ensure_ascii=False) + "\n")
                    tag = "EXACT" if kind == "exact" else "BLOOM?"
                    print(f"[{tag}] {addr}", file=sys.stderr)

            pending.clear()

            now = time.monotonic()
            if now - last_stats >= args.stats_interval:
                elapsed = now - start
                rate = totals["tried"] / elapsed if elapsed > 0 else 0
                print(
                    f"try={totals['tried']:,} ({rate:,.0f}/s) | "
                    f"bloom+={totals['bloom_hits']:,} fp={totals['bloom_fp']:,} | "
                    f"exact={totals['exact_hits']:,} net={totals['network_ok']:,}",
                    file=sys.stderr,
                    flush=True,
                )
                publish_stats("running")
                last_stats = now

            if args.max_keys and totals["tried"] >= args.max_keys:
                break

    elapsed = time.monotonic() - start
    final_status = "completed" if not (args.stop_file and args.stop_file.is_file()) else "stopped"
    publish_stats(final_status)
    print(
        f"完成 try={totals['tried']:,} elapsed={elapsed:.1f}s | "
        f"bloom_hits={totals['bloom_hits']:,} bloom_fp={totals['bloom_fp']:,} | "
        f"exact={totals['exact_hits']:,}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
