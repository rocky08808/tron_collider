#!/usr/bin/env python3
"""持续随机 BIP39 助记词 → TRON 地址 → Bloom/CSV（多进程，供 UI 驱动）。"""

from __future__ import annotations

import argparse
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
from collider import load_address_set
from collider import load_csv_usdt_balances
from collider import resolve_csv_path
from scan_lifetime import bootstrap_lifetime_from_stats
from scan_lifetime import read_lifetime_total
from scan_lifetime import write_lifetime_total
from tron_hd import random_mnemonic
from tron_hd import tron_address_from_mnemonic
from verify_address import verify_candidate

_worker_bloom: BloomFilter | None = None
_worker_exact: frozenset[str] | None = None
_worker_path: str = ""
_worker_words: int = 12


def _init_worker(bloom_path: str, csv_path: str, derivation_path: str, words: int) -> None:
    global _worker_bloom, _worker_exact, _worker_path, _worker_words
    _worker_bloom = BloomFilter.load(Path(bloom_path))
    _worker_exact = load_address_set(Path(csv_path))
    _worker_path = derivation_path
    _worker_words = int(words)


def _scan_batch(
    batch_size: int, *, network_on_bloom: bool
) -> dict[str, int | list[tuple[str, str, str, str]]]:
    assert _worker_bloom is not None and _worker_exact is not None
    stats = {"tried": 0, "bloom_hits": 0, "exact_hits": 0}
    candidates: list[tuple[str, str, str, str]] = []

    for _ in range(batch_size):
        phrase = random_mnemonic(_worker_words)
        try:
            addr, _, pk = tron_address_from_mnemonic(phrase, path=_worker_path)
        except ValueError:
            continue
        stats["tried"] += 1
        if tron_address_key(addr) not in _worker_bloom:
            continue
        stats["bloom_hits"] += 1
        exact = addr in _worker_exact
        if exact:
            stats["exact_hits"] += 1
        if network_on_bloom or exact:
            kind = "exact" if exact else "bloom_fp"
            candidates.append((phrase, pk.hex(), addr, kind))

    return {**stats, "candidates": candidates}


def main() -> None:
    parser = argparse.ArgumentParser(description="助记词随机碰撞（Bloom + CSV）")
    parser.add_argument("--bloom", type=Path, default=Path("data/usdt_top200000.bloom"))
    parser.add_argument("--address-csv", type=Path, default=None)
    parser.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 4) - 1))
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--max-keys", type=int, default=0)
    parser.add_argument("--words", type=int, choices=(12, 24), default=12)
    parser.add_argument("--derivation-path", type=str, default="m/44'/195'/0'/0/0")
    parser.add_argument("--hits-file", type=Path, default=Path("data/mnemonic_hits.jsonl"))
    parser.add_argument("--network", choices=("tronscan", "trongrid", "off"), default="off")
    parser.add_argument("--on-bloom-network", action="store_true")
    parser.add_argument("--stats-interval", type=float, default=2.0)
    parser.add_argument("--stats-file", type=Path, default=None)
    parser.add_argument("--stop-file", type=Path, default=None)
    args = parser.parse_args()

    if not args.bloom.is_file():
        print(f"找不到 Bloom: {args.bloom}", file=sys.stderr)
        sys.exit(1)

    project_root = Path(__file__).resolve().parent
    try:
        csv_path = resolve_csv_path(args.bloom, args.address_csv)
    except OSError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    ok, err = validate_bloom_csv_pair(
        args.bloom.resolve(), csv_path.resolve(), project_root=project_root
    )
    if not ok:
        print(f"Bloom/CSV 校验失败: {err}", file=sys.stderr)
        sys.exit(1)

    csv_balances = load_csv_usdt_balances(csv_path)
    print(
        f"助记词碰撞 words={args.words} path={args.derivation_path} | "
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

    pid_file = args.stats_file.with_name("mnemonic.pid") if args.stats_file else None
    lifetime_path = (
        args.stats_file.with_name("mnemonic_scan_lifetime.json")
        if args.stats_file
        else Path("data/mnemonic_scan_lifetime.json")
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
            "words": args.words,
            "derivation_path": args.derivation_path,
        }
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
        initargs=(
            str(args.bloom.resolve()),
            str(csv_path.resolve()),
            args.derivation_path,
            args.words,
        ),
    ) as pool:
        pending = []
        while True:
            if args.stop_file and args.stop_file.is_file():
                publish_stats("stopped")
                print("助记词扫描：收到停止信号", file=sys.stderr)
                break
            if args.max_keys and totals["tried"] >= args.max_keys:
                break
            need = args.workers
            if args.max_keys:
                remaining = args.max_keys - totals["tried"]
                if remaining <= 0:
                    break
                need = min(need, max(1, remaining // args.batch_size + 1))

            round_remaining = args.max_keys - totals["tried"] if args.max_keys else None
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

                for phrase, pk_hex, addr, kind in result["candidates"]:
                    record: dict[str, Any] = {
                        "mnemonic": phrase,
                        "address": addr,
                        "private_key_hex": pk_hex,
                        "derivation_path": args.derivation_path,
                        "match_kind": kind,
                        "ts": time.time(),
                    }
                    if addr in csv_balances:
                        record["csv_balance_usdt"] = csv_balances[addr]
                    if args.network != "off":
                        try:
                            v = verify_candidate(session, addr, backend=args.network)
                            record["verify"] = v
                            totals["network_ok"] += 1
                        except requests.RequestException as e:
                            record["verify_error"] = str(e)
                    if kind == "exact" or args.on_bloom_network:
                        with args.hits_file.open("a", encoding="utf-8") as hf:
                            hf.write(json.dumps(record, ensure_ascii=False) + "\n")
                    tag = "MN-EXACT" if kind == "exact" else "MN-BLOOM?"
                    print(f"[{tag}] {addr}", file=sys.stderr)

            pending.clear()

            now = time.monotonic()
            if now - last_stats >= args.stats_interval:
                elapsed = now - start
                rate = totals["tried"] / elapsed if elapsed > 0 else 0
                print(
                    f"mn_try={totals['tried']:,} ({rate:,.0f}/s) | "
                    f"bloom+={totals['bloom_hits']:,} fp={totals['bloom_fp']:,} | "
                    f"exact={totals['exact_hits']:,}",
                    file=sys.stderr,
                    flush=True,
                )
                publish_stats("running")
                last_stats = now

            if args.max_keys and totals["tried"] >= args.max_keys:
                break

    final_status = (
        "completed" if not (args.stop_file and args.stop_file.is_file()) else "stopped"
    )
    publish_stats(final_status)


if __name__ == "__main__":
    main()
