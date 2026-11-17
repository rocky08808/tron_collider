#!/usr/bin/env python3
"""随机私钥 → 地址 → 联网查余额；有余额则写入 hits，无余额跳过。"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

import requests

from scan_lifetime import bootstrap_lifetime_from_stats
from scan_lifetime import read_lifetime_total
from scan_lifetime import write_lifetime_total
from tron_crypto import private_key_to_address, random_private_key_bytes
from verify_address import fetch_account_balances
from verify_address import has_positive_balance


def main() -> None:
    parser = argparse.ArgumentParser(description="随机地址联网查余额（无 Bloom）")
    parser.add_argument(
        "--backend",
        choices=("trongrid", "tronscan"),
        default="trongrid",
        help="余额查询后端（trongrid 一次 v1；tronscan 为 TronGrid 账户 + TronScan USDT）",
    )
    parser.add_argument(
        "--asset",
        choices=("any", "trx", "usdt"),
        default="any",
        help="判定「有余额」：任意 / 仅 TRX / 仅 USDT",
    )
    parser.add_argument(
        "--request-delay-ms",
        type=float,
        default=0.0,
        help="每次联网请求后的额外等待（毫秒，用于限流）",
    )
    parser.add_argument(
        "--max-keys",
        type=int,
        default=0,
        help="最多尝试地址数，0 表示不限制",
    )
    parser.add_argument(
        "--hits-file",
        type=Path,
        default=Path("data/balance_hits.jsonl"),
    )
    parser.add_argument("--stats-interval", type=float, default=2.0)
    parser.add_argument("--stats-file", type=Path, default=None)
    parser.add_argument("--stop-file", type=Path, default=None)
    args = parser.parse_args()

    totals = {
        "tried": 0,
        "balance_hits": 0,
        "network_errors": 0,
        "rate_limited": 0,
    }
    session = requests.Session()
    args.hits_file.parent.mkdir(parents=True, exist_ok=True)
    args.hits_file.touch(exist_ok=True)
    if args.stop_file and args.stop_file.is_file():
        args.stop_file.unlink(missing_ok=True)

    start = time.monotonic()
    last_stats = start
    pid_file = args.stats_file.with_name("balance.pid") if args.stats_file else None
    lifetime_path = (
        args.stats_file.with_name("balance_scan_lifetime.json")
        if args.stats_file
        else Path("data/balance_scan_lifetime.json")
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
        payload: dict[str, Any] = {
            "status": status,
            "updated_at": time.time(),
            "pid": os.getpid(),
            "elapsed_sec": round(elapsed, 2),
            "rate_per_sec": round(rate, 2),
            "total_tried": total_tried,
            "session_base_tried": session_base_tried,
            **totals,
            "backend": args.backend,
            "asset": args.asset,
            "request_delay_ms": args.request_delay_ms,
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
    print(
        f"联网查余额 backend={args.backend} asset={args.asset} "
        f"delay_ms={args.request_delay_ms}",
        file=sys.stderr,
    )

    delay_sec = max(0.0, args.request_delay_ms / 1000.0)

    while True:
        if args.stop_file and args.stop_file.is_file():
            publish_stats("stopped")
            print("联网查余额：收到停止信号", file=sys.stderr)
            break
        if args.max_keys and totals["tried"] >= args.max_keys:
            break

        pk = random_private_key_bytes()
        addr = private_key_to_address(pk)
        totals["tried"] += 1

        try:
            balances = fetch_account_balances(session, addr, backend=args.backend)
        except requests.HTTPError as e:
            totals["network_errors"] += 1
            if e.response is not None and e.response.status_code == 429:
                totals["rate_limited"] += 1
                time.sleep(5.0)
            elif delay_sec:
                time.sleep(delay_sec)
            continue
        except requests.RequestException:
            totals["network_errors"] += 1
            if delay_sec:
                time.sleep(delay_sec)
            continue

        if delay_sec:
            time.sleep(delay_sec)

        if has_positive_balance(balances, asset=args.asset):
            totals["balance_hits"] += 1
            record = {
                "address": addr,
                "private_key_hex": pk.hex(),
                "match_kind": "on_chain_balance",
                "backend": args.backend,
                "asset_filter": args.asset,
                "trx_sun": balances.get("trx_sun"),
                "trx": balances.get("trx"),
                "usdt_balance": balances.get("usdt_balance"),
                "trc20": balances.get("trc20"),
                "activated": balances.get("activated"),
                "ts": time.time(),
            }
            with args.hits_file.open("a", encoding="utf-8") as hf:
                hf.write(json.dumps(record, ensure_ascii=False) + "\n")
            print(
                f"[BALANCE] {addr} trx={balances.get('trx')} "
                f"usdt={balances.get('usdt_balance')}",
                file=sys.stderr,
                flush=True,
            )

        now = time.monotonic()
        if now - last_stats >= args.stats_interval:
            elapsed = now - start
            rate = totals["tried"] / elapsed if elapsed > 0 else 0.0
            print(
                f"bal_try={totals['tried']:,} ({rate:,.2f}/s) | "
                f"hits={totals['balance_hits']:,} | "
                f"net_err={totals['network_errors']:,} "
                f"429={totals['rate_limited']:,}",
                file=sys.stderr,
                flush=True,
            )
            publish_stats("running")
            last_stats = now

    final = (
        "stopped"
        if args.stop_file and args.stop_file.is_file()
        else "completed"
    )
    publish_stats(final)
    elapsed = time.monotonic() - start
    print(
        f"完成 bal_try={totals['tried']:,} elapsed={elapsed:.1f}s "
        f"hits={totals['balance_hits']:,}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
