#!/usr/bin/env python3
"""
从 TronScan 导出 TRON 主网有余额地址。

- trx：按 TRX 余额降序（account/list）
- usdt：按 USDT(TRC20) 余额降序（token_trc20/holders）

公开接口 start+limit 合计不超过 10000，每种最多约 1 万条，非链上全量。
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any, Callable

import requests

from download_progress import publish as publish_progress
from download_progress import resolve_stop_file
from download_progress import sleep_interruptible
from download_progress import stop_requested

ACCOUNT_LIST_API = "https://apilist.tronscanapi.com/api/account/list"
USDT_HOLDERS_API = "https://apilist.tronscanapi.com/api/token_trc20/holders"
USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
SUN_PER_TRX = 1_000_000
USDT_DECIMALS = 1_000_000
MAX_START_PLUS_LIMIT = 10_000
PAGE_LIMIT = 50


def api_headers(api_key: str | None) -> dict[str, str]:
    if not api_key:
        return {}
    return {"TRON-PRO-API-KEY": api_key}


def fetch_json(
    session: requests.Session,
    url: str,
    params: dict[str, Any],
    api_key: str | None,
    *,
    max_retries: int = 5,
    stop_file: Path | None = None,
) -> dict[str, Any]:
    for attempt in range(max_retries + 1):
        if stop_requested(stop_file):
            raise InterruptedError("download stopped")
        resp = session.get(
            url, params=params, headers=api_headers(api_key), timeout=25
        )
        if resp.status_code == 429:
            wait = 120
            body = resp.text
            m = re.search(r"suspended for (\d+) s", body)
            if m:
                wait = int(m.group(1)) + 2
            print(
                f"触发限流，等待 {wait}s 后重试（{attempt + 1}/{max_retries}）…",
                file=sys.stderr,
            )
            if attempt >= max_retries:
                resp.raise_for_status()
            if sleep_interruptible(wait, stop_file):
                raise InterruptedError("download stopped")
            continue
        resp.raise_for_status()
        return resp.json()
    raise requests.HTTPError("429 retries exhausted")


def sun_to_trx(sun: int | float) -> float:
    return float(sun) / SUN_PER_TRX


def raw_to_usdt(raw: int | str) -> float:
    return float(raw) / USDT_DECIMALS


def paginate_download(
    session: requests.Session,
    *,
    fetch_page: Callable[[int, int], dict[str, Any]],
    parse_batch: Callable[[list[dict[str, Any]]], list[dict[str, Any]]],
    delay_sec: float,
    intro: Callable[[dict[str, Any]], None],
    progress_path: Path | None = None,
    progress_job: str = "tronscan",
    progress_target: int = MAX_START_PLUS_LIMIT,
    stop_file: Path | None = None,
) -> tuple[list[dict[str, Any]], int | None, str]:
    rows: list[dict[str, Any]] = []
    start = 0
    range_total: int | None = None
    publish_progress(
        progress_path,
        status="running",
        job=progress_job,
        current=0,
        target=progress_target,
        message="正在请求 TronScan…",
    )

    stopped = "complete"
    while start < MAX_START_PLUS_LIMIT:
        if stop_requested(stop_file):
            stopped = "stopped"
            publish_progress(
                progress_path,
                status="stopped",
                job=progress_job,
                current=min(start, progress_target),
                target=progress_target,
                fetched_rows=len(rows),
                message="用户停止下载",
            )
            break
        remaining = MAX_START_PLUS_LIMIT - start
        limit = min(PAGE_LIMIT, remaining)
        if limit <= 0:
            break

        try:
            payload = fetch_page(start, limit)
        except InterruptedError:
            stopped = "stopped"
            publish_progress(
                progress_path,
                status="stopped",
                job=progress_job,
                current=min(start, progress_target),
                target=progress_target,
                fetched_rows=len(rows),
                message="用户停止下载",
            )
            break
        if range_total is None:
            range_total = payload.get("rangeTotal")
            intro(payload)

        batch = payload.get("data") or payload.get("trc20_tokens") or []
        if not batch:
            break

        rows.extend(parse_batch(batch))
        start += limit
        print(f"已拉取 start={start}，累计 {len(rows)} 条", file=sys.stderr)
        publish_progress(
            progress_path,
            status="running",
            job=progress_job,
            current=min(start, progress_target),
            target=progress_target,
            fetched_rows=len(rows),
            message=f"已请求 offset {start}/{progress_target}",
        )

        if len(batch) < limit:
            break
        if sleep_interruptible(delay_sec, stop_file):
            stopped = "stopped"
            publish_progress(
                progress_path,
                status="stopped",
                job=progress_job,
                current=min(start, progress_target),
                target=progress_target,
                fetched_rows=len(rows),
                message="用户停止下载",
            )
            break

    return rows, range_total, stopped


def download_trx(
    session: requests.Session,
    *,
    min_balance_trx: float,
    delay_sec: float,
    api_key: str | None,
    progress_path: Path | None = None,
    stop_file: Path | None = None,
) -> tuple[list[dict[str, Any]], int | None, str, str]:
    def intro(payload: dict[str, Any]) -> None:
        cap = min(payload.get("total", MAX_START_PLUS_LIMIT), MAX_START_PLUS_LIMIT)
        print(
            f"[TRX] 链上账户约 {payload.get('rangeTotal', '?'):,}；"
            f"本接口最多 {cap:,} 条",
            file=sys.stderr,
        )

    def parse_batch(batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for item in batch:
            balance_sun = int(item.get("balance") or 0)
            trx = sun_to_trx(balance_sun)
            if trx < min_balance_trx:
                continue
            out.append(
                {
                    "address": item.get("address", ""),
                    "balance_trx": trx,
                    "balance_sun": balance_sun,
                    "total_balance_sun": int(item.get("totalBalance") or 0),
                    "tx_count": int(item.get("totalTransactionCount") or 0),
                }
            )
        return out

    rows, range_total, stopped = paginate_download(
        session,
        fetch_page=lambda start, limit: fetch_json(
            session,
            ACCOUNT_LIST_API,
            {"sort": "-balance", "start": start, "limit": limit},
            api_key,
            stop_file=stop_file,
        ),
        parse_batch=parse_batch,
        delay_sec=delay_sec,
        intro=intro,
        progress_path=progress_path,
        progress_job="tronscan-trx",
        stop_file=stop_file,
    )
    return rows, range_total, ACCOUNT_LIST_API, stopped


def download_usdt(
    session: requests.Session,
    *,
    min_balance_usdt: float,
    delay_sec: float,
    api_key: str | None,
    progress_path: Path | None = None,
    stop_file: Path | None = None,
) -> tuple[list[dict[str, Any]], int | None, str, str]:
    def intro(payload: dict[str, Any]) -> None:
        cap = min(payload.get("total", MAX_START_PLUS_LIMIT), MAX_START_PLUS_LIMIT)
        print(
            f"[USDT] 持有人约 {payload.get('rangeTotal', '?'):,}；"
            f"本接口最多 {cap:,} 条（合约 {USDT_CONTRACT}）",
            file=sys.stderr,
        )
        if min_balance_usdt > 0:
            print(
                f"[USDT] 仅保留余额 > {min_balance_usdt} USDT；"
                "注意：接口只能拉余额最高的约 1 万地址，"
                "无法覆盖全网所有 >100U 的中小额持有人。",
                file=sys.stderr,
            )

    def parse_batch(batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for item in batch:
            raw = int(item.get("balance") or 0)
            usdt = raw_to_usdt(raw)
            if usdt <= min_balance_usdt:
                continue
            out.append(
                {
                    "address": item.get("holder_address", ""),
                    "balance_usdt": usdt,
                    "balance_raw": str(raw),
                    "balance_usd": item.get("balanceInUsd", ""),
                    "address_tag": item.get("addressTag", ""),
                }
            )
        return out

    rows, range_total, stopped = paginate_download(
        session,
        fetch_page=lambda start, limit: fetch_json(
            session,
            USDT_HOLDERS_API,
            {
                "contract_address": USDT_CONTRACT,
                "start": start,
                "limit": limit,
            },
            api_key,
            stop_file=stop_file,
        ),
        parse_batch=parse_batch,
        delay_sec=delay_sec,
        intro=intro,
        progress_path=progress_path,
        progress_job="tronscan-usdt",
        stop_file=stop_file,
    )
    return rows, range_total, USDT_HOLDERS_API, stopped


def write_output(
    *,
    output: Path,
    fmt: str,
    asset: str,
    meta: dict[str, Any],
    rows: list[dict[str, Any]],
    fieldnames: list[str],
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        with output.open("w", encoding="utf-8") as f:
            json.dump(
                {"asset": asset, **meta, "count": len(rows), "accounts": rows},
                f,
                ensure_ascii=False,
                indent=2,
            )
    else:
        with output.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="从 TronScan 下载有余额地址（TRX 或 USDT，各最多约 1 万条）"
    )
    parser.add_argument(
        "--asset",
        choices=("trx", "usdt"),
        default="usdt",
        help="导出资产类型（默认 usdt）",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="输出路径；默认 data/usdt_holders.csv 或 data/balanced_addresses.csv",
    )
    parser.add_argument(
        "--min-balance-trx",
        type=float,
        default=0.0,
        help="最小 TRX（仅 --asset trx）",
    )
    parser.add_argument(
        "--min-balance-usdt",
        type=float,
        default=100.0,
        help="只保留 USDT 余额严格大于该值（默认 100，即 >100U）",
    )
    parser.add_argument(
        "--format",
        choices=("csv", "json"),
        default=None,
        help="输出格式；默认按扩展名推断",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.4,
        help="分页请求间隔（秒）；无 API Key 时建议 ≥0.4",
    )
    parser.add_argument(
        "--progress-file",
        type=Path,
        default=None,
        help="写入下载进度 JSON（供 UI 显示）",
    )
    parser.add_argument(
        "--stop-file",
        type=Path,
        default=None,
        help="若存在则停止下载并保存已拉取部分",
    )
    args = parser.parse_args()
    args.stop_file = resolve_stop_file(args.stop_file)
    pid_file = (
        args.progress_file.with_name("download.pid")
        if args.progress_file
        else Path("data/download.pid")
    )
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(str(os.getpid()), encoding="utf-8")

    if args.stop_file and args.stop_file.is_file():
        args.stop_file.unlink(missing_ok=True)

    if args.output is None:
        args.output = (
            Path("data/usdt_holders_gt100.csv")
            if args.asset == "usdt"
            else Path("data/balanced_addresses.csv")
        )

    fmt = args.format
    if fmt is None:
        fmt = "json" if args.output.suffix.lower() == ".json" else "csv"

    api_key = os.environ.get("TRONSCAN_API_KEY") or os.environ.get("TRON_PRO_API_KEY")
    session = requests.Session()
    session.headers.setdefault("User-Agent", "tron-collider-address-export/1.1")

    stopped = "complete"
    rows: list[dict] = []
    fieldnames: list[str] | None = None
    meta: dict | None = None
    try:
        if args.asset == "usdt":
            rows, range_total, source, stopped = download_usdt(
                session,
                min_balance_usdt=args.min_balance_usdt,
                delay_sec=args.delay,
                api_key=api_key,
                progress_path=args.progress_file,
                stop_file=args.stop_file,
            )
            fieldnames = [
                "address",
                "balance_usdt",
                "balance_raw",
                "balance_usd",
                "address_tag",
            ]
            meta = {
                "source": source,
                "contract": USDT_CONTRACT,
                "min_balance_usdt": args.min_balance_usdt,
                "range_total": range_total,
            }
        else:
            rows, range_total, source, stopped = download_trx(
                session,
                min_balance_trx=args.min_balance_trx,
                delay_sec=args.delay,
                api_key=api_key,
                progress_path=args.progress_file,
                stop_file=args.stop_file,
            )
            fieldnames = [
                "address",
                "balance_trx",
                "balance_sun",
                "total_balance_sun",
                "tx_count",
            ]
            meta = {
                "source": source,
                "min_balance_trx": args.min_balance_trx,
                "range_total": range_total,
            }

        write_output(
            output=args.output,
            fmt=fmt,
            asset=args.asset,
            meta=meta,
            rows=rows,
            fieldnames=fieldnames,
        )
        print(f"已写入 {args.output}（{len(rows)} 条）", file=sys.stderr)
        final = "stopped" if stopped == "stopped" else "completed"
        publish_progress(
            args.progress_file,
            status=final,
            job=f"tronscan-{args.asset}",
            current=len(rows),
            target=len(rows),
            fetched_rows=len(rows),
            output=str(args.output),
            message="已停止，部分已保存" if final == "stopped" else "下载完成",
        )
        if args.stop_file and args.stop_file.is_file():
            args.stop_file.unlink(missing_ok=True)
    except requests.HTTPError as e:
        if rows and fieldnames is not None and meta is not None:
            write_output(
                output=args.output,
                fmt=fmt,
                asset=args.asset,
                meta=meta,
                rows=rows,
                fieldnames=fieldnames,
            )
            print(f"已保存部分结果 {len(rows)} 条到 {args.output}", file=sys.stderr)
        publish_progress(
            args.progress_file,
            status="error",
            message=str(e),
        )
        print(f"HTTP 错误: {e}", file=sys.stderr)
        if e.response is not None:
            print(e.response.text[:500], file=sys.stderr)
        sys.exit(1)
    except requests.RequestException as e:
        if rows and fieldnames is not None and meta is not None:
            write_output(
                output=args.output,
                fmt=fmt,
                asset=args.asset,
                meta=meta,
                rows=rows,
                fieldnames=fieldnames,
            )
            print(f"已保存部分结果 {len(rows)} 条到 {args.output}", file=sys.stderr)
        publish_progress(
            args.progress_file,
            status="error",
            message=str(e),
        )
        print(f"请求失败: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        with suppress(OSError):
            pid_file.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
