#!/usr/bin/env python3
"""
从 TronGrid 分页导出 USDT(TRC20) 持有人（可超过 TronScan 1 万上限）。

GET /v1/contracts/{USDT}/tokens?limit=200&order_by=balance,desc&fingerprint=...

需要 TRONGRID_API_KEY 时更稳（环境变量 TRONGRID_API_KEY / TRON_PRO_API_KEY）。
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

import requests

from download_progress import publish as publish_progress
from download_progress import resolve_stop_file
from download_progress import sleep_interruptible
from download_progress import stop_requested

USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TRONGRID_URL = f"https://api.trongrid.io/v1/contracts/{USDT_CONTRACT}/tokens"
SUN = 1_000_000
MAX_PAGE = 200
def _atomic_replace(src: Path, dst: Path, *, retries: int = 15, delay: float = 0.3) -> None:
    """Windows 上 CSV 常被 Excel / 扫描器占用，replace 需重试。"""
    last: OSError | None = None
    for attempt in range(retries):
        try:
            os.replace(src, dst)
            return
        except PermissionError as e:
            last = e
            if attempt + 1 < retries:
                time.sleep(delay)
    if last is not None:
        raise last


CSV_FIELDS = [
    "address",
    "balance_usdt",
    "balance_raw",
    "balance_usd",
    "address_tag",
    "source",
]
CHECKPOINT_VERSION = 1


def checkpoint_path(output: Path) -> Path:
    return output.with_name(f"{output.stem}.checkpoint.json")


def save_checkpoint(
    output: Path,
    *,
    max_holders: int,
    min_balance_usdt: float,
    fingerprint: str | None,
    page: int,
    row_count: int,
    phase: str = "download",
    rebuild_matched: int | None = None,
) -> None:
    if not fingerprint or row_count <= 0:
        return
    path = checkpoint_path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "version": CHECKPOINT_VERSION,
        "output": str(output.resolve()),
        "max_holders": max_holders,
        "min_balance_usdt": min_balance_usdt,
        "fingerprint": fingerprint,
        "page": page,
        "row_count": row_count,
        "phase": phase,
        "updated_at": time.time(),
    }
    if phase == "rebuild" and rebuild_matched is not None:
        payload["rebuild_matched"] = int(rebuild_matched)
    if phase == "skip" and rebuild_matched is not None:
        payload["skip_index"] = int(rebuild_matched)
        payload["rebuild_matched"] = int(rebuild_matched)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def read_checkpoint(output: Path) -> dict[str, Any] | None:
    path = checkpoint_path(output)
    if not path.is_file():
        return None
    try:
        cp = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if cp.get("version") != CHECKPOINT_VERSION:
        return None
    return cp


def clear_checkpoint(output: Path) -> None:
    with suppress(OSError):
        checkpoint_path(output).unlink(missing_ok=True)


def load_existing_rows(output: Path, fmt: str) -> list[dict[str, Any]]:
    if not output.is_file() or output.stat().st_size == 0:
        return []
    if fmt == "json":
        doc = json.loads(output.read_text(encoding="utf-8"))
        accounts = doc.get("accounts") or []
        return [dict(a) for a in accounts if isinstance(a, dict)]
    rows: list[dict[str, Any]] = []
    with output.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("address"):
                rows.append(dict(row))
    return rows


def _resume_from_meta(
    output: Path,
    fmt: str,
    *,
    max_holders: int,
    fingerprint: str,
    page: int,
    expected: int,
) -> tuple[list[dict[str, Any]], str, int] | None:
    rows = load_existing_rows(output, fmt)
    if expected != len(rows):
        return None
    if len(rows) >= max_holders or len(rows) <= 0:
        return None
    return rows, fingerprint, page


def find_resume_state(
    output: Path,
    fmt: str,
    *,
    max_holders: int,
    min_balance_usdt: float,
    progress_path: Path | None = None,
) -> tuple[list[dict[str, Any]], str, int] | None:
    cp_path = checkpoint_path(output)
    if cp_path.is_file():
        try:
            cp = json.loads(cp_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            cp = None
        if cp and cp.get("version") == CHECKPOINT_VERSION:
            try:
                same_out = Path(cp["output"]).resolve() == output.resolve()
            except (KeyError, OSError):
                same_out = False
            cp_max = int(cp.get("max_holders") or 0)
            if (
                same_out
                and cp_max > 0
                and cp_max <= max_holders
                and float(cp.get("min_balance_usdt") or 0) == float(min_balance_usdt)
                and cp.get("phase") in (None, "download")
            ):
                fingerprint = cp.get("fingerprint")
                if fingerprint and isinstance(fingerprint, str):
                    page = int(cp.get("page") or 0)
                    expected = int(cp.get("row_count") or 0)
                    got = _resume_from_meta(
                        output,
                        fmt,
                        max_holders=max_holders,
                        fingerprint=fingerprint,
                        page=page,
                        expected=expected,
                    )
                    if got:
                        return got
                    if (
                        cp_max < max_holders
                        and expected > 0
                        and expected == len(load_existing_rows(output, fmt))
                        and expected < max_holders
                    ):
                        return (
                            load_existing_rows(output, fmt),
                            fingerprint,
                            page,
                        )

    if progress_path and progress_path.is_file():
        try:
            prog = json.loads(progress_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            prog = None
        if prog and prog.get("job") == "trongrid-usdt":
            try:
                prog_out = Path(str(prog.get("output", ""))).resolve()
                same_out = prog_out == output.resolve()
            except OSError:
                same_out = False
            prog_target = int(prog.get("target") or 0)
            if (
                same_out
                and prog_target > 0
                and prog_target <= max_holders
                and float(prog.get("min_balance_usdt") or 0) == float(min_balance_usdt)
            ):
                fingerprint = prog.get("fingerprint")
                if fingerprint and isinstance(fingerprint, str):
                    page = int(prog.get("page") or 0)
                    expected = int(prog.get("current") or 0)
                    got = _resume_from_meta(
                        output,
                        fmt,
                        max_holders=max_holders,
                        fingerprint=fingerprint,
                        page=page,
                        expected=expected,
                    )
                    if got:
                        return got
                    if (
                        prog_target < max_holders
                        and expected > 0
                        and expected == len(load_existing_rows(output, fmt))
                        and expected < max_holders
                    ):
                        return (
                            load_existing_rows(output, fmt),
                            fingerprint,
                            page,
                        )
    return None


def try_load_resume(
    output: Path,
    fmt: str,
    *,
    max_holders: int,
    min_balance_usdt: float,
    progress_path: Path | None = None,
) -> tuple[list[dict[str, Any]], str, int] | None:
    got = find_resume_state(
        output,
        fmt,
        max_holders=max_holders,
        min_balance_usdt=min_balance_usdt,
        progress_path=progress_path,
    )
    if got:
        rows, _, page = got
        print(
            f"续传：已加载 {len(rows):,} 条，从第 {page} 页之后继续",
            file=sys.stderr,
        )
    return got


def partial_download_count(
    output: Path, fmt: str, *, max_holders: int
) -> int | None:
    rows = load_existing_rows(output, fmt)
    n = len(rows)
    if 0 < n < max_holders:
        return n
    return None


def can_continue_download(
    output: Path,
    fmt: str,
    *,
    max_holders: int,
    min_balance_usdt: float = 0.0,
    progress_path: Path | None = None,
) -> bool:
    if find_resume_state(
        output,
        fmt,
        max_holders=max_holders,
        min_balance_usdt=min_balance_usdt,
        progress_path=progress_path,
    ):
        return True
    return partial_download_count(output, fmt, max_holders=max_holders) is not None


def _rebuild_fingerprint_for_rows(
    session: requests.Session,
    rows: list[dict[str, Any]],
    *,
    max_holders: int,
    min_balance_usdt: float,
    output: Path,
    fmt: str,
    progress_path: Path | None,
    stop_file: Path | None,
    worker_pid: int,
    delay_sec: float,
    initial_matched: int = 0,
    initial_page: int = 0,
    initial_fingerprint: str | None = None,
) -> tuple[list[dict[str, Any]], str, int] | None:
    """无 checkpoint 时，按 CSV 地址集对齐 TronGrid 分页并恢复 fingerprint。"""
    if not rows or len(rows) >= max_holders:
        return None
    seen = {str(r["address"]) for r in rows}
    if len(seen) != len(rows):
        print("CSV 地址重复，无法安全续传", file=sys.stderr)
        return None
    need = len(rows)
    matched = max(0, int(initial_matched))
    fingerprint: str | None = initial_fingerprint
    page = max(0, int(initial_page))
    resume_note = (
        f"（续对齐，从第 {page} 页 / 已对齐 {matched:,} 起）"
        if matched > 0 or page > 0
        else ""
    )
    publish_progress(
        progress_path,
        status="running",
        job="trongrid-usdt",
        phase="rebuild",
        pid=worker_pid,
        current=len(rows),
        target=max_holders,
        base_rows=need,
        rebuild_matched=matched,
        rebuild_total=need,
        page=page,
        message=f"正在根据 CSV（{need:,} 条）重建断点…{resume_note}",
        output=str(output),
        min_balance_usdt=min_balance_usdt,
    )
    while matched < need:
        if stop_requested(stop_file):
            return None
        params: dict[str, Any] = {
            "limit": MAX_PAGE,
            "order_by": "balance,desc",
        }
        if fingerprint:
            params["fingerprint"] = fingerprint
        resp = session.get(
            TRONGRID_URL, params=params, headers=api_headers(), timeout=10
        )
        if resp.status_code == 429:
            wait = 30
            if sleep_interruptible(wait, stop_file):
                return None
            continue
        resp.raise_for_status()
        payload = resp.json()
        batch = payload.get("data") or []
        if not batch:
            print("重建断点时 API 无更多数据", file=sys.stderr)
            return None
        page += 1
        for item in batch:
            parsed = parse_row(item)
            if not parsed:
                continue
            address, _ = parsed
            if address in seen:
                matched += 1
        meta = payload.get("meta") or {}
        fingerprint = meta.get("fingerprint")
        publish_progress(
            progress_path,
            status="running",
            job="trongrid-usdt",
            phase="rebuild",
            pid=worker_pid,
            current=len(rows),
            target=max_holders,
            base_rows=need,
            rebuild_matched=matched,
            rebuild_total=need,
            page=page,
            message=f"重建断点：已对齐 {matched:,} / {need:,}（第 {page} 页）",
            output=str(output),
            min_balance_usdt=min_balance_usdt,
        )
        if fingerprint:
            save_checkpoint(
                output,
                max_holders=max_holders,
                min_balance_usdt=min_balance_usdt,
                fingerprint=fingerprint,
                page=page,
                row_count=len(rows),
                phase="rebuild",
                rebuild_matched=matched,
            )
        if matched > need:
            print("CSV 与链上排序不一致，无法续传", file=sys.stderr)
            return None
        if matched == need and fingerprint:
            save_checkpoint(
                output,
                max_holders=max_holders,
                min_balance_usdt=min_balance_usdt,
                fingerprint=fingerprint,
                page=page,
                row_count=len(rows),
                phase="download",
            )
            print(
                f"断点已重建：{len(rows):,} 条，从第 {page} 页后继续",
                file=sys.stderr,
            )
            return rows, fingerprint, page
        if not fingerprint or len(batch) < MAX_PAGE:
            break
        if sleep_interruptible(delay_sec, stop_file):
            return None
    print("无法根据当前 CSV 重建 TronGrid 断点", file=sys.stderr)
    return None


def _skip_csv_prefix(
    session: requests.Session,
    rows: list[dict[str, Any]],
    *,
    max_holders: int,
    min_balance_usdt: float,
    output: Path,
    fmt: str,
    progress_path: Path | None,
    stop_file: Path | None,
    worker_pid: int,
    delay_sec: float,
    initial_skip: int = 0,
    initial_fingerprint: str | None = None,
    initial_page: int = 0,
) -> tuple[str, int] | None:
    """在链上降序流中按子序列定位 CSV 全部地址（允许榜单插入），再续拉。"""
    n = len(rows)
    if n <= 0:
        return None
    skip_idx = max(0, min(int(initial_skip), n))
    fingerprint: str | None = initial_fingerprint
    page = max(0, int(initial_page))
    seen = {str(r["address"]) for r in rows}
    min_raw = int(min_balance_usdt * SUN)
    stalled_pages = 0

    while skip_idx < n:
        if stop_requested(stop_file):
            return None
        params: dict[str, Any] = {
            "limit": MAX_PAGE,
            "order_by": "balance,desc",
        }
        if fingerprint:
            params["fingerprint"] = fingerprint
        resp = session.get(
            TRONGRID_URL, params=params, headers=api_headers(), timeout=10
        )
        if resp.status_code == 429:
            wait = 30
            if sleep_interruptible(wait, stop_file):
                return None
            continue
        resp.raise_for_status()
        payload = resp.json()
        batch = payload.get("data") or []
        if not batch:
            print("定位 CSV 时 API 无更多页", file=sys.stderr)
            return None
        page += 1
        prev_skip = skip_idx
        parsed_batch: list[tuple[str, int]] = []
        for item in batch:
            parsed = parse_row(item)
            if parsed:
                parsed_batch.append(parsed)

        bi = 0
        while bi < len(parsed_batch) and skip_idx < n:
            address, _ = parsed_batch[bi]
            bi += 1
            if address == str(rows[skip_idx]["address"]):
                skip_idx += 1

        if skip_idx == prev_skip:
            stalled_pages += 1
        else:
            stalled_pages = 0
        if stalled_pages > 300:
            print(
                f"连续 {stalled_pages} 页未能再匹配 CSV（停在 {skip_idx:,}/{n:,}）",
                file=sys.stderr,
            )
            return None

        meta = payload.get("meta") or {}
        fingerprint = meta.get("fingerprint")

        if skip_idx >= n:
            while bi < len(parsed_batch) and len(rows) < max_holders:
                address, balance_raw = parsed_batch[bi]
                bi += 1
                if balance_raw <= min_raw:
                    continue
                if address in seen:
                    continue
                seen.add(address)
                rows.append(
                    {
                        "address": address,
                        "balance_usdt": balance_raw / SUN,
                        "balance_raw": str(balance_raw),
                        "balance_usd": "",
                        "address_tag": "",
                        "source": "trongrid",
                    }
                )
            write_rows_snapshot(
                rows,
                output,
                fmt,
                min_balance_usdt=min_balance_usdt,
                max_holders=max_holders,
                stopped="partial",
            )
            break

        publish_progress(
            progress_path,
            status="running",
            job="trongrid-usdt",
            phase="skip",
            pid=worker_pid,
            current=len(rows),
            target=max_holders,
            base_rows=n,
            skip_index=skip_idx,
            skip_total=n,
            page=page,
            message=(
                f"链上定位已有 CSV：{skip_idx:,} / {n:,}（第 {page} 页，"
                "允许链上插入新地址）"
            ),
            output=str(output),
            min_balance_usdt=min_balance_usdt,
        )
        if fingerprint:
            save_checkpoint(
                output,
                max_holders=max_holders,
                min_balance_usdt=min_balance_usdt,
                fingerprint=fingerprint,
                page=page,
                row_count=len(rows),
                phase="skip",
                rebuild_matched=skip_idx,
            )
        if not fingerprint or len(batch) < MAX_PAGE:
            return None
        if sleep_interruptible(delay_sec, stop_file):
            return None

    if not fingerprint:
        return None
    save_checkpoint(
        output,
        max_holders=max_holders,
        min_balance_usdt=min_balance_usdt,
        fingerprint=fingerprint,
        page=page,
        row_count=n,
        phase="download",
    )
    print(
        f"已跳过 CSV 前缀 {n:,} 条，从第 {page} 页后继续拉取并写入",
        file=sys.stderr,
    )
    return str(fingerprint), page


def bootstrap_resume(
    session: requests.Session,
    output: Path,
    fmt: str,
    *,
    max_holders: int,
    min_balance_usdt: float,
    progress_path: Path | None,
    stop_file: Path | None,
    worker_pid: int,
    delay_sec: float,
) -> tuple[list[dict[str, Any]], str | None, int]:
    got = find_resume_state(
        output,
        fmt,
        max_holders=max_holders,
        min_balance_usdt=min_balance_usdt,
        progress_path=progress_path,
    )
    if got:
        rows, fp, page = got
        print(
            f"续传：已加载 {len(rows):,} 条，从第 {page} 页之后继续",
            file=sys.stderr,
        )
        return rows, fp, page
    rows = load_existing_rows(output, fmt)
    if 0 < len(rows) < max_holders:
        skip_kw: dict[str, Any] = {}
        cp = read_checkpoint(output)
        if cp and cp.get("phase") == "rebuild":
            clear_checkpoint(output)
            cp = None
        if (
            cp
            and Path(str(cp.get("output", ""))).resolve() == output.resolve()
            and int(cp.get("max_holders") or 0) == max_holders
            and cp.get("phase") == "skip"
        ):
            skip_kw = {
                "initial_skip": int(cp.get("rebuild_matched") or cp.get("skip_index") or 0),
                "initial_page": int(cp.get("page") or 0),
                "initial_fingerprint": cp.get("fingerprint"),
            }
        skipped = _skip_csv_prefix(
            session,
            rows,
            max_holders=max_holders,
            min_balance_usdt=min_balance_usdt,
            output=output,
            fmt=fmt,
            progress_path=progress_path,
            stop_file=stop_file,
            worker_pid=worker_pid,
            delay_sec=delay_sec,
            **skip_kw,
        )
        if skipped:
            fp, page = skipped
            return rows, fp, page
        return rows, None, -1
    return [], None, 0


def api_headers() -> dict[str, str]:
    h = {"User-Agent": "tron-collider-trongrid-export/1.0"}
    key = os.environ.get("TRONGRID_API_KEY") or os.environ.get("TRON_PRO_API_KEY")
    if key:
        h["TRON-PRO-API-KEY"] = key
    return h


def parse_row(item: dict[str, Any]) -> tuple[str, int] | None:
    if not item or len(item) != 1:
        return None
    address, raw = next(iter(item.items()))
    try:
        balance = int(raw)
    except (TypeError, ValueError):
        return None
    return str(address), balance


def download_holders(
    *,
    max_holders: int,
    min_balance_usdt: float,
    delay_sec: float,
    output: Path,
    fmt: str,
    progress_path: Path | None = None,
    stop_file: Path | None = None,
    resume: bool = True,
) -> int:
    worker_pid = os.getpid()
    session = requests.Session()
    min_raw = int(min_balance_usdt * SUN)
    seen: set[str] = set()
    if resume:
        rows, fingerprint, page = bootstrap_resume(
            session,
            output,
            fmt,
            max_holders=max_holders,
            min_balance_usdt=min_balance_usdt,
            progress_path=progress_path,
            stop_file=stop_file,
            worker_pid=worker_pid,
            delay_sec=delay_sec,
        )
        seen = {str(r["address"]) for r in rows}
        if page == -1:
            publish_progress(
                progress_path,
                status="error",
                job="trongrid-usdt",
                current=len(rows),
                target=max_holders,
                message=(
                    "无法在链上定位全部已有 CSV 地址（榜单变化过大或 CSV 过旧）。"
                    "请用「重新下载」对现有 CSV 从头拉取目标条数。"
                ),
                output=str(output),
            )
            return 0
        partial_n = partial_download_count(output, fmt, max_holders=max_holders)
        if partial_n and len(rows) == 0:
            publish_progress(
                progress_path,
                status="error",
                job="trongrid-usdt",
                current=partial_n,
                target=max_holders,
                message="无法根据现有 CSV 重建断点，请使用「重新下载」",
                output=str(output),
            )
            return 0
    else:
        clear_checkpoint(output)
        rows = []
        fingerprint = None
        page = 0
        write_rows_snapshot(
            rows,
            output,
            fmt,
            min_balance_usdt=min_balance_usdt,
            max_holders=max_holders,
            stopped="restarted",
        )

    start_msg = (
        f"续传：已有 {len(rows):,} 条，继续拉取…"
        if rows
        else "正在请求 TronGrid…"
    )
    publish_progress(
        progress_path,
        status="running",
        job="trongrid-usdt",
        pid=worker_pid,
        current=len(rows),
        target=max_holders,
        page=page,
        message=start_msg,
        output=str(output),
        resumed=bool(rows),
        delay_sec=delay_sec,
        min_balance_usdt=min_balance_usdt,
    )

    while len(rows) < max_holders:
        if stop_requested(stop_file):
            return _write_output(
                rows,
                output,
                fmt,
                min_balance_usdt,
                max_holders,
                stopped="stopped",
                progress_path=progress_path,
            )
        params: dict[str, Any] = {
            "limit": MAX_PAGE,
            "order_by": "balance,desc",
        }
        if fingerprint:
            params["fingerprint"] = fingerprint

        if stop_requested(stop_file):
            return _write_output(
                rows,
                output,
                fmt,
                min_balance_usdt,
                max_holders,
                stopped="stopped",
                progress_path=progress_path,
            )
        resp = session.get(
            TRONGRID_URL, params=params, headers=api_headers(), timeout=10
        )
        if resp.status_code == 429:
            wait = 30
            print(f"TronGrid 429，等待 {wait}s…", file=sys.stderr)
            publish_progress(
                progress_path,
                status="running",
                job="trongrid-usdt",
                pid=worker_pid,
                current=len(rows),
                target=max_holders,
                page=page,
                message=f"限流，等待最多 {wait}s…",
                output=str(output),
            )
            if sleep_interruptible(wait, stop_file):
                return _write_output(
                    rows,
                    output,
                    fmt,
                    min_balance_usdt,
                    max_holders,
                    stopped="stopped",
                    progress_path=progress_path,
                )
            continue
        resp.raise_for_status()
        payload = resp.json()
        if not payload.get("success", True):
            raise requests.HTTPError(f"TronGrid error: {payload}")

        batch = payload.get("data") or []
        if not batch:
            break

        page += 1
        for item in batch:
            parsed = parse_row(item)
            if not parsed:
                continue
            address, balance_raw = parsed
            if balance_raw <= min_raw:
                if min_raw > 0:
                    return _write_output(
                        rows,
                        output,
                        fmt,
                        min_balance_usdt,
                        max_holders,
                        stopped="min_balance",
                        progress_path=progress_path,
                    )
                continue
            if address in seen:
                continue
            seen.add(address)
            rows.append(
                {
                    "address": address,
                    "balance_usdt": balance_raw / SUN,
                    "balance_raw": str(balance_raw),
                    "balance_usd": "",
                    "address_tag": "",
                    "source": "trongrid",
                }
            )
            if len(rows) >= max_holders:
                break

        meta = payload.get("meta") or {}
        fingerprint = meta.get("fingerprint")
        if fingerprint:
            save_checkpoint(
                output,
                max_holders=max_holders,
                min_balance_usdt=min_balance_usdt,
                fingerprint=fingerprint,
                page=page,
                row_count=len(rows),
                phase="download",
            )
        if rows:
            write_rows_snapshot(
                rows,
                output,
                fmt,
                min_balance_usdt=min_balance_usdt,
                max_holders=max_holders,
                stopped="partial",
            )
        print(
            f"第 {page} 页，累计 {len(rows):,} / {max_holders:,}（已写入 CSV）",
            file=sys.stderr,
        )
        publish_progress(
            progress_path,
            status="running",
            job="trongrid-usdt",
            pid=worker_pid,
            current=len(rows),
            target=max_holders,
            page=page,
            fingerprint=fingerprint,
            min_balance_usdt=min_balance_usdt,
            message=f"第 {page} 页，已 {len(rows):,} / {max_holders:,}（已写入 CSV）",
            output=str(output),
        )
        if not fingerprint or len(batch) < MAX_PAGE:
            break
        if sleep_interruptible(delay_sec, stop_file):
            return _write_output(
                rows,
                output,
                fmt,
                min_balance_usdt,
                max_holders,
                stopped="stopped",
                progress_path=progress_path,
            )

    return _write_output(
        rows,
        output,
        fmt,
        min_balance_usdt,
        max_holders,
        stopped="complete",
        progress_path=progress_path,
    )


def write_rows_snapshot(
    rows: list[dict[str, Any]],
    output: Path,
    fmt: str,
    *,
    min_balance_usdt: float,
    max_holders: int,
    stopped: str = "partial",
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    part = output.with_name(output.name + ".part")
    try:
        if fmt == "json":
            doc = {
                "source": TRONGRID_URL,
                "contract": USDT_CONTRACT,
                "min_balance_usdt": min_balance_usdt,
                "max_holders": max_holders,
                "stopped": stopped,
                "count": len(rows),
                "accounts": rows,
            }
            part.write_text(
                json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        else:
            with part.open("w", encoding="utf-8", newline="") as f:
                w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                w.writeheader()
                w.writerows(rows)
        _atomic_replace(part, output)
    finally:
        if part.is_file() and part.resolve() != output.resolve():
            with suppress(OSError):
                part.unlink()


def _write_output(
    rows: list[dict[str, Any]],
    output: Path,
    fmt: str,
    min_balance_usdt: float,
    max_holders: int,
    *,
    stopped: str,
    progress_path: Path | None = None,
) -> int:
    write_rows_snapshot(
        rows,
        output,
        fmt,
        min_balance_usdt=min_balance_usdt,
        max_holders=max_holders,
        stopped=stopped,
    )

    print(f"已写入 {output}（{len(rows)} 条，{stopped}）", file=sys.stderr)
    final_status = "stopped" if stopped == "stopped" else "completed"
    if final_status == "completed":
        clear_checkpoint(output)
    publish_progress(
        progress_path,
        status=final_status,
        job="trongrid-usdt",
        current=len(rows),
        target=max_holders,
        fetched_rows=len(rows),
        min_balance_usdt=min_balance_usdt,
        output=str(output),
        message=(
            "已停止，部分已保存"
            if final_status == "stopped"
            else f"完成（{stopped}）"
        ),
    )
    return len(rows)


def main() -> None:
    from env_local import load_local_env

    load_local_env(Path(__file__).resolve().parent)
    parser = argparse.ArgumentParser(
        description="从 TronGrid 导出 USDT 持有人（支持 10 万+）"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("data/usdt_top200000.csv"),
    )
    parser.add_argument(
        "--max-holders",
        type=int,
        default=200_000,
        help="最多导出持有人数（20万/30万请配合 -o 独立 CSV 路径）",
    )
    parser.add_argument(
        "--min-balance-usdt",
        type=float,
        default=0.0,
        help="余额低于该值（USDT）时停止翻页（按降序，适合阈值截断）",
    )
    parser.add_argument(
        "--format",
        choices=("csv", "json"),
        default=None,
    )
    parser.add_argument("--delay", type=float, default=0.15, help="分页间隔秒")
    parser.add_argument(
        "--progress-file",
        type=Path,
        default=Path("data/download_progress.json"),
        help="进度 JSON 路径",
    )
    parser.add_argument(
        "--stop-file",
        type=Path,
        default=None,
        help="若存在则停止并保存已下载部分",
    )
    parser.add_argument(
        "--no-resume",
        dest="resume",
        action="store_false",
        default=True,
        help="不从 checkpoint 续传，从头下载",
    )
    args = parser.parse_args()
    out_raw = str(args.output or "").strip()
    if not out_raw or out_raw in (".", ".."):
        print(
            "错误：输出路径为空。例如 data/usdt_top200000.csv 或 data/usdt_top300000.csv",
            file=sys.stderr,
        )
        sys.exit(2)
    args.output = Path(out_raw)
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

    fmt = args.format
    if fmt is None:
        fmt = "json" if args.output.suffix.lower() == ".json" else "csv"

    try:
        download_holders(
            max_holders=args.max_holders,
            min_balance_usdt=args.min_balance_usdt,
            delay_sec=args.delay,
            output=args.output,
            fmt=fmt,
            progress_path=args.progress_file,
            stop_file=args.stop_file,
            resume=args.resume,
        )
        if args.stop_file and args.stop_file.is_file():
            args.stop_file.unlink(missing_ok=True)
    except requests.RequestException as e:
        publish_progress(
            args.progress_file,
            status="error",
            job="trongrid-usdt",
            message=str(e),
        )
        print(f"请求失败: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        with suppress(OSError):
            pid_file.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
