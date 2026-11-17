#!/usr/bin/env python3
"""TRON Collider 可视化控制台（Streamlit）。"""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import time
from contextlib import suppress
from datetime import timedelta
from pathlib import Path

import streamlit as st

from bloom_csv_match import csv_address_count
from bloom_csv_match import validate_bloom_csv_pair
from scan_lifetime import bootstrap_lifetime_from_stats
from scan_lifetime import read_lifetime_total
from download_process import discover_balance_scan_pids
from download_process import discover_bloom_build_pids
from download_process import discover_collider_pids
from download_process import discover_mnemonic_collider_pids
from download_process import discover_download_pids
from download_progress import publish as publish_progress
from download_usdt_trongrid import can_continue_download
from download_usdt_trongrid import find_resume_state
from download_usdt_trongrid import partial_download_count
from env_local import api_key_status
from env_local import load_local_env
from env_local import render_api_key_badge

ROOT = Path(__file__).resolve().parent
load_local_env(ROOT)
DATA = ROOT / "data"
DEFAULT_CSV_REL = "data/usdt_top200000.csv"
DEFAULT_BLOOM_REL = "data/usdt_top200000.bloom"
CSV_PATH = DATA / "usdt_top200000.csv"
BLOOM_PATH = DATA / "usdt_top200000.bloom"
TOP200K_CSV_PATH = CSV_PATH
TOP200K_TARGET = 200_000
TOP300K_CSV_REL = "data/usdt_top300000.csv"
TOP300K_BLOOM_REL = "data/usdt_top300000.bloom"
TOP300K_CSV_PATH = DATA / "usdt_top300000.csv"
TOP300K_BLOOM_PATH = DATA / "usdt_top300000.bloom"
TOP300K_TARGET = 300_000
TOP100K_CSV_REL = "data/usdt_top100000.csv"
TOP100K_BLOOM_REL = "data/usdt_top100000.bloom"
TRONSCAN_CSV_PATH = DATA / "usdt_top10000.csv"
HITS_PATH = DATA / "hits.jsonl"
STATS_PATH = DATA / "scan_stats.json"
LIFETIME_PATH = DATA / "scan_lifetime.json"
PID_PATH = DATA / "scan.pid"
STOP_PATH = DATA / "stop.scan"
MNEMONIC_STATS_PATH = DATA / "mnemonic_scan_stats.json"
MNEMONIC_LIFETIME_PATH = DATA / "mnemonic_scan_lifetime.json"
MNEMONIC_STOP_PATH = DATA / "stop.mnemonic"
MNEMONIC_PID_PATH = DATA / "mnemonic.pid"
MNEMONIC_HITS_PATH = DATA / "mnemonic_hits.jsonl"
BALANCE_STATS_PATH = DATA / "balance_scan_stats.json"
BALANCE_LIFETIME_PATH = DATA / "balance_scan_lifetime.json"
BALANCE_STOP_PATH = DATA / "stop.balance"
BALANCE_PID_PATH = DATA / "balance.pid"
BALANCE_HITS_PATH = DATA / "balance_hits.jsonl"
LOG_PATH = DATA / "scan.log"
DOWNLOAD_PROGRESS_PATH = DATA / "download_progress.json"
BLOOM_PROGRESS_PATH = DATA / "bloom_build_progress.json"
STOP_DOWNLOAD_PATH = DATA / "stop.download"
STATS_STALE_SEC = 20
DOWNLOAD_PID_PATH = DATA / "download.pid"
UI_PREFS_PATH = DATA / "ui_prefs.json"


def load_ui_prefs() -> dict:
    if not UI_PREFS_PATH.is_file():
        return {}
    try:
        return json.loads(UI_PREFS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def normalize_tg_output(raw: str) -> str:
    path = str(raw or "").strip()
    return path if path else DEFAULT_CSV_REL


def csv_target_for_path(path: Path) -> int | None:
    name = path.name.lower()
    if "300000" in name:
        return TOP300K_TARGET
    if "200000" in name:
        return TOP200K_TARGET
    if "100000" in name:
        return 100_000
    return None


def apply_tg_download_preset(which: str) -> None:
    if which == "300k":
        rel, target = TOP300K_CSV_REL, TOP300K_TARGET
    elif which == "100k":
        rel, target = TOP100K_CSV_REL, 100_000
    else:
        rel, target = DEFAULT_CSV_REL, TOP200K_TARGET
    st.session_state.tg_out = rel
    st.session_state.tg_max = target
    save_ui_prefs(tg_out=rel, tg_max=target)


def _bloom_preset_200k() -> None:
    st.session_state.bloom_in = DEFAULT_CSV_REL
    st.session_state.bloom_out = DEFAULT_BLOOM_REL


def _bloom_preset_300k() -> None:
    st.session_state.bloom_in = TOP300K_CSV_REL
    st.session_state.bloom_out = TOP300K_BLOOM_REL


def _scan_preset_200k() -> None:
    st.session_state.scan_bloom = DEFAULT_BLOOM_REL
    st.session_state.scan_csv = DEFAULT_CSV_REL
    save_ui_prefs(scan_bloom=DEFAULT_BLOOM_REL, scan_csv=DEFAULT_CSV_REL)


def _scan_preset_300k() -> None:
    st.session_state.scan_bloom = TOP300K_BLOOM_REL
    st.session_state.scan_csv = TOP300K_CSV_REL
    save_ui_prefs(scan_bloom=TOP300K_BLOOM_REL, scan_csv=TOP300K_CSV_REL)


def _scan_preset_100k() -> None:
    st.session_state.scan_bloom = TOP100K_BLOOM_REL
    st.session_state.scan_csv = TOP100K_CSV_REL
    save_ui_prefs(scan_bloom=TOP100K_BLOOM_REL, scan_csv=TOP100K_CSV_REL)


def save_ui_prefs(**fields: object) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    if "tg_out" in fields:
        fields = {**fields, "tg_out": normalize_tg_output(str(fields["tg_out"]))}
    data = load_ui_prefs()
    data.update({k: v for k, v in fields.items() if v is not None})
    UI_PREFS_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _bloom_meta_csv(bloom_rel: str) -> str | None:
    bp = (ROOT / bloom_rel).resolve()
    meta_path = bp.with_suffix(bp.suffix + ".meta.json")
    if not meta_path.is_file():
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    src = meta.get("source_csv")
    if not src:
        return None
    try:
        p = Path(src)
        if p.is_file():
            return str(p.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        pass
    return str(src).replace("\\", "/")


def scan_path_defaults() -> tuple[str, str]:
    prefs = load_ui_prefs()
    bloom = str(prefs.get("scan_bloom") or "").strip() or DEFAULT_BLOOM_REL
    csv = str(prefs.get("scan_csv") or "").strip()
    if bloom.replace("\\", "/").endswith("usdt_top10000.bloom"):
        bloom = DEFAULT_BLOOM_REL
    if csv.replace("\\", "/").endswith("usdt_top10000.csv"):
        csv = DEFAULT_CSV_REL
    if not csv:
        from_meta = _bloom_meta_csv(bloom)
        csv = from_meta or DEFAULT_CSV_REL
    return bloom, csv


def resolve_scan_paths() -> tuple[Path, Path]:
    bloom_rel, csv_rel = scan_path_defaults()
    if "scan_bloom" in st.session_state:
        bloom_rel = str(st.session_state.scan_bloom)
    if "scan_csv" in st.session_state:
        csv_rel = str(st.session_state.scan_csv)
    return (ROOT / bloom_rel).resolve(), (ROOT / csv_rel).resolve()


def ensure_runtime_files() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    for path in (HITS_PATH, LOG_PATH, MNEMONIC_HITS_PATH):
        if not path.is_file():
            path.touch()


@st.cache_data(show_spinner=False, ttl=10)
def cached_csv_address_count(path_str: str, bloom_path_str: str = "") -> int:
    path = Path(path_str)
    if not path.is_file() or path.stat().st_size == 0:
        return 0
    bloom = Path(bloom_path_str) if bloom_path_str else None
    try:
        return csv_address_count(path, bloom_path=bloom, project_root=ROOT)
    except OSError:
        return 0


def render_count_stats_markdown(items: list[tuple[str, str]]) -> None:
    """整行 markdown，避免 st.metric 在窄列里把 200,000 显示成 20…"""
    st.markdown("  \n".join(f"**{label}：** {value}" for label, value in items))


def render_csv_exact_count_line(
    csv_path: Path,
    *,
    target: int | None = None,
    label: str | None = None,
    bloom_path: Path | None = None,
) -> None:
    name = label or csv_path.name
    bloom_s = (
        str(bloom_path.resolve())
        if bloom_path is not None and bloom_path.is_file()
        else ""
    )
    n = cached_csv_address_count(str(csv_path.resolve()), bloom_s)
    if not csv_path.is_file():
        st.caption(f"**{name}**：文件缺失")
        if target:
            render_count_stats_markdown(
                [("CSV 精确条数", "0"), ("目标", f"{target:,}"), ("完成度", "0%")]
            )
        else:
            render_count_stats_markdown([("CSV 精确条数", "0")])
        return
    badge = file_badge(csv_path)
    pct = min(100.0, 100.0 * n / target) if target and target > 0 else 0.0
    if target and target > 0:
        render_count_stats_markdown(
            [
                ("CSV 精确条数", f"{n:,}"),
                ("目标", f"{target:,}"),
                ("完成度", f"{pct:.1f}%"),
            ]
        )
    else:
        render_count_stats_markdown([("CSV 精确条数", f"{n:,}"), ("文件", badge)])
    st.caption(f"`{name}` · {badge} · address 去重，与 Bloom/扫描一致")


def file_badge(path: Path, *, optional_empty: bool = False) -> str:
    if not path.is_file():
        if optional_empty:
            return "空 (0 条)"
        return "缺失"
    size = path.stat().st_size
    if size == 0 and optional_empty:
        return "空 (0 条)"
    if size > 1_048_576:
        return f"OK ({size / 1_048_576:.1f} MB)"
    if size > 1024:
        return f"OK ({size / 1024:.1f} KB)"
    return f"OK ({size} B)"


def run_script(args: list[str], log_path: Path) -> subprocess.Popen:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = log_path.open("a", encoding="utf-8")
    log_file.write(f"\n--- {' '.join(args)} @ {time.ctime()} ---\n")
    log_file.flush()
    return subprocess.Popen(
        [sys.executable, "-u", *args],
        cwd=str(ROOT),
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env={
            **os.environ,
            "PYTHONUNBUFFERED": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
        },
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )


def read_download_progress() -> dict | None:
    if not DOWNLOAD_PROGRESS_PATH.is_file():
        return None
    try:
        return json.loads(DOWNLOAD_PROGRESS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _collect_download_pids() -> set[int]:
    """仅返回命令行可识别的下载脚本进程（避免 Windows PID 复用误判）。"""
    pids: set[int] = set(discover_download_pids(ROOT))
    proc: subprocess.Popen | None = st.session_state.get("job_proc")
    name = st.session_state.get("job_name", "")
    if (
        proc is not None
        and proc.poll() is None
        and name in ("download", "trongrid_download")
        and proc.pid
    ):
        pids.add(int(proc.pid))
    return {p for p in pids if p > 0 and _pid_alive(p)}


def _read_download_pid() -> int | None:
    prog = read_download_progress()
    if prog:
        raw = prog.get("pid")
        if raw is not None:
            try:
                return int(raw)
            except (TypeError, ValueError):
                pass
    if DOWNLOAD_PID_PATH.is_file():
        try:
            return int(DOWNLOAD_PID_PATH.read_text(encoding="utf-8").strip())
        except ValueError:
            return None
    return None


def _kill_download_pid(pid: int) -> None:
    if pid <= 0:
        return
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            check=False,
            capture_output=True,
        )
    else:
        with suppress(OSError):
            os.kill(pid, 15)


def reconcile_download_progress() -> None:
    """进度仍为 running 但进程已退出时，标记为 stopped。"""
    prog = read_download_progress()
    if not prog or prog.get("status") != "running":
        return
    if any(_pid_alive(p) for p in _collect_download_pids()):
        return
    publish_progress(
        DOWNLOAD_PROGRESS_PATH,
        status="stopped",
        job=prog.get("job", "download"),
        current=int(prog.get("current") or 0),
        target=int(prog.get("target") or 0),
        message="下载已结束（进程不存在，可能已停止或异常退出）",
        output=prog.get("output", ""),
    )
    with suppress(OSError):
        DOWNLOAD_PID_PATH.unlink(missing_ok=True)
    STOP_DOWNLOAD_PATH.unlink(missing_ok=True)


def is_download_active() -> bool:
    reconcile_download_progress()
    return any(_pid_alive(p) for p in _collect_download_pids())


def summarize_background_jobs() -> tuple[list[str], bool]:
    """真正占用 CPU/网络的后台子进程（不含 Streamlit 自身刷新）。"""
    names: list[str] = []
    if is_download_active():
        names.append("TronGrid 下载")
    if is_bloom_build_active():
        names.append("Bloom 构建")
    if is_scan_active(_read_stats_raw(), st.session_state.get("scan_proc")):
        names.append("私钥碰撞")
    if is_mnemonic_scan_active(
        _read_mnemonic_stats_raw(), st.session_state.get("mn_scan_proc")
    ):
        names.append("助记词碰撞")
    if is_balance_scan_active(
        _read_balance_stats_raw(), st.session_state.get("balance_scan_proc")
    ):
        names.append("联网查余额")
    job = st.session_state.get("job_proc")
    if job is not None and job.poll() is None:
        jn = str(st.session_state.get("job_name") or "task")
        if jn not in ("download", "bloom") and jn not in names:
            names.append(jn)
    return names, bool(names)


def request_stop_download() -> None:
    STOP_DOWNLOAD_PATH.parent.mkdir(parents=True, exist_ok=True)
    STOP_DOWNLOAD_PATH.write_text("stop", encoding="utf-8")

    prog = read_download_progress() or {}
    publish_progress(
        DOWNLOAD_PROGRESS_PATH,
        status="running",
        job=prog.get("job", "download"),
        current=int(prog.get("current") or 0),
        target=int(prog.get("target") or 0),
        message="正在停止，保存已下载部分…",
        output=prog.get("output", ""),
    )

    pids = _collect_download_pids()

    for _ in range(8):
        if not any(_pid_alive(p) for p in pids):
            break
        time.sleep(0.25)

    pids = _collect_download_pids()
    if any(_pid_alive(p) for p in pids):
        for pid in list(pids):
            _kill_download_pid(pid)
        time.sleep(0.5)

    still_alive = any(_pid_alive(p) for p in _collect_download_pids())
    if not still_alive:
        publish_progress(
            DOWNLOAD_PROGRESS_PATH,
            status="stopped",
            job=prog.get("job", "download"),
            current=int(prog.get("current") or 0),
            target=int(prog.get("target") or 0),
            message="已停止",
            output=prog.get("output", ""),
        )
        with suppress(OSError):
            DOWNLOAD_PID_PATH.unlink(missing_ok=True)
        STOP_DOWNLOAD_PATH.unlink(missing_ok=True)
    elif still_alive:
        publish_progress(
            DOWNLOAD_PROGRESS_PATH,
            status="running",
            job=prog.get("job", "download"),
            current=int(prog.get("current") or 0),
            target=int(prog.get("target") or 0),
            message="停止失败：请再点一次停止，或关闭占用下载的 Python 进程",
            output=prog.get("output", ""),
        )


def start_trongrid_download(
    *,
    max_holders: int,
    output: str,
    delay_sec: float,
    resume: bool,
) -> bool:
    output = normalize_tg_output(output)
    if is_download_active():
        request_stop_download()
        time.sleep(0.5)
    if _collect_download_pids():
        st.error("仍有下载进程在运行，请先点上方 **停止下载** 后再试。")
        return False
    STOP_DOWNLOAD_PATH.unlink(missing_ok=True)
    publish_progress(
        DOWNLOAD_PROGRESS_PATH,
        status="running",
        job="trongrid-usdt",
        current=0,
        target=int(max_holders),
        message="正在启动 TronGrid 下载进程…"
        if not resume
        else "正在启动 TronGrid 续传…",
        output=str(output),
        delay_sec=float(delay_sec),
    )
    st.session_state.busy = True
    tg_cmd = [
        "download_usdt_trongrid.py",
        "--max-holders",
        str(int(max_holders)),
        "-o",
        output,
        "--delay",
        str(delay_sec),
        "--progress-file",
        str(DOWNLOAD_PROGRESS_PATH.relative_to(ROOT)),
        "--stop-file",
        str(STOP_DOWNLOAD_PATH.relative_to(ROOT)),
    ]
    if not resume:
        tg_cmd.append("--no-resume")
    proc = run_script(tg_cmd, LOG_PATH)
    st.session_state.job_proc = proc
    st.session_state.job_name = "trongrid_download"
    if proc.pid:
        DOWNLOAD_PID_PATH.write_text(str(proc.pid), encoding="utf-8")
    time.sleep(0.35)
    if proc.poll() is not None:
        publish_progress(
            DOWNLOAD_PROGRESS_PATH,
            status="error",
            job="trongrid-usdt",
            current=0,
            target=int(max_holders),
            message=f"下载进程立即退出 (code={proc.returncode})，请查看 scan.log 末尾",
            output=str(output),
        )
        st.session_state.job_proc = None
        st.session_state.busy = False
        st.error("下载未能启动，请打开 **scan.log** 看报错（常见：缺 API Key / 网络）。")
        return False
    save_ui_prefs(
        tg_delay=float(delay_sec),
        tg_max=int(max_holders),
        tg_out=str(output),
    )
    return True


def discover_live_collider_pids() -> set[int]:
    """私钥 collider.py 进程（不含 mnemonic_collider.py）。"""
    return {p for p in discover_collider_pids(ROOT) if p > 0 and _pid_alive(p)}


def _collect_scan_pids() -> set[int]:
    pids = set(discover_live_collider_pids())
    proc: subprocess.Popen | None = st.session_state.get("scan_proc")
    if proc is not None and proc.poll() is None and proc.pid:
        pids.add(int(proc.pid))
    if PID_PATH.is_file():
        with suppress(ValueError):
            file_pid = int(PID_PATH.read_text(encoding="utf-8").strip())
            if file_pid > 0 and _pid_alive(file_pid):
                pids.add(file_pid)
    return pids


def mark_scan_stats_stopped(message: str = "用户停止") -> None:
    stats = _read_stats_raw()
    if not stats:
        return
    payload = {**stats, "status": "stopped", "message": message}
    STATS_PATH.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    with suppress(OSError):
        PID_PATH.unlink(missing_ok=True)


def signal_stop_scan(*, force_kill: bool = False) -> set[int]:
    """写 stop.scan；残留/卡住时可 force_kill 结束 collider 进程树。"""
    STOP_PATH.parent.mkdir(parents=True, exist_ok=True)
    STOP_PATH.write_text("stop", encoding="utf-8")
    killed: set[int] = set()
    if force_kill:
        for pid in discover_live_collider_pids():
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True,
                    timeout=30,
                )
            else:
                with suppress(OSError):
                    os.kill(pid, 9)
            killed.add(pid)
    mark_scan_stats_stopped(
        "已强制结束残留 collider" if force_kill and killed else "已发送停止信号"
    )
    return killed


def render_download_progress() -> None:
    reconcile_download_progress()
    prog = read_download_progress()

    if not prog:
        st.caption("暂无下载任务")
        return

    status = prog.get("status", "")
    pct = float(prog.get("percent") or 0)
    current = int(prog.get("current") or 0)
    target = int(prog.get("target") or 0)
    job = prog.get("job", "download")
    msg = prog.get("message", "")

    if status in ("running", "completed", "stopped"):
        st.progress(min(max(pct / 100.0, 0.0), 1.0))

    disk_n: int | None = None
    out_raw = prog.get("output")
    if out_raw:
        out_path = Path(str(out_raw))
        if not out_path.is_absolute():
            out_path = (ROOT / out_path).resolve()
        if out_path.is_file():
            disk_n = cached_csv_address_count(str(out_path))

    phase = prog.get("phase") or ""
    skip_i = int(prog.get("skip_index") or prog.get("rebuild_matched") or 0)
    skip_t = int(prog.get("skip_total") or prog.get("rebuild_total") or 0)
    disk_s = f"{disk_n:,}" if disk_n is not None else "—"
    stats: list[tuple[str, str]] = []
    if phase in ("skip", "rebuild") and skip_t > 0:
        stats.append(("链上定位", f"{skip_i:,} / {skip_t:,}"))
        stats.append(("磁盘 CSV 条数", disk_s))
    else:
        stats.append(("任务计数", f"{current:,}"))
        stats.append(("磁盘 CSV 条数", disk_s))
    stats.append(("目标", f"{target:,}"))
    stats.append(("进度", f"{pct:.1f}%"))
    render_count_stats_markdown(stats)

    delay_note = ""
    raw_delay = prog.get("delay_sec")
    if raw_delay is not None:
        try:
            delay_note = f" · 间隔 **{float(raw_delay):.2f}s**"
        except (TypeError, ValueError):
            pass
    st.caption(f"**{job}** · {status} · {msg}{delay_note}")
    if disk_n is not None and disk_n != current and phase not in ("skip", "rebuild"):
        st.caption(f"（任务计数 {current:,}，磁盘精确 **{disk_n:,}** 条；以磁盘为准）")
    if status == "completed":
        st.success(f"下载完成：{prog.get('output', '')}")
    elif status == "stopped":
        st.warning(f"已停止，部分已保存：{prog.get('output', '')}")
    elif status == "error":
        st.error(prog.get("message", "下载失败"))
        out_err = str(prog.get("output") or "").strip()
        if not out_err:
            st.caption(
                f"常见原因：**输出 CSV 为空**。请确认下方路径为 `{DEFAULT_CSV_REL}` 后再点 **重新下载**。"
            )


def read_bloom_build_progress() -> dict | None:
    if not BLOOM_PROGRESS_PATH.is_file():
        return None
    try:
        return json.loads(BLOOM_PROGRESS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _live_bloom_build_pids() -> set[int]:
    return {
        p
        for p in discover_bloom_build_pids(ROOT)
        if p > 0 and _pid_alive(p)
    }


def reconcile_bloom_build_progress() -> None:
    prog = read_bloom_build_progress()
    if not prog or prog.get("status") != "running":
        return
    if _live_bloom_build_pids():
        return
    proc: subprocess.Popen | None = st.session_state.get("job_proc")
    name = st.session_state.get("job_name", "")
    if proc is not None and proc.poll() is None and name == "bloom":
        return
    publish_progress(
        BLOOM_PROGRESS_PATH,
        status="stopped",
        job="bloom-build",
        current=int(prog.get("current") or 0),
        target=int(prog.get("target") or 0),
        message="构建已结束（进程已退出，请查看 scan.log）",
        output=prog.get("output", ""),
    )


def is_bloom_build_active() -> bool:
    reconcile_bloom_build_progress()
    if _live_bloom_build_pids():
        return True
    proc: subprocess.Popen | None = st.session_state.get("job_proc")
    if (
        proc is not None
        and proc.poll() is None
        and st.session_state.get("job_name") == "bloom"
    ):
        return True
    prog = read_bloom_build_progress()
    return bool(prog and prog.get("status") == "running")


def render_bloom_build_progress() -> None:
    reconcile_bloom_build_progress()
    prog = read_bloom_build_progress()
    if not isinstance(prog, dict):
        return
    status = str(prog.get("status") or "")
    if status not in ("running", "completed", "stopped", "error"):
        return
    try:
        pct = float(prog.get("percent") or 0)
    except (TypeError, ValueError):
        pct = 0.0
    if not (pct == pct and pct != float("inf") and pct != float("-inf")):
        pct = 0.0
    try:
        current = int(prog.get("current") or 0)
        target = int(prog.get("target") or 0)
    except (TypeError, ValueError):
        current, target = 0, 0
    msg = str(prog.get("message") or "")
    phase = str(prog.get("phase") or "")
    phase_note = f" · {phase}" if phase else ""
    if status == "running":
        bar = (
            0.05
            if target <= 0
            else min(max(pct / 100.0, 0.0), 1.0)
        )
        st.progress(bar)
        st.caption(
            f"**Bloom 构建**{phase_note} · {msg} · **{current:,} / {target:,}**"
            f"（{pct:.1f}%）"
        )
    elif status == "completed":
        st.caption(
            f"**Bloom 构建** · {msg} · **{current:,} / {target:,}**（{pct:.1f}%）"
        )
    elif status in ("stopped", "error"):
        st.caption(
            f"**Bloom 构建**{phase_note} · {msg} · **{current:,} / {target:,}**"
        )
    if status == "completed":
        out = prog.get("output", "")
        nbytes = prog.get("file_bytes")
        extra = f"（约 {nbytes} 字节）" if nbytes else ""
        st.success(f"构建完成：{out}{extra}")
    elif status == "error":
        st.error(prog.get("message", "构建失败"))
    elif status == "stopped":
        st.warning(prog.get("message", "构建已中断"))


def _bloom_progress_is_live() -> bool:
    if is_bloom_build_active():
        return True
    prog = read_bloom_build_progress()
    return bool(isinstance(prog, dict) and prog.get("status") == "running")


def bloom_build_progress_panel() -> None:
    """构建中走 fragment 刷新；完成后静态展示（无进度条动画）。"""
    if hasattr(st, "fragment") and _bloom_progress_is_live():
        _bloom_build_live_panel()
        return
    if not hasattr(st, "fragment") and _bloom_progress_is_live():
        render_bloom_build_progress()
        return
    prog = read_bloom_build_progress()
    if isinstance(prog, dict) and prog.get("status") in (
        "completed",
        "stopped",
        "error",
    ):
        render_bloom_build_progress()


def download_progress_ui() -> None:
    if hasattr(st, "fragment") and _download_progress_is_live():
        download_progress_panel()
    elif read_download_progress():
        render_download_progress()


def csv_count_panel_ui(
    csv_path: Path,
    *,
    target: int,
    label: str,
    bloom_path: Path,
    live_panel: object,
) -> None:
    if hasattr(st, "fragment") and _csv_count_panel_needs_poll(
        csv_path, target, bloom_path
    ):
        live_panel()
    else:
        render_csv_exact_count_line(
            csv_path,
            target=target,
            label=label,
            bloom_path=bloom_path,
        )


def _download_progress_is_live() -> bool:
    if is_download_active():
        return True
    prog = read_download_progress()
    return bool(isinstance(prog, dict) and prog.get("status") == "running")


def _csv_count_panel_needs_poll(csv_path: Path, target: int, bloom_path: Path) -> bool:
    if is_download_active():
        return True
    if not csv_path.is_file():
        return True
    bloom_s = str(bloom_path.resolve()) if bloom_path.is_file() else ""
    try:
        n = cached_csv_address_count(str(csv_path.resolve()), bloom_s)
    except OSError:
        return True
    return n < target


if hasattr(st, "fragment"):

    @st.fragment(run_every=timedelta(seconds=1))
    def _bloom_build_live_panel() -> None:
        try:
            render_bloom_build_progress()
        except Exception as exc:
            st.warning(f"Bloom 进度显示异常：{exc}")

    @st.fragment(run_every=timedelta(seconds=2))
    def download_progress_panel() -> None:
        if _download_progress_is_live():
            render_download_progress()

    @st.fragment(run_every=timedelta(seconds=2))
    def top200k_count_panel() -> None:
        if not _csv_count_panel_needs_poll(
            TOP200K_CSV_PATH, TOP200K_TARGET, BLOOM_PATH
        ):
            return
        render_csv_exact_count_line(
            TOP200K_CSV_PATH,
            target=TOP200K_TARGET,
            label="data/usdt_top200000.csv",
            bloom_path=BLOOM_PATH,
        )

    @st.fragment(run_every=timedelta(seconds=2))
    def top300k_count_panel() -> None:
        if not _csv_count_panel_needs_poll(
            TOP300K_CSV_PATH, TOP300K_TARGET, TOP300K_BLOOM_PATH
        ):
            return
        render_csv_exact_count_line(
            TOP300K_CSV_PATH,
            target=TOP300K_TARGET,
            label="data/usdt_top300000.csv",
            bloom_path=TOP300K_BLOOM_PATH,
        )

else:

    def download_progress_panel() -> None:
        render_download_progress()

    def top200k_count_panel() -> None:
        render_csv_exact_count_line(
            TOP200K_CSV_PATH,
            target=TOP200K_TARGET,
            label="data/usdt_top200000.csv",
            bloom_path=BLOOM_PATH,
        )

    def top300k_count_panel() -> None:
        render_csv_exact_count_line(
            TOP300K_CSV_PATH,
            target=TOP300K_TARGET,
            label="data/usdt_top300000.csv",
            bloom_path=TOP300K_BLOOM_PATH,
        )


def _read_stats_raw() -> dict | None:
    if not STATS_PATH.is_file():
        return None
    try:
        return json.loads(STATS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _stats_age_sec(stats: dict | None) -> float | None:
    if not stats:
        return None
    updated = float(stats.get("updated_at") or 0)
    if updated <= 0:
        return None
    return max(0.0, time.time() - updated)


def _format_stats_age(age_sec: float | None) -> str:
    if age_sec is None:
        return "未知"
    if age_sec < 90:
        return f"{age_sec:.0f} 秒前"
    if age_sec < 3600:
        return f"{age_sec / 60:.0f} 分钟前"
    if age_sec < 86400:
        return f"{age_sec / 3600:.1f} 小时前"
    return f"{age_sec / 86400:.1f} 天前"


def reconcile_scan_stats() -> None:
    stats = _read_stats_raw()
    if not stats or stats.get("status") != "running":
        return
    age = _stats_age_sec(stats)
    pid = stats.get("pid")
    alive = isinstance(pid, int) and pid > 0 and _pid_alive(pid)
    if not alive and PID_PATH.is_file():
        try:
            file_pid = int(PID_PATH.read_text(encoding="utf-8").strip())
            alive = _pid_alive(file_pid)
        except ValueError:
            alive = False
    extant = {
        p for p in discover_collider_pids(ROOT) if p > 0 and _pid_alive(p)
    }
    stale_limit = max(STATS_STALE_SEC * 15, 120)
    if age is not None and age > stale_limit:
        payload = {
            **stats,
            "status": "stopped",
            "message": "统计长时间未更新（进程可能已退出或卡住）",
        }
        STATS_PATH.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        with suppress(OSError):
            PID_PATH.unlink(missing_ok=True)
        return
    if alive or extant:
        return
    payload = {**stats, "status": "stopped", "message": "进程已退出"}
    STATS_PATH.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    with suppress(OSError):
        PID_PATH.unlink(missing_ok=True)


def read_stats() -> dict | None:
    reconcile_scan_stats()
    return _read_stats_raw()


def total_tried_count(stats: dict | None) -> int:
    bootstrap_lifetime_from_stats(LIFETIME_PATH, STATS_PATH)
    if stats and stats.get("total_tried") is not None:
        return int(stats["total_tried"])
    lifetime = read_lifetime_total(LIFETIME_PATH)
    session = int(stats.get("tried") or 0) if stats else 0
    return max(lifetime, session)


def format_count_full(n: int) -> str:
    return f"{max(0, int(n)):,}"


def format_count_compact(n: int) -> str:
    n = max(0, int(n))
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.3f} B"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f} M"
    if n >= 10_000:
        return f"{n / 1_000:.1f} K"
    return format_count_full(n)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        kernel32 = ctypes.windll.kernel32
        SYNCHRONIZE = 0x00100000
        handle = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
        if not handle:
            return False
        kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def is_scan_active(stats: dict | None, proc: subprocess.Popen | None) -> bool:
    if proc is not None and proc.poll() is None:
        return True
    if not stats or stats.get("status") != "running":
        return False
    age = _stats_age_sec(stats)
    if age is not None and age > max(STATS_STALE_SEC * 15, 120):
        return False
    if _collect_scan_pids():
        return True
    pid = stats.get("pid")
    if isinstance(pid, int) and pid > 0:
        return _pid_alive(pid)
    if PID_PATH.is_file():
        with suppress(ValueError):
            file_pid = int(PID_PATH.read_text(encoding="utf-8").strip())
            return _pid_alive(file_pid)
    return False


def _read_mnemonic_stats_raw() -> dict | None:
    if not MNEMONIC_STATS_PATH.is_file():
        return None
    try:
        return json.loads(MNEMONIC_STATS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def reconcile_mnemonic_stats() -> None:
    stats = _read_mnemonic_stats_raw()
    if not stats or stats.get("status") != "running":
        return
    age = _stats_age_sec(stats)
    pid = stats.get("pid")
    alive = isinstance(pid, int) and pid > 0 and _pid_alive(pid)
    extant = {
        p for p in discover_mnemonic_collider_pids(ROOT) if p > 0 and _pid_alive(p)
    }
    stale_limit = max(STATS_STALE_SEC * 15, 120)
    if age is not None and age > stale_limit:
        payload = {
            **stats,
            "status": "stopped",
            "message": "统计长时间未更新（进程可能已退出或卡住）",
        }
        MNEMONIC_STATS_PATH.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        with suppress(OSError):
            MNEMONIC_PID_PATH.unlink(missing_ok=True)
        return
    if alive or extant:
        return
    payload = {**stats, "status": "stopped", "message": "进程已退出"}
    MNEMONIC_STATS_PATH.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    with suppress(OSError):
        MNEMONIC_PID_PATH.unlink(missing_ok=True)


def read_mnemonic_stats() -> dict | None:
    reconcile_mnemonic_stats()
    return _read_mnemonic_stats_raw()


def total_mnemonic_tried_count(stats: dict | None) -> int:
    bootstrap_lifetime_from_stats(MNEMONIC_LIFETIME_PATH, MNEMONIC_STATS_PATH)
    if stats and stats.get("total_tried") is not None:
        return int(stats["total_tried"])
    lifetime = read_lifetime_total(MNEMONIC_LIFETIME_PATH)
    session = int(stats.get("tried") or 0) if stats else 0
    return max(lifetime, session)


def discover_live_mnemonic_pids() -> set[int]:
    return {p for p in discover_mnemonic_collider_pids(ROOT) if p > 0 and _pid_alive(p)}


def is_mnemonic_scan_active(
    stats: dict | None, proc: subprocess.Popen | None
) -> bool:
    if proc is not None and proc.poll() is None:
        return True
    if not stats or stats.get("status") != "running":
        return False
    age = _stats_age_sec(stats)
    if age is not None and age > max(STATS_STALE_SEC * 15, 120):
        return False
    if discover_live_mnemonic_pids():
        return True
    pid = stats.get("pid")
    if isinstance(pid, int) and pid > 0:
        return _pid_alive(pid)
    if MNEMONIC_PID_PATH.is_file():
        with suppress(ValueError):
            file_pid = int(MNEMONIC_PID_PATH.read_text(encoding="utf-8").strip())
            return _pid_alive(file_pid)
    return False


def signal_stop_mnemonic_scan(*, force_kill: bool = False) -> set[int]:
    MNEMONIC_STOP_PATH.parent.mkdir(parents=True, exist_ok=True)
    MNEMONIC_STOP_PATH.write_text("stop", encoding="utf-8")
    killed: set[int] = set()
    if force_kill:
        for pid in discover_live_mnemonic_pids():
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True,
                    timeout=30,
                )
            else:
                with suppress(OSError):
                    os.kill(pid, 9)
            killed.add(pid)
    stats = _read_mnemonic_stats_raw()
    if stats:
        payload = {
            **stats,
            "status": "stopped",
            "message": "已强制结束" if force_kill and killed else "已发送停止信号",
        }
        MNEMONIC_STATS_PATH.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    with suppress(OSError):
        MNEMONIC_PID_PATH.unlink(missing_ok=True)
    return killed


def render_mnemonic_scan_metrics() -> None:
    stats = read_mnemonic_stats()
    tried = int(stats.get("tried") or 0) if stats else 0
    total = total_mnemonic_tried_count(stats)
    rate = float(stats.get("rate_per_sec") or 0) if stats else 0.0
    st.markdown("**累计总尝试**（`data/mnemonic_scan_lifetime.json`）")
    st.markdown(f"### `{format_count_full(total)}`")
    st.caption(
        f"约 **{format_count_compact(total)}** · "
        "清空 **scan.log** 不会改累计；仅删除 lifetime 文件或新进程读不到旧文件时会从 0 累加。"
    )
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric(
        "本次已尝试",
        format_count_compact(tried),
        help=format_count_full(tried),
    )
    m2.metric("速度", f"{rate:,.1f}/s")
    m3.metric("精确命中", f"{int(stats.get('exact_hits') or 0):,}" if stats else "0")
    m4.metric("布隆疑似", f"{int(stats.get('bloom_hits') or 0):,}" if stats else "0")
    m5.metric("布隆假阳", f"{int(stats.get('bloom_fp') or 0):,}" if stats else "0")
    if stats:
        age = _stats_age_sec(stats)
        running = stats.get("status") == "running"
        st.caption(
            f"状态: **{stats.get('status', '?')}** · 统计 **{_format_stats_age(age)}** · "
            f"{stats.get('words', '?')} 词 · `{stats.get('derivation_path', '')}`"
        )
        if not running:
            st.warning("未在运行或已停止；数字为历史快照。点 **开始** 继续累加累计总尝试。")


def render_mnemonic_metrics_and_log() -> None:
    render_mnemonic_scan_metrics()
    log_busy = is_log_busy()
    log_head, log_clear = st.columns([5, 1])
    with log_head:
        st.subheader("运行日志")
    with log_clear:
        if st.button(
            "清空日志",
            key="clear_mnemonic_log_btn",
            disabled=log_busy,
            help="须先停止私钥/助记词碰撞及下载/Bloom 任务；运行中清空会导致日志异常",
        ):
            clear_scan_log_file()
            st.toast("已清空 scan.log")
            st.rerun()
    st.caption(
        f"共用 `{LOG_PATH.name}`（约 **{log_file_summary()}**），仅显示 `mn_try=` 进度行（最新在上）。"
        + (" · **有任务运行中，请先停止再清空**" if log_busy else "")
    )
    raw = tail_log(80, newest_first=True)
    mn_lines = [ln for ln in raw.splitlines() if ln.lstrip().startswith("mn_try=")]
    st.code("\n".join(mn_lines[:20]) or "(暂无助记词进度行)", language="text")


def detect_orphan_scan_pids() -> set[int]:
    """collider 进程仍在，但 stats 已 stopped 或长期不刷新。"""
    stats = _read_stats_raw()
    pids = discover_live_collider_pids()
    if not pids:
        return set()
    if stats and stats.get("status") == "running":
        age = _stats_age_sec(stats)
        if age is None or age <= max(STATS_STALE_SEC * 15, 120):
            return set()
    return pids


def _read_balance_stats_raw() -> dict | None:
    if not BALANCE_STATS_PATH.is_file():
        return None
    try:
        return json.loads(BALANCE_STATS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def reconcile_balance_stats() -> None:
    stats = _read_balance_stats_raw()
    if not stats or stats.get("status") != "running":
        return
    age = _stats_age_sec(stats)
    pid = stats.get("pid")
    alive = isinstance(pid, int) and pid > 0 and _pid_alive(pid)
    extant = {
        p for p in discover_balance_scan_pids(ROOT) if p > 0 and _pid_alive(p)
    }
    stale_limit = max(STATS_STALE_SEC * 15, 120)
    if age is not None and age > stale_limit:
        payload = {
            **stats,
            "status": "stopped",
            "message": "统计长时间未更新（进程可能已退出或卡住）",
        }
        BALANCE_STATS_PATH.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        with suppress(OSError):
            BALANCE_PID_PATH.unlink(missing_ok=True)
        return
    if alive or extant:
        return
    payload = {**stats, "status": "stopped", "message": "进程已退出"}
    BALANCE_STATS_PATH.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    with suppress(OSError):
        BALANCE_PID_PATH.unlink(missing_ok=True)


def read_balance_stats() -> dict | None:
    reconcile_balance_stats()
    return _read_balance_stats_raw()


def total_balance_tried_count(stats: dict | None) -> int:
    bootstrap_lifetime_from_stats(BALANCE_LIFETIME_PATH, BALANCE_STATS_PATH)
    if stats and stats.get("total_tried") is not None:
        return int(stats["total_tried"])
    lifetime = read_lifetime_total(BALANCE_LIFETIME_PATH)
    session = int(stats.get("tried") or 0) if stats else 0
    return max(lifetime, session)


def discover_live_balance_pids() -> set[int]:
    return {p for p in discover_balance_scan_pids(ROOT) if p > 0 and _pid_alive(p)}


def is_balance_scan_active(
    stats: dict | None, proc: subprocess.Popen | None
) -> bool:
    if proc is not None and proc.poll() is None:
        return True
    if not stats or stats.get("status") != "running":
        return False
    age = _stats_age_sec(stats)
    if age is not None and age > max(STATS_STALE_SEC * 15, 120):
        return False
    if discover_live_balance_pids():
        return True
    pid = stats.get("pid")
    if isinstance(pid, int) and pid > 0:
        return _pid_alive(pid)
    if BALANCE_PID_PATH.is_file():
        with suppress(ValueError):
            file_pid = int(BALANCE_PID_PATH.read_text(encoding="utf-8").strip())
            return _pid_alive(file_pid)
    return False


def signal_stop_balance_scan(*, force_kill: bool = False) -> set[int]:
    BALANCE_STOP_PATH.parent.mkdir(parents=True, exist_ok=True)
    BALANCE_STOP_PATH.write_text("stop", encoding="utf-8")
    killed: set[int] = set()
    if force_kill:
        for pid in discover_live_balance_pids():
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True,
                    timeout=30,
                )
            else:
                with suppress(OSError):
                    os.kill(pid, 9)
            killed.add(pid)
    stats = _read_balance_stats_raw()
    if stats:
        payload = {
            **stats,
            "status": "stopped",
            "message": "已强制结束" if force_kill and killed else "已发送停止信号",
        }
        BALANCE_STATS_PATH.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    with suppress(OSError):
        BALANCE_PID_PATH.unlink(missing_ok=True)
    return killed


def render_balance_scan_metrics() -> None:
    stats = read_balance_stats()
    tried = int(stats.get("tried") or 0) if stats else 0
    total = total_balance_tried_count(stats)
    rate = float(stats.get("rate_per_sec") or 0) if stats else 0.0
    st.markdown("**累计联网尝试**（`data/balance_scan_lifetime.json`）")
    st.markdown(f"### `{format_count_full(total)}`")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("本次已尝试", format_count_compact(tried), help=format_count_full(tried))
    m2.metric("速度", f"{rate:,.2f}/s")
    m3.metric("有余额命中", f"{int(stats.get('balance_hits') or 0):,}" if stats else "0")
    m4.metric(
        "网络错误",
        f"{int(stats.get('network_errors') or 0):,}" if stats else "0",
    )
    if stats:
        st.caption(
            f"状态: **{stats.get('status', '?')}** · "
            f"后端 **{stats.get('backend', '?')}** · "
            f"资产 **{stats.get('asset', '?')}** · "
            f"429={int(stats.get('rate_limited') or 0):,}"
        )


def render_balance_metrics_and_log() -> None:
    render_balance_scan_metrics()
    st.subheader("运行日志")
    st.caption(
        f"共用 `{LOG_PATH.name}`，仅显示 `bal_try=` 进度行（最新在上）。"
    )
    raw = tail_log(80, newest_first=True)
    bal_lines = [ln for ln in raw.splitlines() if ln.lstrip().startswith("bal_try=")]
    st.code("\n".join(bal_lines[:20]) or "(暂无联网查余额进度行)", language="text")
    hits = _read_jsonl_tail(BALANCE_HITS_PATH, 5)
    if hits:
        st.subheader("最近有余额记录")
        st.dataframe(
            [
                {
                    "address": h.get("address"),
                    "trx": h.get("trx"),
                    "usdt": h.get("usdt_balance"),
                    "time": h.get("ts"),
                }
                for h in hits
            ],
            use_container_width=True,
            hide_index=True,
        )


def is_log_busy() -> bool:
    """scan.log 被下载 / Bloom / 扫描子进程占用写入时为 True。"""
    if is_scan_active(_read_stats_raw(), st.session_state.get("scan_proc")):
        return True
    if is_mnemonic_scan_active(
        _read_mnemonic_stats_raw(), st.session_state.get("mn_scan_proc")
    ):
        return True
    if is_balance_scan_active(
        _read_balance_stats_raw(), st.session_state.get("balance_scan_proc")
    ):
        return True
    if is_download_active():
        return True
    if is_bloom_build_active():
        return True
    job = st.session_state.get("job_proc")
    return job is not None and job.poll() is None


def clear_scan_log_file() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.write_text("", encoding="utf-8")


def _read_jsonl_tail(path: Path, limit: int) -> list[dict]:
    if not path.is_file() or limit <= 0:
        return []
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    out: list[dict] = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(out))


def read_hits(limit: int = 50) -> list[dict]:
    return _read_jsonl_tail(HITS_PATH, limit)


def read_merged_hits(limit: int = 100, source: str = "全部") -> list[dict]:
    """合并私钥 / 助记词 / 联网查余额 hits。"""
    items: list[dict] = []
    if source in ("全部", "私钥碰撞"):
        for rec in _read_jsonl_tail(HITS_PATH, limit):
            items.append({**rec, "hit_source": "私钥碰撞"})
    if source in ("全部", "助记词碰撞"):
        for rec in _read_jsonl_tail(MNEMONIC_HITS_PATH, limit):
            items.append({**rec, "hit_source": "助记词碰撞"})
    if source in ("全部", "联网查余额"):
        for rec in _read_jsonl_tail(BALANCE_HITS_PATH, limit):
            items.append({**rec, "hit_source": "联网查余额"})
    items.sort(key=lambda r: float(r.get("ts") or 0), reverse=True)
    return items[:limit]


def hits_table_rows(hits: list[dict]) -> list[dict]:
    rows: list[dict] = []
    for h in hits:
        verify = h.get("verify") or {}
        usdt = h.get("usdt_balance")
        if usdt is None and isinstance(verify, dict):
            usdt = verify.get("usdt_balance")
        if usdt is None:
            usdt = h.get("csv_balance_usdt")
        rows.append(
            {
                "来源": h.get("hit_source"),
                "match_kind": h.get("match_kind"),
                "address": h.get("address"),
                "mnemonic": h.get("mnemonic") or "",
                "derivation_path": h.get("derivation_path") or "",
                "private_key_hex": h.get("private_key_hex"),
                "trx": h.get("trx"),
                "usdt_balance": usdt,
                "csv_balance_usdt": h.get("csv_balance_usdt"),
                "time": h.get("ts"),
            }
        )
    return rows


def log_file_summary() -> str:
    if not LOG_PATH.is_file():
        return "暂无"
    size = LOG_PATH.stat().st_size
    if size >= 1_048_576:
        return f"{size / 1_048_576:.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def _decode_log_line(raw: bytes) -> str:
    if not raw:
        return ""
    try:
        text = raw.decode("utf-8")
        if "\ufffd" not in text:
            return text
    except UnicodeDecodeError:
        pass
    return raw.decode("gbk", errors="replace")


def tail_log(max_lines: int = 80, *, newest_first: bool = True) -> str:
    if not LOG_PATH.is_file():
        return ""
    chunk = 65536
    data = b""
    with LOG_PATH.open("rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        while pos > 0 and data.count(b"\n") <= max_lines + 2:
            read_size = min(chunk, pos)
            pos -= read_size
            f.seek(pos)
            data = f.read(read_size) + data
    lines = [_decode_log_line(line) for line in data.splitlines()]
    lines = lines[-max_lines:]
    if newest_first:
        lines.reverse()
    return "\n".join(lines)


def render_scan_metrics_compact(stats: dict | None) -> None:
    if not stats:
        st.caption("暂无私钥碰撞统计")
        return
    tried = int(stats.get("tried") or 0)
    total = total_tried_count(stats)
    rate = float(stats.get("rate_per_sec") or 0)
    exact = int(stats.get("exact_hits") or 0)
    updated = float(stats.get("updated_at") or 0)
    age = time.time() - updated if updated else 999.0
    st.caption("累计总尝试")
    st.markdown(f"`{format_count_full(total)}`")
    c1, c2 = st.columns(2)
    c1.metric("本次", format_count_compact(tried), help=format_count_full(tried))
    c2.metric("速度", f"{rate:,.0f}/s")
    st.caption(
        f"**{stats.get('status', '?')}** · 精确 {exact:,} · "
        f"统计 {age:.0f}s 前更新"
    )


def render_scan_metrics_and_log() -> None:
    stats = read_stats()
    tried = int(stats.get("tried", 0) if stats else 0)
    total = total_tried_count(stats)
    rate = stats.get("rate_per_sec", 0) if stats else 0
    exact = stats.get("exact_hits", 0) if stats else 0
    bloom_hits = stats.get("bloom_hits", 0) if stats else 0
    bloom_fp = stats.get("bloom_fp", 0) if stats else 0
    st.markdown("**累计总尝试**（历次私钥碰撞，见 `data/scan_lifetime.json`）")
    st.markdown(f"### `{format_count_full(total)}`")
    st.caption(f"约 **{format_count_compact(total)}** · 悬停下方「本次」可看本次完整数字")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric(
        "本次已尝试",
        format_count_compact(tried),
        help=f"当前会话：{format_count_full(tried)}",
    )
    m2.metric("速度", f"{rate:,.0f}/s")
    m3.metric(
        "精确命中",
        f"{exact:,}",
        help="随机地址真的落在 Top1万 CSV 里（极罕见；>0 才表示可能撞库成功）",
    )
    m4.metric(
        "布隆疑似",
        f"{bloom_hits:,}",
        help="布隆过滤器认为「可能在 Top1万」的次数，包含误报",
    )
    m5.metric(
        "布隆假阳",
        f"{bloom_fp:,}",
        help="布隆疑似后经 CSV 核对，确认不在 Top1万 的次数（默认不联网）",
    )
    if stats:
        age = _stats_age_sec(stats)
        age_note = _format_stats_age(age)
        running = stats.get("status") == "running"
        stale = age is not None and age > max(STATS_STALE_SEC * 3, 30)
        st.caption(
            f"状态: **{stats.get('status', '?')}** · 统计更新 **{age_note}** · "
            f"联网验证 {stats.get('network_ok', 0):,} 次 · "
            f"运行 {stats.get('elapsed_sec', 0)}s"
        )
        if not running or stale:
            st.warning(
                "私钥碰撞 **未在运行** 或 **统计已停更**，上方数字为 **历史快照**，不会继续增加。"
                "请点 **「开始」** 重新跑；若仍无速度，看下方日志是否在刷 `try=` 行。"
            )
    log_head, log_clear = st.columns([5, 1])
    with log_head:
        st.subheader("运行日志")
    with log_clear:
        log_busy = is_log_busy()
        if st.button(
            "清空日志",
            key="clear_scan_log_btn",
            disabled=log_busy,
            help="须先停止私钥/助记词碰撞及下载/Bloom 任务；运行中清空会导致日志异常",
        ):
            clear_scan_log_file()
            st.toast("已清空 scan.log")
            st.rerun()
    st.caption(
        f"`{LOG_PATH.name}` 约 **{log_file_summary()}**（下载 / Bloom / 碰撞共用；"
        "下方 **最新在上**；私钥碰撞约每 2 秒一行 `try=` 进度）"
        + (" · **有任务运行中，请先停止再清空**" if log_busy else "")
        + (
            ""
            if log_busy
            else " · **无后台任务时不自动刷新日志**（点「立即刷新」或切页可更新）"
        )
    )
    st.code(tail_log(20) or "(暂无日志)", language="text")


def _scan_sidebar_should_show() -> bool:
    stats = read_stats()
    if not stats:
        return False
    if discover_live_collider_pids():
        return True
    pid = stats.get("pid")
    running_file = stats.get("status") == "running"
    alive = isinstance(pid, int) and pid > 0 and _pid_alive(pid)
    return bool(running_file and alive)


def scan_live_panel() -> None:
    """有后台任务写 scan.log 时才自动刷新，避免日志区一闪一闪。"""
    if hasattr(st, "fragment") and is_log_busy():
        _scan_live_poll()
    else:
        render_scan_metrics_and_log()


def mnemonic_live_panel() -> None:
    if hasattr(st, "fragment") and is_log_busy():
        _mnemonic_live_poll()
    else:
        render_mnemonic_metrics_and_log()


def scan_sidebar_live() -> None:
    if not _scan_sidebar_should_show():
        return
    if hasattr(st, "fragment"):
        _scan_sidebar_poll()
    else:
        stats = read_stats()
        if stats:
            st.subheader("私钥碰撞实时")
            render_scan_metrics_compact(stats)


if hasattr(st, "fragment"):

    @st.fragment(run_every=timedelta(seconds=2))
    def _scan_live_poll() -> None:
        render_scan_metrics_and_log()

    @st.fragment(run_every=timedelta(seconds=2))
    def _mnemonic_live_poll() -> None:
        render_mnemonic_metrics_and_log()

    @st.fragment(run_every=timedelta(seconds=2))
    def _scan_sidebar_poll() -> None:
        stats = read_stats()
        if not stats:
            return
        st.subheader("私钥碰撞实时")
        render_scan_metrics_compact(stats)
        pid = stats.get("pid")
        running_file = stats.get("status") == "running"
        alive = isinstance(pid, int) and pid > 0 and _pid_alive(pid)
        if running_file and not alive:
            st.warning("状态为 running 但进程不存在，请点「刷新」或重新开始。")

    @st.fragment(run_every=timedelta(seconds=2))
    def _balance_live_poll() -> None:
        render_balance_metrics_and_log()


@st.cache_data(show_spinner=False)
def load_exact_address_set(csv_path: str) -> frozenset[str]:
    path = Path(csv_path)
    if not path.is_file():
        return frozenset()
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return frozenset(
            (row.get("address") or "").strip()
            for row in reader
            if (row.get("address") or "").strip()
        )


def classify_top10k_address(address: str) -> str:
    """
    返回: error | not_in_set | bloom_false_positive | in_set

    对当前扫描 CSV 精确表：在就在、不在就不在。
    布隆仅用于扫描加速；快测以 CSV 精确集为准。
    """
    from bloom import BloomFilter, tron_address_key

    addr = address.strip()
    if not addr:
        return "error"
    bloom_path, csv_path = resolve_scan_paths()
    if not bloom_path.is_file() or not csv_path.is_file():
        return "error"
    exact = load_exact_address_set(str(csv_path))
    if addr in exact:
        return "in_set"
    bf = BloomFilter.load(bloom_path)
    if tron_address_key(addr) in bf:
        return "bloom_false_positive"
    return "not_in_set"


st.set_page_config(page_title="TRON Collider", layout="wide", initial_sidebar_state="expanded")
ensure_runtime_files()

st.title("TRON Collider 控制台")
st.caption(
    "TronGrid Top20万 / **独立 Top30万** USDT CSV → Bloom → 私钥/助记词碰撞 / 按需联网"
)

with st.sidebar:
    st.subheader("API Key")
    _keys = api_key_status()
    _tg_ok, _tg_var = _keys["trongrid"]
    _ts_ok, _ts_var = _keys["tronscan"]
    st.markdown(
        f"**TronGrid**（20 万下载）: {render_api_key_badge(_tg_ok)}"
        + (f" · `{_tg_var}`" if _tg_var else "")
    )
    st.markdown(
        f"**TronScan**（1 万下载）: {render_api_key_badge(_ts_ok)}"
        + (f" · `{_ts_var}`" if _ts_var else "")
    )
    if (ROOT / ".env").is_file():
        st.caption("配置来源：项目根目录 `.env`（由 launch_ui 加载）")
    else:
        st.caption("未找到 `.env`，可使用系统环境变量或复制 `.env.example`。")
    if st.button("刷新 API / 文件状态", use_container_width=True):
        load_local_env(ROOT)
        st.rerun()

    st.divider()
    st.subheader("碰撞数据（当前使用）")
    _sb, _sc = scan_path_defaults()
    if "scan_bloom" in st.session_state:
        _sb = str(st.session_state.scan_bloom)
    if "scan_csv" in st.session_state:
        _sc = str(st.session_state.scan_csv)
    st.markdown(f"**Bloom** `{Path(_sb).name}`: {file_badge(ROOT / _sb)}")
    st.markdown(f"**CSV** `{Path(_sc).name}`: {file_badge(ROOT / _sc)}")
    st.caption("默认 **20 万** CSV/Bloom；**私钥碰撞** 页可改路径。")

    st.divider()
    st.subheader("Top20万 CSV")
    render_csv_exact_count_line(
        TOP200K_CSV_PATH,
        target=TOP200K_TARGET,
        label="usdt_top200000.csv",
        bloom_path=BLOOM_PATH,
    )
    st.subheader("Top30万 CSV（独立文件）")
    render_csv_exact_count_line(
        TOP300K_CSV_PATH,
        target=TOP300K_TARGET,
        label="usdt_top300000.csv",
        bloom_path=TOP300K_BLOOM_PATH,
    )

    st.divider()
    st.subheader("其它文件")
    st.markdown(f"**Hits** `{HITS_PATH.name}`: {file_badge(HITS_PATH, optional_empty=True)}")

    scan_sidebar_live()

tab_data, tab_scan, tab_hits, tab_tools, tab_pubkey, tab_mnemonic, tab_balance = st.tabs(
    [
        "数据准备",
        "私钥碰撞",
        "命中记录",
        "工具",
        "公钥恢复",
        "助记词碰撞",
        "联网查余额",
    ]
)

with tab_data:
    st.subheader("下载进度")
    _bg_jobs, _bg_busy = summarize_background_jobs()
    if _bg_busy:
        st.success(f"**后台子进程：** {' · '.join(_bg_jobs)}")
    else:
        st.info(
            "**后台子进程：** 无（TronGrid / Bloom / 碰撞均已停）。"
            "浏览器右上角 **Running…** 是 Streamlit **自动刷新界面**（约每 1～2 秒），"
            "**不是** 下载还在跑；以下以 **stopped / running** 为准。"
        )
    dl_active = is_download_active()
    _dl_head, _dl_stop = st.columns([3, 1])
    with _dl_stop:
        if st.button(
            "停止下载",
            disabled=not dl_active,
            type="primary" if dl_active else "secondary",
            key="stop_download_btn",
        ):
            request_stop_download()
            st.toast("已发送停止信号")
            st.rerun()
    download_progress_ui()

    st.subheader("Top20万 / Top30万 地址表")
    csv_count_panel_ui(
        TOP200K_CSV_PATH,
        target=TOP200K_TARGET,
        label="data/usdt_top200000.csv",
        bloom_path=BLOOM_PATH,
        live_panel=top200k_count_panel,
    )
    csv_count_panel_ui(
        TOP300K_CSV_PATH,
        target=TOP300K_TARGET,
        label="data/usdt_top300000.csv",
        bloom_path=TOP300K_BLOOM_PATH,
        live_panel=top300k_count_panel,
    )
    st.caption(
        "两套 **独立** CSV/Bloom；**下载进行中** 时条数约每 2 秒刷新，"
        "**完成后** 改为静态显示，避免整页一闪一闪。"
    )

    st.subheader("1a. TronGrid 下载 USDT 持有人")
    _tab_keys = api_key_status()
    _tab_tg_ok = _tab_keys["trongrid"][0]
    if _tab_tg_ok:
        st.success("TronGrid API Key 已配置，限流通常更轻。")
    else:
        st.warning(
            "TronGrid API Key **未配置**：易 429 限流。"
            "请在 `.env` 中设置 `TRONGRID_API_KEY` 后重启 UI（见左侧栏状态）。"
        )
    st.write(
        "突破 TronScan 1 万限制：`/v1/contracts/USDT/tokens` 分页。"
        "约 500 次请求。"
    )
    _tg_prefs = load_ui_prefs()
    if "tg_max" not in st.session_state:
        st.session_state.tg_max = int(
            _tg_prefs.get("tg_max", TOP300K_TARGET)
        )
    if "tg_delay" not in st.session_state:
        st.session_state.tg_delay = float(_tg_prefs.get("tg_delay", 0.15))
    if "tg_out" not in st.session_state:
        st.session_state.tg_out = normalize_tg_output(str(_tg_prefs.get("tg_out", "")))
    st.session_state.tg_out = normalize_tg_output(str(st.session_state.tg_out))

    tp1, tp2 = st.columns(2)
    with tp1:
        if st.button(
            "下载目标：Top20万（usdt_top200000.csv）",
            use_container_width=True,
            key="tg_preset_200k",
        ):
            apply_tg_download_preset("200k")
            st.rerun()
    with tp2:
        if st.button(
            "下载目标：Top30万（usdt_top300000.csv）",
            type="primary",
            use_container_width=True,
            key="tg_preset_300k",
        ):
            apply_tg_download_preset("300k")
            st.rerun()

    g1, g2, g3 = st.columns(3)
    with g1:
        tg_max = st.number_input(
            "导出数量",
            min_value=1000,
            max_value=500_000,
            step=1000,
            key="tg_max",
            help="与输出 CSV 配套：20万文件用 200000，30万独立文件用 300000",
        )
    with g2:
        tg_delay = st.slider(
            "TronGrid 间隔 (秒)",
            min_value=0.05,
            max_value=0.5,
            step=0.05,
            key="tg_delay",
        )
    with g3:
        tg_out = st.text_input(
            "输出 CSV",
            key="tg_out",
            placeholder=DEFAULT_CSV_REL,
            help="留空默认 Top20万 路径；30万请点上方按钮或填 data/usdt_top300000.csv",
        )
    tg_out = normalize_tg_output(str(st.session_state.tg_out))

    save_ui_prefs(
        tg_delay=float(tg_delay),
        tg_max=int(tg_max),
        tg_out=tg_out,
    )
    st.caption(
        f"分页间隔 **{float(tg_delay):.2f}s** 会作为 `--delay` 传给下载进程；"
        f"已保存到 `{UI_PREFS_PATH.relative_to(ROOT)}`，刷新页面后仍保留。"
    )

    _tg_out_path = (ROOT / tg_out).resolve()
    _tg_fmt = "json" if _tg_out_path.suffix.lower() == ".json" else "csv"
    _tg_max = int(tg_max)
    _tg_target_hint = csv_target_for_path(_tg_out_path)
    if _tg_fmt == "csv" and _tg_target_hint:
        _tg_bloom = (
            TOP300K_BLOOM_PATH
            if _tg_target_hint == TOP300K_TARGET
            else BLOOM_PATH
            if _tg_target_hint == TOP200K_TARGET
            else None
        )
        render_csv_exact_count_line(
            _tg_out_path,
            target=_tg_target_hint,
            label=f"当前输出 ({_tg_out_path.name})",
            bloom_path=_tg_bloom,
        )
    elif _tg_fmt == "csv" and _tg_out_path.is_file():
        _n_out = cached_csv_address_count(str(_tg_out_path))
        st.caption(f"当前输出文件精确地址：**{_n_out:,}** / {_tg_max:,}")
    _tg_resume_state = find_resume_state(
        _tg_out_path,
        _tg_fmt,
        max_holders=_tg_max,
        min_balance_usdt=0.0,
        progress_path=DOWNLOAD_PROGRESS_PATH,
    )
    _tg_partial = partial_download_count(
        _tg_out_path, _tg_fmt, max_holders=_tg_max
    )
    tg_can_resume = can_continue_download(
        _tg_out_path,
        _tg_fmt,
        max_holders=_tg_max,
        progress_path=DOWNLOAD_PROGRESS_PATH,
    )
    tg_job_busy = is_download_active()

    if _tg_resume_state:
        _tg_rows, _, _tg_page = _tg_resume_state
        st.caption(
            f"可继续下载：**{len(_tg_rows):,}** / {_tg_max:,} 条"
            f"（已完成第 {_tg_page} 页）"
        )
    elif _tg_partial is not None:
        st.caption(
            f"本地 CSV 已有 **{_tg_partial:,}** / {_tg_max:,} 条。"
            f"**继续下载** 会先按链上顺序 **跳过** 这 {_tg_partial:,} 条（约 500 页，不写新行），"
            f"之后 **每拉一页立刻写入 CSV**（最多 +200 条/页）。"
            f"若 CSV 与链上排序不一致会报错，请用 **重新下载**。"
        )
    elif _tg_out_path.is_file() and _tg_out_path.stat().st_size > 0:
        st.caption(
            "有 CSV 但条数已达导出上限，或路径/数量与上次不一致。"
            "请调整 **导出数量** / 输出路径，或使用 **重新下载**。"
        )
    else:
        st.caption("暂无未完成进度；首次请点 **重新下载**。")

    if tg_job_busy:
        st.warning("检测到 **下载进程仍在运行**，请先点上方 **停止下载**；否则「继续/重新下载」按钮不可用。")
    if is_scan_active(_read_stats_raw(), st.session_state.get("scan_proc")) or is_mnemonic_scan_active(
        _read_mnemonic_stats_raw(), st.session_state.get("mn_scan_proc")
    ):
        st.warning(
            "私钥或助记词碰撞在跑时，Windows 可能 **锁 CSV** 导致下载写盘失败。"
            "建议先 **停止碰撞**，并关闭用 Excel 打开的 CSV。"
        )
    tg_btn_cont, tg_btn_fresh = st.columns(2)
    with tg_btn_cont:
        if st.button(
            "继续下载",
            disabled=tg_job_busy or not tg_can_resume,
            use_container_width=True,
            key="tg_btn_continue",
        ):
            ok = start_trongrid_download(
                max_holders=int(tg_max),
                output=tg_out,
                delay_sec=tg_delay,
                resume=True,
            )
            if ok:
                st.toast("TronGrid 续传已启动")
            st.rerun()
    with tg_btn_fresh:
        if st.button(
            "重新下载",
            type="primary",
            disabled=tg_job_busy,
            use_container_width=True,
            key="tg_btn_fresh",
        ):
            ok = start_trongrid_download(
                max_holders=int(tg_max),
                output=tg_out,
                delay_sec=tg_delay,
                resume=False,
            )
            if ok:
                st.toast("TronGrid 已从头下载（会清空断点并重写 CSV）")
            st.rerun()

    st.divider()
    st.subheader("1b. TronScan Top 1 万（旧）")
    _tab_ts_ok = api_key_status()["tronscan"][0]
    if _tab_ts_ok:
        st.success("TronScan API Key 已配置。")
    else:
        st.info("TronScan API Key 未配置（可选）；可在 `.env` 设置 `TRONSCAN_API_KEY`。")
    st.write("从 TronScan 拉取持有人列表（约 3～5 分钟，受 API 限流影响）。")
    c1, c2 = st.columns(2)
    with c1:
        dl_delay = st.slider("请求间隔 (秒)", 0.2, 1.0, 0.45, 0.05)
    with c2:
        dl_out = st.text_input(
            "输出 CSV", value=str(TRONSCAN_CSV_PATH.relative_to(ROOT))
        )

    if st.button("开始下载", type="primary", disabled=st.session_state.get("busy", False)):
        if is_download_active():
            request_stop_download()
            time.sleep(0.5)
        if _collect_download_pids():
            st.error("仍有下载进程在运行，请先停止后再开始。")
        else:
            STOP_DOWNLOAD_PATH.unlink(missing_ok=True)
            st.session_state.busy = True
            rel = Path(dl_out)
            proc = run_script(
                [
                    str(ROOT / "download_balanced_addresses.py"),
                    "--asset",
                    "usdt",
                    "--min-balance-usdt",
                    "0",
                    "-o",
                    str(rel),
                    "--delay",
                    str(dl_delay),
                    "--progress-file",
                    str(DOWNLOAD_PROGRESS_PATH.relative_to(ROOT)),
                    "--stop-file",
                    str(STOP_DOWNLOAD_PATH.resolve()),
                ],
                LOG_PATH,
            )
            st.session_state.job_proc = proc
            st.session_state.job_name = "download"
            if proc.pid:
                DOWNLOAD_PID_PATH.write_text(str(proc.pid), encoding="utf-8")
            st.info("下载已在后台运行，可在「私钥碰撞」页查看日志尾部。")

    st.divider()
    st.subheader("2. 构建布隆过滤器")
    bloom_build_progress_panel()
    if "bloom_in" not in st.session_state:
        st.session_state.bloom_in = DEFAULT_CSV_REL
    if "bloom_out" not in st.session_state:
        st.session_state.bloom_out = DEFAULT_BLOOM_REL
    bp1, bp2 = st.columns(2)
    with bp1:
        st.button(
            "20万 Bloom",
            use_container_width=True,
            key="bloom_preset_200k",
            on_click=_bloom_preset_200k,
        )
    with bp2:
        st.button(
            "30万 Bloom",
            use_container_width=True,
            key="bloom_preset_300k",
            on_click=_bloom_preset_300k,
        )
    b1, b2 = st.columns(2)
    with b1:
        bloom_in = st.text_input("输入 CSV", key="bloom_in")
    with b2:
        bloom_out = st.text_input("输出 Bloom", key="bloom_out")

    bloom_busy = is_bloom_build_active()
    if st.button("构建 Bloom", disabled=st.session_state.get("busy", False) or bloom_busy):
        proc = run_script(
            [
                str(ROOT / "build_bloom_filter.py"),
                "-i",
                bloom_in,
                "-o",
                bloom_out,
                "--progress-file",
                str(BLOOM_PROGRESS_PATH.relative_to(ROOT)),
            ],
            LOG_PATH,
        )
        st.session_state.job_proc = proc
        st.session_state.job_name = "bloom"
        st.session_state.busy = True
        st.info("Bloom 构建已在后台运行，请查看下方进度条与 scan.log。")
        st.rerun()

with tab_scan:
    st.subheader("私钥持续碰撞")
    st.caption(
        "后台 **collider.py** 随机私钥 → TRON 地址 → Bloom/CSV；"
        "累计见 `data/scan_lifetime.json`，命中 `data/hits.jsonl`；日志行以 `try=` 开头。"
    )
    stats_for_controls = read_stats()
    proc: subprocess.Popen | None = st.session_state.get("scan_proc")
    if proc is not None and proc.poll() is not None:
        st.session_state.scan_proc = None
        proc = None
    scan_running = is_scan_active(stats_for_controls, proc)
    collider_pids = discover_live_collider_pids()
    orphan_pids = detect_orphan_scan_pids()
    if orphan_pids:
        op = ", ".join(str(p) for p in sorted(orphan_pids))
        st.warning(
            f"残留 collider（PID {op}），统计已停更；请点下方 **停止** 结束进程后再 **开始**。"
        )

    _def_bloom, _def_csv = scan_path_defaults()
    if "scan_bloom" not in st.session_state:
        st.session_state.scan_bloom = _def_bloom
    if "scan_csv" not in st.session_state:
        st.session_state.scan_csv = _def_csv

    st.subheader("碰撞数据文件")
    sp1, sp2, sp3 = st.columns(3)
    with sp1:
        st.button("20万", use_container_width=True, key="scan_preset_200k", on_click=_scan_preset_200k)
    with sp2:
        st.button("30万", use_container_width=True, key="scan_preset_300k", on_click=_scan_preset_300k)
    with sp3:
        st.button("10万", use_container_width=True, key="scan_preset_100k", on_click=_scan_preset_100k)
    sc1, sc2 = st.columns(2)
    with sc1:
        st.text_input("Bloom 文件", key="scan_bloom")
    with sc2:
        st.text_input("精确地址 CSV", key="scan_csv")
    save_ui_prefs(
        scan_bloom=str(st.session_state.scan_bloom),
        scan_csv=str(st.session_state.scan_csv),
    )
    scan_bloom_path, scan_csv_path = resolve_scan_paths()
    if not scan_bloom_path.is_file():
        st.warning(f"找不到 Bloom：`{scan_bloom_path.relative_to(ROOT)}`，请先在数据准备页构建。")
    elif not scan_csv_path.is_file():
        st.warning(f"找不到 CSV：`{scan_csv_path.relative_to(ROOT)}`")
    else:
        try:
            _n = cached_csv_address_count(
                str(scan_csv_path.resolve()),
                str(scan_bloom_path.resolve()),
            )
            st.caption(
                f"将使用 **{scan_bloom_path.name}** + **{scan_csv_path.name}**"
                f" · CSV 精确 **{_n:,}** 条地址（去重）"
            )
            _csv_target = csv_target_for_path(scan_csv_path)
            if _csv_target is not None and _n < _csv_target:
                st.warning(
                    f"**{scan_csv_path.name}** 目前 **{_n:,}** 条，目标 **{_csv_target:,}**。"
                    "请到 **数据准备** 选对独立文件并 **继续/重新下载**，满额后 **重建对应 Bloom**。"
                )
            elif _n > 0:
                ok, err = validate_bloom_csv_pair(
                    scan_bloom_path, scan_csv_path, project_root=ROOT
                )
                if not ok:
                    st.warning(f"Bloom 与 CSV：{err}")
        except OSError:
            pass

    st.subheader("参数")
    p1, p2, p3 = st.columns(3)
    with p1:
        workers = st.number_input("Workers", 1, 32, max(1, (__import__("os").cpu_count() or 4) - 1))
        batch_size = st.number_input("Batch size", 500, 20000, 2000, 500)
    with p2:
        max_keys = st.number_input("最大密钥数 (0=不限)", 0, 10_000_000, 0, 10_000)
        stats_iv = st.slider("统计刷新间隔 (秒)", 1.0, 30.0, 2.0)
    with p3:
        network = st.selectbox("联网验证", ["tronscan", "trongrid", "off"])
        on_bloom_net = st.checkbox("布隆疑似即联网（假阳也会打 API，不推荐）", value=False)

    can_stop_scan = scan_running or bool(collider_pids)
    cstart, cstop, crefresh = st.columns([1, 1, 1])
    with cstart:
        bloom_ok, bloom_err = validate_bloom_csv_pair(
            scan_bloom_path, scan_csv_path, project_root=ROOT
        )
        if not bloom_ok and scan_bloom_path.is_file() and scan_csv_path.is_file():
            st.error(f"Bloom 与 CSV 不匹配：{bloom_err}")
        start_disabled = (
            scan_running
            or not scan_bloom_path.is_file()
            or not scan_csv_path.is_file()
            or not bloom_ok
        )
        if start_disabled and not scan_bloom_path.is_file():
            st.warning("请先构建 Bloom 或修正上方 Bloom 路径")
        if collider_pids and not scan_running:
            start_disabled = True
        if st.button("开始", type="primary", disabled=start_disabled, key="pk_start"):
            ok, err = validate_bloom_csv_pair(
                scan_bloom_path, scan_csv_path, project_root=ROOT
            )
            if not ok:
                st.error(err)
            elif discover_live_collider_pids():
                st.error("已有 collider 进程在运行，请先停止。")
            else:
                STOP_PATH.unlink(missing_ok=True)
                cmd = [
                    str(ROOT / "collider.py"),
                    "--bloom",
                    str(scan_bloom_path.relative_to(ROOT)),
                    "--address-csv",
                    str(scan_csv_path.relative_to(ROOT)),
                    "--workers",
                    str(int(workers)),
                    "--batch-size",
                    str(int(batch_size)),
                    "--max-keys",
                    str(int(max_keys)),
                    "--network",
                    network,
                    "--stats-interval",
                    str(stats_iv),
                    "--stats-file",
                    str(STATS_PATH.relative_to(ROOT)),
                    "--stop-file",
                    str(STOP_PATH.relative_to(ROOT)),
                    "--hits-file",
                    str(HITS_PATH.relative_to(ROOT)),
                ]
                if on_bloom_net:
                    cmd.append("--on-bloom-network")
                st.session_state.scan_proc = run_script(cmd, LOG_PATH)
                st.rerun()

    with cstop:
        if st.button(
            "停止",
            disabled=not can_stop_scan,
            type="primary" if can_stop_scan else "secondary",
            key="pk_stop",
            help="正常发 stop.scan；残留 collider 会尝试强制结束",
        ):
            force = bool(collider_pids) and not scan_running
            killed = signal_stop_scan(force_kill=force)
            if force and killed:
                st.toast(f"已结束残留 collider：{', '.join(map(str, sorted(killed)))}")
            else:
                st.toast("已发送停止信号，私钥碰撞将在当前批次结束后退出")
            st.rerun()

    with crefresh:
        if st.button("立即刷新", key="pk_refresh"):
            st.rerun()

    if scan_running and proc is None and stats_for_controls:
        st.caption(
            f"私钥碰撞在后台运行（PID {stats_for_controls.get('pid', '?')}）。"
            "刷新页面后仍可用「停止」；若数字超过 2 分钟不变，请看日志是否还有 `try=`。"
        )
    elif (
        stats_for_controls
        and stats_for_controls.get("status") == "running"
        and not scan_running
    ):
        st.warning(
            "状态文件仍为 running，但进程可能已退出；可再次「开始」或手动删除 data/stop.scan。"
        )

    st.caption("指标约每 1 秒刷新；切到其他标签页时请看左侧栏「私钥碰撞实时」。")
    scan_live_panel()

with tab_hits:
    st.subheader("命中记录")
    st.caption(
        "**私钥** → `hits.jsonl` · **助记词** → `mnemonic_hits.jsonl` · "
        "**联网查余额** → `balance_hits.jsonl`。均含私钥等敏感信息，请勿泄露。"
    )
    hit_source_filter = st.radio(
        "来源筛选",
        ["全部", "私钥碰撞", "助记词碰撞", "联网查余额"],
        horizontal=True,
        key="hits_source_filter",
    )

    @st.fragment(run_every=timedelta(seconds=3))
    def hits_panel() -> None:
        hits = read_merged_hits(100, source=hit_source_filter)
        if not hits:
            st.info("当前筛选下尚无命中（精确命中极罕见）")
        else:
            st.dataframe(hits_table_rows(hits), use_container_width=True, hide_index=True)
            with st.expander("原始 JSON"):
                st.json(hits)

    if hasattr(st, "fragment"):
        hits_panel()
    else:
        hits = read_merged_hits(100, source=hit_source_filter)
        if hits:
            st.dataframe(hits_table_rows(hits), use_container_width=True, hide_index=True)

    clear_pk, clear_mn, clear_bal = st.columns(3)
    with clear_pk:
        if HITS_PATH.is_file() and st.button("清空私钥 hits.jsonl", key="clear_pk_hits"):
            HITS_PATH.write_text("", encoding="utf-8")
            st.toast("已清空 hits.jsonl")
            st.rerun()
    with clear_mn:
        if MNEMONIC_HITS_PATH.is_file() and st.button(
            "清空助记词 mnemonic_hits.jsonl", key="clear_mn_hits"
        ):
            MNEMONIC_HITS_PATH.write_text("", encoding="utf-8")
            st.toast("已清空 mnemonic_hits.jsonl")
            st.rerun()
    with clear_bal:
        if BALANCE_HITS_PATH.is_file() and st.button(
            "清空 balance_hits.jsonl", key="clear_bal_hits"
        ):
            BALANCE_HITS_PATH.write_text("", encoding="utf-8")
            st.toast("已清空 balance_hits.jsonl")
            st.rerun()

with tab_tools:
    st.subheader("Top1万 地址检测")
    st.caption(
        "以 CSV 精确表为准：在就在、不在就不在。"
        "布隆「未命中」也表示一定不在；仅扫描阶段用布隆「命中」做初筛（约 0.1% 误报）。"
    )
    addr = st.text_input("TRON 地址", placeholder="T...")
    if st.button("检测") and addr.strip():
        result = classify_top10k_address(addr)
        if result == "error":
            st.error("无法加载 Bloom/CSV 或地址无效")
        elif result == "in_set":
            st.success("在 Top1万 USDT 集合中")
        elif result == "not_in_set":
            st.info("不在 Top1万 USDT 集合中")
        elif result == "bloom_false_positive":
            st.warning(
                "不在 Top1万 集合中（布隆过滤器误报为「疑似」；"
                "扫描时会被精确表挡掉，不会联网）"
            )

    st.divider()
    st.subheader("单次流程演示")
    st.caption("随机 1 个私钥，逐步展示与 collider 相同的筛选逻辑。")
    demo_net = st.selectbox(
        "演示：精确命中时是否联网",
        ["off", "tronscan", "trongrid"],
        index=0,
        key="demo_network",
    )
    if st.button("执行单次尝试", type="primary"):
        try:
            from try_once import run_single_attempt

            _db, _dc = resolve_scan_paths()
            demo = run_single_attempt(
                bloom_path=_db,
                csv_path=_dc,
                network=demo_net,
            )
        except (OSError, ValueError) as e:
            st.error(str(e))
        else:
            outcome_map = {
                "rejected_by_bloom": ("info", "布隆未命中 → 直接丢弃，继续扫下一个"),
                "bloom_false_positive": (
                    "warning",
                    "布隆疑似但 CSV 没有 → 假阳，默认不联网",
                ),
                "exact_hit": ("success", "精确命中 Top1万 → 应记录并联网验证"),
            }
            kind, msg = outcome_map.get(demo["outcome"], ("info", demo["outcome"]))
            getattr(st, kind)(msg)
            for s in demo["steps"]:
                title = f"步骤 {s['step']}：{s['name']}"
                with st.expander(title, expanded=True):
                    st.write(s["detail"])
                    extras = {
                        k: v
                        for k, v in s.items()
                        if k not in ("step", "name", "detail") and v not in (None, False)
                    }
                    if extras:
                        st.json(extras)

    st.divider()
    st.markdown("**命令行单次尝试**")
    st.code("python try_once.py", language="bash")
    st.markdown("**启动界面（自动关闭同端口旧实例）**")
    st.code("python launch_ui.py", language="bash")

with tab_pubkey:
    st.subheader("从链上交易恢复公钥")
    st.caption(
        "地址是公钥哈希，**不能从地址 alone 算出公钥**。"
        "若该账户 **曾用私钥签过名** 并上链，可从 TronGrid 拉交易并用 ECDSA 恢复。"
        "需要 `.env` 里配置 **TRONGRID_API_KEY**（与下载相同）。"
    )
    pk_addr = st.text_input(
        "TRON 地址",
        placeholder="T...",
        key="pubkey_recover_addr",
    )
    pk_max = st.slider("最多扫描交易笔数", 5, 100, 40, key="pubkey_recover_max")
    if st.button("查询并恢复", type="primary", key="pubkey_recover_btn"):
        import requests as _req

        from tron_pubkey import recover_public_key_from_chain

        with st.spinner("正在请求 TronGrid…"):
            try:
                result = recover_public_key_from_chain(
                    _req.Session(),
                    pk_addr.strip(),
                    max_tx_scan=int(pk_max),
                )
            except _req.RequestException as e:
                st.error(f"请求失败：{e}")
            else:
                st.session_state.pubkey_recover_result = result
    result = st.session_state.get("pubkey_recover_result")
    if result:
        if result.get("ok"):
            st.success(result.get("message", "已恢复"))
            st.markdown(f"**地址：** `{result.get('address')}`")
            st.markdown(f"**派生地址校验：** `{result.get('derived_address')}`")
            st.markdown("**公钥（64 字节 x||y，hex）：**")
            st.code(result.get("public_key_hex", ""), language="text")
            tx_id = str(result.get("tx_id") or "")
            if tx_id:
                st.markdown(
                    f"**来源交易：** [`{tx_id[:16]}…`](https://tronscan.org/#/transaction/{tx_id}) "
                    f"（扫描 {result.get('scanned_txs', '?')} 笔内命中）"
                )
            st.info(
                "这 **不是私钥**，也 **不能** 用来推私钥（经典计算机下仍不可行）。"
                "仅用于理解「签名上链 ≈ 公钥暴露」。"
            )
        else:
            st.warning(result.get("message", "未能恢复"))

with tab_mnemonic:
    from tron_hd import tron_path

    st.subheader("助记词持续碰撞")
    st.caption(
        "后台 **mnemonic_collider.py** 持续随机 BIP39 → BIP44(TRON) → Bloom/CSV；"
        "累计见 `data/mnemonic_scan_lifetime.json`，命中 `data/mnemonic_hits.jsonl`。"
        "日志行以 `mn_try=` 开头（比私钥碰撞慢，Batch 建议约 100）。"
    )
    scan_bloom_path, scan_csv_path = resolve_scan_paths()
    mn_stats = read_mnemonic_stats()
    mn_proc: subprocess.Popen | None = st.session_state.get("mn_scan_proc")
    if mn_proc is not None and mn_proc.poll() is not None:
        st.session_state.mn_scan_proc = None
        mn_proc = None
    mn_running = is_mnemonic_scan_active(mn_stats, mn_proc)
    mn_collider_pids = discover_live_mnemonic_pids()
    if mn_collider_pids and not mn_running:
        st.warning(
            f"残留助记词进程 PID {', '.join(map(str, sorted(mn_collider_pids)))}；请点 **停止**。"
        )

    with st.expander("单次演示（不后台）", expanded=False):
        dm1, dm2, dm3 = st.columns(3)
        with dm1:
            mn_words_demo = st.selectbox("词数", [12, 24], index=0, key="mn_words_demo")
        with dm2:
            mn_account_demo = st.number_input("account'", 0, 10, 0, key="mn_account_demo")
        with dm3:
            mn_index_demo = st.number_input("index", 0, 20, 0, key="mn_index_demo")
        mn_pass_demo = st.text_input(
            "附加口令（可选）", type="password", key="mn_passphrase_demo"
        )
        mn_mode_demo = st.radio(
            "模式",
            ["随机一组", "手输助记词"],
            horizontal=True,
            key="mn_mode_demo",
        )
        mn_custom_demo = ""
        if mn_mode_demo == "手输助记词":
            mn_custom_demo = st.text_area("助记词", height=80, key="mn_custom_demo")
        mn_net_demo = st.selectbox(
            "精确命中联网", ["off", "tronscan", "trongrid"], key="mn_network_demo"
        )
        if st.button("试一次", key="mn_try_once"):
            from mnemonic_try import run_mnemonic_attempt

            try:
                demo = run_mnemonic_attempt(
                    bloom_path=scan_bloom_path,
                    csv_path=scan_csv_path,
                    network=mn_net_demo,
                    mnemonic=mn_custom_demo.strip()
                    if mn_mode_demo == "手输助记词"
                    else None,
                    passphrase=mn_pass_demo or "",
                    words=int(mn_words_demo),
                    account=int(mn_account_demo),
                    address_index=int(mn_index_demo),
                )
            except (OSError, ValueError) as e:
                st.error(str(e))
            else:
                st.session_state.mn_last_result = demo
        demo = st.session_state.get("mn_last_result")
        if demo:
            if demo.get("outcome") == "invalid_mnemonic":
                st.error(demo.get("error", "助记词无效"))
            elif demo.get("address"):
                st.markdown(f"**地址：** `{demo.get('address', '')}` · {demo.get('outcome')}")

    st.subheader("参数")
    p1, p2, p3 = st.columns(3)
    with p1:
        _mn_workers_max = 32
        mn_workers = st.number_input(
            "Workers",
            1,
            _mn_workers_max,
            min(_mn_workers_max, max(1, (os.cpu_count() or 4) - 1)),
            key="mn_workers",
        )
        mn_batch = st.number_input("Batch size", 10, 500, 100, 10, key="mn_batch_size")
    with p2:
        mn_words = st.selectbox("随机词数", [12, 24], index=0, key="mn_words")
        mn_account = st.number_input("account'", 0, 10, 0, key="mn_account")
        mn_index = st.number_input("address index", 0, 20, 0, key="mn_index")
    with p3:
        mn_max = st.number_input(
            "最大尝试 (0=不限)", 0, 10_000_000, 0, 1000, key="mn_max_keys"
        )
        mn_stats_iv = st.slider("统计刷新 (秒)", 1.0, 30.0, 2.0, key="mn_stats_iv")
        mn_net = st.selectbox(
            "精确命中联网", ["off", "tronscan", "trongrid"], key="mn_network"
        )
    mn_on_bloom_net = st.checkbox(
        "布隆疑似即联网（不推荐）", value=False, key="mn_on_bloom_net"
    )
    mn_deriv_path = tron_path(int(mn_account), 0, int(mn_index))
    st.caption(f"派生路径：`{mn_deriv_path}` · 与私钥碰撞共用 Bloom/CSV")

    mc1, mc2, mc3 = st.columns(3)
    bloom_ok_mn, bloom_err_mn = validate_bloom_csv_pair(
        scan_bloom_path, scan_csv_path, project_root=ROOT
    )
    can_stop_mn = mn_running or bool(mn_collider_pids)
    start_mn_disabled = (
        mn_running
        or not scan_bloom_path.is_file()
        or not scan_csv_path.is_file()
        or not bloom_ok_mn
        or bool(mn_collider_pids)
    )
    with mc1:
        if not bloom_ok_mn and scan_bloom_path.is_file() and scan_csv_path.is_file():
            st.error(f"Bloom/CSV：{bloom_err_mn}")
        if st.button("开始", type="primary", disabled=start_mn_disabled, key="mn_start"):
            if discover_live_mnemonic_pids():
                st.error("已有助记词碰撞进程在运行")
            else:
                MNEMONIC_STOP_PATH.unlink(missing_ok=True)
                cmd = [
                    str(ROOT / "mnemonic_collider.py"),
                    "--bloom",
                    str(scan_bloom_path.relative_to(ROOT)),
                    "--address-csv",
                    str(scan_csv_path.relative_to(ROOT)),
                    "--workers",
                    str(int(mn_workers)),
                    "--batch-size",
                    str(int(mn_batch)),
                    "--max-keys",
                    str(int(mn_max)),
                    "--words",
                    str(int(mn_words)),
                    "--derivation-path",
                    mn_deriv_path,
                    "--network",
                    mn_net,
                    "--stats-interval",
                    str(mn_stats_iv),
                    "--stats-file",
                    str(MNEMONIC_STATS_PATH.relative_to(ROOT)),
                    "--stop-file",
                    str(MNEMONIC_STOP_PATH.relative_to(ROOT)),
                    "--hits-file",
                    str(MNEMONIC_HITS_PATH.relative_to(ROOT)),
                ]
                if mn_on_bloom_net:
                    cmd.append("--on-bloom-network")
                st.session_state.mn_scan_proc = run_script(cmd, LOG_PATH)
                st.rerun()
    with mc2:
        if st.button("停止", disabled=not can_stop_mn, key="mn_stop"):
            force = bool(mn_collider_pids) and not mn_running
            killed = signal_stop_mnemonic_scan(force_kill=force)
            if force and killed:
                st.toast(f"已结束残留进程：{', '.join(map(str, sorted(killed)))}")
            else:
                st.toast("已发送停止信号")
            st.rerun()
    with mc3:
        if st.button("立即刷新", key="mn_refresh"):
            st.rerun()

    if mn_running and mn_proc is None and mn_stats:
        st.caption(
            f"助记词碰撞在后台运行（PID {mn_stats.get('pid', '?')}）。"
            "刷新页面后仍可用「停止」。"
        )

    st.caption("指标约每 1 秒刷新。")
    mnemonic_live_panel()

with tab_balance:
    st.subheader("随机地址 · 联网查余额")
    st.caption(
        "后台 **balance_scan.py**：随机私钥 → 地址 → **TronGrid / TronScan 查余额**；"
        "无余额跳过，有余额写入 `data/balance_hits.jsonl`。"
        "**不经过 Bloom**，速度受 API 限流约束（通常远慢于私钥碰撞）。"
        "随机命中仍极不现实，仅供实验/理解链上查询。"
    )
    _bal_keys = api_key_status()
    st.markdown(
        f"**TronGrid**（推荐）: {render_api_key_badge(_bal_keys['trongrid'][0])} · "
        f"**TronScan**（tronscan 后端 USDT）: "
        f"{render_api_key_badge(_bal_keys['tronscan'][0])}"
    )
    bal_stats = read_balance_stats()
    bal_proc: subprocess.Popen | None = st.session_state.get("balance_scan_proc")
    if bal_proc is not None and bal_proc.poll() is not None:
        st.session_state.balance_scan_proc = None
        bal_proc = None
    bal_running = is_balance_scan_active(bal_stats, bal_proc)
    bal_pids = discover_live_balance_pids()
    if bal_pids and not bal_running:
        st.warning(
            f"残留联网查余额进程 PID {', '.join(map(str, sorted(bal_pids)))}；请点 **停止**。"
        )

    b1, b2, b3 = st.columns(3)
    with b1:
        bal_backend = st.selectbox(
            "余额后端",
            ["trongrid", "tronscan"],
            index=0,
            key="bal_backend",
            help="trongrid：v1/accounts 一次；tronscan：TronGrid 账户 + TronScan USDT",
        )
        bal_asset = st.selectbox(
            "计为命中",
            ["any", "trx", "usdt"],
            index=0,
            format_func=lambda x: {"any": "任意余额", "trx": "仅 TRX", "usdt": "仅 USDT"}[x],
            key="bal_asset",
        )
    with b2:
        bal_delay = st.number_input(
            "请求间隔 (毫秒)",
            0.0,
            5000.0,
            0.0,
            50.0,
            key="bal_delay_ms",
            help="每次联网后额外等待，遇 429 时脚本会自动多等 5 秒",
        )
        bal_max = st.number_input(
            "最大尝试 (0=不限)", 0, 10_000_000, 0, 1000, key="bal_max_keys"
        )
    with b3:
        bal_stats_iv = st.slider(
            "统计刷新 (秒)", 1.0, 30.0, 2.0, key="bal_stats_iv"
        )

    bc1, bc2, bc3 = st.columns(3)
    can_stop_bal = bal_running or bool(bal_pids)
    with bc1:
        if st.button(
            "开始",
            type="primary",
            disabled=bal_running or bool(bal_pids),
            key="bal_start",
        ):
            if discover_live_balance_pids():
                st.error("已有联网查余额进程在运行")
            else:
                BALANCE_STOP_PATH.unlink(missing_ok=True)
                cmd = [
                    str(ROOT / "balance_scan.py"),
                    "--backend",
                    bal_backend,
                    "--asset",
                    bal_asset,
                    "--request-delay-ms",
                    str(float(bal_delay)),
                    "--max-keys",
                    str(int(bal_max)),
                    "--stats-interval",
                    str(bal_stats_iv),
                    "--stats-file",
                    str(BALANCE_STATS_PATH.relative_to(ROOT)),
                    "--stop-file",
                    str(BALANCE_STOP_PATH.relative_to(ROOT)),
                    "--hits-file",
                    str(BALANCE_HITS_PATH.relative_to(ROOT)),
                ]
                st.session_state.balance_scan_proc = run_script(cmd, LOG_PATH)
                st.rerun()
    with bc2:
        if st.button("停止", disabled=not can_stop_bal, key="bal_stop"):
            force = bool(bal_pids) and not bal_running
            killed = signal_stop_balance_scan(force_kill=force)
            if force and killed:
                st.toast(f"已结束残留进程：{', '.join(map(str, sorted(killed)))}")
            else:
                st.toast("已发送停止信号")
            st.rerun()
    with bc3:
        if st.button("立即刷新", key="bal_refresh"):
            st.rerun()

    if bal_running and bal_proc is None and bal_stats:
        st.caption(
            f"联网查余额在后台运行（PID {bal_stats.get('pid', '?')}）。"
            "日志关键字 `bal_try=`。"
        )

    if hasattr(st, "fragment") and is_balance_scan_active(
        read_balance_stats(), st.session_state.get("balance_scan_proc")
    ):
        _balance_live_poll()
    else:
        render_balance_metrics_and_log()

# 通用后台任务状态
job_proc = st.session_state.get("job_proc")
if job_proc is not None:
    if job_proc.poll() is None:
        st.session_state.busy = True
    else:
        st.session_state.job_proc = None
        st.session_state.busy = False
        name = st.session_state.get("job_name", "task")
        st.sidebar.success(f"{name} 已完成 (code={job_proc.returncode})")
