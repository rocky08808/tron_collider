"""定位正在运行的地址下载子进程（供 UI 停止 / 状态检测）。"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

DOWNLOAD_SCRIPT_MARKERS = (
    "download_usdt_trongrid.py",
    "download_balanced_addresses.py",
)
SCAN_SCRIPT_MARKERS = ("collider.py",)
MNEMONIC_SCRIPT_MARKERS = ("mnemonic_collider.py",)
BALANCE_SCAN_SCRIPT_MARKERS = ("balance_scan.py",)
BLOOM_BUILD_SCRIPT_MARKERS = ("build_bloom_filter.py",)


def _discover_pids(project_root: Path, markers: tuple[str, ...]) -> set[int]:
    root = project_root.resolve()
    root_s = str(root).lower()
    found: set[int] = set()

    if sys.platform == "win32":
        try:
            ps_cmd = (
                "Get-CimInstance Win32_Process | "
                "Where-Object { $_.Name -match 'python' -and $_.CommandLine } | "
                "ForEach-Object { \"$($_.ProcessId)`t$($_.CommandLine)\" }"
            )
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=20,
                encoding="utf-8",
                errors="replace",
            )
            for line in (out.stdout or "").splitlines():
                line = line.strip()
                if not line or "\t" not in line:
                    continue
                pid_s, cmd = line.split("\t", 1)
                cmd_l = cmd.lower()
                if root_s not in cmd_l:
                    continue
                if not any(m.lower() in cmd_l for m in markers):
                    continue
                try:
                    found.add(int(pid_s.strip()))
                except ValueError:
                    continue
        except (OSError, subprocess.SubprocessError):
            pass
        return found

    try:
        out = subprocess.run(
            ["ps", "-eo", "pid,args"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in (out.stdout or "").splitlines()[1:]:
            m = re.match(r"^\s*(\d+)\s+(.*)$", line)
            if not m:
                continue
            pid = int(m.group(1))
            cmd_l = m.group(2).lower()
            if root_s not in cmd_l:
                continue
            if any(marker.lower() in cmd_l for marker in markers):
                found.add(pid)
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return found


def discover_download_pids(project_root: Path | None = None) -> set[int]:
    root = project_root or Path(__file__).resolve().parent
    return _discover_pids(root, DOWNLOAD_SCRIPT_MARKERS)


def discover_collider_pids(project_root: Path | None = None) -> set[int]:
    root = project_root or Path(__file__).resolve().parent
    # mnemonic_collider.py 也含子串 collider.py，须排除
    raw = _discover_pids(root, SCAN_SCRIPT_MARKERS)
    mnemonic = _discover_pids(root, MNEMONIC_SCRIPT_MARKERS)
    return raw - mnemonic


def discover_mnemonic_collider_pids(project_root: Path | None = None) -> set[int]:
    root = project_root or Path(__file__).resolve().parent
    return _discover_pids(root, MNEMONIC_SCRIPT_MARKERS)


def discover_balance_scan_pids(project_root: Path | None = None) -> set[int]:
    root = project_root or Path(__file__).resolve().parent
    return _discover_pids(root, BALANCE_SCAN_SCRIPT_MARKERS)


def discover_bloom_build_pids(project_root: Path | None = None) -> set[int]:
    root = project_root or Path(__file__).resolve().parent
    return _discover_pids(root, BLOOM_BUILD_SCRIPT_MARKERS)
