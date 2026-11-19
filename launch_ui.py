#!/usr/bin/env python3
"""启动 Streamlit 控制台；若同端口已有旧实例则先结束。"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
APP = ROOT / "app.py"
DEFAULT_PORT = 8501

from env_local import load_local_env  # noqa: E402


def pids_listening_on_port(port: int) -> set[int]:
    pids: set[int] = set()
    try:
        out = subprocess.check_output(
            ["netstat", "-ano"],
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return pids

    port_s = f":{port}"
    for line in out.splitlines():
        if "LISTENING" not in line:
            continue
        if port_s not in line:
            continue
        parts = line.split()
        if not parts:
            continue
        try:
            pids.add(int(parts[-1]))
        except ValueError:
            continue
    return pids


def kill_pid(pid: int) -> None:
    if pid <= 0 or pid == os.getpid():
        return
    subprocess.run(
        ["taskkill", "/PID", str(pid), "/F"],
        check=False,
        capture_output=True,
    )


def main() -> None:
    load_local_env(ROOT)
    port = int(os.environ.get("STREAMLIT_PORT", str(DEFAULT_PORT)))
    me = os.getpid()

    for pid in pids_listening_on_port(port):
        if pid != me:
            print(f"结束占用 {port} 的旧进程 PID {pid}", file=sys.stderr)
            kill_pid(pid)

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(APP),
        "--server.port",
        str(port),
    ]
    print(f"启动 UI: http://localhost:{port}", file=sys.stderr)
    try:
        raise SystemExit(subprocess.call(cmd))
    except KeyboardInterrupt:
        print("\n已停止 UI（Ctrl+C）", file=sys.stderr)
        raise SystemExit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n已停止 UI（Ctrl+C）", file=sys.stderr)
        raise SystemExit(0)
