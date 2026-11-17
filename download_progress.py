"""下载任务进度 JSON（供 CLI / Streamlit 读取）。"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def stop_requested(stop_file: Path | None) -> bool:
    if stop_file is None:
        return False
    return Path(stop_file).resolve().is_file()


def sleep_interruptible(seconds: float, stop_file: Path | None) -> bool:
    """Sleep up to `seconds`. Return True if stop was requested."""
    if seconds <= 0:
        return stop_requested(stop_file)
    deadline = time.time() + seconds
    while time.time() < deadline:
        if stop_requested(stop_file):
            return True
        time.sleep(min(0.25, max(0.0, deadline - time.time())))
    return False


def default_stop_file() -> Path:
    return Path(__file__).resolve().parent / "data" / "stop.download"


def resolve_stop_file(path: Path | None) -> Path | None:
    if path is None:
        path = default_stop_file()
    return path.expanduser().resolve()


def _compute_percent(fields: dict[str, Any]) -> float:
    if "percent" in fields:
        try:
            return round(float(fields["percent"]), 2)
        except (TypeError, ValueError):
            pass
    current = int(fields.get("current") or 0)
    target = int(fields.get("target") or 0)
    if target <= 0:
        return 0.0
    if fields.get("phase") in ("rebuild", "skip"):
        base = int(
            fields.get("base_rows")
            or fields.get("rebuild_total")
            or fields.get("skip_total")
            or 0
        )
        done = int(
            fields.get("rebuild_matched")
            if fields.get("phase") == "rebuild"
            else fields.get("skip_index") or 0
        )
        total = int(
            fields.get("rebuild_total")
            or fields.get("skip_total")
            or base
            or 1
        )
        if base > 0 and total > 0:
            return round(100.0 * base * done / (target * total), 2)
    return round(100.0 * current / target, 2)


def publish(path: Path | None, **fields: Any) -> None:
    if path is None:
        return
    percent = _compute_percent(fields)
    payload = {
        "updated_at": time.time(),
        "percent": percent,
        **fields,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
