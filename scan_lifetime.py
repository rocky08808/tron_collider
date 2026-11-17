"""扫描累计尝试次数（跨多次「开始扫描」累加）。"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path


def read_lifetime_total(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return int(data.get("total_tried") or 0)
    except (json.JSONDecodeError, TypeError, ValueError):
        return 0


def write_lifetime_total(path: Path, total_tried: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    part = path.with_name(path.name + ".part")
    payload = {"total_tried": max(0, int(total_tried))}
    part.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    last: OSError | None = None
    for attempt in range(15):
        try:
            os.replace(part, path)
            return
        except PermissionError as e:
            last = e
            if attempt + 1 < 15:
                time.sleep(0.3)
    if last is not None:
        raise last


def bootstrap_lifetime_from_stats(lifetime_path: Path, stats_path: Path) -> None:
    if lifetime_path.is_file() or not stats_path.is_file():
        return
    try:
        stats = json.loads(stats_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return
    tried = int(stats.get("tried") or 0)
    if stats.get("total_tried") is not None:
        tried = max(tried, int(stats.get("total_tried") or 0))
    if tried > 0:
        write_lifetime_total(lifetime_path, tried)
