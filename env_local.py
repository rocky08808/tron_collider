"""本地 .env 与 API Key 配置检测（不记录、不展示密钥内容）。"""

from __future__ import annotations

import os
from pathlib import Path


def load_local_env(project_root: Path) -> None:
    path = project_root / ".env"
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        val = val.strip().strip('"').strip("'")
        if val:
            os.environ.setdefault(key, val)


def _non_empty(name: str) -> bool:
    return bool(os.environ.get(name, "").strip())


def api_key_status() -> dict[str, tuple[bool, str]]:
    """
    返回各场景是否已配置，以及命中的环境变量名（不含值）。
    TronGrid / TronScan 与 download_*.py 逻辑一致。
    """
    if _non_empty("TRONGRID_API_KEY"):
        trongrid = (True, "TRONGRID_API_KEY")
    elif _non_empty("TRON_PRO_API_KEY"):
        trongrid = (True, "TRON_PRO_API_KEY")
    else:
        trongrid = (False, "")

    if _non_empty("TRONSCAN_API_KEY"):
        tronscan = (True, "TRONSCAN_API_KEY")
    elif _non_empty("TRON_PRO_API_KEY"):
        tronscan = (True, "TRON_PRO_API_KEY")
    else:
        tronscan = (False, "")

    return {"trongrid": trongrid, "tronscan": tronscan}


def render_api_key_badge(configured: bool) -> str:
    return "已配置 ✓" if configured else "未配置"
