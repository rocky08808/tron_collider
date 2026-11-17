"""校验 Bloom 与精确地址 CSV 是否匹配（避免 Bloom/CSV 漂移导致假阴性）。"""

from __future__ import annotations

import csv
import json
from pathlib import Path


def count_unique_addresses(csv_path: Path) -> int:
    seen: set[str] = set()
    with csv_path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            addr = (row.get("address") or "").strip()
            if addr:
                seen.add(addr)
    return len(seen)


def count_csv_data_rows(csv_path: Path) -> int:
    """非空数据行数（不 dedupe，内存占用低）。"""
    n = 0
    with csv_path.open(encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if not row:
                continue
            if any((cell or "").strip() for cell in row):
                n += 1
    return n


def csv_address_count(
    csv_path: Path,
    *,
    bloom_path: Path | None = None,
    project_root: Path | None = None,
) -> int:
    """UI / 校验用：优先 Bloom meta，内存不足时降级为行数统计。"""
    csv_path = csv_path.resolve()
    if not csv_path.is_file() or csv_path.stat().st_size == 0:
        return 0
    if bloom_path and bloom_path.is_file():
        meta_path = bloom_path.with_suffix(bloom_path.suffix + ".meta.json")
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                expected = int(meta.get("unique_addresses") or 0)
                src = meta.get("source_csv")
                if expected > 0 and src and project_root is not None:
                    ref = resolve_meta_csv_path(
                        str(src), project_root=project_root, bloom_path=bloom_path
                    )
                    if ref is not None and ref.resolve() == csv_path:
                        rows = count_csv_data_rows(csv_path)
                        if rows == expected:
                            return expected
            except (json.JSONDecodeError, TypeError, ValueError, OSError):
                pass
    try:
        return count_unique_addresses(csv_path)
    except MemoryError:
        return count_csv_data_rows(csv_path)


def resolve_meta_csv_path(
    meta_src: str,
    *,
    project_root: Path,
    bloom_path: Path,
) -> Path | None:
    raw = Path(meta_src)
    if raw.is_file():
        return raw.resolve()
    for base in (project_root, bloom_path.parent, Path.cwd()):
        cand = (base / meta_src).resolve()
        if cand.is_file():
            return cand
    return None


def validate_bloom_csv_pair(
    bloom_path: Path,
    csv_path: Path,
    *,
    project_root: Path,
) -> tuple[bool, str]:
    bloom_path = bloom_path.resolve()
    csv_path = csv_path.resolve()
    if not bloom_path.is_file():
        return False, f"找不到 Bloom：{bloom_path}"
    if not csv_path.is_file():
        return False, f"找不到 CSV：{csv_path}"

    try:
        csv_count = count_unique_addresses(csv_path)
    except MemoryError:
        csv_count = count_csv_data_rows(csv_path)
    meta_path = bloom_path.with_suffix(bloom_path.suffix + ".meta.json")
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return False, f"Bloom meta 无法解析：{meta_path.name}"
        expected = int(meta.get("unique_addresses") or 0)
        if expected > 0 and csv_count != expected:
            return (
                False,
                f"CSV 唯一地址 {csv_count:,} 条与 Bloom meta 的 {expected:,} 不一致，"
                "请用同一份 CSV 重建 Bloom",
            )
        src = meta.get("source_csv")
        if src:
            ref = resolve_meta_csv_path(
                str(src), project_root=project_root, bloom_path=bloom_path
            )
            if ref is None:
                return (
                    False,
                    f"Bloom meta 记录的源 CSV 不存在：{src}；"
                    f"当前扫描 CSV 为 {csv_path.name}",
                )
            if ref.resolve() != csv_path.resolve():
                return (
                    False,
                    f"扫描 CSV 与构建 Bloom 时的源文件不是同一份："
                    f"meta 源 {src}，当前 {csv_path}",
                )
        try:
            if csv_path.stat().st_mtime > bloom_path.stat().st_mtime + 1:
                return (
                    False,
                    f"CSV 比 Bloom 更新（{csv_path.name} 晚于 {bloom_path.name}），"
                    "请重新构建 Bloom 后再扫描",
                )
        except OSError:
            pass
    elif csv_count == 0:
        return False, "CSV 中没有有效 address 行"

    return True, ""
