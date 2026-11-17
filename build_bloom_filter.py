#!/usr/bin/env python3
"""从地址 CSV 构建布隆过滤器。"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

from bloom import BloomFilter, tron_address_key
from download_progress import publish as publish_progress

PROGRESS_EVERY = 5_000


def load_addresses(
    csv_path: Path,
    *,
    progress_path: Path | None = None,
) -> list[str]:
    publish_progress(
        progress_path,
        status="running",
        job="bloom-build",
        phase="load",
        current=0,
        target=0,
        message=f"正在读取 {csv_path.name}…",
        input=str(csv_path),
    )
    with csv_path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "address" not in reader.fieldnames:
            raise ValueError("CSV 需要 address 列")
        seen: set[str] = set()
        out: list[str] = []
        for row in reader:
            addr = (row.get("address") or "").strip()
            if not addr or addr in seen:
                continue
            seen.add(addr)
            out.append(addr)
            n = len(out)
            if progress_path and n % PROGRESS_EVERY == 0:
                publish_progress(
                    progress_path,
                    status="running",
                    job="bloom-build",
                    phase="load",
                    current=n,
                    target=n,
                    message=f"读取 CSV… {n:,} 条",
                    input=str(csv_path),
                )
        return out


def build(
    addresses: list[str],
    *,
    error_rate: float,
    progress_path: Path | None = None,
    output: Path | None = None,
) -> BloomFilter:
    total = len(addresses)
    publish_progress(
        progress_path,
        status="running",
        job="bloom-build",
        phase="build",
        current=0,
        target=total,
        message=f"构建 Bloom（0 / {total:,}）…",
        input=str(output) if output else "",
        output=str(output) if output else "",
    )
    bf = BloomFilter.create(total, error_rate)
    t0 = time.time()
    for i, addr in enumerate(addresses, 1):
        bf.add(tron_address_key(addr))
        if progress_path and (i % PROGRESS_EVERY == 0 or i == total):
            elapsed = time.time() - t0
            rate = i / elapsed if elapsed > 0 else 0
            publish_progress(
                progress_path,
                status="running",
                job="bloom-build",
                phase="build",
                current=i,
                target=total,
                message=f"写入 Bloom… {i:,} / {total:,}（{rate:,.0f} 条/s）",
                output=str(output) if output else "",
            )
    return bf


def verify(bf: BloomFilter, addresses: list[str]) -> int:
    missing = [a for a in addresses if tron_address_key(a) not in bf]
    return len(missing)


def main() -> None:
    parser = argparse.ArgumentParser(description="用地址列表构建布隆过滤器")
    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        default=Path("data/usdt_top200000.csv"),
        help="输入 CSV（含 address 列）",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("data/usdt_top200000.bloom"),
        help="输出 .bloom 二进制文件",
    )
    parser.add_argument(
        "--error-rate",
        type=float,
        default=0.001,
        help="目标假阳性率（默认 0.1%%）",
    )
    parser.add_argument(
        "--check",
        type=str,
        default=None,
        help="构建后测试单个地址是否在过滤器中",
    )
    parser.add_argument(
        "--progress-file",
        type=Path,
        default=Path("data/bloom_build_progress.json"),
        help="进度 JSON（供 UI 读取）",
    )
    args = parser.parse_args()

    try:
        addresses = load_addresses(args.input, progress_path=args.progress_file)
    except (OSError, ValueError) as e:
        publish_progress(
            args.progress_file,
            status="error",
            job="bloom-build",
            message=str(e),
            input=str(args.input),
        )
        print(f"读取失败: {e}", file=sys.stderr)
        sys.exit(1)

    if not addresses:
        publish_progress(
            args.progress_file,
            status="error",
            job="bloom-build",
            message="没有有效地址",
            input=str(args.input),
        )
        print("没有有效地址", file=sys.stderr)
        sys.exit(1)

    publish_progress(
        args.progress_file,
        status="running",
        job="bloom-build",
        phase="build",
        current=0,
        target=len(addresses),
        message=f"共 {len(addresses):,} 地址，开始构建…",
        input=str(args.input),
        output=str(args.output),
    )
    bf = build(
        addresses,
        error_rate=args.error_rate,
        progress_path=args.progress_file,
        output=args.output,
    )
    publish_progress(
        args.progress_file,
        status="running",
        job="bloom-build",
        phase="verify",
        current=len(addresses),
        target=len(addresses),
        message="校验 Bloom…",
        output=str(args.output),
    )
    missing = verify(bf, addresses)
    if missing:
        publish_progress(
            args.progress_file,
            status="error",
            job="bloom-build",
            message=f"校验失败：{missing} 条未命中",
            output=str(args.output),
        )
        print(f"校验失败：{missing} 条未命中", file=sys.stderr)
        sys.exit(1)

    meta = {
        "source_csv": str(args.input.resolve()),
        "unique_addresses": len(addresses),
        "error_rate_target": args.error_rate,
        "m_bits": bf.m,
        "k_hashes": bf.k,
        "file_bytes": (bf.m + 7) // 8 + 17,
    }
    bf.save(args.output, meta=meta)

    publish_progress(
        args.progress_file,
        status="completed",
        job="bloom-build",
        current=len(addresses),
        target=len(addresses),
        message="构建完成",
        input=str(args.input),
        output=str(args.output),
        unique_addresses=len(addresses),
        file_bytes=meta["file_bytes"],
    )

    print(
        f"已写入 {args.output}：{len(addresses)} 地址，"
        f"m={bf.m} bit，k={bf.k}，约 {meta['file_bytes']} 字节",
        file=sys.stderr,
    )

    if args.check:
        hit = tron_address_key(args.check) in bf
        print(f"check {args.check}: {'可能命中' if hit else '一定不在集合'}")


if __name__ == "__main__":
    main()
