"""Simple persistent Bloom filter (stdlib only)."""

from __future__ import annotations

import hashlib
import json
import math
import struct
from pathlib import Path
from typing import BinaryIO, Iterable

MAGIC = b"TBF1"
_VERSION = 1


def optimal_size(n: int, error_rate: float) -> tuple[int, int]:
    if n <= 0:
        raise ValueError("n must be positive")
    if not 0 < error_rate < 1:
        raise ValueError("error_rate must be in (0, 1)")
    m = math.ceil(-n * math.log(error_rate) / (math.log(2) ** 2))
    k = max(1, round(m / n * math.log(2)))
    return m, k


class BloomFilter:
    def __init__(self, m: int, k: int, *, bitarray: bytearray | None = None) -> None:
        if m <= 0 or k <= 0:
            raise ValueError("invalid bloom parameters")
        self.m = m
        self.k = k
        self._bits = bitarray if bitarray is not None else bytearray((m + 7) // 8)
        self._count = 0

    @classmethod
    def create(cls, expected_items: int, error_rate: float = 0.001) -> BloomFilter:
        m, k = optimal_size(expected_items, error_rate)
        return cls(m, k)

    def _indexes(self, key: bytes) -> Iterable[int]:
        for i in range(self.k):
            digest = hashlib.blake2b(
                key, digest_size=16, person=struct.pack(">I", i)
            ).digest()
            yield int.from_bytes(digest, "big") % self.m

    def add(self, key: bytes) -> None:
        for idx in self._indexes(key):
            byte_i, bit_i = divmod(idx, 8)
            self._bits[byte_i] |= 1 << bit_i
        self._count += 1

    def __contains__(self, key: bytes) -> bool:
        for idx in self._indexes(key):
            byte_i, bit_i = divmod(idx, 8)
            if not (self._bits[byte_i] & (1 << bit_i)):
                return False
        return True

    @property
    def count(self) -> int:
        return self._count

    def save(self, path: Path, *, meta: dict | None = None) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as f:
            self._write(f)
        if meta is not None:
            meta_path = path.with_suffix(path.suffix + ".meta.json")
            meta_path.write_text(
                json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
            )

    @classmethod
    def load(cls, path: Path) -> BloomFilter:
        with path.open("rb") as f:
            return cls._read(f)

    def _write(self, f: BinaryIO) -> None:
        f.write(MAGIC)
        f.write(struct.pack(">BII", _VERSION, self.k, self.m))
        f.write(struct.pack(">I", self._count))
        f.write(self._bits)

    @classmethod
    def _read(cls, f: BinaryIO) -> BloomFilter:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("not a TBF1 bloom file")
        version, k, m = struct.unpack(">BII", f.read(9))
        if version != _VERSION:
            raise ValueError(f"unsupported bloom version {version}")
        (count,) = struct.unpack(">I", f.read(4))
        nbytes = (m + 7) // 8
        bits = bytearray(f.read(nbytes))
        if len(bits) != nbytes:
            raise ValueError("truncated bloom file")
        bf = cls(m, k, bitarray=bits)
        bf._count = count
        return bf


def tron_address_key(address: str) -> bytes:
    addr = address.strip()
    if not addr:
        raise ValueError("empty address")
    return addr.encode("utf-8")
