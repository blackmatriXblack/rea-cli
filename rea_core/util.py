"""Bounds-checked binary readers and small formatting helpers."""

from __future__ import annotations

import hashlib
import math
import os
import re
import struct
from typing import Any, Iterator, Sequence

from .errors import FormatError

CHUNK = 1 << 20
_STRING_RE = re.compile(rb"[\x20-\x7e\t]{4,}")


def sha256_file(path: str | os.PathLike[str]) -> str:
    """Hash a file incrementally so multi-gigabyte targets stay bounded."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes | bytearray | memoryview) -> str:
    return hashlib.sha256(data).hexdigest()


def human_bytes(value: float) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    size = float(value)
    for unit in units:
        if abs(size) < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TiB"


def human_int(value: int) -> str:
    return f"{value:,}"


def entropy(data: bytes | memoryview, limit: int = 1 << 20) -> float:
    """Shannon entropy in bits per byte over at most ``limit`` bytes."""
    sample = bytes(data[:limit])
    if not sample:
        return 0.0
    counts = [0] * 256
    for byte in sample:
        counts[byte] += 1
    total = len(sample)
    result = 0.0
    for count in counts:
        if count:
            p = count / total
            result -= p * math.log2(p)
    return round(result, 4)


def hexdump(data: bytes | memoryview, limit: int = 256, width: int = 16) -> str:
    view = bytes(data[:limit])
    lines: list[str] = []
    for offset in range(0, len(view), width):
        row = view[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in row)
        text_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row)
        lines.append(f"{offset:08x}  {hex_part:<{width * 3 - 1}}  |{text_part}|")
    return "\n".join(lines)


def printable_strings(
    data: bytes | memoryview,
    *,
    min_len: int = 4,
    limit: int = 4000,
    offset: int = 0,
    max_bytes: int | None = None,
) -> list[dict[str, Any]]:
    """Return offset/text pairs for ASCII runs, in source order."""
    view = data if max_bytes is None else data[:max_bytes]
    found: list[dict[str, Any]] = []
    for match in _STRING_RE.finditer(view):
        text = match.group().decode("latin-1")
        found.append({"offset": offset + match.start(), "text": text})
        if len(found) >= limit:
            break
    return found


def decode_text(data: bytes, encodings: Sequence[str] = ("utf-8-sig", "utf-16", "latin-1")) -> str | None:
    for encoding in encodings:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def looks_like_text(data: bytes | memoryview) -> bool:
    sample = bytes(data[:4096])
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    control = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return control / len(sample) < 0.02


def slug(text: str, fallback: str = "artifact") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._-")
    return cleaned[:80] or fallback


def shorten(text: str, limit: int = 160) -> str:
    flat = " ".join(str(text).split())
    if len(flat) <= limit:
        return flat
    return flat[: max(0, limit - 3)] + "..."


def ratio(part: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round(part / total, 4)


class Reader:
    """Bounds-checked random access over ``bytes``, ``bytearray`` or ``mmap``.

    Every accessor raises :class:`FormatError` instead of reading past the end,
    so a truncated artifact fails at a named field rather than corrupting the
    surrounding analysis.
    """

    __slots__ = ("data", "endian", "pos", "label")

    def __init__(
        self,
        data: bytes | bytearray | memoryview,
        endian: str = "<",
        pos: int = 0,
        label: str = "artifact",
    ) -> None:
        self.data = data
        self.endian = endian
        self.pos = pos
        self.label = label

    def __len__(self) -> int:
        return len(self.data)

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def _need(self, count: int) -> None:
        if count < 0 or self.pos + count > len(self.data):
            raise FormatError(
                f"{self.label}: truncated read at offset 0x{self.pos:x} "
                f"({count} bytes requested, {self.remaining} available)"
            )

    def seek(self, pos: int) -> "Reader":
        if pos < 0 or pos > len(self.data):
            raise FormatError(f"{self.label}: seek target 0x{pos:x} outside 0x0-0x{len(self.data):x}")
        self.pos = pos
        return self

    def skip(self, count: int) -> "Reader":
        self._need(count)
        self.pos += count
        return self

    def read(self, count: int) -> bytes:
        self._need(count)
        chunk = bytes(self.data[self.pos : self.pos + count])
        self.pos += count
        return chunk

    def peek(self, count: int) -> bytes:
        return bytes(self.data[self.pos : self.pos + count])

    def bytes_at(self, offset: int, count: int) -> bytes:
        if offset < 0 or offset + count > len(self.data):
            raise FormatError(f"{self.label}: range 0x{offset:x}+0x{count:x} outside the artifact")
        return bytes(self.data[offset : offset + count])

    def slice(self, offset: int, count: int) -> "Reader":
        if offset < 0 or offset + count > len(self.data):
            raise FormatError(f"{self.label}: range 0x{offset:x}+0x{count:x} outside the artifact")
        return Reader(self.data[offset : offset + count], self.endian, 0, self.label)

    def sub(self, offset: int, count: int, endian: str | None = None) -> "Reader":
        return Reader(self.data[offset : offset + count], endian or self.endian, 0, self.label)

    def unpack(self, fmt: str) -> tuple[Any, ...]:
        size = struct.calcsize(fmt)
        self._need(size)
        values = struct.unpack_from(self.endian + fmt, self.data, self.pos)
        self.pos += size
        return values

    def u8(self) -> int:
        self._need(1)
        value = self.data[self.pos]
        self.pos += 1
        return int(value)

    def i8(self) -> int:
        value = self.u8()
        return value - 256 if value > 127 else value

    def u16(self) -> int:
        return int(self.unpack("H")[0])

    def i16(self) -> int:
        return int(self.unpack("h")[0])

    def u32(self) -> int:
        return int(self.unpack("I")[0])

    def i32(self) -> int:
        return int(self.unpack("i")[0])

    def u64(self) -> int:
        return int(self.unpack("Q")[0])

    def i64(self) -> int:
        return int(self.unpack("q")[0])

    def f32(self) -> float:
        return float(self.unpack("f")[0])

    def f64(self) -> float:
        return float(self.unpack("d")[0])

    def uint(self, width: int) -> int:
        return int.from_bytes(self.read(width), "little" if self.endian == "<" else "big")

    def cstring(self, limit: int = 4096, encoding: str = "utf-8") -> str:
        start = self.pos
        end = start
        while end < len(self.data) and end - start < limit and self.data[end] != 0:
            end += 1
        raw = bytes(self.data[start:end])
        self.pos = min(end + 1, len(self.data))
        return raw.decode(encoding, "replace")

    def uleb(self, bits: int = 64) -> int:
        result = 0
        shift = 0
        for _ in range((bits + 6) // 7 + 1):
            byte = self.u8()
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7
        raise FormatError(f"{self.label}: LEB128 value exceeds {bits} bits at 0x{self.pos:x}")

    def sleb(self, bits: int = 64) -> int:
        result = 0
        shift = 0
        byte = 0
        for _ in range((bits + 6) // 7 + 1):
            byte = self.u8()
            result |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                if byte & 0x40:
                    result |= -1 << shift
                return result
        raise FormatError(f"{self.label}: signed LEB128 value exceeds {bits} bits at 0x{self.pos:x}")

    def align(self, alignment: int) -> "Reader":
        if alignment <= 1:
            return self
        pad = (alignment - (self.pos % alignment)) % alignment
        return self.skip(pad)

    def iter_chunks(self, size: int) -> Iterator[bytes]:
        while self.remaining > 0:
            yield self.read(min(size, self.remaining))


def read_uleb(data: bytes, pos: int) -> tuple[int, int]:
    """Decode one unsigned LEB128 value from ``data`` at ``pos``."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise FormatError("LEB128 value runs past the end of the artifact")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))
