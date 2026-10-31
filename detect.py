"""Artifact detection from content first, file name second.

Detection never trusts an extension on its own: a renamed artifact keeps the
interpretation its bytes support, and the resulting evidence records how the
format was selected.
"""

from __future__ import annotations

import json
import os
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Any

from .errors import FormatError
from .util import looks_like_text


@dataclass
class Detection:
    format: str
    label: str
    by: str = "magic"
    container: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "label": self.label,
            "detected_by": self.by,
            "container": self.container,
            "details": self.details,
        }


ELF_MACHINES = {
    0x03: "x86",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x28: "ARM",
    0x2A: "SuperH",
    0x32: "IA-64",
    0x3E: "x86-64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
    0x102: "LoongArch",
}

PE_MACHINES = {
    0x014C: "x86",
    0x0166: "MIPS",
    0x01C0: "ARM",
    0x01C2: "Thumb",
    0x01C4: "ARMv7",
    0x8664: "x86-64",
    0xAA64: "AArch64",
    0x0200: "IA-64",
    0x5064: "RISC-V 64",
}

MACHO_CPUS = {
    7: "x86",
    0x01000007: "x86-64",
    12: "ARM",
    0x0100000C: "ARM64",
    18: "PowerPC",
    0x01000012: "PowerPC64",
}

ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def _u16(data: bytes, offset: int, endian: str = "<") -> int:
    return struct.unpack_from(endian + "H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str = "<") -> int:
    return struct.unpack_from(endian + "I", data, offset)[0]


def detect(path: str, data: bytes, name: str | None = None) -> Detection:
    """Classify one local artifact and describe the evidence for that choice."""
    filename = name or os.path.basename(path)
    lower = filename.lower()
    head = bytes(data[:512])

    if head.startswith(b"\x7fELF") and len(head) >= 20:
        return _detect_elf(head)
    if head.startswith(b"MZ") and len(head) >= 0x40:
        return _detect_pe(data, head)
    macho = _detect_macho(head)
    if macho is not None:
        return macho
    if len(head) >= 8 and head[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        java = _detect_java_class(head)
        if java is not None:
            return java
        if head[:4] == b"\xca\xfe\xba\xbe":
            return Detection("macho", "Mach-O universal binary", "magic", details={"fat": True})
    if len(head) >= 4 and head[2:4] == b"\r\n":
        from .formats.pyc import version_for_magic

        magic = _u16(head, 0, "<")
        version = version_for_magic(magic)
        if version:
            return Detection(
                "python-pyc",
                f"CPython bytecode ({version})",
                "magic",
                details={"python_version": version},
            )
        if 3000 <= magic <= 3999:
            return Detection(
                "python-pyc",
                f"CPython bytecode (unmapped magic 0x{magic:04x})",
                "magic",
                details={"python_version": "unknown"},
            )
    if head.startswith(b"\x00asm"):
        version = _u32(head, 4) if len(head) >= 8 else 0
        return Detection("wasm", f"WebAssembly module (version {version})", "magic")
    if len(head) >= 8 and head[:2] == b"\x03\x00" and _u16(head, 2) == 8 and _u32(head, 4) <= len(data):
        return Detection("axml", "Android binary XML", "magic", details={"chunk_size": _u32(head, 4)})
    if head.startswith(b"dex\n") and len(head) >= 8:
        return Detection("dex", f"Dalvik executable (DEX {head[4:7].decode('latin-1')})", "magic")
    if head.startswith(b"SQLite format 3\x00"):
        return Detection("sqlite", "SQLite database", "magic")
    if head.startswith(b"FOR1") and head[8:12] == b"BEAM":
        return Detection("beam", "Erlang/Elixir BEAM module", "magic")
    if head.startswith(b"GGUF"):
        return Detection("gguf", "GGUF model artifact", "magic")
    if head.startswith(b"GDPC"):
        return Detection("godot-pck", "Godot PCK archive", "magic")
    if head.startswith(b"bplist00"):
        return Detection("plist", "Apple binary property list", "magic")
    if head.startswith(b"UnityFS"):
        return Detection("unityfs", "Unity asset bundle", "magic")
    if head.startswith(b"\x1f\x8b"):
        return Detection("gzip", "gzip stream", "magic", container="gzip")
    if head.startswith(b"BZh"):
        return Detection("bzip2", "bzip2 stream", "magic", container="bzip2")
    if head.startswith(b"\xfd7zXZ\x00"):
        return Detection("xz", "xz stream", "magic", container="xz")
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return Detection("7z", "7-Zip archive", "magic", container="7z")
    if head.startswith(b"Rar!\x1a\x07"):
        return Detection("rar", "RAR archive", "magic", container="rar")
    if head[:4] in ZIP_MAGICS:
        return _detect_zip(path, filename)
    if _detect_asar_header(data):
        return Detection("asar", "Electron ASAR archive", "magic", container="asar")
    if len(head) >= 262 and head[257:262] == b"ustar":
        return Detection("tar", "POSIX tar archive", "magic", container="tar")

    text = look_text(lower, head)
    if text is not None:
        return text
    return Detection(
        "blob",
        f"Unrecognized bytes (first 4: {head[:4].hex() or 'empty'})",
        "content",
        details={"extension": os.path.splitext(lower)[1]},
    )


def _detect_elf(head: bytes) -> Detection:
    bits = "64-bit" if head[4] == 2 else "32-bit"
    endian = "little-endian" if head[5] == 1 else "big-endian"
    e_type = _u16(head, 16, "<" if head[5] == 1 else ">")
    machine = _u16(head, 18, "<" if head[5] == 1 else ">")
    kind = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core dump"}.get(e_type, f"type {e_type}")
    arch = ELF_MACHINES.get(machine, f"machine 0x{machine:x}")
    return Detection(
        "elf",
        f"ELF {bits} {endian} {kind}, {arch}",
        "magic",
        details={"bits": 64 if head[4] == 2 else 32, "endian": head[5], "type": e_type, "machine": machine, "arch": arch},
    )


def _detect_pe(data: bytes, head: bytes) -> Detection:
    try:
        pe_offset = _u32(head, 0x3C)
        if pe_offset + 0x18 > len(data) or bytes(data[pe_offset : pe_offset + 4]) != b"PE\x00\x00":
            return Detection("pe", "DOS/PE image with an unreadable PE header", "magic", details={"pe_offset": pe_offset})
        coff = pe_offset + 4
        machine, section_count, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        magic = _u16(bytes(data[opt : opt + 2]), 0)
        arch = PE_MACHINES.get(machine, f"machine 0x{machine:04x}")
        pe32_plus = magic == 0x20B
        managed = False
        cli_rva = 0
        try:
            dd = opt + (112 if pe32_plus else 96)
            if opt + (112 if pe32_plus else 96) + 16 * 8 <= len(data):
                cli_rva, cli_size = struct.unpack_from("<II", data, dd + 14 * 8)
                managed = cli_rva != 0 and cli_size >= 0x48
        except struct.error:
            pass
        characteristics = _u16(bytes(data[coff + 18 : coff + 20]), 0)
        kind = "DLL" if characteristics & 0x2000 else "image"
        label = f"PE32{'+' if pe32_plus else ''} {kind}, {arch}, {section_count} sections"
        if managed:
            return Detection(
                "dotnet",
                f"{label}, managed (.NET)",
                "magic",
                details={"arch": arch, "pe32_plus": pe32_plus, "sections": section_count},
            )
        return Detection(
            "pe",
            label,
            "magic",
            details={"arch": arch, "pe32_plus": pe32_plus, "sections": section_count},
        )
    except (struct.error, IndexError):
        return Detection("pe", "DOS/PE image (truncated header)", "magic")


def _detect_macho(head: bytes) -> Detection | None:
    if len(head) < 8:
        return None
    magic = head[:4]
    if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        endian = "<" if magic[0] in (0xCE, 0xCF) else ">"
        cpu = _u32(head, 4, endian)
        arch = MACHO_CPUS.get(cpu, f"cpu 0x{cpu:x}")
        bits = 64 if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 32
        return Detection(
            "macho",
            f"Mach-O {bits}-bit {arch}",
            "magic",
            details={"arch": arch},
        )
    if magic == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        count = _u32(head, 4, ">")
        if 1 <= count <= 30:
            return Detection("macho", f"Mach-O universal binary ({count} slices)", "magic", details={"slices": count})
    return None


def _detect_java_class(head: bytes) -> Detection | None:
    if len(head) < 8:
        return None
    minor = _u16(head, 4, ">")
    major = _u16(head, 6, ">")
    if minor == 0 and 45 <= major <= 75:
        return Detection(
            "java-class",
            f"Java class file (major {major}, minor {minor})",
            "magic",
            details={"major": major, "minor": minor},
        )
    return None


def _detect_zip(path: str, filename: str) -> Detection:
    names: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist()[:6000]:
                names.append(info.filename)
    except (zipfile.BadZipFile, OSError):
        return Detection("zip", "ZIP container (unreadable central directory)", "magic", container="zip")
    lowered = [name.lower() for name in names]
    has_manifest = "androidmanifest.xml" in lowered
    has_dex = any(name.startswith("classes") and name.endswith(".dex") for name in lowered)
    if has_manifest and has_dex:
        return Detection("apk", "Android package (APK), zip container", "magic", container="zip", details={"entries": len(names)})
    if has_manifest and "bundletool" in " ".join(lowered[:200]):
        return Detection("apk", "Android App Bundle, zip container", "magic", container="zip")
    if any(name.endswith(".class") for name in lowered) or "meta-inf/manifest.mf" in lowered:
        return Detection("jar", "Java archive (JAR), zip container", "magic", container="zip", details={"entries": len(names)})
    if any(name.endswith(".dex") for name in lowered):
        return Detection("dex", "ZIP container holding dex bytecode", "magic", container="zip", details={"entries": len(names)})
    return Detection("zip", f"ZIP container ({len(names)} entries)", "magic", container="zip", details={"entries": len(names)})


def _detect_asar_header(data: bytes) -> bool:
    if len(data) < 20:
        return False
    try:
        header_size = _u32(data, 0)
    except struct.error:
        return False
    if not 8 <= header_size <= 64 * 1024 * 1024 or len(data) < 8 + header_size:
        return False
    # Layout: u32 header size, u32 payload size, then the header JSON.
    return data[8:20].lstrip().startswith(b"{")


def look_text(lower_name: str, head: bytes) -> Detection | None:
    if not looks_like_text(head):
        return None
    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped.startswith(b"<?xml") and b"<plist" in head[:512]:
        return Detection("plist", "Apple XML property list", "content")
    if lower_name.endswith(".json") or (stripped[:1] in (b"{", b"[") and _is_json(head)):
        return Detection("json", "JSON document", "content")
    if lower_name.endswith((".js", ".mjs", ".cjs", ".jsx")) or _looks_like_javascript(stripped):
        return Detection("javascript", "JavaScript source or bundle", "content")
    extension = os.path.splitext(lower_name)[1]
    if extension in (".py", ".lua", ".rb", ".pl", ".ps1", ".bat", ".cmd", ".sh", ".cs", ".java", ".kt", ".swift", ".go", ".rs", ".ts", ".html", ".css", ".sql", ".yaml", ".yml", ".ini", ".cfg", ".toml", ".map", ".txt", ".md"):
        return Detection("text", f"Text source ({extension})", "extension")
    return Detection("text", "Text document", "content")


def _is_json(head: bytes) -> bool:
    try:
        decoder = __import__("json").JSONDecoder()
        decoder.raw_decode(head.decode("utf-8", "replace"))
        return True
    except Exception:
        return False


def _looks_like_javascript(stripped: bytes) -> bool:
    markers = (
        b"function ",
        b"const ",
        b"let ",
        b"var ",
        b"import ",
        b"export ",
        b"(()=>",
        b"(function(",
        b'"use strict"',
        b"'use strict'",
        b"require(",
    )
    window = stripped[:400]
    return any(marker in window for marker in markers)


def describe(detection: Detection) -> str:
    return f"{detection.label} [{detection.format}]"


def summary_json(detection: Detection) -> str:
    return json.dumps(detection.to_dict(), indent=2)
