"""Generic artifact reader: headers, strings and embedded-container evidence.

This is the honest fallback for bytes that no specialized reader claims, and
the light reader for text, JSON, property lists, GGUF and Godot/Unity headers.
"""

from __future__ import annotations

import json
import os
import plistlib
from typing import Any

from ..context import Context
from ..errors import FormatError
from ..report import Report
from ..util import Reader, decode_text, entropy, hexdump, human_bytes, printable_strings, shorten

EMBEDDED_SIGNATURES = (
    (b"PK\x03\x04", "ZIP container"),
    (b"\x7fELF", "ELF image"),
    (b"MZ", "PE/DOS image"),
    (b"\x1f\x8b", "gzip stream"),
    (b"\x00asm", "WebAssembly module"),
    (b"\xca\xfe\xba\xbe", "Java class or Mach-O universal"),
    (b"dex\n", "Dalvik executable"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"%PDF", "PDF document"),
    (b"{\\rtf", "RTF document"),
)


def _scan_embedded(data: bytes, limit: int = 4) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    window = data[: 4 * 1024 * 1024]
    for signature, label in EMBEDDED_SIGNATURES:
        start = window.find(signature)
        if 0 < start < len(window):
            found.append({"offset": start, "signature": label})
            if len(found) >= limit:
                break
    return found


def analyze(ctx: Context) -> Report:
    data = bytes(ctx.data[: ctx.size])
    format_id = ctx.format_id
    report = Report(kind=format_id, label=getattr(ctx.detection, "label", "Unrecognized artifact"))
    if format_id == "json":
        return _analyze_json(ctx, report, data)
    if format_id == "plist":
        return _analyze_plist(ctx, report, data)
    if format_id == "gguf":
        return _analyze_gguf(ctx, report, data)
    if format_id == "text":
        return _analyze_text(ctx, report, data)
    return _analyze_binary(ctx, report, data)


def _analyze_text(ctx: Context, report: Report, data: bytes) -> Report:
    text = decode_text(data) or data.decode("latin-1", "replace")
    lines = text.splitlines()
    words = len(text.split())
    report.summary.update(
        {
            "encoding": "utf-8" if _is_utf8(data) else "latin-1",
            "lines": len(lines),
            "words": words,
            "characters": len(text),
            "entropy": entropy(data),
        }
    )
    section = report.section("Content preview")
    section.lines.extend(shorten(line, 160) for line in lines[:60])
    if len(lines) > 60:
        section.add(f"... {len(lines) - 60} more lines")

    tokens = _interesting_tokens(text)
    if tokens:
        token_section = report.section("Selected tokens")
        for kind, values in tokens.items():
            token_section.add(f"{kind} ({len(values)}): " + ", ".join(values[:40]))

    report.payload = {
        "encoding": "utf-8" if _is_utf8(data) else "latin-1",
        "lines": len(lines),
        "words": words,
        "sha256": ctx.sha256,
    }
    report.coverage = {"status": "complete", "examined": len(lines), "total": len(lines), "exhausted": True}
    report.next_steps.append("Text input is inspected, not decompiled; pass a compiled artifact for code recovery.")
    return report


def _interesting_tokens(text: str) -> dict[str, list[str]]:
    import re

    patterns = {
        "urls": r"https?://[^\s\"'<>()]+",
        "paths": r"(?:[A-Za-z]:\\\\[^\s\"']+|/(?:usr|etc|var|home)/[^\s\"']+)",
        "hashes": r"\b[0-9a-fA-F]{32,64}\b",
        "emails": r"[\w.+-]+@[\w-]+\.[\w.]+",
    }
    result: dict[str, list[str]] = {}
    for name, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            unique = list(dict.fromkeys(matches))
            result[name] = unique[:60]
    return result


def _is_utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _analyze_json(ctx: Context, report: Report, data: bytes) -> Report:
    text = decode_text(data) or ""
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FormatError(f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    top_type = type(parsed).__name__
    report.summary.update({"top_level": top_type, "keys": len(parsed) if isinstance(parsed, (dict, list)) else 0})
    if isinstance(parsed, dict):
        preview = report.section("Top-level keys")
        for key, value in list(parsed.items())[:80]:
            preview.add(f"{shorten(str(key), 40):<42} {type(value).__name__}")
    pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
    stem = os.path.splitext(os.path.basename(ctx.path))[0] or "document"
    ctx.add_artifact(f"sources/{stem}.pretty.json", pretty, kind="reformatted")
    report.payload = {"top_level": top_type, "size_keys": len(parsed) if isinstance(parsed, (dict, list)) else 0}
    report.coverage = {"status": "complete"}
    return report


def _analyze_plist(ctx: Context, report: Report, data: bytes) -> Report:
    try:
        parsed = plistlib.loads(data)
    except Exception as exc:  # plistlib raises several unrelated types
        raise FormatError(f"property list could not be parsed: {exc}") from exc
    report.summary.update({"top_level": type(parsed).__name__, "keys": len(parsed) if hasattr(parsed, "__len__") else 0})
    section = report.section("Keys")
    if isinstance(parsed, dict):
        for key, value in list(parsed.items())[:100]:
            section.add(f"{shorten(str(key), 44):<46} {shorten(str(value), 80)}")
    xml = plistlib.dumps(parsed, sort_keys=False, fmt=plistlib.FMT_XML).decode("utf-8", "replace")
    stem = os.path.splitext(os.path.basename(ctx.path))[0] or "plist"
    ctx.add_artifact(f"sources/{stem}.plist.xml", xml, kind="reformatted")
    report.payload = {"top_level": type(parsed).__name__}
    report.coverage = {"status": "complete"}
    return report


GGUF_TYPES = {
    0: ("u8", 1),
    1: ("i8", 1),
    2: ("u16", 2),
    3: ("i16", 2),
    4: ("u32", 4),
    5: ("i32", 4),
    6: ("f32", 4),
    7: ("bool", 1),
    8: ("string", -1),
    9: ("array", -1),
    10: ("u64", 8),
    11: ("i64", 8),
    12: ("f64", 8),
}


def _gguf_value(reader: Reader, type_id: int, depth: int = 0) -> Any:
    if depth > 6:
        return "<nested too deep>"
    if type_id not in GGUF_TYPES:
        return f"<unknown type {type_id}>"
    name, width = GGUF_TYPES[type_id]
    if name == "string":
        length = reader.u64()
        if length > 8 * 1024 * 1024:
            raise FormatError(f"GGUF string length {length} exceeds the local budget")
        return reader.read(int(length)).decode("utf-8", "replace")
    if name == "array":
        element_type = reader.u32()
        count = reader.u64()
        if count > 100_000:
            return f"<array of {count} elements elided>"
        return [_gguf_value(reader, element_type, depth + 1) for _ in range(int(count))]
    if name in ("u8", "i8", "bool"):
        return reader.u8()
    if name in ("u16", "i16"):
        return reader.u16() if name == "u16" else reader.i16()
    if name in ("u32", "i32"):
        return reader.u32() if name == "u32" else reader.i32()
    if name == "f32":
        return reader.f32()
    if name in ("u64", "i64"):
        return reader.u64() if name == "u64" else reader.i64()
    return reader.f64()


def _analyze_gguf(ctx: Context, report: Report, data: bytes) -> Report:
    reader = Reader(data, "<", 0, "gguf")
    magic = reader.read(4)
    if magic != b"GGUF":
        raise FormatError("GGUF magic missing")
    version = reader.u32()
    tensor_count = reader.u64()
    kv_count = reader.u64()
    report.summary.update(
        {"version": version, "tensors": tensor_count, "metadata_pairs": kv_count, "size": human_bytes(len(data))}
    )
    entries: list[dict[str, Any]] = []
    section = report.section("Metadata")
    for _ in range(min(kv_count, 4000)):
        key_length = reader.u64()
        if key_length > 65536:
            raise FormatError("GGUF metadata key is implausibly long")
        key = reader.read(int(key_length)).decode("utf-8", "replace")
        type_id = reader.u32()
        value = _gguf_value(reader, type_id)
        entries.append({"key": key, "type": GGUF_TYPES.get(type_id, ("?",))[0], "value": value})
        section.add(f"{key:<48} {shorten(str(value), 100)}")
    if kv_count > 4000:
        ctx.limit("GGUF metadata listing stopped after 4000 pairs.")
    stem = os.path.splitext(os.path.basename(ctx.path))[0] or "model"
    lines = [f"{entry['key']} = {entry['value']}" for entry in entries]
    ctx.add_artifact(f"sources/{stem}.gguf-metadata.txt", "\n".join(lines), kind="metadata")
    report.payload = {
        "version": version,
        "tensor_count": tensor_count,
        "metadata_pairs": kv_count,
        "metadata": entries,
    }
    report.coverage = {"status": "partial", "examined": len(entries), "total": kv_count, "exhausted": len(entries) >= kv_count}
    ctx.limit("Tensor data itself is not decoded; this is header and metadata inspection only.")
    return report


def _analyze_binary(ctx: Context, report: Report, data: bytes) -> Report:
    format_id = ctx.format_id
    sample = data[: 512]
    report.summary.update(
        {
            "size": human_bytes(len(data)),
            "entropy": entropy(data),
            "magic": sample[:16].hex(" "),
        }
    )
    header = report.section("Header")
    header.lines.extend(hexdump(data, limit=256).splitlines())

    strings = printable_strings(data, min_len=5, limit=ctx.options.max_strings, max_bytes=8 * 1024 * 1024)
    ctx.stage(f"strings: {len(strings)} run(s) extracted")
    if strings:
        section = report.section(f"Strings ({len(strings)} shown)")
        for item in strings[:120]:
            section.add(f"0x{item['offset']:08x}  {shorten(item['text'], 120)}")
        if len(strings) > 120:
            section.add(f"... {len(strings) - 120} more in the manifest")
    stem = os.path.splitext(os.path.basename(ctx.path))[0] or "artifact"
    if strings:
        manifest = "\n".join(f"0x{item['offset']:08x}\t{item['text']}" for item in strings)
        ctx.add_artifact(f"sources/{stem}.strings.txt", manifest, kind="strings")

    embedded = _scan_embedded(data)
    if embedded:
        embedded_section = report.section("Embedded signatures")
        for item in embedded:
            embedded_section.add(f"0x{item['offset']:08x}  {item['signature']}")
        ctx.observe("Embedded container signatures were found inside the artifact.")

    if format_id in ("godot-pck", "unityfs"):
        ctx.limit(
            "Only the container header and strings were read; extracting engine-specific "
            "resources needs a dedicated reader that this build does not ship."
        )
    else:
        ctx.limit(
            "The bytes match no supported executable or source format, so no decompilation "
            "was attempted. Header and string evidence is complete for the bytes that were read."
        )
    report.payload = {
        "size": len(data),
        "sha256": ctx.sha256,
        "entropy": entropy(data),
        "magic_hex": sample[:16].hex(),
        "strings": strings[: ctx.options.max_strings],
        "embedded": embedded,
    }
    report.coverage = {
        "status": "partial",
        "examined": min(len(strings), ctx.options.max_strings),
        "total": len(strings),
        "exhausted": len(strings) <= ctx.options.max_strings,
    }
    report.next_steps.append("If this is packed or compressed, unpack it externally first; this build never downloads unpackers.")
    return report
