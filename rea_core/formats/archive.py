"""Archive readers: ZIP/JAR inventory, decompilation of nested classes, and
single-stream decompression that re-runs detection on the inner artifact."""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import lzma
import os
import tarfile
import zipfile
from typing import Any

from .. import detect as detection_module
from ..context import ChildContext, Context
from ..errors import FormatError, LimitError
from ..report import Report
from ..util import human_bytes, human_int, printable_strings, shorten
from . import java_class

MAX_EXTRACT_FILES = 400
MAX_EXTRACT_BYTES = 24 * 1024 * 1024
TEXT_SUFFIXES = (
    ".js",
    ".mjs",
    ".cjs",
    ".json",
    ".txt",
    ".md",
    ".xml",
    ".html",
    ".css",
    ".properties",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".mf",
    ".map",
)


def analyze(ctx: Context) -> Report:
    format_id = ctx.format_id
    if format_id in ("zip", "jar"):
        return _analyze_zip(ctx, format_id)
    if format_id == "tar":
        return _analyze_tar(ctx)
    if format_id in ("gzip", "bzip2", "xz"):
        return _analyze_compressed(ctx)
    if format_id in ("7z", "rar"):
        return _analyze_foreign(ctx)
    raise FormatError(f"unsupported archive format '{format_id}'")


def _kind_for(name: str) -> str:
    lower = name.lower()
    if lower.endswith(".class"):
        return "java-class"
    if lower.endswith(".dex"):
        return "dex"
    if lower.endswith((".so", ".dll", ".dylib", ".exe", ".node")):
        return "native"
    if lower.endswith((".js", ".mjs", ".cjs")):
        return "javascript"
    if lower.endswith((".json", ".xml", ".properties", ".txt", ".md", ".html", ".css")):
        return "text"
    if lower.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico")):
        return "image"
    return "data"


def _analyze_zip(ctx: Context, format_id: str) -> Report:
    report = Report(kind=format_id, label="Java archive (JAR)" if format_id == "jar" else "ZIP container")
    try:
        archive = zipfile.ZipFile(io.BytesIO(bytes(ctx.data[: ctx.size])))
    except (zipfile.BadZipFile, OSError) as exc:
        raise FormatError(f"ZIP central directory could not be read: {exc}") from exc

    entries: list[dict[str, Any]] = []
    kinds: dict[str, int] = {}
    classes: list[dict[str, Any]] = []
    decompiled = 0
    skipped = 0
    manifest_text: str | None = None

    for info in archive.infolist():
        if info.is_dir():
            continue
        kind = _kind_for(info.filename)
        kinds[kind] = kinds.get(kind, 0) + 1
        entries.append(
            {
                "name": info.filename,
                "size": info.file_size,
                "compressed": info.compress_size,
                "crc": f"{info.CRC:08x}",
                "kind": kind,
            }
        )

    report.summary.update(
        {
            "entries": len(entries),
            "uncompressed": human_bytes(sum(entry["size"] for entry in entries)),
            "classes": kinds.get("java-class", 0),
            "dex": kinds.get("dex", 0),
            "native": kinds.get("native", 0),
            "javascript": kinds.get("javascript", 0),
        }
    )
    ctx.stage(f"zip: {len(entries)} entr(ies)")

    inventory = report.section("Entries")
    for entry in entries[:300]:
        inventory.add(
            f"{entry['size']:>10}  {human_bytes(entry['compressed']):>10}  {entry['kind']:<10} {entry['name']}"
        )
    if len(entries) > 300:
        inventory.add(f"... {len(entries) - 300} more entries")

    if "meta-inf/manifest.mf" in [entry["name"].lower() for entry in entries]:
        try:
            manifest_text = archive.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
            manifest_section = report.section("MANIFEST.MF")
            manifest_section.lines.extend(manifest_text.splitlines()[:80])
            ctx.add_artifact("sources/META-INF-MANIFEST.MF", manifest_text, kind="metadata")
        except KeyError:
            manifest_text = None

    limit = min(ctx.options.max_items, MAX_EXTRACT_FILES)
    for entry in entries:
        if entry["kind"] != "java-class":
            continue
        if decompiled >= limit:
            skipped = kinds.get("java-class", 0) - decompiled
            ctx.limit(
                f"Stopped after {limit} class files; {skipped} further classes were inventoried only. "
                "Raise --max-items to decompile more."
            )
            break
        try:
            raw = archive.read(entry["name"])
        except (KeyError, RuntimeError, zipfile.BadZipFile) as exc:
            ctx.limit(f"Entry {entry['name']} could not be read: {exc}")
            continue
        child = ChildContext(
            ctx,
            path=f"{ctx.path}!/{entry['name']}",
            data=raw,
            sha256=hashlib.sha256(raw).hexdigest(),
            prefix="classes",
        )
        try:
            class_report = java_class.analyze(child)
        except FormatError as exc:
            ctx.limit(f"{entry['name']}: {exc.message}")
            continue
        decompiled += 1
        classes.append(
            {
                "entry": entry["name"],
                "class": class_report.payload.get("class_name"),
                "methods": len(class_report.payload.get("methods", [])),
                "fields": len(class_report.payload.get("fields", [])),
            }
        )

    if classes:
        section = report.section("Decompiled classes")
        for item in classes[:200]:
            section.add(f"{item['class']:<60} methods={item['methods']:<4} fields={item['fields']}")
        if len(classes) > 200:
            section.add(f"... {len(classes) - 200} more")
        ctx.stage(f"classes decompiled: {len(classes)}")

    # Text entries are copied out so a stale JAR still yields readable sources.
    extracted = 0
    for entry in entries:
        if entry["kind"] != "text":
            continue
        if extracted >= MAX_EXTRACT_FILES:
            ctx.limit("Text extraction stopped at the file-count cap.")
            break
        if entry["size"] > 2 * 1024 * 1024:
            continue
        if not entry["name"].lower().endswith(TEXT_SUFFIXES):
            continue
        try:
            raw = archive.read(entry["name"])
        except (KeyError, RuntimeError, zipfile.BadZipFile):
            continue
        if b"\x00" in raw[:2048]:
            continue
        ctx.add_artifact(f"sources/extracted/{entry['name']}", raw.decode("utf-8", "replace"), kind="extracted")
        extracted += 1
    if extracted:
        ctx.observe(f"Extracted {extracted} text entries from the container.")

    report.payload = {
        "entries": entries,
        "kinds": kinds,
        "classes": classes,
        "manifest": manifest_text,
        "decompiled_classes": decompiled,
        "skipped_classes": skipped,
    }
    total = len(entries)
    report.coverage = {
        "status": "complete" if decompiled + skipped >= kinds.get("java-class", 0) else "partial",
        "examined": total,
        "total": total,
        "exhausted": True,
    }
    report.next_steps.append("Open classes/ for one .javap.txt per class file.")
    if kinds.get("dex"):
        report.next_steps.append("Containers with dex bytecode are read by the DEX/APK workflow.")
    return report


def _analyze_tar(ctx: Context) -> Report:
    report = Report(kind="tar", label="POSIX tar archive")
    try:
        archive = tarfile.open(fileobj=io.BytesIO(bytes(ctx.data[: ctx.size])), mode="r:*")
    except tarfile.TarError as exc:
        raise FormatError(f"tar archive could not be read: {exc}") from exc

    members = archive.getmembers()
    report.summary.update(
        {
            "members": len(members),
            "uncompressed": human_bytes(sum(member.size for member in members if member.isfile())),
        }
    )
    section = report.section("Members")
    for member in members[:300]:
        kind = "dir" if member.isdir() else "link" if member.issym() else "file"
        section.add(f"{member.size:>10}  {kind:<5} {member.name}")
    if len(members) > 300:
        section.add(f"... {len(members) - 300} more")

    extracted = 0
    for member in members:
        if not member.isfile() or extracted >= MAX_EXTRACT_FILES:
            continue
        if not member.name.lower().endswith(TEXT_SUFFIXES) or member.size > 2 * 1024 * 1024:
            continue
        handle = archive.extractfile(member)
        if handle is None:
            continue
        raw = handle.read()
        if b"\x00" in raw[:2048]:
            continue
        ctx.add_artifact(f"sources/extracted/{member.name}", raw.decode("utf-8", "replace"), kind="extracted")
        extracted += 1
    report.payload = {
        "members": [
            {"name": member.name, "size": member.size, "type": "file" if member.isfile() else "other"}
            for member in members
        ],
        "extracted_text_files": extracted,
    }
    report.coverage = {"status": "complete", "examined": len(members), "total": len(members), "exhausted": True}
    return report


def _decompress(format_id: str, data: bytes) -> tuple[bytes, str]:
    if format_id == "gzip":
        return gzip.decompress(data), "gzip"
    if format_id == "bzip2":
        return bz2.decompress(data), "bzip2"
    return lzma.decompress(data), "xz"


def _analyze_compressed(ctx: Context) -> Report:
    format_id = ctx.format_id
    report = Report(kind=format_id, label=f"{format_id} compressed stream")
    try:
        payload, codec = _decompress(format_id, bytes(ctx.data[: ctx.size]))
    except (OSError, EOFError, lzma.LZMAError) as exc:
        raise FormatError(f"{format_id} stream could not be decompressed: {exc}") from exc
    if len(payload) > 512 * 1024 * 1024:
        raise LimitError("Decompressed payload exceeds the 512 MiB in-memory budget")

    report.summary.update(
        {
            "codec": codec,
            "compressed_size": human_bytes(ctx.size),
            "payload_size": human_bytes(len(payload)),
            "compression_ratio": round(len(payload) / max(1, ctx.size), 2),
        }
    )
    inner_name = os.path.basename(ctx.path)
    for suffix in (".gz", ".bz2", ".xz"):
        if inner_name.lower().endswith(suffix):
            inner_name = inner_name[: -len(suffix)]
            break
    inner_detection = detection_module.detect(inner_name, payload)

    section = report.section("Inner artifact")
    section.add(f"name    {inner_name}")
    section.add(f"format  {inner_detection.label} [{inner_detection.format}]")
    section.add(f"size    {human_bytes(len(payload))}")

    inner_report = None
    try:
        from . import HANDLERS, analyze as analyze_format

        if inner_detection.format in HANDLERS:
            child = ChildContext(
                ctx,
                path=f"{ctx.path}!/{inner_name}",
                data=payload,
                sha256=hashlib.sha256(payload).hexdigest(),
                prefix="inner",
                detection=inner_detection,
            )
            inner_report = analyze_format(child, inner_detection)
            ctx.stage(f"inner {inner_detection.format} analyzed")
            for entry in inner_report.sections:
                if entry.lines:
                    target_section = report.section(f"Inner: {entry.title}")
                    target_section.lines.extend(entry.lines[:80])
            report.payload["inner"] = {
                "format": inner_detection.format,
                "label": inner_detection.label,
                "size": len(payload),
                "summary": inner_report.summary,
                "payload_keys": sorted(inner_report.payload),
            }
        else:
            ctx.limit(f"Inner format '{inner_detection.format}' has no built-in reader.")
    except LimitError as exc:
        ctx.limit(exc.message)

    report.payload.update(
        {
            "codec": codec,
            "compressed_size": ctx.size,
            "payload_size": len(payload),
            "inner_name": inner_name,
            "inner_detection": inner_detection.to_dict(),
        }
    )
    report.coverage = {"status": "complete"}
    report.next_steps.append("The inner artifact was analyzed in memory; inner/ holds its decompiled products.")
    return report


def _analyze_foreign(ctx: Context) -> Report:
    from .. import engines as engine_module

    report = Report(kind=ctx.format_id, label=f"{ctx.format_id} archive")
    strings = printable_strings(ctx.data, min_len=5, limit=ctx.options.max_strings, max_bytes=4 * 1024 * 1024)
    section = report.section("Strings")
    for item in strings[:120]:
        section.add(f"0x{item['offset']:08x}  {shorten(item['text'], 120)}")
    report.summary.update({"strings": len(strings), "size": human_bytes(ctx.size)})
    engine = engine_module.discover().find("7z")
    if engine:
        code, stdout, stderr = engine_module.run_tool([engine.path, "l", "-slt", ctx.path], timeout=60)
        if code == 0:
            listing = report.section("7-Zip listing (local engine)")
            listing.lines.extend(stdout.splitlines()[:200])
        else:
            ctx.limit(f"The local 7z engine could not list the archive: {stderr.strip()[:200]}")
    else:
        ctx.limit(
            f"No local {ctx.format_id} extractor is installed. This build never downloads one; "
            "the container is reported through strings and magic only."
        )
    report.payload = {"strings": strings, "entries": None}
    report.coverage = {"status": "partial", "examined": len(strings), "total": None, "exhausted": False}
    return report
