"""JavaScript, Electron ASAR and application-directory analysis.

The reader recovers structure, not runtime behavior: module boundaries,
imports, URLs, dangerous sink calls, embedded source maps and unpacked ASAR
entries. Nothing is executed and no package manager is invoked.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from typing import Any

from ..context import Context
from ..errors import FormatError, InvalidRequest, LimitError
from ..report import Report
from ..util import Reader, human_bytes, printable_strings, shorten

MAX_ASAR_ENTRY = 4 * 1024 * 1024
MAX_DIRECTORY_FILES = 20000
MAX_RECOVERED_FILES = 600

REQUIRE_RE = re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""")
IMPORT_FROM_RE = re.compile(r"""\bfrom\s*['"]([^'"]+)['"]""")
IMPORT_BARE_RE = re.compile(r"""\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)""")
DEFINITION_RE = re.compile(r"\b(?:function|class)\s+([A-Za-z_$][\w$]*)")
URL_RE = re.compile(r"https?://[^\s\"'`)<>]+")
SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)")
ELECTRON_MARKERS = (
    "contextBridge",
    "ipcMain",
    "ipcRenderer",
    "webPreferences",
    "nodeIntegration",
    "contextIsolation",
    "loadURL",
    "loadFile",
    "app.whenReady",
    "BrowserWindow",
)
SINK_MARKERS = ("eval(", "new Function(", "atob(", "Buffer.from(", "child_process", "execSync", "spawnSync")


def _facts(text: str) -> dict[str, Any]:
    imports = list(dict.fromkeys(REQUIRE_RE.findall(text) + IMPORT_FROM_RE.findall(text) + IMPORT_BARE_RE.findall(text)))
    definitions = list(dict.fromkeys(DEFINITION_RE.findall(text)))
    urls = list(dict.fromkeys(URL_RE.findall(text)))
    markers = [marker for marker in ELECTRON_MARKERS if marker in text]
    sinks = [marker for marker in SINK_MARKERS if marker in text]
    source_map = SOURCE_MAP_RE.findall(text)
    return {
        "imports": imports,
        "definitions": definitions,
        "urls": urls,
        "electron_markers": markers,
        "sinks": sinks,
        "source_mapping_urls": source_map,
        "lines": text.count("\n") + 1,
        "longest_line": max((len(line) for line in text.splitlines()), default=0),
    }


def _looks_minified(text: str) -> bool:
    lines = text.splitlines() or [""]
    average = sum(len(line) for line in lines) / len(lines)
    return average > 200 or (len(lines) < 5 and len(text) > 4000)


def pretty_js(text: str, indent: str = "  ") -> str:
    """Re-indent a minified bundle without changing its token content."""
    out: list[str] = []
    depth = 0
    index = 0
    length = len(text)
    pending_space = False
    previous_significant = ""

    def emit(piece: str) -> None:
        nonlocal pending_space
        if pending_space and out and not out[-1].endswith((" ", "\n", "\t")):
            out.append(" ")
        pending_space = False
        out.append(piece)

    while index < length:
        char = text[index]
        if char in ('"', "'", "`"):
            quote = char
            start = index
            index += 1
            while index < length:
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == quote:
                    index += 1
                    break
                index += 1
            emit(text[start:index])
            previous_significant = quote
            continue
        if char == "/" and index + 1 < length:
            nxt = text[index + 1]
            if nxt == "/":
                end = text.find("\n", index)
                end = length if end < 0 else end
                emit(text[index:end].rstrip())
                index = end
                continue
            if nxt == "*":
                end = text.find("*/", index + 2)
                end = length if end < 0 else end + 2
                emit(text[index:end])
                index = end
                continue
        if char in " \t\r\n":
            pending_space = True
            index += 1
            continue
        if char == "{":
            depth += 1
            emit("{\n" + indent * depth)
            previous_significant = char
            index += 1
            continue
        if char == "}":
            depth = max(0, depth - 1)
            emit("\n" + indent * depth + "}")
            previous_significant = char
            index += 1
            continue
        if char == ";":
            emit(";\n" + indent * depth)
            previous_significant = char
            index += 1
            continue
        emit(char)
        previous_significant = char
        index += 1
    result = "".join(out)
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result


def _collect_source_map(ctx: Context, text: str, stem: str) -> dict[str, Any] | None:
    matches = SOURCE_MAP_RE.findall(text)
    if not matches:
        return None
    reference = matches[-1]
    if reference.startswith("data:"):
        header, _, payload = reference.partition(",")
        try:
            raw = base64.b64decode(payload, validate=False)
            parsed = json.loads(raw.decode("utf-8", "replace"))
        except (binascii.Error, ValueError):
            ctx.limit("An inline source map was referenced but could not be decoded.")
            return None
        ctx.add_artifact(f"sources/{stem}.map.json", json.dumps(parsed, indent=2, ensure_ascii=False), kind="sourcemap")
        sources = parsed.get("sources") or []
        ctx.observe(f"Decoded an inline source map with {len(sources)} source entries.")
        return {"inline": True, "sources": sources[:200], "source_count": len(sources)}
    ctx.limit(
        f"The bundle references an external source map '{shorten(reference, 80)}'; "
        "recover it from the application directory to rebuild original sources."
    )
    return {"inline": False, "reference": reference}


def analyze_file(ctx: Context) -> Report:
    data = bytes(ctx.data[: ctx.size])
    text = data.decode("utf-8", "replace")
    stem = os.path.splitext(os.path.basename(ctx.path))[0] or "bundle"
    facts = _facts(text)
    report = Report(kind="javascript", label="JavaScript source or bundle")
    report.summary.update(
        {
            "lines": facts["lines"],
            "bytes": human_bytes(len(data)),
            "imports": len(facts["imports"]),
            "urls": len(facts["urls"]),
            "definitions": len(facts["definitions"]),
            "minified": _looks_minified(text),
            "electron_markers": len(facts["electron_markers"]),
        }
    )

    imports_section = report.section("Imports")
    for item in facts["imports"][:200]:
        imports_section.add(item)
    if not facts["imports"]:
        imports_section.add("(no require/import edges found)")

    urls_section = report.section("URLs")
    for item in facts["urls"][:120]:
        urls_section.add(shorten(item, 150))
    if not facts["urls"]:
        urls_section.add("(none)")

    if facts["electron_markers"] or facts["sinks"]:
        marker_section = report.section("Runtime markers")
        for marker in facts["electron_markers"]:
            marker_section.add(f"electron  {marker}")
        for sink in facts["sinks"]:
            marker_section.add(f"sink      {sink}")

    definitions_section = report.section("Top-level definitions")
    for item in facts["definitions"][:120]:
        definitions_section.add(item)
    if not facts["definitions"]:
        definitions_section.add("(none)")

    pretty = pretty_js(text) if _looks_minified(text) else text
    ctx.add_artifact(f"sources/{stem}.js", pretty, kind="reformatted")
    source_map = _collect_source_map(ctx, text, stem)

    report.payload = {
        "facts": facts,
        "source_map": source_map,
        "sha256": ctx.sha256,
        "minified": _looks_minified(text),
    }
    report.coverage = {"status": "complete"}
    report.next_steps.append("Open the reformatted .js artifact for readable indentation.")
    if source_map and source_map.get("inline"):
        report.next_steps.append("The inline source map restores original file names and mappings.")
    return report


def _parse_asar(data: bytes) -> tuple[dict[str, Any], int]:
    if len(data) < 16:
        raise FormatError("ASAR header is shorter than 16 bytes")
    reader = Reader(data, "<", 0, "asar")
    header_size = reader.u32()
    if header_size < 8 or header_size > len(data) - 8:
        raise FormatError(f"ASAR header size {header_size} is outside the artifact")
    payload_size = reader.u32()
    header = json.loads(reader.read(header_size).decode("utf-8", "replace"))
    return header, payload_size


def _walk_asar(node: dict[str, Any], prefix: str, out: list[dict[str, Any]], depth: int = 0) -> None:
    if depth > 64:
        return
    if "files" in node:
        for name, child in node["files"].items():
            _walk_asar(child, f"{prefix}/{name}" if prefix else name, out, depth + 1)
        return
    entry = {
        "path": prefix,
        "size": int(node.get("size", 0)),
        "offset": int(node.get("offset", 0)),
        "unpacked": bool(node.get("unpacked", False)),
        "link": node.get("link"),
        "executable": bool(node.get("executable", False)),
        "integrity": node.get("integrity"),
    }
    out.append(entry)


def analyze_asar(ctx: Context) -> Report:
    data = bytes(ctx.data[: ctx.size])
    header, _payload_size = _parse_asar(data)
    files: list[dict[str, Any]] = []
    _walk_asar(header, "", files)
    ctx.stage(f"asar header: {len(files)} file entr(ies)")

    report = Report(kind="asar", label="Electron ASAR archive")
    report.summary.update(
        {
            "files": len(files),
            "unpacked": sum(1 for entry in files if entry["unpacked"]),
            "links": sum(1 for entry in files if entry["link"]),
            "total_bytes": human_bytes(sum(entry["size"] for entry in files)),
        }
    )

    # ASAR payload offsets are relative to the end of the header, which stores the
    # JSON length ahead of the JSON itself.
    raw_header = Reader(data, "<", 0, "asar")
    header_size = raw_header.u32()
    payload_start = 8 + header_size
    payload_length = raw_header.u32()

    inventory = report.section("Files")
    for entry in sorted(files, key=lambda item: item["path"])[:400]:
        flags = []
        if entry["unpacked"]:
            flags.append("unpacked")
        if entry["link"]:
            flags.append("link")
        inventory.add(f"{entry['size']:>10}  {' '.join(flags):<9} {entry['path']}")
    if len(files) > 400:
        inventory.add(f"... {len(files) - 400} more files")

    extracted = 0
    js_bundles: list[dict[str, Any]] = []
    for entry in files:
        if entry["unpacked"] or entry["link"]:
            continue
        if entry["size"] <= 0 or entry["size"] > MAX_ASAR_ENTRY:
            continue
        if extracted >= MAX_RECOVERED_FILES:
            ctx.limit(f"Stopped extracting ASAR entries after {MAX_RECOVERED_FILES} files.")
            break
        start = payload_start + entry["offset"]
        end = start + entry["size"]
        if end > len(data):
            ctx.limit(f"Entry {entry['path']} runs past the end of the archive and was skipped.")
            continue
        raw = data[start:end]
        lower = entry["path"].lower()
        if lower.endswith((".js", ".mjs", ".cjs", ".json", ".html", ".css", ".md", ".txt", ".yml", ".yaml", ".map")):
            if b"\x00" in raw[:1024]:
                continue
            text = raw.decode("utf-8", "replace")
            if lower.endswith((".js", ".mjs", ".cjs")):
                if _looks_minified(text):
                    text = pretty_js(text)
                js_bundles.append({"path": entry["path"], **_facts(text)})
            ctx.add_artifact(f"sources/extracted/{entry['path']}", text, kind="extracted")
            extracted += 1

    if js_bundles:
        imports = sorted({item for bundle in js_bundles for item in bundle["imports"]})
        urls = sorted({item for bundle in js_bundles for item in bundle["urls"]})
        markers = sorted({item for bundle in js_bundles for item in bundle["electron_markers"]})
        bundle_section = report.section("JavaScript bundles")
        for bundle in js_bundles[:200]:
            bundle_section.add(
                f"{shorten(bundle_path(bundle), 60):<62} imports={len(bundle['imports']):<3} urls={len(bundle['urls'])}"
            )
        if len(js_bundles) > 200:
            bundle_section.add(f"... {len(js_bundles) - 200} more")
        edges_section = report.section("Module edges")
        for item in imports[:200]:
            edges_section.add(item)
        if urls:
            url_section = report.section("URLs")
            for item in urls[:120]:
                url_section.add(shorten(item, 150))
        if markers:
            marker_section = report.section("Electron markers")
            marker_section.add(", ".join(markers))
        report.payload["javascript"] = {
            "bundles": [
                {key: value for key, value in bundle.items() if key != "definitions"} for bundle in js_bundles
            ],
            "imports": imports,
            "urls": urls,
            "electron_markers": markers,
        }

    report.payload.update(
        {
            "files": files,
            "payload_start": payload_start,
            "payload_length": payload_length,
            "unpacked_entries": [entry for entry in files if entry["unpacked"]],
        }
    )
    report.coverage = {
        "status": "complete" if extracted < MAX_RECOVERED_FILES else "partial",
        "examined": len(files),
        "total": len(files),
        "exhausted": extracted < MAX_RECOVERED_FILES,
    }
    report.next_steps.append("Open sources/extracted/ to read the unpacked bundle files.")
    report.next_steps.append("An 'unpacked' entry lives in the adjacent app.asar.unpacked directory; point rea at that directory too.")
    return report


def bundle_path(bundle: dict[str, Any]) -> str:
    return str(bundle.get("path", "?"))


def analyze_directory(ctx: Context, directory: str) -> Report:
    files: list[dict[str, Any]] = []
    js_files: list[str] = []
    digest = hashlib.sha256()
    total = 0
    skipped = 0
    for root, dirs, names in os.walk(directory):
        dirs[:] = [name for name in dirs if name not in ("node_modules", ".git", "__pycache__")]
        for name in names:
            full = os.path.join(root, name)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            relative = os.path.relpath(full, directory).replace("\\", "/")
            total += size
            files.append({"path": relative, "size": size})
            digest.update(f"{relative}:{size}".encode("utf-8", "replace"))
            if name.lower().endswith((".js", ".mjs", ".cjs")):
                js_files.append(relative)
            if len(files) >= MAX_DIRECTORY_FILES:
                skipped = 1
                break
        if skipped:
            ctx.limit(f"Directory walk stopped after {MAX_DIRECTORY_FILES} files.")
            break

    if not files:
        raise InvalidRequest(f"directory contains no readable files: {directory}")

    ctx.sha256 = digest.hexdigest()
    ctx.size = total

    package_json: dict[str, Any] | None = None
    entry_hint = None
    for candidate in ("package.json", "app/package.json", "resources/app/package.json"):
        full = os.path.join(directory, *candidate.split("/"))
        if os.path.isfile(full):
            try:
                package_json = json.loads(open(full, "r", encoding="utf-8", errors="replace").read())
                entry_hint = package_json.get("main") or package_json.get("name")
            except (OSError, ValueError):
                package_json = None
            break

    report = Report(kind="javascript", label="JavaScript/Electron application directory")
    report.summary.update(
        {
            "files": len(files),
            "javascript_files": len(js_files),
            "bytes": human_bytes(total),
            "package": (package_json or {}).get("name", "(no package.json)"),
            "entry": entry_hint or "(unknown)",
            "directory_digest": ctx.sha256,
        }
    )
    ctx.stage(f"directory: {len(files)} file(s), {len(js_files)} JavaScript file(s)")

    inventory_lines = [f"{item['size']:>10}  {item['path']}" for item in sorted(files, key=lambda item: item["path"])]
    ctx.add_artifact("sources/inventory.txt", "\n".join(inventory_lines), kind="inventory")

    # Analyze up to a bounded number of JavaScript entry points in memory.
    candidates = [path for path in js_files if "node_modules/" not in path][:MAX_RECOVERED_FILES]
    aggregates: dict[str, set[str]] = {"imports": set(), "urls": set(), "markers": set(), "sinks": set()}
    analyzed = 0
    for relative in candidates:
        full = os.path.join(directory, *relative.split("/"))
        try:
            if os.path.getsize(full) > MAX_ASAR_ENTRY:
                continue
            text = open(full, "r", encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        facts = _facts(text)
        analyzed += 1
        aggregates["imports"].update(facts["imports"])
        aggregates["urls"].update(facts["urls"])
        aggregates["markers"].update(facts["electron_markers"])
        aggregates["sinks"].update(facts["sinks"])
        if _looks_minified(text):
            ctx.add_artifact(f"sources/reformatted/{relative}", pretty_js(text), kind="reformatted")
        _collect_source_map(ctx, text, os.path.splitext(os.path.basename(relative))[0])

    section = report.section("Application files")
    for item in sorted(files, key=lambda item: -item["size"])[:120]:
        section.add(f"{item['size']:>10}  {item['path']}")
    ctx.stage(f"module facts: {analyzed} JavaScript file(s) analyzed")

    edges = report.section("Module edges")
    for item in sorted(aggregates["imports"])[:300]:
        edges.add(item)
    if not aggregates["imports"]:
        edges.add("(no import edges found)")

    if aggregates["markers"] or aggregates["sinks"]:
        marker_section = report.section("Runtime markers")
        for item in sorted(aggregates["markers"]):
            marker_section.add(f"electron  {item}")
        for item in sorted(aggregates["sinks"]):
            marker_section.add(f"sink      {item}")

    report.payload = {
        "files": sorted(files, key=lambda item: item["path"]),
        "javascript_files": sorted(js_files),
        "package_json": package_json,
        "analyzed_files": analyzed,
        "imports": sorted(aggregates["imports"]),
        "urls": sorted(aggregates["urls"]),
        "electron_markers": sorted(aggregates["markers"]),
        "sinks": sorted(aggregates["sinks"]),
    }
    report.coverage = {
        "status": "complete" if not skipped else "partial",
        "examined": analyzed,
        "total": len(js_files),
        "exhausted": analyzed >= len(js_files),
    }
    ctx.limit(
        "Runtime behavior is not observed: this reader performs static analysis only, "
        "and no application code was executed."
    )
    report.next_steps.append("Open sources/inventory.txt for the complete file inventory.")
    return report
