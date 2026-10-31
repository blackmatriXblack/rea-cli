"""Android package reader: binary manifest, dex classes, native libraries."""

from __future__ import annotations

import hashlib
import io
import os
import zipfile
from typing import Any

from .. import engines as engine_module
from ..context import ChildContext, Context
from ..errors import FormatError
from ..report import Report
from ..util import Reader, human_bytes
from . import dalvik

MAX_DEX_FILES = 6
MAX_DEX_CLASSES = 1500

ANDROID_NS = "http://schemas.android.com/apk/res/android"

ANDROID_ATTRIBUTES = {
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010006: "permission",
    0x0101000E: "enabled",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010011: "process",
    0x0101001C: "priority",
    0x0101001D: "launchMode",
    0x0101001E: "screenOrientation",
    0x0101001F: "configChanges",
    0x01010018: "authorities",
    0x01010019: "syncable",
    0x0101001A: "initOrder",
    0x0101001B: "grantUriPermissions",
    0x0101000B: "sharedUserId",
    0x0101000C: "hasCode",
    0x01010012: "taskAffinity",
    0x01010013: "multiprocess",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x0101021E: "versionCodeMajor",
    0x01010270: "targetSdkVersion",
    0x01010271: "maxSdkVersion",
    0x0101028E: "allowBackup",
    0x010102B4: "largeHeap",
    0x010102C9: "usesCleartextTraffic",
    0x0101032B: "required",
    0x010103AE: "extractNativeLibs",
    0x0101049C: "roundIcon",
}

VALUE_TYPES = {
    0x00: "null",
    0x01: "reference",
    0x02: "attribute",
    0x03: "string",
    0x04: "float",
    0x05: "dimension",
    0x06: "fraction",
    0x10: "int",
    0x11: "hex",
    0x12: "bool",
    0x1C: "color",
}

STRING_POOL_UTF8 = 0x100
TYPE_STRING_POOL = 0x0001
TYPE_RESOURCE_MAP = 0x0180
TYPE_START_NAMESPACE = 0x0100
TYPE_END_NAMESPACE = 0x0101
TYPE_START_ELEMENT = 0x0102
TYPE_END_ELEMENT = 0x0103
TYPE_CDATA = 0x0104


class Axml:
    """Decoder for Android's compiled binary XML (resource chunk format)."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.reader = Reader(data, "<", 0, "AndroidManifest.xml")
        self.strings: list[str] = []
        self.resource_ids: list[int] = []
        self.namespaces: dict[str, str] = {}

    def parse(self) -> list[dict[str, Any]]:
        reader = self.reader
        if reader.size < 8:
            raise FormatError("binary XML is shorter than a chunk header")
        while reader.remaining >= 8:
            chunk_type = reader.u16()
            header_size = reader.u16()
            chunk_size = reader.u32()
            if chunk_size < 8 or chunk_size > reader.remaining + 8:
                raise FormatError(f"binary XML chunk 0x{chunk_type:04x} has an impossible size {chunk_size}")
            start = reader.pos - 8
            body = reader.sub(start, chunk_size)
            body.seek(header_size)
            if chunk_type == TYPE_STRING_POOL:
                self._string_pool(body, header_size)
            elif chunk_type == TYPE_RESOURCE_MAP:
                self.resource_ids = [body.u32() for _ in range(body.remaining // 4)]
            # The document chunk wraps every node chunk; descend by its header size.
            advance = header_size if chunk_type == 0x0003 else chunk_size
            reader.seek(start + advance)

        elements = self._read_nodes()
        return elements

    def _string_pool(self, body: Reader, header_size: int) -> None:
        body.seek(8)
        string_count = body.u32()
        _style_count = body.u32()
        flags = body.u32()
        strings_start = body.u32()
        _styles_start = body.u32()
        offsets = [body.u32() for _ in range(string_count)]
        utf8 = bool(flags & STRING_POOL_UTF8)
        raw = body.data
        for offset in offsets:
            position = strings_start + offset
            try:
                if utf8:
                    cursor = position
                    # UTF-16 length (varint), then UTF-8 byte length (varint)
                    for _ in range(2):
                        while raw[cursor] & 0x80:
                            cursor += 1
                        cursor += 1
                    end = raw.index(b"\x00", cursor)
                    self.strings.append(raw[cursor:end].decode("utf-8", "replace"))
                else:
                    cursor = position
                    length = int.from_bytes(raw[cursor : cursor + 2], "little")
                    cursor += 2
                    if length & 0x8000:
                        length = ((length & 0x7FFF) << 16) | int.from_bytes(raw[cursor : cursor + 2], "little")
                        cursor += 2
                    self.strings.append(raw[cursor : cursor + length * 2].decode("utf-16-le", "replace"))
            except (IndexError, ValueError):
                self.strings.append("")

    def string(self, index: int) -> str:
        if 0 <= index < len(self.strings):
            return self.strings[index]
        return f"@string/{index}"

    def _read_nodes(self) -> list[dict[str, Any]]:
        reader = Reader(self.data, "<", 8, "AndroidManifest.xml")
        root: list[dict[str, Any]] = []
        stack: list[dict[str, Any]] = []
        while reader.remaining >= 8:
            chunk_type = reader.u16()
            header_size = reader.u16()
            chunk_size = reader.u32()
            if chunk_size < 8:
                break
            start = reader.pos - 8
            if start + chunk_size > reader.size:
                break
            node = reader.sub(start, chunk_size)
            node.seek(8)
            if chunk_type == TYPE_START_NAMESPACE:
                node.u32()  # line number
                node.u32()  # comment
                prefix = self.string(node.u32())
                uri = self.string(node.u32())
                self.namespaces[uri] = prefix
            elif chunk_type == TYPE_START_ELEMENT:
                node.u32()  # line
                node.u32()  # comment
                _ns = node.u32()
                name = self.string(node.u32())
                node.u16()  # attributeStart
                attribute_size = node.u16()
                attribute_count = node.u16()
                node.u16()
                node.u16()
                node.u16()
                attributes: list[tuple[str, str, str]] = []
                for _ in range(attribute_count):
                    attribute = node.sub(node.pos, attribute_size)
                    node.skip(attribute_size)
                    ns = self.string(attribute.u32())
                    key_index = attribute.u32()
                    key = self.string(key_index)
                    raw_value = attribute.i32()
                    attribute.u16()  # typed value size
                    attribute.u8()
                    data_type = attribute.u8()
                    data_value = attribute.u32()
                    if key.startswith("@") and data_value in ANDROID_ATTRIBUTES:
                        key = ANDROID_ATTRIBUTES[data_value]
                    elif key.startswith("@") and 0 <= data_value < len(self.resource_ids):
                        key = f"res/0x{self.resource_ids[data_value]:08x}"
                    value = self._value(raw_value, data_type, data_value)
                    prefix = self.namespaces.get(ns, "")
                    qualified = f"{prefix}:{key}" if prefix else key
                    attributes.append((qualified, value, data_type == 0x01 and str(data_value)))
                element = {"tag": name, "attributes": attributes, "children": []}
                if stack:
                    stack[-1]["children"].append(element)
                else:
                    root.append(element)
                stack.append(element)
            elif chunk_type == TYPE_END_ELEMENT:
                if stack:
                    stack.pop()
            reader.seek(start + chunk_size)
        return root

    def _value(self, raw_value: int, data_type: int, data_value: int) -> str:
        if raw_value != -1:
            return self.string(raw_value)
        kind = VALUE_TYPES.get(data_type, f"0x{data_type:02x}")
        if data_type == 0x01:
            return f"@0x{data_value:08x}"
        if data_type == 0x03:
            return self.string(data_value)
        if data_type == 0x12:
            return "true" if data_value else "false"
        if data_type == 0x11:
            return f"0x{data_value:x}"
        if data_type in (0x10,):
            return str(data_value if data_value < 0x80000000 else data_value - 0x100000000)
        return f"{kind}:0x{data_value:x}"


def render_xml(elements: list[dict[str, Any]], indent: str = "  ") -> str:
    lines = ['<?xml version="1.0" encoding="utf-8"?>']

    def emit(element: dict[str, Any], depth: int) -> None:
        pad = indent * depth
        attributes = " ".join(f'{key}="{_escape(value)}"' for key, value, *_ in element["attributes"])
        head = f"{pad}<{element['tag']}" + (f" {attributes}" if attributes else "")
        if element["children"]:
            lines.append(head + ">")
            for child in element["children"]:
                emit(child, depth + 1)
            lines.append(f"{pad}</{element['tag']}>")
        else:
            lines.append(head + " />")

    for element in elements:
        emit(element, 0)
    return "\n".join(lines)


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _find(element: dict[str, Any], tag: str) -> list[dict[str, Any]]:
    found = []
    for child in element.get("children", []):
        if child["tag"] == tag:
            found.append(child)
        found.extend(_find(child, tag))
    return found


def _attr(element: dict[str, Any], name: str) -> str | None:
    for key, value, *_ in element["attributes"]:
        if key == name or key.endswith(":" + name):
            return value
    return None


def _count_elements(elements: list[dict[str, Any]]) -> int:
    total = 0
    for element in elements:
        total += 1 + _count_elements(element["children"])
    return total


def analyze_axml(ctx: Context) -> Report:
    """Decode a standalone Android binary XML document."""
    raw = bytes(ctx.data[: ctx.size])
    axml = Axml(raw)
    elements = axml.parse()
    stem = os.path.splitext(os.path.basename(ctx.path))[0] or "document"
    report = Report(kind="axml", label="Android binary XML")
    strings = axml.strings
    report.summary.update(
        {
            "roots": len(elements),
            "elements": _count_elements(elements),
            "strings": len(strings),
            "resource_ids": len(axml.resource_ids),
            "size": human_bytes(ctx.size),
        }
    )
    xml_text = render_xml(elements)
    ctx.add_artifact(f"sources/{stem}.decoded.xml", xml_text, kind="manifest")
    section = report.section("Decoded tree")
    for element in elements[:20]:
        section.add(f"<{element['tag']}> with {len(element['attributes'])} attribute(s) and {len(element['children'])} child(ren)")
        for key, value, *_ in element["attributes"][:20]:
            section.add(f"    {key} = {value}")
    string_section = report.section(f"String pool ({len(strings)} entries)")
    for index, value in enumerate(strings[:100]):
        string_section.add(f"[{index:>3}] {value}")
    report.payload = {
        "strings": strings,
        "resource_ids": [f"0x{item:08x}" for item in axml.resource_ids],
        "xml": xml_text,
        "elements": [
            {"tag": element["tag"], "attributes": [list(item) for item in element["attributes"]]}
            for element in elements
        ],
    }
    report.coverage = {"status": "complete"}
    report.next_steps.append("Open the .decoded.xml artifact for the reconstructed XML tree.")
    return report


def analyze(ctx: Context) -> Report:
    data = bytes(ctx.data[: ctx.size])
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as exc:
        raise FormatError(f"APK container is unreadable: {exc}") from exc

    names = [info.filename for info in archive.infolist() if not info.is_dir()]
    lowercase = {name.lower(): name for name in names}
    dex_entries = sorted(name for name in names if name.startswith("classes") and name.endswith(".dex"))
    native_entries = [name for name in names if name.startswith("lib/") and name.endswith(".so")]
    signature_entries = [
        name for name in names if name.upper().startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC", ".SF"))
    ]
    assets = [name for name in names if name.startswith("assets/")]
    ctx.stage(f"zip: {len(names)} entries, {len(dex_entries)} dex, {len(native_entries)} native libraries")

    report = Report(kind="apk", label="Android package (APK)")
    report.summary.update(
        {
            "entries": len(names),
            "dex_files": len(dex_entries),
            "native_libraries": len(native_entries),
            "assets": len(assets),
            "signature_files": len(signature_entries),
            "size": human_bytes(ctx.size),
        }
    )

    manifest_elements: list[dict[str, Any]] = []
    manifest_name = lowercase.get("androidmanifest.xml")
    if manifest_name:
        try:
            raw_manifest = archive.read(manifest_name)
        except KeyError:
            raw_manifest = b""
        if raw_manifest.startswith(b"\x03\x00\x08\x00"):
            manifest = Axml(raw_manifest)
            try:
                manifest_elements = manifest.parse()
            except FormatError as exc:
                ctx.limit(f"AndroidManifest.xml could not be decoded: {exc.message}")
            if manifest_elements:
                xml_text = render_xml(manifest_elements)
                ctx.add_artifact("sources/AndroidManifest.xml", xml_text, kind="manifest")
                ctx.stage(f"manifest decoded: {len(manifest_elements)} root element(s)")
        else:
            ctx.limit("AndroidManifest.xml is not compiled binary XML; it was copied without decoding.")
            ctx.add_artifact(
                "sources/AndroidManifest.xml",
                raw_manifest.decode("utf-8", "replace"),
                kind="manifest",
            )

    package_facts: dict[str, Any] = {}
    if manifest_elements:
        root = manifest_elements[0]
        package_facts = {
            "package": _attr(root, "package"),
            "version_code": _attr(root, "versionCode"),
            "version_name": _attr(root, "versionName"),
            "min_sdk": None,
            "target_sdk": None,
            "permissions": sorted(
                {
                    _attr(item, "name")
                    for item in _find(root, "uses-permission")
                    if _attr(item, "name")
                }
            ),
            "components": [],
        }
        for node in _find(root, "uses-sdk"):
            package_facts["min_sdk"] = _attr(node, "minSdkVersion")
            package_facts["target_sdk"] = _attr(node, "targetSdkVersion")
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for node in _find(root, tag):
                package_facts["components"].append(
                    {
                        "type": tag,
                        "name": _attr(node, "name"),
                        "exported": _attr(node, "exported"),
                        "permission": _attr(node, "permission"),
                        "actions": [
                            _attr(intent, "name")
                            for intent in _find(node, "action")
                            if _attr(intent, "name")
                        ],
                    }
                )
        manifest_section = report.section("Manifest")
        manifest_section.add(f"package       {package_facts.get('package') or '-'}")
        manifest_section.add(
            f"version       {package_facts.get('version_name') or '-'} "
            f"({package_facts.get('version_code') or '-'})"
        )
        manifest_section.add(
            f"sdk           min={package_facts.get('min_sdk') or '-'} "
            f"target={package_facts.get('target_sdk') or '-'}"
        )
        if package_facts["permissions"]:
            manifest_section.add("permissions   " + ", ".join(package_facts["permissions"][:40]))
        if package_facts["components"]:
            components_section = report.section("Components")
            for component in package_facts["components"][:200]:
                flags = []
                if component["exported"]:
                    flags.append("exported=" + component["exported"])
                if component["permission"]:
                    flags.append("permission=" + component["permission"])
                actions = f"  actions={component['actions']}" if component["actions"] else ""
                components_section.add(f"{component['type']:<14} {component['name']} {' '.join(flags)}{actions}")

    if native_entries:
        section = report.section("Native libraries")
        for name in native_entries[:100]:
            section.add(name)
        if len(native_entries) > 100:
            section.add(f"... {len(native_entries) - 100} more")

    if signature_entries:
        section = report.section("Signature files")
        for name in signature_entries:
            section.add(name)
        ctx.limit(
            "Signature files are listed only; certificate chains and APK Signature Scheme v2/v3 "
            "blocks are not verified by this build."
        )

    dex_facts: list[dict[str, Any]] = []
    java_sources: list[str] = []
    ctx.stage(f"decompiling {min(len(dex_entries), MAX_DEX_FILES)} dex file(s)")
    for index, name in enumerate(dex_entries[:MAX_DEX_FILES]):
        try:
            raw = archive.read(name)
        except KeyError:
            continue
        child = ChildContext(
            ctx,
            path=f"{ctx.path}!/{name}",
            data=raw,
            sha256=hashlib.sha256(raw).hexdigest(),
            prefix=f"dex{index + 1}" if index else "dex",
        )
        try:
            facts = dalvik.parse_dex(
                raw,
                name,
                max_classes=min(ctx.options.max_items, MAX_DEX_CLASSES),
                disassemble=ctx.options.disassemble,
            )
        except FormatError as exc:
            ctx.limit(f"{name}: {exc.message}")
            continue
        for limitation in facts.limitations:
            ctx.limit(f"{name}: {limitation}")
        for path, text in facts.smali:
            child.add_artifact(path, text, kind="disassembly")
        if ctx.options.source:
            smali_texts = {path: text for path, text in facts.smali}
            for path, text in dalvik._java_skeletons(facts, smali_texts, f"{ctx.path}!/{name}"):
                if child.add_artifact(path, text, kind="source"):
                    java_sources.append(f"{'dex' if index == 0 else f'dex{index + 1}'}/java/{path.split('java/', 1)[-1]}")
        dex_facts.append({"name": name, "size": len(raw), "facts": facts})
    if len(dex_entries) > MAX_DEX_FILES:
        ctx.limit(f"Only the first {MAX_DEX_FILES} dex files were decompiled; {len(dex_entries) - MAX_DEX_FILES} were inventoried.")
    ctx.stage(f"dex classes: {sum(len(item['facts'].classes) for item in dex_facts)}")

    if dex_facts:
        section = report.section("Dex classes")
        total_classes = 0
        total_methods = 0
        for item in dex_facts:
            facts = item["facts"]
            total_classes += len(facts.classes)
            total_methods += facts.method_count
            section.add(
                f"{item['name']:<16} classes={len(facts.classes):<6} methods={facts.method_count:<7} "
                f"strings={facts.string_count:<6} instructions={facts.instructions}"
            )
        report.summary["dex_classes"] = total_classes
        report.summary["dex_methods"] = total_methods

        class_section = report.section("Selected classes")
        for item in dex_facts:
            for entry in item["facts"].classes[:60]:
                class_section.add(f"{entry['descriptor']:<60} methods={len(entry['methods'])}")

    if java_sources:
        source_section = report.section("Recovered Java sources")
        source_section.add(f"{len(java_sources)} file(s) lifted from Dalvik; smali kept beside them")
        for path in java_sources[:60]:
            source_section.add(path)
        ctx.limit(
            "Lifted Java bodies cover straight-line code, branches and common opcodes; "
            "unusual control flow stays in goto form. A local jadx adds higher fidelity."
        )

    external_java: list[str] = []
    if ctx.options.source and ctx.options.engine != "none":
        engine = engine_module.discover().find("jadx")
        if engine:
            files, error = engine_module.run_source_engine(
                [engine.path, "-d", "{out}", "--no-res", "-q", ctx.path], ".java"
            )
            if error:
                ctx.limit(f"The local jadx engine produced no Java output: {error}")
            else:
                for relative, text in files:
                    path = f"sources/jadx/{relative}"
                    if ctx.add_artifact(path, text, kind="source"):
                        external_java.append(path)
                if external_java:
                    ctx.observe(f"{len(external_java)} Java file(s) came from the local jadx engine.")
                    java_sources.extend(external_java)
                    external_section = report.section("External Java sources (local jadx)")
                    for path in external_java[:60]:
                        external_section.add(path)

    if "resources.arsc" in lowercase:
        ctx.limit("resources.arsc is inventoried but resource values are not decoded to names in this build.")

    report.payload = {
        "entries": names,
        "manifest": package_facts,
        "manifest_xml": render_xml(manifest_elements) if manifest_elements else None,
        "dex": [
            {
                "name": item["name"],
                "size": item["size"],
                **item["facts"].summary(),
                "classes": item["facts"].classes,
            }
            for item in dex_facts
        ],
        "native_libraries": native_entries,
        "signature_files": signature_entries,
        "assets": assets[:500],
        "source": {"language": "java", "files": java_sources, "bodies": "smali", "external": external_java},
    }
    total_dex_classes = sum(len(item["facts"].classes) for item in dex_facts)
    report.coverage = {
        "status": "complete" if len(dex_facts) == min(len(dex_entries), MAX_DEX_FILES) else "partial",
        "examined": len(dex_facts),
        "total": len(dex_entries),
        "exhausted": len(dex_facts) >= len(dex_entries),
    }
    if total_dex_classes == 0:
        ctx.limit("No dex class definitions were decoded from this package.")
    report.next_steps.append("Open sources/AndroidManifest.xml for the decoded manifest tree.")
    report.next_steps.append("Open dex*/java/ for lifted Java and dex*/sources/ for the smali bodies.")
    report.next_steps.append("Java lifting is built in; a local jadx adds fidelity and signature checks need apksigner.")
    return report
