"""Native image reader for PE, ELF and Mach-O containers.

The reader reports layout, imports, exports, symbols, notes, mitigations and
language/runtime metadata from the bytes themselves. Disassembly is delegated
to an already-installed ``objdump`` when one exists; nothing is downloaded and
no analysis engine is configured.
"""

from __future__ import annotations

import os
import re
import struct
from typing import Any

from .. import engines as engine_module
from ..context import Context
from ..errors import FormatError
from ..report import Report
from ..util import Reader, entropy, hexdump, human_bytes, human_int, printable_strings, shorten

SECTION_CHARACTERISTICS = {
    0x00000020: "code",
    0x00000040: "initialized-data",
    0x00000080: "uninitialized-data",
    0x02000000: "discardable",
    0x04000000: "not-cached",
    0x08000000: "not-paged",
    0x10000000: "shared",
    0x20000000: "executable",
    0x40000000: "readable",
    0x80000000: "writable",
}

ELF_SECTION_TYPES = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    10: "SHLIB",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
    16: "PREINIT_ARRAY",
    17: "GROUP",
    18: "SYMTAB_SHNDX",
}

ELF_SYMBOL_TYPES = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 5: "COMMON", 6: "TLS"}

ELF_MACHINES = {
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    42: "SuperH",
    50: "IA-64",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
    258: "LoongArch",
}

MACHO_LOAD_COMMANDS = {
    0x1: "LC_SEGMENT",
    0x2: "LC_SYMTAB",
    0x4: "LC_THREAD",
    0x5: "LC_UNIXTHREAD",
    0xB: "LC_DYSYMTAB",
    0xC: "LC_LOAD_DYLIB",
    0xD: "LC_ID_DYLIB",
    0xE: "LC_LOAD_DYLINKER",
    0x19: "LC_SEGMENT_64",
    0x1B: "LC_UUID",
    0x1D: "LC_CODE_SIGNATURE",
    0x1E: "LC_SEGMENT_SPLIT_INFO",
    0x26: "LC_FUNCTION_STARTS",
    0x28: "LC_MAIN",
    0x32: "LC_BUILD_VERSION",
    0x33: "LC_DYLD_EXPORTS_TRIE",
    0x34: "LC_DYLD_CHAINED_FIXUPS",
    0x38: "LC_LOAD_DYLIB_2",
}

GO_BUILDINFO_RE = re.compile(rb"go1\.\d+(?:\.\d+)?[A-Za-z0-9.+]*")
RUST_VERSION_RE = re.compile(rb"rustc-?\s*(\d+\.\d+\.\d+)[^\x00]{0,120}")


def analyze(ctx: Context) -> Report:
    format_id = ctx.format_id
    ctx.stage(f"parsing {format_id} headers")
    if format_id == "elf":
        report = _analyze_elf(ctx)
    elif format_id == "pe":
        report = _analyze_pe(ctx)
    elif format_id == "macho":
        report = _analyze_macho(ctx)
    else:
        raise FormatError(f"unsupported native format '{format_id}'")
    ctx.stage(f"{format_id}: {len(report.sections)} section(s) of evidence")
    _language_facts(ctx, report)
    _external_disassembly(ctx, report)
    return report


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


def _string_table(data: bytes, offset: int, size: int) -> bytes:
    return data[offset : offset + size]


def _cstring_at(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("utf-8", "replace")


def _strings_section(ctx: Context, report: Report) -> list[dict[str, Any]]:
    strings = printable_strings(ctx.data, min_len=5, limit=min(ctx.options.max_strings, 4000), max_bytes=16 * 1024 * 1024)
    if strings:
        section = report.section(f"Strings ({len(strings)} shown)")
        for item in strings[:100]:
            section.add(f"0x{item['offset']:08x}  {shorten(item['text'], 120)}")
        if len(strings) > 100:
            section.add(f"... {len(strings) - 100} more")
        stem = os.path.splitext(os.path.basename(ctx.path))[0] or "binary"
        ctx.add_artifact(
            f"sources/{stem}.strings.txt",
            "\n".join(f"0x{item['offset']:08x}\t{item['text']}" for item in strings),
            kind="strings",
        )
    report.payload["strings"] = strings[:600]
    return strings


def _language_facts(ctx: Context, report: Report) -> None:
    data = bytes(ctx.data[: min(ctx.size, 8 * 1024 * 1024)])
    facts: dict[str, Any] = {}
    go_matches = GO_BUILDINFO_RE.findall(data)
    if go_matches:
        facts["go_version"] = go_matches[0].decode("latin-1")
    if b"Go build ID:" in data or b"\xff Go buildinf:" in data:
        facts["go_buildinfo"] = True
    rust_matches = RUST_VERSION_RE.findall(data)
    if rust_matches:
        facts["rust_version"] = rust_matches[0].decode("latin-1")
    if b"cargo/registry" in data or b".rustc" in data:
        facts["rust_markers"] = True
    for marker, name in (
        (b"pyinstaller", "PyInstaller"),
        (b"python3", "CPython runtime"),
        (b"Electron", "Electron"),
        (b"napi_", "Node-API addon"),
        (b"mscoree.dll", "CLR host"),
        (b"UnityPlayer", "Unity player"),
        (b"flutter_engine", "Flutter engine"),
        (b"Xamarin", "Xamarin"),
        (b"golang", "Go"),
    ):
        if marker in data:
            facts.setdefault("markers", []).append(name)
    if facts:
        section = report.section("Language and runtime markers")
        for key, value in facts.items():
            section.add(f"{key:<18} {value}")
        report.payload["language"] = facts
        if facts.get("rust_version") or facts.get("rust_markers"):
            ctx.observe("Rust build markers are present; symbol names may be mangled.")


def _external_disassembly(ctx: Context, report: Report) -> None:
    if not ctx.options.disassemble or ctx.options.engine == "none":
        return
    engines = engine_module.discover()
    engine = engines.find("objdump") or engines.find("llvm-objdump")
    if engine is None:
        ctx.limit(
            "No local objdump/llvm-objdump is installed. This build never downloads an "
            "engine; native pseudocode needs a provider such as Hopper, Ghidra or IDA."
        )
        return
    argv = [engine.path, "-d", "--no-show-raw-insn", ctx.path]
    try:
        code, stdout, stderr = engine_module.run_tool(argv, timeout=180)
    except OSError as exc:
        ctx.limit(f"The local {engine.name} engine could not be started: {exc}")
        return
    if code != 0 or not stdout.strip():
        ctx.limit(f"Local {engine.name} returned no disassembly: {stderr.strip()[:200]}")
        return
    lines = stdout.splitlines()
    if len(lines) > 6000:
        lines = lines[:6000]
        ctx.limit("Disassembly output was capped at 6000 lines.")
    stem = os.path.splitext(os.path.basename(ctx.path))[0] or "binary"
    ctx.add_artifact(f"sources/{stem}.objdump.asm", "\n".join(lines), kind="disassembly")
    report.section(f"Disassembly ({engine.name}, local engine)").lines.extend(line[:200] for line in lines[:200])
    report.payload["disassembly_engine"] = {"name": engine.name, "path": engine.path, "lines": len(lines)}
    ctx.observe(f"Disassembly was produced by the local {engine.name} executable.")


def _finish(report: Report, ctx: Context, examined: int, total: int) -> None:
    report.coverage = {
        "status": "complete" if examined >= total else "partial",
        "examined": examined,
        "total": total,
        "exhausted": examined >= total,
    }
    report.summary.setdefault("entropy", entropy(ctx.data))


# ---------------------------------------------------------------------------
# PE
# ---------------------------------------------------------------------------


def _analyze_pe(ctx: Context) -> Report:
    data = bytes(ctx.data[: ctx.size])
    reader = Reader(data, "<", 0, "pe")
    reader.seek(0x3C)
    pe_offset = reader.u32()
    reader.seek(pe_offset)
    if reader.read(4) != b"PE\x00\x00":
        raise FormatError("PE signature missing")
    machine = reader.u16()
    section_count = reader.u16()
    timestamp = reader.u32()
    reader.u32()
    reader.u32()
    optional_size = reader.u16()
    characteristics = reader.u16()
    optional_start = reader.pos
    magic = reader.u16()
    pe32_plus = magic == 0x20B
    reader.u8()
    reader.u8()
    reader.u32()
    reader.u32()
    reader.u32()
    entry = reader.u32()
    base_of_code = reader.u32()
    if not pe32_plus:
        reader.u32()
    image_base = reader.u64() if pe32_plus else reader.u32()
    section_alignment = reader.u32()
    file_alignment = reader.u32()
    reader.u16()
    reader.u16()
    reader.u16()
    reader.u16()
    reader.u16()
    reader.u16()
    reader.u32()
    image_size = reader.u32()
    headers_size = reader.u32()
    checksum = reader.u32()
    subsystem = reader.u16()
    dll_characteristics = reader.u16()
    if pe32_plus:
        stack_reserve = reader.u64()
        reader.u64()
        reader.u64()
        reader.u64()
    else:
        stack_reserve = reader.u32()
        reader.u32()
        reader.u32()
        reader.u32()
    reader.u32()
    directory_count = reader.u32()
    directories: list[tuple[int, int]] = []
    for _ in range(min(directory_count, 16)):
        directories.append((reader.u32(), reader.u32()))
    while len(directories) < 16:
        directories.append((0, 0))
    reader.seek(optional_start + optional_size)
    sections: list[dict[str, Any]] = []
    for _ in range(section_count):
        name = reader.read(8).rstrip(b"\x00").decode("latin-1")
        virtual_size = reader.u32()
        virtual_address = reader.u32()
        raw_size = reader.u32()
        raw_pointer = reader.u32()
        reader.u32()
        reader.u32()
        reader.u16()
        reader.u16()
        section_characteristics = reader.u32()
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_pointer": raw_pointer,
                "characteristics": section_characteristics,
                "perm": [label for bit, label in SECTION_CHARACTERISTICS.items() if section_characteristics & bit],
            }
        )

    def rva_to_offset(rva: int) -> int:
        for section in sections:
            start = section["virtual_address"]
            if start <= rva < start + max(section["virtual_size"], section["raw_size"]):
                return section["raw_pointer"] + (rva - start)
        return 0

    def read_rva(rva: int, size: int) -> bytes:
        offset = rva_to_offset(rva)
        if offset <= 0 or offset + size > len(data):
            return b""
        return data[offset : offset + size]

    report = Report(kind="pe", label=f"PE32{'+' if pe32_plus else ''} image")
    report.summary.update(
        {
            "machine": _pe_machine(machine),
            "subsystem": _pe_subsystem(subsystem),
            "image_base": f"0x{image_base:x}",
            "entry_point": f"0x{entry:x}",
            "sections": len(sections),
            "timestamp": timestamp,
            "image_size": human_bytes(image_size),
            "characteristics": f"0x{characteristics:04x}",
            "fingerprint": f"{machine:04x}:{timestamp:08x}:{image_size:x}",
        }
    )

    section_lines = report.section("Sections")
    for section in sections:
        section_lines.add(
            f"{section['name']:<10} rva=0x{section['virtual_address']:08x} vsize=0x{section['virtual_size']:<8x} "
            f"raw=0x{section['raw_pointer']:08x} size=0x{section['raw_size']:<8x} {','.join(section['perm'])}"
        )

    imports, import_count = _pe_imports(data, directories, read_rva, pe32_plus)
    if imports:
        import_section = report.section("Imports")
        for dll, functions in imports:
            import_section.add(f"{dll} ({len(functions)} symbols)")
            for symbol in functions[:40]:
                import_section.add(f"    {symbol}")
            if len(functions) > 40:
                import_section.add(f"    ... {len(functions) - 40} more")
    else:
        report.section("Imports").add("(none)")

    exports = _pe_exports(read_rva, directories)
    export_section = report.section("Exports")
    if exports:
        for name, rva in exports[:200]:
            export_section.add(f"{name:<50} rva=0x{rva:08x}")
    else:
        export_section.add("(none)")

    debug_entries = _pe_debug(data, directories, rva_to_offset)
    if debug_entries:
        debug_section = report.section("Debug directory")
        for item in debug_entries:
            debug_section.add(str(item))

    certificates = _pe_certificates(data, directories)
    if certificates:
        report.section("Authenticode").lines.extend(certificates)

    resources = _pe_resources(data, directories, rva_to_offset, read_rva)
    if resources:
        report.section("Resources").lines.extend(resources)

    mitigations = _pe_mitigations(dll_characteristics, directories)
    report.section("Mitigations").lines.extend(mitigations)

    strings = _strings_section(ctx, report)
    payload = {
        "machine": _pe_machine(machine),
        "subsystem": _pe_subsystem(subsystem),
        "pe32_plus": pe32_plus,
        "image_base": image_base,
        "entry_point": entry,
        "timestamp": timestamp,
        "sections": sections,
        "imports": [{"dll": dll, "functions": functions} for dll, functions in imports],
        "import_count": import_count,
        "exports": [{"name": name, "rva": rva} for name, rva in exports],
        "debug": debug_entries,
        "certificates": certificates,
        "resources": resources,
        "mitigations": mitigations,
        "strings": strings[:600],
    }
    report.payload = payload
    _finish(report, ctx, len(sections), len(sections))
    report.next_steps.append("Read the sections and imports before choosing a function to trace.")
    report.next_steps.append("Native pseudocode needs a local provider; none is installed or downloaded by this build.")
    return report


def _pe_machine(machine: int) -> str:
    return {
        0x014C: "x86",
        0x0166: "MIPS",
        0x01C0: "ARM",
        0x01C4: "ARMv7",
        0x8664: "x86-64",
        0xAA64: "AArch64",
        0x0200: "IA-64",
    }.get(machine, f"machine 0x{machine:04x}")


def _pe_subsystem(subsystem: int) -> str:
    return {
        1: "native",
        2: "windows-gui",
        3: "windows-console",
        5: "os2-console",
        7: "posix-console",
        9: "windows-ce",
        10: "efi-application",
        14: "xbox",
    }.get(subsystem, f"subsystem {subsystem}")


def _pe_imports(
    data: bytes, directories: list[tuple[int, int]], read_rva, pe32_plus: bool
) -> tuple[list[tuple[str, list[str]]], int]:
    imports: list[tuple[str, list[str]]] = []
    total = 0
    width = 8 if pe32_plus else 4
    rva, size = directories[1]
    if rva == 0:
        return imports, total
    descriptor_offset = _resolve_rva(data, directories, rva)
    if descriptor_offset <= 0:
        return imports, total
    reader = Reader(data, "<", descriptor_offset, "imports")
    for _ in range(512):
        original_thunk = reader.u32()
        reader.u32()
        reader.u32()
        name_rva = reader.u32()
        first_thunk = reader.u32()
        if original_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break
        name_offset = _resolve_rva(data, directories, name_rva)
        dll = _cstring_at(data, name_offset) if name_offset else f"<dll rva 0x{name_rva:x}>"
        thunk_rva = original_thunk or first_thunk
        functions: list[str] = []
        thunk_offset = _resolve_rva(data, directories, thunk_rva)
        if thunk_offset > 0:
            cursor = Reader(data, "<", thunk_offset, "thunks")
            for _ in range(4096):
                if cursor.remaining < width:
                    break
                value = cursor.u64() if width == 8 else cursor.u32()
                if value == 0:
                    break
                if value >> (width * 8 - 1):
                    functions.append(f"ordinal#{value & 0xFFFF}")
                else:
                    hint_offset = _resolve_rva(data, directories, value & 0x7FFFFFFF)
                    if hint_offset > 0:
                        functions.append(_cstring_at(data, hint_offset + 2))
                total += 1
        imports.append((dll, functions))
    return imports, total


def _resolve_rva(data: bytes, directories: list[tuple[int, int]], rva: int) -> int:
    """Resolve an RVA through the section table reconstructed from the PE header."""
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
        optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        table = pe_offset + 24 + optional_size
        for index in range(section_count):
            entry = table + index * 40
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", data, entry + 8)
            span = max(virtual_size, raw_size)
            if virtual_address <= rva < virtual_address + span:
                return raw_pointer + (rva - virtual_address)
    except struct.error:
        return 0
    return 0


def _pe_exports(read_rva, directories: list[tuple[int, int]]) -> list[tuple[str, int]]:
    rva, size = directories[0]
    if rva == 0:
        return []
    raw = read_rva(rva, 40)
    if len(raw) < 40:
        return []
    reader = Reader(raw, "<", 0, "exports")
    reader.u32()
    reader.u32()
    reader.u16()
    reader.u16()
    name_rva = reader.u32()
    base = reader.u32()
    function_count = reader.u32()
    name_count = reader.u32()
    functions_rva = reader.u32()
    names_rva = reader.u32()
    ordinals_rva = reader.u32()
    functions_raw = read_rva(functions_rva, min(function_count, 4096) * 4)
    names_raw = read_rva(names_rva, min(name_count, 4096) * 4)
    ordinals_raw = read_rva(ordinals_rva, min(name_count, 4096) * 2)
    results: list[tuple[str, int]] = []
    if len(names_raw) >= 4 and len(functions_raw) >= 4 and len(ordinals_raw) >= 2:
        name_count = min(name_count, len(names_raw) // 4, len(ordinals_raw) // 2, 4096)
        for index in range(name_count):
            name_rva_item = struct.unpack_from("<I", names_raw, index * 4)[0]
            ordinal = struct.unpack_from("<H", ordinals_raw, index * 2)[0]
            name_offset = _resolve_rva_stub(read_rva, name_rva_item)
            name = name_offset or f"ordinal_{base + ordinal}"
            if ordinal * 4 + 4 <= len(functions_raw):
                function_rva = struct.unpack_from("<I", functions_raw, ordinal * 4)[0]
                results.append((name, function_rva))
    return results


def _resolve_rva_stub(read_rva, rva: int) -> str:
    raw = read_rva(rva, 512)
    if not raw:
        return ""
    end = raw.find(b"\x00")
    return raw[: end if end >= 0 else len(raw)].decode("latin-1", "replace")


def _pe_debug(data: bytes, directories: list[tuple[int, int]], rva_to_offset) -> list[str]:
    rva, size = directories[6]
    if rva == 0:
        return []
    offset = rva_to_offset(rva)
    if offset <= 0:
        return []
    results: list[str] = []
    count = min(size // 28, 32)
    for index in range(count):
        entry = offset + index * 28
        if entry + 28 > len(data):
            break
        characteristics, timestamp, major, minor, debug_type, data_size, data_rva, data_pointer = struct.unpack_from(
            "<IIHHIIII", data, entry
        )
        kind = {1: "coff", 2: "codeview", 12: "pdb", 16: "repro"}.get(debug_type, str(debug_type))
        detail = ""
        if data_pointer and data_pointer + data_size <= len(data):
            blob = data[data_pointer : data_pointer + data_size]
            if blob[:4] == b"RSDS" and len(blob) >= 24:
                guid = blob[4:20]
                age = struct.unpack_from("<I", blob, 20)[0]
                pdb = blob[24:].split(b"\x00", 1)[0].decode("latin-1", "replace")
                detail = f" guid={guid.hex()} age={age} pdb={pdb}"
            elif blob[:4] == b"NB10":
                pdb = blob[16:].split(b"\x00", 1)[0].decode("latin-1", "replace")
                detail = f" pdb={pdb}"
        results.append(f"type={kind} size={data_size} timestamp={timestamp}{detail}")
    return results


def _pe_certificates(data: bytes, directories: list[tuple[int, int]]) -> list[str]:
    rva, size = directories[4]
    if rva == 0 or size == 0:
        return []
    offset = rva if rva < len(data) else 0
    results: list[str] = []
    cursor = 0
    while cursor + 8 <= size and offset + cursor + 8 <= len(data):
        length, revision, cert_type = struct.unpack_from("<IHH", data, offset + cursor)
        if length < 8:
            break
        kind = {1: "x509", 2: "pkcs-signed-data", 3: "reserved", 4: "ts-stack-signed"}.get(cert_type, str(cert_type))
        results.append(f"WIN_CERTIFICATE length={length} revision={revision:#06x} type={kind}")
        cursor += (length + 7) & ~7
        if len(results) >= 16:
            break
    return results


def _pe_resources(data: bytes, directories: list[tuple[int, int]], rva_to_offset, read_rva) -> list[str]:
    rva, size = directories[2]
    if rva == 0:
        return []
    offset = rva_to_offset(rva)
    if offset <= 0 or offset + 16 > len(data):
        return []
    results: list[str] = []

    def walk(base: int, level: int, prefix: str) -> None:
        if level > 3 or len(results) > 200 or base + 16 > len(data):
            return
        characteristics, timestamp, major, minor, named, ids = struct.unpack_from("<IIHHHH", data, base)
        for index in range(min(named + ids, 64)):
            entry = base + 16 + index * 8
            if entry + 8 > len(data):
                break
            name_field, offset_field = struct.unpack_from("<II", data, entry)
            label = None
            if name_field & 0x80000000:
                name_offset = rva_to_offset(rva + (name_field & 0x7FFFFFFF))
                if name_offset > 0:
                    length = struct.unpack_from("<H", data, name_offset)[0]
                    label = data[name_offset + 2 : name_offset + 2 + length * 2].decode("utf-16-le", "replace")
            else:
                label = str(name_field)
            if offset_field & 0x80000000:
                walk(rva_to_offset(rva + (offset_field & 0x7FFFFFFF)), level + 1, f"{prefix}/{label}")
            else:
                data_entry = rva_to_offset(rva + offset_field)
                if data_entry > 0 and data_entry + 16 <= len(data):
                    data_rva, data_size, codepage, _ = struct.unpack_from("<IIII", data, data_entry)
                    kind = "named" if name_field & 0x80000000 else "id"
                    results.append(f"{prefix}/{label} ({kind}) rva=0x{data_rva:08x} size={data_size}")

    walk(offset, 0, "")
    return results


def _pe_mitigations(dll_characteristics: int, directories: list[tuple[int, int]]) -> list[str]:
    results = []
    results.append(f"ASLR {'enabled' if dll_characteristics & 0x0040 else 'disabled'}")
    results.append(f"DEP/NX {'enabled' if dll_characteristics & 0x0100 else 'disabled'}")
    results.append(f"CFG {'enabled' if dll_characteristics & 0x4000 else 'disabled'}")
    if directories[5][0]:
        results.append("load config present")
    return results


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------


def _analyze_elf(ctx: Context) -> Report:
    data = bytes(ctx.data[: ctx.size])
    probe = Reader(data, "<", 0, "elf")
    if probe.read(4) != b"\x7fELF":
        raise FormatError("ELF magic missing")
    elf_class = probe.u8()
    endian_flag = probe.u8()
    endian = "<" if endian_flag == 1 else ">"
    probe.u8()  # EI_VERSION
    os_abi = probe.u8()
    probe.u8()  # EI_ABIVERSION
    probe.skip(7)
    reader = Reader(data, endian, 16, "elf")
    e_type = reader.u16()
    e_machine = reader.u16()
    reader.u32()  # e_version
    entry = reader.u64() if elf_class == 2 else reader.u32()
    phoff = reader.u64() if elf_class == 2 else reader.u32()
    shoff = reader.u64() if elf_class == 2 else reader.u32()
    reader.u32()  # e_flags
    reader.u16()  # e_ehsize
    phentsize = reader.u16()
    phnum = reader.u16()
    shentsize = reader.u16()
    shnum = reader.u16()
    shstrndx = reader.u16()

    sections: list[dict[str, Any]] = []
    if shoff and shnum and shoff + shentsize * shnum <= len(data):
        for index in range(shnum):
            base = shoff + index * shentsize
            if elf_class == 2:
                name, section_type, flags, addr, offset, size, link, info, align, entry_size = struct.unpack_from(
                    endian + "IIQQQQIIQQ", data, base
                )
            else:
                name, section_type, flags, addr, offset, size, link, info, align, entry_size = struct.unpack_from(
                    endian + "IIIIIIIIII", data, base
                )
            sections.append(
                {
                    "index": index,
                    "name_offset": name,
                    "type": section_type,
                    "flags": flags,
                    "addr": addr,
                    "offset": offset,
                    "size": size,
                    "link": link,
                    "entsize": entry_size,
                }
            )
    names = b""
    if shstrndx < len(sections):
        names = data[sections[shstrndx]["offset"] : sections[shstrndx]["offset"] + sections[shstrndx]["size"]]
    for section in sections:
        section["name"] = _cstring_at(names, section["name_offset"]) if names else f"section_{section['index']}"

    report = Report(kind="elf", label="ELF image")
    report.summary.update(
        {
            "class": "64-bit" if elf_class == 2 else "32-bit",
            "endian": "little" if endian == "<" else "big",
            "type": {1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}.get(e_type, str(e_type)),
            "machine": ELF_MACHINES.get(e_machine, f"machine {e_machine}"),
            "os_abi": os_abi,
            "entry_point": f"0x{entry:x}",
            "sections": len(sections),
            "segments": phnum,
        }
    )
    section_lines = report.section("Sections")
    for section in sections:
        kind = ELF_SECTION_TYPES.get(section["type"], str(section["type"]))
        section_lines.add(
            f"[{section['index']:>2}] {section['name']:<22} {kind:<12} addr=0x{section['addr']:09x} "
            f"off=0x{section['offset']:08x} size=0x{section['size']:<8x} flags=0x{section['flags']:x}"
        )

    segments: list[dict[str, Any]] = []
    if phoff and phnum and phoff + phentsize * phnum <= len(data):
        for index in range(phnum):
            base = phoff + index * phentsize
            if elf_class == 2:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                    endian + "IIQQQQQQ", data, base
                )
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(
                    endian + "IIIIIIII", data, base
                )
            segments.append(
                {
                    "type": p_type,
                    "flags": p_flags,
                    "offset": p_offset,
                    "vaddr": p_vaddr,
                    "filesz": p_filesz,
                    "memsz": p_memsz,
                }
            )
    if segments:
        segment_section = report.section("Segments")
        for segment in segments:
            perms = "".join(
                letter for bit, letter in ((4, "R"), (2, "W"), (1, "X")) if segment["flags"] & bit
            )
            segment_section.add(
                f"type={segment['type']:<2} {perms:<3} vaddr=0x{segment['vaddr']:012x} "
                f"filesz=0x{segment['filesz']:<8x} memsz=0x{segment['memsz']:x}"
            )

    dynamic = _elf_dynamic(data, sections, endian, elf_class)
    if dynamic["needed"] or dynamic["soname"]:
        dynamic_section = report.section("Dynamic")
        if dynamic["soname"]:
            dynamic_section.add(f"soname   {dynamic['soname']}")
        for item in dynamic["needed"]:
            dynamic_section.add(f"needed   {item}")
        for item in dynamic["rpath"]:
            dynamic_section.add(f"rpath    {item}")

    symbols = _elf_symbols(data, sections, endian, elf_class)
    exports = [item for item in symbols if item["scope"] == "global" and item["type"] in ("FUNC", "OBJECT")]
    if exports:
        export_section = report.section("Exported symbols")
        for item in exports[:200]:
            export_section.add(f"{item['name']:<60} {item['type']:<8} 0x{item['value']:x} size={item['size']}")
    if dynamic["imports"]:
        import_section = report.section("Imported symbols")
        for item in dynamic["imports"][:200]:
            import_section.add(item)

    notes = _elf_notes(data, sections, segments, endian)
    if notes:
        note_section = report.section("Notes")
        for note in notes[:80]:
            note_section.add(str(note))
        report.payload["notes"] = notes

    _strings_section(ctx, report)
    report.payload.update(
        {
            "class": elf_class,
            "endian": endian,
            "type": e_type,
            "machine": e_machine,
            "entry_point": entry,
            "sections": sections,
            "segments": segments,
            "dynamic": dynamic,
            "symbols": symbols[:2000],
        }
    )
    _finish(report, ctx, len(sections), len(sections))
    report.next_steps.append("Use exported symbols and imports to choose a starting function.")
    report.next_steps.append("No provider is configured; pseudocode needs a local Hopper/Ghidra/IDA installation.")
    return report


def _elf_dynamic(data: bytes, sections: list[dict[str, Any]], endian: str, elf_class: int) -> dict[str, Any]:
    result: dict[str, Any] = {"needed": [], "soname": None, "rpath": [], "imports": []}
    dynamic = next((section for section in sections if section["type"] == 6), None)
    dynstr = None
    dynsym = next((section for section in sections if section["type"] == 11), None)
    if dynamic is None:
        return result
    strtab_index = dynamic.get("link")
    if strtab_index is not None and 0 <= strtab_index < len(sections):
        target = sections[strtab_index]
        dynstr = data[target["offset"] : target["offset"] + target["size"]]
    if dynstr is None:
        return result
    entry_size = 16 if elf_class == 2 else 8
    count = dynamic["size"] // entry_size if entry_size else 0
    offset = dynamic["offset"]
    imports: list[str] = []
    for index in range(min(count, 4096)):
        base = offset + index * entry_size
        if base + entry_size > len(data):
            break
        if elf_class == 2:
            tag, value = struct.unpack_from(endian + "qQ", data, base)
        else:
            tag, value = struct.unpack_from(endian + "iI", data, base)
        if tag == 0:
            break
        if tag == 1:
            name = _cstring_at(dynstr, value)
            if name:
                result["needed"].append(name)
        elif tag == 14:
            result["soname"] = _cstring_at(dynstr, value)
        elif tag in (15, 29):
            name = _cstring_at(dynstr, value)
            if name:
                result["rpath"].append(name)
        elif tag == 0x6FFFFEFA or tag == 0x6FFFFFF9:
            continue
    if dynsym is not None:
        symstr = b""
        if 0 <= dynsym["link"] < len(sections):
            target = sections[dynsym["link"]]
            symstr = data[target["offset"] : target["offset"] + target["size"]]
        size = 24 if elf_class == 2 else 16
        for index in range(1, min(dynsym["size"] // size if size else 0, 20000)):
            base = dynsym["offset"] + index * size
            if base + size > len(data):
                break
            if elf_class == 2:
                name_index, info, _other, shndx, value, sym_size = struct.unpack_from(endian + "IBBHQQ", data, base)
            else:
                name_index, value, sym_size, info, _other, shndx = struct.unpack_from(endian + "IIIBBH", data, base)
            if shndx == 0 and name_index:
                name = _cstring_at(symstr, name_index)
                if name:
                    imports.append(name)
    result["imports"] = imports
    return result


def _elf_symbols(data: bytes, sections: list[dict[str, Any]], endian: str, elf_class: int) -> list[dict[str, Any]]:
    symbols: list[dict[str, Any]] = []
    for section in sections:
        if section["type"] not in (2, 11):
            continue
        strtab = b""
        if 0 <= section["link"] < len(sections):
            target = sections[section["link"]]
            strtab = data[target["offset"] : target["offset"] + target["size"]]
        size = 24 if elf_class == 2 else 16
        count = section["size"] // size if size else 0
        for index in range(min(count, 50000)):
            base = section["offset"] + index * size
            if base + size > len(data):
                break
            if elf_class == 2:
                name_index, info, _other, shndx, value, sym_size = struct.unpack_from(endian + "IBBHQQ", data, base)
            else:
                name_index, value, sym_size, info, _other, shndx = struct.unpack_from(endian + "IIIBBH", data, base)
            if name_index == 0:
                continue
            name = _cstring_at(strtab, name_index)
            if not name:
                continue
            binding = {0: "local", 1: "global", 2: "weak"}.get(info >> 4, str(info >> 4))
            kind = ELF_SYMBOL_TYPES.get(info & 0xF, str(info & 0xF))
            symbols.append(
                {
                    "name": name,
                    "type": kind,
                    "scope": binding,
                    "section_index": shndx,
                    "value": value,
                    "size": sym_size,
                    "table": "symtab" if section["type"] == 2 else "dynsym",
                }
            )
    return symbols


def _elf_notes(data: bytes, sections: list[dict[str, Any]], segments: list[dict[str, Any]], endian: str) -> list[dict[str, Any]]:
    notes: list[dict[str, Any]] = []
    blocks: list[tuple[int, int]] = [(section["offset"], section["size"]) for section in sections if section["type"] == 7]
    blocks.extend((segment["offset"], segment["filesz"]) for segment in segments if segment["type"] == 4)
    for offset, size in blocks[:16]:
        cursor = offset
        end = min(offset + size, len(data))
        while cursor + 12 <= end and len(notes) < 200:
            namesz, descsz, note_type = struct.unpack_from(endian + "III", data, cursor)
            cursor += 12
            if namesz > 1024 or descsz > 65536 or cursor + namesz + descsz > end:
                break
            name = data[cursor : cursor + namesz].split(b"\x00", 1)[0].decode("latin-1", "replace")
            cursor += (namesz + 3) & ~3
            desc = data[cursor : cursor + descsz]
            cursor += (descsz + 3) & ~3
            entry: dict[str, Any] = {"name": name, "type": note_type, "desc_size": descsz}
            if name == "GNU" and note_type == 3:
                entry["build_id"] = desc.hex()
            elif name == "GNU" and note_type == 1:
                entry["abi_tag"] = desc.hex()
            else:
                printable = "".join(chr(byte) if 0x20 <= byte < 0x7F else "." for byte in desc[:64])
                entry["desc_ascii"] = printable
            notes.append(entry)
    return notes


# ---------------------------------------------------------------------------
# Mach-O
# ---------------------------------------------------------------------------


def _analyze_macho(ctx: Context) -> Report:
    data = bytes(ctx.data[: ctx.size])
    if data[:4] == b"\xca\xfe\xba\xbe":
        return _analyze_fat_macho(ctx, data)
    reader = Reader(data, "<", 0, "macho")
    magic = reader.read(4)
    endian = "<" if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else ">"
    bits = 64 if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 32
    reader = Reader(data, endian, 4, "macho")
    cpu_type = reader.u32()
    cpu_subtype = reader.u32()
    file_type = reader.u32()
    command_count = reader.u32()
    command_size = reader.u32()
    flags = reader.u32()
    if bits == 64:
        reader.u32()

    report = Report(kind="macho", label=f"Mach-O {bits}-bit image")
    report.summary.update(
        {
            "bits": bits,
            "cputype": cpu_type,
            "cpusubtype": cpu_subtype,
            "file_type": {1: "object", 2: "execute", 6: "dynamic-library", 8: "bundle"}.get(file_type, str(file_type)),
            "load_commands": command_count,
            "flags": f"0x{flags:08x}",
        }
    )

    commands: list[dict[str, Any]] = []
    segments: list[dict[str, Any]] = []
    dylibs: list[str] = []
    entry_point = None
    uuid = None
    symbol_table: dict[str, Any] | None = None
    cursor = reader.pos
    end = cursor + command_size
    for _ in range(min(command_count, 4096)):
        if cursor + 8 > min(end, len(data)):
            break
        cmd, size = struct.unpack_from(endian + "II", data, cursor)
        name = MACHO_LOAD_COMMANDS.get(cmd & 0x7FFFFFFF, f"cmd_0x{cmd:x}")
        commands.append({"cmd": name, "size": size})
        if size < 8 or cursor + size > len(data):
            break
        if (cmd & 0x7FFFFFFF) == 0x1 and bits == 32:
            segname = data[cursor + 8 : cursor + 24].split(b"\x00", 1)[0].decode("latin-1", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(endian + "IIII", data, cursor + 24)
            segments.append({"name": segname, "vmaddr": vmaddr, "vmsize": vmsize, "fileoff": fileoff, "filesize": filesize})
        elif (cmd & 0x7FFFFFFF) == 0x19 and bits == 64:
            segname = data[cursor + 8 : cursor + 24].split(b"\x00", 1)[0].decode("latin-1", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(endian + "QQQQ", data, cursor + 24)
            segments.append({"name": segname, "vmaddr": vmaddr, "vmsize": vmsize, "fileoff": fileoff, "filesize": filesize})
        elif (cmd & 0x7FFFFFFF) in (0xC, 0xD, 0x38):
            name_offset = struct.unpack_from(endian + "I", data, cursor + 8)[0]
            dylibs.append(_cstring_at(data, cursor + name_offset))
        elif (cmd & 0x7FFFFFFF) == 0x28:
            entry_offset = struct.unpack_from(endian + "Q", data, cursor + 8)[0]
            entry_point = entry_offset
        elif (cmd & 0x7FFFFFFF) == 0x1B:
            uuid = data[cursor + 8 : cursor + 24].hex()
        elif (cmd & 0x7FFFFFFF) == 0x2:
            symoff, nsyms, stroff, strsize = struct.unpack_from(endian + "IIII", data, cursor + 8)
            symbol_table = {"symoff": symoff, "nsyms": nsyms, "stroff": stroff, "strsize": strsize}
        cursor += size

    command_section = report.section("Load commands")
    for item in commands[:120]:
        command_section.add(f"{item['cmd']:<28} size={item['size']}")
    if len(commands) > 120:
        command_section.add(f"... {len(commands) - 120} more")

    if segments:
        segment_section = report.section("Segments")
        for segment in segments:
            segment_section.add(
                f"{segment['name']:<16} vmaddr=0x{segment['vmaddr']:x} vmsize=0x{segment['vmsize']:x} "
                f"fileoff=0x{segment['fileoff']:x} filesize=0x{segment['filesize']:x}"
            )
    if dylibs:
        report.section("Linked libraries").lines.extend(dylibs[:100])
    if uuid:
        report.summary["uuid"] = uuid
    if entry_point is not None:
        report.summary["entry_offset"] = f"0x{entry_point:x}"

    symbols: list[dict[str, Any]] = []
    if symbol_table:
        string_table = data[symbol_table["stroff"] : symbol_table["stroff"] + symbol_table["strsize"]]
        entry_size = 16 if bits == 64 else 12
        for index in range(min(symbol_table["nsyms"], 50000)):
            base = symbol_table["symoff"] + index * entry_size
            if base + entry_size > len(data):
                break
            if bits == 64:
                strx, ntype, sect, desc, value = struct.unpack_from(endian + "IBBHQ", data, base)
            else:
                strx, ntype, sect, desc, value = struct.unpack_from(endian + "IBBHI", data, base)
            symbol_name = _cstring_at(string_table, strx)
            if symbol_name:
                symbols.append(
                    {
                        "name": symbol_name,
                        "type": ntype,
                        "section": sect,
                        "value": value,
                        "external": bool(ntype & 0x01),
                    }
                )
    if symbols:
        exported = [item for item in symbols if item["external"]]
        symbol_section = report.section("Symbols")
        for item in (exported or symbols)[:200]:
            symbol_section.add(f"0x{item['value']:012x} {item['name']}")
        report.payload["symbols"] = symbols[:5000]

    _strings_section(ctx, report)
    report.payload.update(
        {
            "bits": bits,
            "cputype": cpu_type,
            "file_type": file_type,
            "load_commands": commands,
            "segments": segments,
            "dylibs": dylibs,
            "uuid": uuid,
            "entry_offset": entry_point,
        }
    )
    _finish(report, ctx, len(commands), len(commands))
    report.next_steps.append("Native pseudocode needs a local provider; this build installs nothing.")
    return report


def _analyze_fat_macho(ctx: Context, data: bytes) -> Report:
    reader = Reader(data, ">", 4, "fat macho")
    count = reader.u32()
    slices = []
    for _ in range(min(count, 32)):
        cpu, subtype, offset, size, align = reader.u32(), reader.u32(), reader.u32(), reader.u32(), reader.u32()
        slices.append({"cputype": cpu, "cpusubtype": subtype, "offset": offset, "size": size, "align": align})
    report = Report(kind="macho", label=f"Mach-O universal binary ({len(slices)} slices)")
    report.summary.update({"slices": len(slices)})
    section = report.section("Slices")
    for item in slices:
        section.add(
            f"cputype=0x{item['cputype']:x} offset=0x{item['offset']:x} size=0x{item['size']:x} align=2^{item['align']}"
        )
    _strings_section(ctx, report)
    report.payload = {"slices": slices}
    _finish(report, ctx, len(slices), len(slices))
    ctx.limit("Universal binaries are inventoried slice by slice; select one slice for full analysis.")
    return report
