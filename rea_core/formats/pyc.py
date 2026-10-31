"""Offline CPython ``.pyc`` reader: header facts, marshal graph, bytecode text.

The reader never imports or executes the artifact. Marshal decoding uses the
running interpreter, so a pyc produced by the same feature release yields full
code-object facts and disassembly; any other release keeps header and container
facts and records the decode gap as a limitation.
"""

from __future__ import annotations

import dis
import hashlib
import marshal
import os
import platform
import sys
import types
from typing import Any

from ..context import Context
from ..errors import FormatError
from ..report import Report
from ..util import Reader, human_int, shorten

#: Magic-number windows per CPython feature release. Values inside a window are
#: a local approximation: the header alone does not prove the patch release.
MAGIC_WINDOWS: tuple[tuple[int, int, str, str], ...] = (
    (3390, 3399, "3.7", "py37"),
    (3400, 3413, "3.8", "py38"),
    (3414, 3428, "3.9", "py39"),
    (3430, 3439, "3.10", "py310"),
    (3450, 3499, "3.11", "py311"),
    (3500, 3549, "3.12", "py311"),
    (3550, 3599, "3.13", "py311"),
    (3600, 3649, "3.14", "py311"),
    (3650, 3699, "3.15", "py311"),
)

MAX_CODE_OBJECTS = 5000
MAX_INSTRUCTIONS = 200_000


def version_for_magic(magic: int) -> str | None:
    for low, high, version, _layout in MAGIC_WINDOWS:
        if low <= magic <= high:
            return version
    return None


def _layout_for_magic(magic: int) -> str | None:
    for low, high, _version, layout in MAGIC_WINDOWS:
        if low <= magic <= high:
            return layout
    return None


def _header(data: bytes, size: int) -> dict[str, Any]:
    reader = Reader(data[: size], label="pyc header")
    magic = reader.u16()
    reader.skip(2)  # carriage-return + newline trailer of the 4-byte magic
    version = version_for_magic(magic)
    layout = _layout_for_magic(magic)
    flags = reader.u32()
    hash_based = bool(flags & 0x01)
    check_source = bool(flags & 0x02)
    header: dict[str, Any] = {
        "magic": magic,
        "magic_hex": f"0x{magic:04x}",
        "python_version": version or "unknown",
        "known_magic": version is not None,
        "code_layout": layout,
        "flags": flags,
        "hash_based": hash_based,
        "check_source": check_source,
    }
    if hash_based:
        header["source_hash_hex"] = reader.read(8).hex()
        header["header_size"] = 20
        header["source_size"] = reader.u32()
    else:
        header["source_mtime"] = reader.u32()
        header["source_size"] = reader.u32()
        header["header_size"] = 16
    return header


def _const_kind(value: Any) -> str:
    if isinstance(value, types.CodeType):
        return "code"
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, complex):
        return "complex"
    if isinstance(value, str):
        return "str"
    if isinstance(value, bytes):
        return "bytes"
    if isinstance(value, tuple):
        return "tuple"
    if isinstance(value, frozenset):
        return "frozenset"
    return type(value).__name__


def _const_preview(value: Any, limit: int = 60) -> Any:
    if isinstance(value, types.CodeType):
        return f"<code {value.co_name}>"
    if isinstance(value, (str, bytes)):
        text = value if isinstance(value, str) else value.decode("latin-1", "replace")
        return shorten(text, limit)
    if isinstance(value, (tuple, list, frozenset, set)):
        return f"<{type(value).__name__} len={len(value)}>"
    if isinstance(value, (int, float, complex, bool)) or value is None:
        return value
    return f"<{type(value).__name__}>"


def _collect(root: types.CodeType) -> list[types.CodeType]:
    """Walk the marshal graph once, top-level module first."""
    order: list[types.CodeType] = []
    seen: set[int] = set()
    queue = [root]
    while queue:
        code = queue.pop(0)
        if id(code) in seen or len(order) >= MAX_CODE_OBJECTS:
            continue
        seen.add(id(code))
        order.append(code)
        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                queue.append(const)
    return order


def _nested_indexes(code: types.CodeType, order: list[types.CodeType]) -> list[int]:
    positions = {id(item): index for index, item in enumerate(order)}
    nested: list[int] = []
    for const in code.co_consts:
        if isinstance(const, types.CodeType) and id(const) in positions:
            index = positions[id(const)]
            if index not in nested:
                nested.append(index)
    return nested


def _disassemble(code: types.CodeType, limit: int) -> tuple[list[str], int]:
    lines: list[str] = []
    count = 0
    try:
        instructions = dis.get_instructions(code)
    except Exception as exc:  # pragma: no cover - interpreter-specific guard
        return [f"# disassembly unavailable: {exc}"], 0
    for instruction in instructions:
        count += 1
        if count > limit:
            lines.append(f"# ... {human_int(limit)} instruction budget reached")
            break
        argument = ""
        if instruction.arg is not None:
            argument = f" {instruction.arg}"
            if instruction.argrepr:
                argument += f"  ; {instruction.argrepr}"
        lines.append(f"{instruction.offset:6d}  {instruction.opname:<30}{argument}")
    return lines, count


def analyze(ctx: Context) -> Report:
    data = bytes(ctx.data[: ctx.size])
    if len(data) < 16:
        raise FormatError("pyc file is shorter than a supported header")

    header = _header(data, ctx.size)
    report = Report(kind="python-pyc", label=f"CPython bytecode ({header['python_version']})")
    report.summary.update(
        {
            "python_version": header["python_version"],
            "magic": f"{header['magic_hex']} ({header['magic']})",
            "code_layout": header["code_layout"],
            "flags": f"0x{header['flags']:08x}",
            "hash_based": header["hash_based"],
            "check_source": header["check_source"],
            "header_size": header["header_size"],
        }
    )
    if header["hash_based"]:
        report.summary["source_hash"] = header["source_hash_hex"]
    else:
        report.summary["source_mtime"] = header["source_mtime"]
    report.summary["source_size"] = header["source_size"]

    payload: dict[str, Any] = {"header": header, "code_objects": [], "marshal": {}}
    report.payload = payload
    start = header["header_size"]
    marker = data[start : start + 1]
    report.section("Header").lines.extend(
        [
            f"magic            {header['magic_hex']} ({header['magic']})",
            f"python version   {header['python_version']}" + ("" if header["known_magic"] else " (unknown magic window)"),
            f"code layout      {header['code_layout']}",
            f"PEP 552 flags    0x{header['flags']:08x} (hash_based={header['hash_based']}, check_source={header['check_source']})",
            (
                f"source identity  hash {header['source_hash_hex']}"
                if header["hash_based"]
                else f"source identity  mtime {header['source_mtime']}, size {header['source_size']}"
            ),
            f"payload start    0x{start:x} first byte 0x{marker.hex() or '00'}",
        ]
    )

    if not header["known_magic"]:
        ctx.limit(
            "The header magic is outside the bundled CPython 3.7-3.15 windows; "
            "version mapping and marshal decoding are unverified for this file."
        )
    ctx.stage(f"header: CPython {header['python_version']}, magic {header['magic_hex']}")

    if header["known_magic"] and header["python_version"] != f"{sys.version_info.major}.{sys.version_info.minor}":
        ctx.limit(
            f"Decoding a {header['python_version']} marshal stream with the running "
            f"CPython {platform.python_version()} interpreter is not supported; "
            "header facts are exact, bytecode facts are unavailable."
        )

    decoded: Any = None
    decode_error: str | None = None
    try:
        decoded = marshal.loads(data[start:])
    except (EOFError, ValueError, TypeError) as exc:
        decode_error = f"{type(exc).__name__}: {exc}"

    if decode_error is not None:
        payload["marshal"] = {"decoded": False, "error": decode_error}
        report.section("Marshal").lines.extend(
            [
                "decode failed; the payload was not interpreted",
                f"reason: {decode_error}",
            ]
        )
        if header["python_version"] == f"{sys.version_info.major}.{sys.version_info.minor}" and header["known_magic"]:
            ctx.limit(
                "The header claims the running CPython release but marshal decoding failed; "
                "the file may be truncated or hand-assembled."
            )
        _fallback(report, ctx, data)
        return report

    top_kind = type(decoded).__name__
    payload["marshal"] = {"decoded": True, "top_level_type": top_kind}
    ctx.stage(f"marshal decoded: top-level {top_kind}")
    report.section("Marshal").lines.append(f"decoded top-level object: {top_kind}")

    if not isinstance(decoded, types.CodeType):
        ctx.limit("The marshal payload top-level object is not a code object; bytecode was not inspected.")
        _fallback(report, ctx, data)
        return report

    order = _collect(decoded)
    ctx.stage(f"disassembling {len(order)} code object(s)")
    objects: list[dict[str, Any]] = []
    dump_lines: list[str] = [
        f"# CPython bytecode listing",
        f"# artifact : {ctx.path}",
        f"# sha256   : {ctx.sha256}",
        f"# runtime  : {platform.python_version()}",
        f"# objects  : {len(order)}",
        "",
    ]
    instruction_budget = MAX_INSTRUCTIONS
    total_instructions = 0
    for index, code in enumerate(order):
        entry: dict[str, Any] = {
            "index": index,
            "name": code.co_name,
            "qualname": getattr(code, "co_qualname", code.co_name),
            "filename": code.co_filename,
            "firstlineno": code.co_firstlineno,
            "argcount": code.co_argcount,
            "posonlyargcount": getattr(code, "co_posonlyargcount", 0),
            "kwonlyargcount": code.co_kwonlyargcount,
            "nlocals": code.co_nlocals,
            "stacksize": code.co_stacksize,
            "flags": code.co_flags,
            "names": list(code.co_names),
            "varnames": list(code.co_varnames),
            "freevars": list(code.co_freevars),
            "cellvars": list(code.co_cellvars),
            "const_count": len(code.co_consts),
            "const_kinds": [_const_kind(value) for value in code.co_consts],
            "bytecode_length": len(code.co_code),
            "bytecode_sha256": hashlib.sha256(code.co_code).hexdigest(),
            "nested_code": _nested_indexes(code, order),
        }
        objects.append(entry)
        budget = max(0, instruction_budget)
        body, used = _disassemble(code, budget)
        instruction_budget -= used
        total_instructions += used
        dump_lines.append(
            f"# --- code object {index}: {entry['qualname']}  file={code.co_filename}  line={code.co_firstlineno}"
        )
        dump_lines.append(
            f"#     args={code.co_argcount} kwonly={code.co_kwonlyargcount} locals={code.co_nlocals} "
            f"stack={code.co_stacksize} flags=0x{code.co_flags:x}"
        )
        if code.co_names:
            dump_lines.append(f"#     names: {', '.join(code.co_names)}")
        if code.co_varnames:
            dump_lines.append(f"#     varnames: {', '.join(code.co_varnames)}")
        constants = [_const_preview(value) for value in code.co_consts]
        if constants:
            dump_lines.append(f"#     consts: {constants}")
        dump_lines.extend(body)
        dump_lines.append("")

    if instruction_budget <= 0:
        ctx.limit(f"Disassembly stopped after {human_int(MAX_INSTRUCTIONS)} instructions across all code objects.")

    payload["code_objects"] = objects
    payload["instruction_count"] = total_instructions

    section = report.section("Code objects")
    section.add(f"{len(objects)} code objects reachable from the top-level module code")
    section.add(f"{human_int(total_instructions)} instructions decoded")
    section.add("")
    for entry in objects[:60]:
        section.add(
            f"[{entry['index']:>3}] {entry['qualname']:<44} line {entry['firstlineno']:<5} "
            f"{entry['bytecode_length']:>6} bytes  locals={entry['nlocals']}"
        )
    if len(objects) > 60:
        section.add(f"... {len(objects) - 60} more (see evidence JSON)")

    module_stem = os.path.splitext(os.path.basename(ctx.path))[0] or "module"
    ctx.add_artifact(f"sources/{module_stem}.pyc.dis.txt", "\n".join(dump_lines), kind="disassembly")

    source_path = None
    if ctx.options.source:
        from .pysrc import emit_module

        ctx.stage("reconstructing Python source from bytecode")

        try:
            source_text = emit_module(decoded, ctx.path, ctx.sha256, header["python_version"])
        except Exception as exc:  # the lifter is intentionally defensive
            source_text = ""
            ctx.limit(f"Python source reconstruction stopped early: {type(exc).__name__}: {exc}")
        if source_text:
            source_path = f"sources/recovered/{module_stem}.py"
            ctx.stage(f"Python source: {source_path}")
            if ctx.add_artifact(source_path, source_text, kind="source"):
                source_section = report.section("Recovered Python source")
                source_section.add(source_path)
                ctx.observe("Python source is pattern-lifted from bytecode; unhandled constructs keep a pass statement.")
    report.payload["source"] = {"language": "python", "files": [source_path] if source_path else []}

    report.coverage = {
        "status": "complete",
        "examined": len(objects),
        "total": len(order),
        "exhausted": True,
    }
    report.next_steps.append("Open the .dis.txt artifact for the full instruction listing.")
    report.next_steps.append("Use --json for bytecode hashes and nested code-object indexes.")
    return report


def _fallback(report: Report, ctx: Context, data: bytes) -> None:
    """Report what the raw payload supports when marshal decoding is impossible."""
    from ..util import hexdump, entropy

    report.section("Payload preview").lines.extend(hexdump(data[16:], limit=192).splitlines())
    report.payload["payload_preview"] = {
        "length": len(data) - 16,
        "entropy": entropy(data[16:]),
        "first_hex": data[16:80].hex(),
    }
    ctx.limit("Bytecode was not decompiled: no supported marshal decode for this artifact.")
