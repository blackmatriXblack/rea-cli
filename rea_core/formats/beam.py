"""Erlang/Elixir BEAM module reader: chunks, atoms, exports and imports."""

from __future__ import annotations

import hashlib
import os
from typing import Any

from ..context import Context
from ..errors import FormatError
from ..report import Report
from ..util import Reader, human_int

INTERESTING_CHUNKS = ("AtU8", "Atom", "ExpT", "ImpT", "FunT", "LitT", "Code", "StrT", "Attr", "CInf", "Line", "Dbgi", "Docs")


def _atoms(reader: Reader, utf8: bool) -> list[str]:
    count = reader.u32()
    atoms: list[str] = []
    for _ in range(min(count, 2_000_000)):
        if utf8:
            length = reader.u8()
            atoms.append(reader.read(length).decode("utf-8", "replace"))
        else:
            length = reader.u8()
            atoms.append(reader.read(length).decode("latin-1"))
    return atoms


def _exports(reader: Reader, atoms: list[str]) -> list[dict[str, Any]]:
    count = reader.u32()
    exports: list[dict[str, Any]] = []
    for _ in range(min(count, 200_000)):
        name_index = reader.u32()
        arity = reader.u32()
        label = reader.u32()
        exports.append(
            {
                "function": atoms[name_index] if name_index < len(atoms) else f"<atom {name_index}>",
                "arity": arity,
                "label": label,
            }
        )
    return exports


def _imports(reader: Reader, atoms: list[str]) -> list[dict[str, Any]]:
    count = reader.u32()
    imports: list[dict[str, Any]] = []
    for _ in range(min(count, 200_000)):
        module_index = reader.u32()
        function_index = reader.u32()
        arity = reader.u32()

        def name(index: int) -> str:
            return atoms[index] if index < len(atoms) else f"<atom {index}>"

        imports.append({"module": name(module_index), "function": name(function_index), "arity": arity})
    return imports


def analyze(ctx: Context) -> Report:
    data = bytes(ctx.data[: ctx.size])
    reader = Reader(data, ">", 0, "beam")
    if reader.read(4) != b"FOR1":
        raise FormatError("BEAM container magic FOR1 missing")
    total_size = reader.u32()
    if reader.read(4) != b"BEAM":
        raise FormatError("BEAM chunk magic missing")

    chunks: list[dict[str, Any]] = []
    atoms: list[str] = []
    exports: list[dict[str, Any]] = []
    imports: list[dict[str, Any]] = []
    code_info: dict[str, Any] = {}
    while reader.pos + 8 <= min(len(data), total_size + 8):
        chunk_id = reader.read(4).decode("latin-1")
        chunk_size = reader.u32()
        if reader.pos + chunk_size > len(data):
            ctx.limit(f"Chunk {chunk_id} extends past the end of the file.")
            break
        start = reader.pos
        chunks.append({"id": chunk_id, "size": chunk_size, "offset": start})
        if chunk_id in ("Atom", "AtU8"):
            atoms = _atoms(reader.sub(start, chunk_size, ">"), chunk_id == "AtU8")
        elif chunk_id == "ExpT":
            exports = _exports(reader.sub(start, chunk_size, ">"), atoms)
        elif chunk_id == "ImpT":
            imports = _imports(reader.sub(start, chunk_size, ">"), atoms)
        elif chunk_id == "Code":
            sub = reader.sub(start, chunk_size, ">")
            header_size = sub.u32()
            if header_size in (16, 20) and sub.remaining >= 12:
                sub.seek(header_size)
                code_info = {
                    "info_size": sub.u32(),
                    "version": sub.u32(),
                    "code_size": sub.u32() if header_size == 20 else None,
                }
        elif chunk_id == "CInf":
            sub = reader.sub(start, chunk_size, ">")
            code_info["compile_info"] = sub.read(min(chunk_size, 512)).decode("latin-1", "replace").strip("\x00")
        reader.seek(start + chunk_size)

    module_name = None
    for item in chunks:
        if item["id"] in ("Atom", "AtU8") and atoms:
            module_name = atoms[0]
            break

    report = Report(kind="beam", label=f"BEAM module {module_name or ''}".strip())
    report.summary.update(
        {
            "module": module_name or "(unknown)",
            "atoms": len(atoms),
            "exports": len(exports),
            "imports": len(imports),
            "chunks": len(chunks),
            "container_size": human_int(total_size + 8),
        }
    )

    chunk_section = report.section("Chunks")
    for item in chunks:
        chunk_section.add(f"{item['id']:<6} offset=0x{item['offset']:08x} size={human_int(item['size'])}")

    export_section = report.section("Exports")
    for item in exports[:200]:
        export_section.add(f"{item['function']}/{item['arity']:<3} label={item['label']}")
    if not exports:
        export_section.add("(none)")
    if len(exports) > 200:
        export_section.add(f"... {len(exports) - 200} more")

    import_section = report.section("Imports")
    for item in imports[:200]:
        import_section.add(f"{item['module']}:{item['function']}/{item['arity']}")
    if not imports:
        import_section.add("(none)")
    if len(imports) > 200:
        import_section.add(f"... {len(imports) - 200} more")

    atom_section = report.section("Atoms")
    atom_section.add(", ".join(atoms[:400]) if atoms else "(none)")

    stem = module_name or os.path.splitext(os.path.basename(ctx.path))[0] or "module"
    dump = [
        f"# BEAM module {module_name}",
        f"# sha256 {ctx.sha256}",
        "",
        "## chunks",
        *[f"{item['id']} 0x{item['offset']:x} {item['size']}" for item in chunks],
        "",
        "## exports",
        *[f"{item['function']}/{item['arity']}" for item in exports],
        "",
        "## imports",
        *[f"{item['module']}:{item['function']}/{item['arity']}" for item in imports],
        "",
        "## atoms",
        *atoms,
    ]
    ctx.add_artifact(f"sources/{stem}.beam.txt", "\n".join(dump), kind="disassembly")
    report.payload = {
        "module": module_name,
        "chunks": chunks,
        "atoms": atoms[:20_000],
        "exports": exports,
        "imports": imports,
        "code_info": code_info,
        "code_md5": hashlib.md5(data).hexdigest(),
    }
    report.coverage = {"status": "complete", "examined": len(chunks), "total": len(chunks), "exhausted": True}
    ctx.limit("BEAM bytecode is not translated to Erlang source; exports, imports and atoms are exact.")
    report.next_steps.append("If the module retains debug info, the Dbgi chunk usually embeds an Erlang abstract syntax tree.")
    return report
