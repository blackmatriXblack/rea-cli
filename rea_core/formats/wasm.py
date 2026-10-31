"""WebAssembly reader: sections, type/import/export facts and WAT-style code."""

from __future__ import annotations

import os
import struct
from typing import Any

from ..context import Context
from ..errors import FormatError
from ..report import Report
from ..util import Reader, human_bytes, human_int, shorten

VALTYPES = {
    0x7F: "i32",
    0x7E: "i64",
    0x7D: "f32",
    0x7C: "f64",
    0x7B: "v128",
    0x70: "funcref",
    0x6F: "externref",
    0x6E: "anyref",
    0x6D: "eqref",
    0x6C: "i31ref",
    0x6B: "structref",
    0x6A: "arrayref",
    0x69: "exnref",
}

SECTION_NAMES = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "data-count",
    13: "tag",
}

# instruction -> immediate kind
IMM_NONE = "none"
IMM_BLOCKTYPE = "blocktype"
IMM_U32 = "u32"
IMM_MEMARG = "memarg"
IMM_MEMIDX = "memidx"
IMM_MEMIDX2 = "memidx2"
IMM_S32 = "s32"
IMM_S64 = "s64"
IMM_F32 = "f32"
IMM_F64 = "f64"
IMM_BRTABLE = "brtable"
IMM_SELECT_T = "select_t"
IMM_CALLINDIRECT = "call_indirect"
IMM_REFTYPE = "reftype"

OPCODES: dict[int, tuple[str, str]] = {}


def _op(code: int, name: str, imm: str = IMM_NONE) -> None:
    OPCODES[code] = (name, imm)


def _range(start: int, names: tuple[str, ...], imm: str = IMM_NONE) -> None:
    for offset, name in enumerate(names):
        _op(start + offset, name, imm)


_op(0x00, "unreachable")
_op(0x01, "nop")
_op(0x02, "block", IMM_BLOCKTYPE)
_op(0x03, "loop", IMM_BLOCKTYPE)
_op(0x04, "if", IMM_BLOCKTYPE)
_op(0x05, "else")
_op(0x06, "try", IMM_BLOCKTYPE)
_op(0x07, "catch", IMM_U32)
_op(0x08, "throw", IMM_U32)
_op(0x09, "rethrow")
_op(0x0A, "throw_ref")
_op(0x0B, "end")
_op(0x0C, "br", IMM_U32)
_op(0x0D, "br_if", IMM_U32)
_op(0x0E, "br_table", IMM_BRTABLE)
_op(0x0F, "return")
_op(0x10, "call", IMM_U32)
_op(0x11, "call_indirect", IMM_CALLINDIRECT)
_op(0x12, "return_call", IMM_U32)
_op(0x13, "return_call_indirect", IMM_CALLINDIRECT)
_op(0x14, "call_ref", IMM_U32)
_op(0x15, "return_call_ref", IMM_U32)
_op(0x1A, "drop")
_op(0x1B, "select")
_op(0x1C, "select_t", IMM_SELECT_T)
_op(0x20, "local.get", IMM_U32)
_op(0x21, "local.set", IMM_U32)
_op(0x22, "local.tee", IMM_U32)
_op(0x23, "global.get", IMM_U32)
_op(0x24, "global.set", IMM_U32)
_op(0x25, "table.get", IMM_U32)
_op(0x26, "table.set", IMM_U32)
_range(
    0x28,
    (
        "i32.load",
        "i64.load",
        "f32.load",
        "f64.load",
        "i32.load8_s",
        "i32.load8_u",
        "i32.load16_s",
        "i32.load16_u",
        "i64.load8_s",
        "i64.load8_u",
        "i64.load16_s",
        "i64.load16_u",
        "i64.load32_s",
        "i64.load32_u",
    ),
    IMM_MEMARG,
)
_range(
    0x36,
    (
        "i32.store",
        "i64.store",
        "f32.store",
        "f64.store",
        "i32.store8",
        "i32.store16",
        "i64.store8",
        "i64.store16",
        "i64.store32",
    ),
    IMM_MEMARG,
)
_op(0x3F, "memory.size", IMM_MEMIDX)
_op(0x40, "memory.grow", IMM_MEMIDX)
_op(0x41, "i32.const", IMM_S32)
_op(0x42, "i64.const", IMM_S64)
_op(0x43, "f32.const", IMM_F32)
_op(0x44, "f64.const", IMM_F64)
_range(0x45, ("i32.eqz", "i32.eq", "i32.ne", "i32.lt_s", "i32.lt_u", "i32.gt_s", "i32.gt_u", "i32.le_s", "i32.le_u", "i32.ge_s", "i32.ge_u"))
_range(0x50, ("i64.eqz", "i64.eq", "i64.ne", "i64.lt_s", "i64.lt_u", "i64.gt_s", "i64.gt_u", "i64.le_s", "i64.le_u", "i64.ge_s", "i64.ge_u"))
_range(0x5B, ("f32.eq", "f32.ne", "f32.lt", "f32.gt", "f32.le", "f32.ge"))
_range(0x61, ("f64.eq", "f64.ne", "f64.lt", "f64.gt", "f64.le", "f64.ge"))
_range(
    0x67,
    (
        "i32.clz",
        "i32.ctz",
        "i32.popcnt",
        "i32.add",
        "i32.sub",
        "i32.mul",
        "i32.div_s",
        "i32.div_u",
        "i32.rem_s",
        "i32.rem_u",
        "i32.and",
        "i32.or",
        "i32.xor",
        "i32.shl",
        "i32.shr_s",
        "i32.shr_u",
        "i32.rotl",
        "i32.rotr",
    ),
)
_range(
    0x79,
    (
        "i64.clz",
        "i64.ctz",
        "i64.popcnt",
        "i64.add",
        "i64.sub",
        "i64.mul",
        "i64.div_s",
        "i64.div_u",
        "i64.rem_s",
        "i64.rem_u",
        "i64.and",
        "i64.or",
        "i64.xor",
        "i64.shl",
        "i64.shr_s",
        "i64.shr_u",
        "i64.rotl",
        "i64.rotr",
    ),
)
_range(
    0x8B,
    (
        "f32.abs",
        "f32.neg",
        "f32.ceil",
        "f32.floor",
        "f32.trunc",
        "f32.nearest",
        "f32.sqrt",
        "f32.add",
        "f32.sub",
        "f32.mul",
        "f32.div",
        "f32.min",
        "f32.max",
        "f32.copysign",
    ),
)
_range(
    0x99,
    (
        "f64.abs",
        "f64.neg",
        "f64.ceil",
        "f64.floor",
        "f64.trunc",
        "f64.nearest",
        "f64.sqrt",
        "f64.add",
        "f64.sub",
        "f64.mul",
        "f64.div",
        "f64.min",
        "f64.max",
        "f64.copysign",
    ),
)
_range(
    0xA7,
    (
        "i32.wrap_i64",
        "i32.trunc_f32_s",
        "i32.trunc_f32_u",
        "i32.trunc_f64_s",
        "i32.trunc_f64_u",
        "i64.extend_i32_s",
        "i64.extend_i32_u",
        "i64.trunc_f32_s",
        "i64.trunc_f32_u",
        "i64.trunc_f64_s",
        "i64.trunc_f64_u",
        "f32.convert_i32_s",
        "f32.convert_i32_u",
        "f32.convert_i64_s",
        "f32.convert_i64_u",
        "f32.demote_f64",
        "f64.convert_i32_s",
        "f64.convert_i32_u",
        "f64.convert_i64_s",
        "f64.convert_i64_u",
        "f64.promote_f32",
        "i32.reinterpret_f32",
        "i64.reinterpret_f64",
        "f32.reinterpret_i32",
        "f64.reinterpret_i64",
    ),
)
_range(0xC0, ("i32.extend8_s", "i32.extend16_s", "i64.extend8_s", "i64.extend16_s", "i64.extend32_s"))
_op(0xD0, "ref.null", IMM_REFTYPE)
_op(0xD1, "ref.is_null")
_op(0xD2, "ref.func", IMM_U32)
_op(0xD3, "ref.eq")
_op(0xD4, "ref.as_non_null")
_op(0xD5, "br_on_null", IMM_U32)
_op(0xD6, "br_on_non_null", IMM_U32)
_op(0xFC, "far-prefix")

FC_OPS = {
    0: ("i32.trunc_sat_f32_s", IMM_NONE),
    1: ("i32.trunc_sat_f32_u", IMM_NONE),
    2: ("i32.trunc_sat_f64_s", IMM_NONE),
    3: ("i32.trunc_sat_f64_u", IMM_NONE),
    4: ("i64.trunc_sat_f32_s", IMM_NONE),
    5: ("i64.trunc_sat_f32_u", IMM_NONE),
    6: ("i64.trunc_sat_f64_s", IMM_NONE),
    7: ("i64.trunc_sat_f64_u", IMM_NONE),
    8: ("memory.init", "dataidx"),
    9: ("data.drop", IMM_U32),
    10: ("memory.copy", IMM_MEMIDX2),
    11: ("memory.fill", IMM_MEMIDX),
    12: ("table.init", IMM_MEMIDX2),
    13: ("elem.drop", IMM_U32),
    14: ("table.copy", IMM_MEMIDX2),
    15: ("table.grow", IMM_U32),
    16: ("table.size", IMM_U32),
    17: ("table.fill", IMM_U32),
}


class Module:
    def __init__(self, data: bytes, label: str) -> None:
        self.data = data
        self.label = label
        self.reader = Reader(data, "<", 0, label)
        if self.reader.read(4) != b"\x00asm":
            raise FormatError("WASM magic missing")
        self.version = self.reader.u32()
        self.sections: list[dict[str, Any]] = []
        self.types: list[dict[str, Any]] = []
        self.imports: list[dict[str, Any]] = []
        self.function_types: list[int] = []
        self.exports: list[dict[str, Any]] = []
        self.globals: list[dict[str, Any]] = []
        self.memories: list[dict[str, Any]] = []
        self.tables: list[dict[str, Any]] = []
        self.start: int | None = None
        self.function_names: dict[int, str] = {}
        self.module_name: str | None = None
        self.code_bodies: list[tuple[int, bytes]] = []
        self.data_segments = 0
        self.element_segments = 0
        self.custom_sections: list[dict[str, Any]] = []
        self._parse()

    def _parse(self) -> None:
        reader = self.reader
        while reader.remaining > 0:
            section_id = reader.u8()
            size = reader.uleb(32)
            if size > reader.remaining:
                raise FormatError(f"section {section_id} declares {size} bytes but only {reader.remaining} remain")
            start = reader.pos
            body = reader.sub(start, size)
            self.sections.append({"id": section_id, "name": SECTION_NAMES.get(section_id, f"unknown-{section_id}"), "size": size})
            if section_id == 1:
                self._types(body)
            elif section_id == 2:
                self._imports(body)
            elif section_id == 3:
                count = body.uleb(32)
                self.function_types = [body.uleb(32) for _ in range(count)]
            elif section_id == 4:
                count = body.uleb(32)
                for _ in range(count):
                    self.tables.append(self._table(body))
            elif section_id == 5:
                count = body.uleb(32)
                for _ in range(count):
                    self.memories.append(self._limits(body))
            elif section_id == 6:
                count = body.uleb(32)
                for _ in range(count):
                    value_type = VALTYPES.get(body.u8(), "?")
                    mutable = body.u8()
                    expression = self._const_expr(body)
                    self.globals.append({"type": value_type, "mutable": bool(mutable), "init": expression})
            elif section_id == 7:
                self._exports(body)
            elif section_id == 8:
                self.start = body.uleb(32)
            elif section_id == 9:
                self.element_segments = body.uleb(32)
            elif section_id == 10:
                count = body.uleb(32)
                for index in range(count):
                    body_size = body.uleb(32)
                    code = body.read(body_size)
                    self.code_bodies.append((index, code))
            elif section_id == 11:
                self.data_segments = body.uleb(32)
            elif section_id == 0:
                self._custom(body)
            reader.seek(start + size)

    def _limits(self, reader: Reader) -> dict[str, Any]:
        flags = reader.u8()
        minimum = reader.uleb(32)
        maximum = reader.uleb(32) if flags & 0x01 else None
        return {"min": minimum, "max": maximum, "shared": bool(flags & 0x02), "memory64": bool(flags & 0x04)}

    def _table(self, reader: Reader) -> dict[str, Any]:
        element_type = VALTYPES.get(reader.u8(), "?")
        limits = self._limits(reader)
        return {"element_type": element_type, **limits}

    def _types(self, reader: Reader) -> None:
        count = reader.uleb(32)
        for _ in range(count):
            form = reader.u8()
            if form != 0x60:
                raise FormatError(f"type entry {form:#x} is not a function type")
            parameters = [VALTYPES.get(reader.u8(), "?") for _ in range(reader.uleb(32))]
            results = [VALTYPES.get(reader.u8(), "?") for _ in range(reader.uleb(32))]
            self.types.append({"params": parameters, "results": results})

    def _imports(self, reader: Reader) -> None:
        count = reader.uleb(32)
        for _ in range(count):
            module = self._name(reader)
            name = self._name(reader)
            kind = reader.u8()
            if kind == 0:
                descriptor: Any = {"type_index": reader.uleb(32)}
                kind_name = "func"
            elif kind == 1:
                descriptor = self._table(reader)
                kind_name = "table"
            elif kind == 2:
                descriptor = self._limits(reader)
                kind_name = "memory"
            elif kind == 3:
                descriptor = {"type": VALTYPES.get(reader.u8(), "?"), "mutable": bool(reader.u8())}
                kind_name = "global"
            else:
                descriptor = {"attribute": reader.uleb(32), "type_index": reader.uleb(32)}
                kind_name = "tag"
            self.imports.append({"module": module, "name": name, "kind": kind_name, "descriptor": descriptor})

    def _exports(self, reader: Reader) -> None:
        count = reader.uleb(32)
        kinds = {0: "func", 1: "table", 2: "memory", 3: "global", 4: "tag"}
        for _ in range(count):
            name = self._name(reader)
            kind = reader.u8()
            index = reader.uleb(32)
            self.exports.append({"name": name, "kind": kinds.get(kind, str(kind)), "index": index})

    def _name(self, reader: Reader) -> str:
        length = reader.uleb(32)
        if length > 1_000_000:
            raise FormatError("name length exceeds the local budget")
        return reader.read(length).decode("utf-8", "replace")

    def _const_expr(self, reader: Reader) -> str:
        parts: list[str] = []
        for _ in range(64):
            opcode = reader.u8()
            if opcode == 0x0B:
                break
            name, imm = OPCODES.get(opcode, (f"op_{opcode:02x}", IMM_NONE))
            if imm == IMM_S32:
                parts.append(f"{name} {reader.sleb(32)}")
            elif imm == IMM_S64:
                parts.append(f"{name} {reader.sleb(64)}")
            elif imm == IMM_F32:
                parts.append(f"{name} {reader.f32():g}")
            elif imm == IMM_F64:
                parts.append(f"{name} {reader.f64():g}")
            elif imm == IMM_REFTYPE:
                parts.append(f"{name} {VALTYPES.get(reader.u8(), '?')}")
            elif imm == IMM_U32:
                parts.append(f"{name} {reader.uleb(32)}")
            else:
                parts.append(name)
        return " ".join(parts)

    def _custom(self, reader: Reader) -> None:
        name = self._name(reader)
        payload = reader.read(reader.remaining)
        self.custom_sections.append({"name": name, "size": len(payload)})
        if name == "name":
            sub = Reader(payload, "<", 0, "name section")
            try:
                while sub.remaining > 0:
                    subsection = sub.u8()
                    length = sub.uleb(32)
                    data = sub.sub(sub.pos, length)
                    sub.skip(length)
                    if subsection == 0:
                        self.module_name = self._name(data)
                    elif subsection == 1:
                        for _ in range(data.uleb(32)):
                            index = data.uleb(32)
                            self.function_names[index] = self._name(data)
            except FormatError:
                pass

    # -- code ---------------------------------------------------------------
    def functions(self) -> list[dict[str, Any]]:
        functions: list[dict[str, Any]] = []
        imported = sum(1 for item in self.imports if item["kind"] == "func")
        for index, type_index in enumerate(self.function_types):
            absolute = imported + index
            signature = self.types[type_index] if type_index < len(self.types) else {"params": [], "results": []}
            functions.append(
                {
                    "index": absolute,
                    "type_index": type_index,
                    "name": self.function_names.get(absolute, f"func{absolute}"),
                    "params": signature["params"],
                    "results": signature["results"],
                }
            )
        return functions

    def disassemble(self, code: bytes, function: dict[str, Any], budget: int = 100_000) -> tuple[list[str], int, bool]:
        reader = Reader(code, "<", 0, "code body")
        local_groups = reader.uleb(32)
        locals_list: list[str] = []
        for _ in range(local_groups):
            count = reader.uleb(32)
            value_type = VALTYPES.get(reader.u8(), "?")
            locals_list.extend(f"{value_type} local{len(locals_list) + offset}" for offset in range(count))
        lines: list[str] = []
        header = f"(func ${function['name']}"
        if function["params"]:
            header += " (param " + " ".join(function["params"]) + ")"
        if function["results"]:
            header += " (result " + " ".join(function["results"]) + ")"
        lines.append(header)
        for declaration in locals_list[:256]:
            lines.append(f"  {declaration}")
        count = 0
        truncated = False
        while reader.remaining > 0:
            opcode = reader.u8()
            if opcode == 0x0B:
                break
            text, consumed = self._instruction(reader, opcode)
            lines.append("  " + text)
            count += 1
            if count >= budget:
                lines.append("  ;; instruction budget reached")
                truncated = True
                break
        lines.append(")")
        return lines, count, truncated

    def _instruction(self, reader: Reader, opcode: int) -> tuple[str, int]:
        if opcode == 0xFC:
            sub = reader.uleb(32)
            name, imm = FC_OPS.get(sub, (f"fc.{sub}", IMM_NONE))
            if imm == "dataidx":
                return f"{name} {reader.uleb(32)}", 0
            if imm == IMM_U32:
                return f"{name} {reader.uleb(32)}", 0
            if imm == IMM_MEMIDX:
                return f"{name} {reader.u8()}", 0
            if imm == IMM_MEMIDX2:
                return f"{name} {reader.u8()} {reader.u8()}", 0
            return name, 0
        if opcode == 0xFD:
            sub = reader.uleb(32)
            return f"simd.{sub} <operands not decoded>", 0
        if opcode == 0xFE:
            sub = reader.uleb(32)
            return f"atomic.{sub} <operands not decoded>", 0
        name, imm = OPCODES.get(opcode, (f"op_{opcode:02x}", IMM_NONE))
        if imm == IMM_NONE:
            return name, 0
        if imm == IMM_BLOCKTYPE:
            byte = reader.u8()
            if byte == 0x40:
                return name, 0
            if byte in VALTYPES:
                return f"{name} (result {VALTYPES[byte]})", 0
            # An LEB type index; the first byte was already consumed.
            value = byte & 0x7F
            shift = 7
            while byte & 0x80:
                byte = reader.u8()
                value |= (byte & 0x7F) << shift
                shift += 7
            return f"{name} (type {value})", 0
        if imm == IMM_U32:
            return f"{name} {reader.uleb(32)}", 0
        if imm == IMM_MEMARG:
            align = reader.uleb(32)
            offset = reader.uleb(32)
            return f"{name} offset={offset} align=2^{align}", 0
        if imm == IMM_MEMIDX:
            return f"{name} {reader.u8()}", 0
        if imm == IMM_MEMIDX2:
            return f"{name} {reader.u8()} {reader.u8()}", 0
        if imm == IMM_S32:
            return f"{name} {reader.sleb(32)}", 0
        if imm == IMM_S64:
            return f"{name} {reader.sleb(64)}", 0
        if imm == IMM_F32:
            return f"{name} {reader.f32():g}", 0
        if imm == IMM_F64:
            return f"{name} {reader.f64():g}", 0
        if imm == IMM_REFTYPE:
            return f"{name} {VALTYPES.get(reader.u8(), '?')}", 0
        if imm == IMM_CALLINDIRECT:
            type_index = reader.uleb(32)
            table_index = reader.uleb(32)
            return f"{name} (type {type_index}) (table {table_index})", 0
        if imm == IMM_SELECT_T:
            count = reader.uleb(32)
            types = [VALTYPES.get(reader.u8(), "?") for _ in range(count)]
            return f"{name} " + " ".join(types), 0
        if imm == IMM_BRTABLE:
            count = reader.uleb(32)
            targets = [reader.uleb(32) for _ in range(count)]
            default = reader.uleb(32)
            joined = " ".join(str(item) for item in targets)
            return f"{name} {joined} default={default}", 0
        return name, 0


def analyze(ctx: Context) -> Report:
    module = Module(bytes(ctx.data[: ctx.size]), os.path.basename(ctx.path))
    ctx.stage(f"sections: {len(module.sections)}, types: {len(module.types)}, functions: {len(module.function_types)}")
    report = Report(kind="wasm", label=f"WebAssembly module (v{module.version})")
    report.summary.update(
        {
            "version": module.version,
            "sections": len(module.sections),
            "types": len(module.types),
            "imports": len(module.imports),
            "functions": len(module.function_types),
            "exports": len(module.exports),
            "memories": len(module.memories),
            "tables": len(module.tables),
            "globals": len(module.globals),
            "size": human_bytes(ctx.size),
        }
    )
    if module.module_name:
        report.summary["module_name"] = module.module_name

    section_lines = []
    for section in module.sections:
        section_lines.append(f"{section['name']:<12} size={human_int(section['size'])}")
    report.section("Sections").lines.extend(section_lines)

    if module.types:
        type_section = report.section("Types")
        for index, item in enumerate(module.types[:200]):
            type_section.add(f"[{index}] (param {' '.join(item['params']) or '-'}) -> (result {' '.join(item['results']) or '-'})")

    if module.imports:
        import_section = report.section("Imports")
        for item in module.imports[:200]:
            import_section.add(f"{item['kind']:<6} {item['module']}.{item['name']}  {shorten(str(item['descriptor']), 80)}")

    if module.exports:
        export_section = report.section("Exports")
        for item in module.exports[:200]:
            export_section.add(f"{item['kind']:<6} {item['name']:<40} index={item['index']}")

    functions = module.functions()
    function_section = report.section("Functions")
    for item in functions[:200]:
        function_section.add(
            f"[{item['index']}] {item['name']:<40} ({' '.join(item['params']) or '-'}) -> "
            f"({' '.join(item['results']) or '-'})"
        )
    if len(functions) > 200:
        function_section.add(f"... {len(functions) - 200} more")

    limit = min(ctx.options.max_items, len(module.code_bodies))
    wat_lines = [
        f"; WebAssembly text recovered from {os.path.basename(ctx.path)}",
        f"; sha256 {ctx.sha256}",
        f"; module {module.module_name or '(unnamed)'}",
        "",
    ]
    if module.types:
        for index, item in enumerate(module.types):
            wat_lines.append(
                f"(type $t{index} (func (param {' '.join(item['params']) or ''}) "
                f"(result {' '.join(item['results']) or ''})))"
            )
        wat_lines.append("")
    for item in module.imports:
        wat_lines.append(f"; import {item['kind']} {item['module']}.{item['name']} {item['descriptor']}")
    if module.memories:
        for memory in module.memories:
            wat_lines.append(f"(memory {memory['min']} {memory['max'] if memory['max'] is not None else ''})".replace(" )", ")"))
    for item in module.exports:
        wat_lines.append(f"(export \"{item['name']}\" ({item['kind']} {item['index']}))")
    wat_lines.append("")

    instructions = 0
    truncated_functions = 0
    disassembled = 0
    if ctx.options.disassemble:
        ctx.stage(f"disassembling {min(limit, len(module.code_bodies))} function body/bodies")
        for position, (body_index, body) in enumerate(module.code_bodies):
            if position >= limit:
                ctx.limit(f"Disassembly stopped after {limit} function bodies; raise --max-items to continue.")
                break
            function = functions[position] if position < len(functions) else {
                "name": f"func{body_index}",
                "params": [],
                "results": [],
                "index": body_index,
            }
            try:
                lines, used, truncated = module.disassemble(body, function)
            except FormatError as exc:
                ctx.limit(f"Function {function['name']} could not be decoded: {exc.message}")
                continue
            watched = wat_lines
            watched.append(f"; code body {position} of {len(module.code_bodies)}")
            watched.extend(lines)
            watched.append("")
            instructions += used
            disassembled += 1
            if truncated:
                truncated_functions += 1

    payload_functions = []
    for item in functions[:limit]:
        payload_functions.append(dict(item))
    report.payload = {
        "version": module.version,
        "module_name": module.module_name,
        "sections": module.sections,
        "types": module.types,
        "imports": module.imports,
        "exports": module.exports,
        "functions": payload_functions,
        "memories": module.memories,
        "tables": module.tables,
        "globals": module.globals,
        "data_segments": module.data_segments,
        "element_segments": module.element_segments,
        "custom_sections": module.custom_sections,
        "start": module.start,
        "instructions": instructions,
        "disassembled_functions": disassembled,
    }
    stem = module.module_name or os.path.splitext(os.path.basename(ctx.path))[0] or "module"
    if ctx.options.disassemble:
        ctx.add_artifact(f"sources/{stem}.wat", "\n".join(wat_lines), kind="disassembly")
        ctx.stage(f"WAT: {instructions} instruction(s)")
    if truncated_functions:
        ctx.limit(f"{truncated_functions} function(s) hit the per-function instruction budget.")
    report.coverage = {
        "status": "complete" if disassembled >= len(module.code_bodies) else "partial",
        "examined": disassembled,
        "total": len(module.code_bodies),
        "exhausted": disassembled >= len(module.code_bodies),
    }
    report.next_steps.append("Open the .wat artifact for the recovered function bodies.")
    report.next_steps.append("A local wasm2wat is optional and never downloaded; this reader is self-contained.")
    return report
