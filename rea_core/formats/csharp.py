"""C# source reconstruction from ECMA-335 metadata and CIL bodies.

This is a pattern-based emitter, not a full compiler round-trip: linear code,
branches (as labels plus ``goto``), calls, fields, arrays and returns are
recovered; irreducible constructs keep their IL as a comment.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from ..errors import FormatError
from ..util import Reader
from . import dotnet
from .sourcegen import CS_KEYWORDS, cs_type, escape_cs, sanitize_identifier, source_header

BINARY_OPS = {
    "add": "+",
    "sub": "-",
    "mul": "*",
    "div": "/",
    "rem": "%",
    "and": "&",
    "or": "|",
    "xor": "^",
    "shl": "<<",
    "shr": ">>",
    "shr.un": ">>",
    "add.ovf": "+",
    "sub.ovf": "-",
    "mul.ovf": "*",
}

COMPARE_OPS = {"ceq": "==", "cgt": ">", "cgt.un": ">", "clt": "<", "clt.un": "<"}

BRANCH_OPS = {
    "beq": "==",
    "bne.un": "!=",
    "bge": ">=",
    "bgt": ">",
    "ble": "<=",
    "blt": "<",
    "bge.un": ">=",
    "bgt.un": ">",
    "ble.un": "<=",
    "blt.un": "<",
}

CONVERSIONS = {
    "conv.i1": "sbyte",
    "conv.u1": "byte",
    "conv.i2": "short",
    "conv.u2": "ushort",
    "conv.i4": "int",
    "conv.u4": "uint",
    "conv.i8": "long",
    "conv.u8": "ulong",
    "conv.r4": "float",
    "conv.r8": "double",
    "conv.i": "IntPtr",
    "conv.u": "UIntPtr",
    "conv.r.un": "double",
    "conv.ovf.i1": "sbyte",
    "conv.ovf.u1": "byte",
    "conv.ovf.i2": "short",
    "conv.ovf.u2": "ushort",
    "conv.ovf.i4": "int",
    "conv.ovf.u4": "uint",
    "conv.ovf.i8": "long",
    "conv.ovf.u8": "ulong",
}

BRANCH_ACCESS = {
    0: "private",
    1: "private",
    2: "private",
    3: "internal",
    4: "protected",
    5: "protected internal",
    6: "public",
}


@dataclass
class Instruction:
    offset: int
    name: str
    operand: str
    value: Any
    next_offset: int


def decode_il(code: bytes) -> list[Instruction]:
    reader = Reader(code, "<", 0, "IL")
    result: list[Instruction] = []
    while reader.remaining > 0:
        offset = reader.pos
        opcode = reader.u8()
        if opcode == 0xFE:
            second = reader.u8()
            name, operand = dotnet.IL_OPS_2BYTE.get(second, (f"fe_{second:02x}", "none"))
        else:
            name, operand = dotnet.IL_OPS.get(opcode, (f"op_{opcode:02x}", "none"))
        value: Any = None
        if operand == "i1":
            value = reader.i8()
        elif operand == "u1":
            value = reader.u8()
        elif operand == "i4":
            value = reader.i32()
        elif operand == "i8":
            value = reader.i64()
        elif operand == "r4":
            value = reader.f32()
        elif operand == "r8":
            value = reader.f64()
        elif operand == "br1":
            value = reader.i8() + reader.pos
        elif operand == "br4":
            value = reader.i32() + reader.pos
        elif operand == "switch":
            count = reader.u32()
            base = reader.pos + 4 * count
            value = [reader.i32() + base for _ in range(count)]
        elif operand in ("tok", "var2"):
            raw = reader.u32() if operand == "tok" else reader.u16()
            value = raw
        elif operand in ("var1",):
            value = reader.u8()
        result.append(Instruction(offset, name, operand, value, reader.pos))
        if reader.pos <= offset:
            break
    return result


def _local_default(type_name: str) -> str:
    text = cs_type(type_name)
    return f"default({text})"


class CSharpEmitter:
    def __init__(self, metadata: Any, artifact: str, sha256: str, max_methods: int = 5000) -> None:
        self.metadata = metadata
        self.artifact = artifact
        self.sha256 = sha256
        self.max_methods = max_methods
        self.type_entries: list[dict[str, Any]] = []
        self.method_owner: dict[int, str] = {}
        self.field_owner: dict[int, str] = {}
        self.interfaces: dict[int, list[str]] = {}
        self.constants: dict[int, str] = {}
        self.emitted_methods = 0
        self._indent = " " * 12

    # -- public -------------------------------------------------------------
    def emit(self, type_entries: list[dict[str, Any]]) -> list[tuple[str, str]]:
        self.type_entries = type_entries
        self._index(type_entries)
        self._read_constants()
        files: list[tuple[str, str]] = []
        for entry in type_entries:
            text = self._type_source(entry)
            if text:
                files.append((self._path(entry), text))
        return files

    # -- indexing -----------------------------------------------------------
    def _index(self, entries: list[dict[str, Any]]) -> None:
        for entry in entries:
            name = self._full_name(entry)
            for offset, method_row in enumerate(entry["methods"]):
                self.method_owner[entry["method_range"][0] + offset] = name
            for offset, field_row in enumerate(entry["fields"]):
                self.field_owner[entry["field_range"][0] + offset] = name
        interface_rows = self.metadata.rows(9)
        for row in interface_rows:
            owner = self.metadata.type_name(2, row["Class"])
            target = self.metadata._type_def_or_ref(row["Interface"])
            self.interfaces.setdefault(row["Class"], []).append(target)

    def _read_constants(self) -> None:
        for row in self.metadata.rows(11):
            table, index = self.metadata.decode_coded(row["Parent"], "HasConstant")
            if table != 4:
                continue
            text = self._constant_text(row["Type"], self.metadata.blob(row["Value"]))
            if text is not None:
                self.constants[index] = text

    def _constant_text(self, element_type: int, blob: bytes) -> str | None:
        try:
            if element_type == 0x08 and len(blob) >= 4:
                return str(struct.unpack_from("<i", blob)[0])
            if element_type == 0x09 and len(blob) >= 4:
                return str(struct.unpack_from("<I", blob)[0])
            if element_type == 0x0A and len(blob) >= 8:
                return str(struct.unpack_from("<q", blob)[0]) + "L"
            if element_type == 0x0B and len(blob) >= 8:
                return str(struct.unpack_from("<Q", blob)[0]) + "UL"
            if element_type == 0x0C and len(blob) >= 4:
                return f"{struct.unpack_from('<f', blob)[0]:g}f"
            if element_type == 0x0D and len(blob) >= 8:
                return f"{struct.unpack_from('<d', blob)[0]:g}"
            if element_type == 0x02 and blob:
                return "true" if blob[0] else "false"
            if element_type == 0x0E:
                return '"' + escape_cs(blob.decode("utf-16-le", "replace")) + '"'
            if element_type in (0x04, 0x05, 0x06, 0x07) and blob:
                return str(struct.unpack_from("<h" if element_type in (0x04, 0x06) else "<H", blob)[0])
            if element_type == 0x03 and len(blob) >= 2:
                return "'" + escape_cs(chr(struct.unpack_from("<H", blob)[0])) + "'"
        except struct.error:
            return None
        return None

    # -- names --------------------------------------------------------------
    def _full_name(self, entry: dict[str, Any]) -> str:
        return entry["name"].replace("/", ".")

    def _simple_name(self, entry: dict[str, Any]) -> str:
        full = self._full_name(entry)
        return full.rsplit(".", 1)[-1]

    def _namespace(self, entry: dict[str, Any]) -> str:
        full = self._full_name(entry)
        return full.rsplit(".", 1)[0] if "." in full else ""

    def _path(self, entry: dict[str, Any]) -> str:
        full = sanitize_identifier(self._full_name(entry).replace(".", "_"), set(), "Type")
        return f"sources/csharp/{full}.cs"

    def _param_names(self, method_index: int, count: int) -> list[str]:
        try:
            rows = self.metadata.rows(6)
            params = self.metadata.rows(8)
        except FormatError:
            return [f"arg{index}" for index in range(count)]
        if not 1 <= method_index <= len(rows):
            return [f"arg{index}" for index in range(count)]
        start = rows[method_index - 1]["ParamList"]
        end = rows[method_index]["ParamList"] if method_index < len(rows) else len(params) + 1
        names: dict[int, str] = {}
        for index in range(start, min(end, len(params) + 1)):
            row = params[index - 1]
            sequence = row["Sequence"]
            if sequence:
                names[sequence] = sanitize_identifier(self.metadata.string(row["Name"]), CS_KEYWORDS, f"arg{sequence}")
        return [names.get(index + 1, f"arg{index}") for index in range(count)]

    # -- type emission ------------------------------------------------------
    def _type_source(self, entry: dict[str, Any]) -> str:
        row = entry["row"]
        flags = row["Flags"]
        name = sanitize_identifier(self._simple_name(entry), CS_KEYWORDS, "Type")
        namespace = self._namespace(entry)
        base = self.metadata._type_def_or_ref(row["Extends"]) if row["Extends"] else None
        is_interface = bool(flags & 0x20)
        is_abstract = bool(flags & 0x80)
        is_sealed = bool(flags & 0x100)
        visibility = "public" if (flags & 0x07) in (1, 2, 4, 5, 7) else "internal"
        is_enum = bool(base and base.endswith("System.Enum"))
        is_struct = bool(base and base.endswith("System.ValueType")) and not is_enum

        kind = "interface" if is_interface else "struct" if is_struct else "enum" if is_enum else "class"
        modifiers = [visibility]
        if kind == "class":
            if is_abstract and is_sealed:
                modifiers = ["public", "static"]
            else:
                if is_abstract:
                    modifiers.append("abstract")
                if is_sealed:
                    modifiers.append("sealed")

        implements = [cs_type(item) for item in self.interfaces.get(entry["index"], [])]
        header = f"{' '.join(modifiers)} {kind} {name}"
        if kind == "class" and base and not base.endswith("System.Object"):
            header += f" : {cs_type(base)}"
        if kind == "struct" and base and not base.endswith("System.ValueType"):
            header += f" : {cs_type(base)}"
        if implements:
            header += (" : " if " : " not in header else ", ") + ", ".join(implements)

        lines = source_header("C#", self.artifact, self.sha256, f"type {self._full_name(entry)}")
        if namespace:
            lines.append(f"namespace {namespace}")
            lines.append("{")
        inner = "    " if namespace else ""
        lines.append(inner + header)
        lines.append(inner + "{")
        member_indent = inner + "    "

        if kind == "enum":
            for field_index, field in enumerate(entry["fields"], start=entry["field_range"][0]):
                literal = self.constants.get(field_index)
                field_name = sanitize_identifier(self.metadata.string(field["Name"]), CS_KEYWORDS, "Value")
                lines.append(member_indent + (f"{field_name} = {literal}," if literal else f"{field_name},"))
        else:
            for field_index, field in enumerate(entry["fields"], start=entry["field_range"][0]):
                lines.append(member_indent + self._field_line(field, field_index))
            if entry["fields"] and entry["methods"]:
                lines.append("")
            for offset, method in enumerate(entry["methods"]):
                if self.emitted_methods >= self.max_methods:
                    lines.append(member_indent + "// method budget reached")
                    break
                method_index = entry["method_range"][0] + offset
                self._indent = member_indent + "    "
                lines.append(member_indent + self._method_header(entry, method_index))
                lines.append(member_indent + "{")
                try:
                    body = self._method_body(entry, method, method_index)
                except FormatError as exc:
                    body = [self._indent + f"// body could not be decoded: {exc.message}"]
                lines.extend(body)
                lines.append(member_indent + "}")
                lines.append("")
                self.emitted_methods += 1

        lines.append(inner + "}")
        if namespace:
            lines.append("}")
        return "\n".join(lines) + "\n"

    def _field_line(self, field: dict[str, Any], field_index: int) -> str:
        flags = field["Flags"]
        access_bits = flags & 0x07
        access = "public" if access_bits == 6 else "protected" if access_bits == 4 else "internal" if access_bits == 3 else "private"
        modifiers = [access]
        if flags & 0x10:
            modifiers.append("static")
        constant = self.constants.get(field_index)
        if flags & 0x40:
            modifiers.append("const")
        elif flags & 0x20:
            modifiers.append("readonly")
        field_type, _ = self.metadata.parse_field_signature(self.metadata.blob(field["Signature"]))
        name = sanitize_identifier(self.metadata.string(field["Name"]), CS_KEYWORDS, "field")
        suffix = f" = {constant};" if constant is not None else ";"
        return f"{' '.join(modifiers)} {cs_type(field_type)} {name}{suffix}"

    def _method_header(self, entry: dict[str, Any], method_index: int) -> str:
        method = self.metadata.row(6, method_index)
        returns, parameters, has_this, _ = self.metadata.method_signature_parts(self.metadata.blob(method["Signature"]))
        name_text = self.metadata.string(method["Name"])
        flags = method["Flags"]
        access = BRANCH_ACCESS.get(flags & 0x07, "private")
        modifiers = [access]
        if flags & 0x10:
            modifiers.append("static")
        if flags & 0x40:
            modifiers.append("virtual")
        if flags & 0x400:
            modifiers.append("abstract")
        names = self._param_names(method_index, len(parameters))
        params_text = ", ".join(
            f"{cs_type(parameter)} {sanitize_identifier(param_name, CS_KEYWORDS, f'arg{index}')}"
            for index, (parameter, param_name) in enumerate(zip(parameters, names))
        )
        if name_text in (".ctor", ".cctor"):
            type_name = sanitize_identifier(self._simple_name(entry), CS_KEYWORDS, "Type")
            if name_text == ".cctor":
                return f"static {type_name}()"
            return f"{' '.join(item for item in modifiers if item not in ('static', 'virtual', 'abstract'))} {type_name}({params_text})"
        if name_text.startswith("get_") or name_text.startswith("set_") or name_text.startswith("add_") or name_text.startswith("remove_"):
            # Keep the accessor as a comment-friendly method name; properties need
            # MethodSemantics association that this emitter does not restructure.
            pass
        method_name = sanitize_identifier(name_text, CS_KEYWORDS, "Method")
        return f"{' '.join(modifiers)} {cs_type(returns)} {method_name}({params_text})"

    # -- method body --------------------------------------------------------
    def _method_body(self, entry: dict[str, Any], method: dict[str, Any], method_index: int) -> list[str]:
        body = self.metadata.method_body(method["RVA"])
        if body is None:
            return [self._indent + "// no IL body (abstract, extern, native or precompiled)"]
        returns, parameters, has_this, _ = self.metadata.method_signature_parts(self.metadata.blob(method["Signature"]))
        names = self._param_names(method_index, len(parameters))
        if has_this:
            names = ["this"] + names
        instructions = decode_il(body["code"])
        locals_types = self.metadata.local_types(body.get("local_sig", 0))
        current_type = self._full_name(entry)

        lines: list[str] = []
        for index, local_type in enumerate(locals_types):
            lines.append(self._indent + f"{cs_type(local_type)} V_{index} = {_local_default(local_type)};")
        if locals_types:
            lines.append("")

        targets = {item.value for item in instructions if item.operand in ("br1", "br4") and isinstance(item.value, int)}
        for item in instructions:
            if item.operand == "switch" and isinstance(item.value, list):
                targets.update(item.value)

        stack: list[str] = []

        def pop(count: int = 1) -> list[str]:
            if count <= 0:
                return []
            values = stack[-count:] if len(stack) >= count else [f"/* stack underrun */"] * (count - len(stack)) + stack
            del stack[-min(count, len(stack)) :]
            return values

        def push(value: str) -> None:
            stack.append(value)

        def emit(text: str) -> None:
            lines.append(self._indent + text)

        def arg_name(index: int) -> str:
            return names[index] if index < len(names) else f"arg{index}"

        for item in instructions:
            if item.offset in targets:
                lines.append(f"IL_{item.offset:04x}:")
            name = item.name
            if item.operand in ("tok", "var1", "var2") and item.value is None:
                emit(f"// {name} has no readable operand")
                continue
            if name in ("nop", "break", "volatile.", "tail.", "unaligned.", "readonly.", "constrained."):
                continue
            if name == "ldnull":
                push("null")
            elif name.startswith("ldc.i4.") and name[7:].lstrip("-").isdigit():
                push(name[7:])
            elif name in ("ldc.i4.s", "ldc.i4"):
                push(str(item.value))
            elif name == "ldc.i8":
                push(f"{item.value}L")
            elif name == "ldc.r4":
                push(f"{item.value:g}f")
            elif name == "ldc.r8":
                push(f"{item.value:g}")
            elif name == "ldstr":
                push('"' + escape_cs(self.metadata.user_string(item.value)) + '"')
            elif name.startswith("ldarg.") and name[6:].isdigit():
                push(arg_name(int(name[6:])))
            elif name in ("ldarg.s", "ldarg", "ldarga.s", "ldarga"):
                push(arg_name(int(item.value or 0)))
            elif name.startswith("ldloc.") and name[6:].isdigit():
                push(f"V_{int(name[6:])}")
            elif name in ("ldloc.s", "ldloc", "ldloca.s", "ldloca"):
                push(f"V_{int(item.value or 0)}")
            elif name.startswith("stloc.") and name[6:].isdigit():
                value = pop()[0]
                emit(f"V_{int(name[6:])} = {value};")
            elif name in ("stloc.s", "stloc"):
                value = pop()[0]
                emit(f"V_{int(item.value or 0)} = {value};")
            elif name == "dup":
                if stack:
                    push(stack[-1])
            elif name == "pop":
                value = pop()[0]
                if "(" in value or value.startswith("new "):
                    emit(f"{value};")
            elif name in BINARY_OPS:
                right = pop()[0]
                left = pop()[0]
                push(f"({left} {BINARY_OPS[name]} {right})")
            elif name in ("neg", "not"):
                value = pop()[0]
                push(f"({'~' if name == 'not' else '-'}{value})")
            elif name in COMPARE_OPS:
                right = pop()[0]
                left = pop()[0]
                push(f"({left} {COMPARE_OPS[name]} {right})")
            elif name in CONVERSIONS:
                value = pop()[0]
                target = CONVERSIONS[name]
                if target in ("IntPtr", "UIntPtr"):
                    push(value)
                else:
                    push(f"(({target}){value})")
            elif name in ("ldfld", "ldflda"):
                target = self.metadata.field_ref(item.value)
                instance = pop()[0]
                push(f"{instance}.{sanitize_identifier(target['name'], CS_KEYWORDS, 'field')}")
            elif name in ("ldsfld", "ldsflda"):
                target = self.metadata.field_ref(item.value)
                owner = (
                    self.field_owner.get(target["index"], target["owner"])
                    if target.get("table") == 0x04
                    else target["owner"]
                )
                field_name = sanitize_identifier(target["name"], CS_KEYWORDS, "field")
                push(f"{cs_type(owner)}.{field_name}" if owner else field_name)
            elif name in ("stfld", "stobj"):
                value = pop()[0]
                instance = pop()[0]
                if name == "stobj":
                    emit(f"{instance} = {value};")
                else:
                    target = self.metadata.field_ref(item.value)
                    emit(f"{instance}.{sanitize_identifier(target['name'], CS_KEYWORDS, 'field')} = {value};")
            elif name in ("stsfld",):
                value = pop()[0]
                target = self.metadata.field_ref(item.value)
                owner = (
                    self.field_owner.get(target["index"], target["owner"])
                    if target.get("table") == 0x04
                    else target["owner"]
                )
                field_name = sanitize_identifier(target["name"], CS_KEYWORDS, "field")
                emit(f"{cs_type(owner)}.{field_name} = {value};" if owner else f"{field_name} = {value};")
            elif name == "newobj":
                target = self.metadata.method_ref(item.value)
                args = pop(len(target["params"]))
                owner = cs_type(self.method_owner.get(target["index"], target["owner"]) or "object")
                push(f"new {owner}({', '.join(args)})")
            elif name in ("call", "callvirt", "jmp"):
                target = self.metadata.method_ref(item.value)
                args = pop(len(target["params"])) if target["params"] else []
                receiver = pop()[0] if target["has_this"] and name != "jmp" else None
                owner = (
                    self.method_owner.get(target["index"], target["owner"])
                    if target.get("table") == 0x06
                    else target["owner"]
                )
                raw_name = target["name"]
                method_name = sanitize_identifier(raw_name, CS_KEYWORDS, "Method")
                property_name = sanitize_identifier(raw_name[4:], CS_KEYWORDS, "Property") if raw_name[4:] else "Property"
                if raw_name.startswith("get_") and not target["params"]:
                    if receiver is not None:
                        push(f"{receiver}.{property_name}")
                    elif owner:
                        push(f"{cs_type(owner)}.{property_name}")
                    else:
                        push(property_name)
                    continue
                if raw_name.startswith("set_") and len(args) == 1:
                    target_text = receiver if receiver is not None else cs_type(owner) if owner else "this"
                    emit(f"{target_text}.{property_name} = {args[0]};")
                    continue
                if raw_name in (".ctor", ".cctor") and receiver == "this":
                    emit(f"// {( 'this' if owner == current_type else 'base' )}.ctor({', '.join(args)})")
                    continue
                if receiver is not None:
                    call_text = f"{receiver}.{method_name}({', '.join(args)})"
                elif owner:
                    call_text = f"{cs_type(owner)}.{method_name}({', '.join(args)})"
                else:
                    call_text = f"{method_name}({', '.join(args)})"
                if cs_type(target["returns"]) == "void":
                    emit(f"{call_text};")
                else:
                    push(call_text)
            elif name == "calli":
                pop(1)
                push("/* calli */ null")
            elif name == "ret":
                if cs_type(returns) == "void" or not stack:
                    emit("return;")
                else:
                    value = pop()[0]
                    if cs_type(returns) == "bool" and value in ("0", "1"):
                        value = "false" if value == "0" else "true"
                    emit(f"return {value};")
            elif name == "rethrow":
                emit("throw;")
            elif name == "throw":
                emit(f"throw {pop()[0]};")
            elif name in ("br", "br.s", "leave", "leave.s"):
                if item.value != item.next_offset:
                    emit(f"goto IL_{item.value:04x};")
            elif name in ("brtrue", "brtrue.s", "brfalse", "brfalse.s"):
                condition = pop()[0]
                if name.startswith("brfalse"):
                    condition = f"!({condition})"
                emit(f"if ({condition}) goto IL_{item.value:04x};")
            elif name.removesuffix(".s") in BRANCH_OPS:
                right = pop()[0]
                left = pop()[0]
                emit(f"if ({left} {BRANCH_OPS[name.removesuffix('.s')]} {right}) goto IL_{item.value:04x};")
            elif name == "switch":
                value = pop()[0]
                emit(f"// switch ({value})")
            elif name == "isinst":
                value = pop()[0]
                target = self.metadata.resolve_token(item.value)
                push(f"({value} as {cs_type(target)})")
            elif name == "castclass":
                value = pop()[0]
                target = self.metadata.resolve_token(item.value)
                push(f"(({cs_type(target)}){value})")
            elif name in ("box", "unbox.any"):
                value = pop()[0]
                target = self.metadata.resolve_token(item.value)
                push(f"(({cs_type(target)}){value})")
            elif name == "newarr":
                count = pop()[0]
                target = self.metadata.resolve_token(item.value)
                push(f"new {cs_type(target)}[{count}]")
            elif name == "ldlen":
                value = pop()[0]
                push(f"{value}.Length")
            elif name.startswith("ldelem"):
                index = pop()[0]
                array = pop()[0]
                push(f"{array}[{index}]")
            elif name.startswith("stelem"):
                value = pop()[0]
                index = pop()[0]
                array = pop()[0]
                emit(f"{array}[{index}] = {value};")
            elif name == "ldtoken":
                push("null")
            elif name == "sizeof":
                target = self.metadata.resolve_token(item.value)
                push(f"sizeof({cs_type(target)})")
            elif name == "initobj":
                address = pop()[0]
                target = self.metadata.resolve_token(item.value)
                emit(f"{address} = default({cs_type(target)});")
            elif name == "ldftn" or name == "ldvirtftn":
                push("null")
            elif name in ("endfinally", "endfilter"):
                emit("// end of exception block")
            elif name in ("arglist",):
                push("__arglist")
            else:
                emit(f"// IL_{item.offset:04x}: {name}")

        while stack:
            value = stack.pop()
            if value not in ("null", "this", "__arglist"):
                lines.append(self._indent + f"// leftover: {value}")
        if not any(line.strip().startswith(("return", "throw", "goto")) for line in lines[-3:]):
            if cs_type(returns) == "void":
                lines.append(self._indent + "return;")
        return lines or [self._indent + "// empty body"]
