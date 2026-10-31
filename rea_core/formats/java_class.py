"""Java class-file reader with javap-style disassembly.

Everything is decoded from the class file itself: constant pool, members,
attributes and JVM bytecode. No JDK, no ``javap`` and no network access are
required.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

from ..context import Context
from ..errors import FormatError
from ..report import Report
from ..util import Reader, shorten

CLASS_FLAGS = {
    0x0001: "ACC_PUBLIC",
    0x0010: "ACC_FINAL",
    0x0020: "ACC_SUPER",
    0x0200: "ACC_INTERFACE",
    0x0400: "ACC_ABSTRACT",
    0x1000: "ACC_SYNTHETIC",
    0x2000: "ACC_ANNOTATION",
    0x4000: "ACC_ENUM",
    0x8000: "ACC_MODULE",
}

FIELD_FLAGS = {
    0x0001: "ACC_PUBLIC",
    0x0002: "ACC_PRIVATE",
    0x0004: "ACC_PROTECTED",
    0x0008: "ACC_STATIC",
    0x0010: "ACC_FINAL",
    0x0040: "ACC_VOLATILE",
    0x0080: "ACC_TRANSIENT",
    0x1000: "ACC_SYNTHETIC",
    0x4000: "ACC_ENUM",
}

METHOD_FLAGS = {
    0x0001: "ACC_PUBLIC",
    0x0002: "ACC_PRIVATE",
    0x0004: "ACC_PROTECTED",
    0x0008: "ACC_STATIC",
    0x0010: "ACC_FINAL",
    0x0020: "ACC_SYNCHRONIZED",
    0x0040: "ACC_BRIDGE",
    0x0080: "ACC_VARARGS",
    0x0100: "ACC_NATIVE",
    0x0400: "ACC_ABSTRACT",
    0x0800: "ACC_STRICT",
    0x1000: "ACC_SYNTHETIC",
}

MAJOR_TO_RELEASE = {
    45: "1.1",
    46: "1.2",
    47: "1.3",
    48: "1.4",
    49: "5",
    50: "6",
    51: "7",
    52: "8",
    53: "9",
    54: "10",
    55: "11",
    56: "12",
    57: "13",
    58: "14",
    59: "15",
    60: "16",
    61: "17",
    62: "18",
    63: "19",
    64: "20",
    65: "21",
    66: "22",
    67: "23",
    68: "24",
    69: "25",
}

# opcode -> (mnemonic, operand kind)
OPCODES: dict[int, tuple[str, str]] = {}


def _op(code: int, name: str, kind: str = "") -> None:
    OPCODES[code] = (name, kind)


_op(0x00, "nop")
_op(0x01, "aconst_null")
_op(0x02, "iconst_m1")
for _i in range(6):
    _op(0x03 + _i, f"iconst_{_i}")
_op(0x09, "lconst_0")
_op(0x0A, "lconst_1")
for _i in range(3):
    _op(0x0B + _i, f"fconst_{_i}")
    _op(0x0E + _i, f"dconst_{_i}")
_op(0x10, "bipush", "s1")
_op(0x11, "sipush", "s2")
_op(0x12, "ldc", "cp1")
_op(0x13, "ldc_w", "cp2")
_op(0x14, "ldc2_w", "cp2")
for _i, _name in enumerate(("iload", "lload", "fload", "dload", "aload")):
    _op(0x15 + _i, _name, "local")
for _i, _name in enumerate(("istore", "lstore", "fstore", "dstore", "astore")):
    _op(0x36 + _i, _name, "local")
for _prefix, _base in (("iload", 0x1A), ("lload", 0x1E), ("fload", 0x22), ("dload", 0x26), ("aload", 0x2A)):
    for _i in range(4):
        _op(_base + _i, f"{_prefix}_{_i}")
for _prefix, _base in (("istore", 0x3B), ("lstore", 0x3F), ("fstore", 0x43), ("dstore", 0x47), ("astore", 0x4B)):
    for _i in range(4):
        _op(_base + _i, f"{_prefix}_{_i}")
for _i, _name in enumerate(
    (
        "iaload",
        "laload",
        "faload",
        "daload",
        "aaload",
        "baload",
        "caload",
        "saload",
    )
):
    _op(0x2E + _i, _name)
for _i, _name in enumerate(
    (
        "iastore",
        "lastore",
        "fastore",
        "dastore",
        "aastore",
        "bastore",
        "castore",
        "sastore",
    )
):
    _op(0x4F + _i, _name)
for _i, _name in enumerate(
    ("pop", "pop2", "dup", "dup_x1", "dup_x2", "dup2", "dup2_x1", "dup2_x2", "swap")
):
    _op(0x57 + _i, _name)
for _i, _name in enumerate(
    (
        "iadd",
        "ladd",
        "fadd",
        "dadd",
        "isub",
        "lsub",
        "fsub",
        "dsub",
        "imul",
        "lmul",
        "fmul",
        "dmul",
        "idiv",
        "ldiv",
        "fdiv",
        "ddiv",
        "irem",
        "lrem",
        "frem",
        "drem",
        "ineg",
        "lneg",
        "fneg",
        "dneg",
        "ishl",
        "lshl",
        "ishr",
        "lshr",
        "iushr",
        "lushr",
        "iand",
        "land",
        "ior",
        "lor",
        "ixor",
        "lxor",
    )
):
    _op(0x60 + _i, _name)
_op(0x84, "iinc", "iinc")
for _i, _name in enumerate(
    ("i2l", "i2f", "i2d", "l2i", "l2f", "l2d", "f2i", "f2l", "f2d", "d2i", "d2l", "d2f", "i2b", "i2c", "i2s")
):
    _op(0x85 + _i, _name)
for _i, _name in enumerate(("lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg")):
    _op(0x94 + _i, _name)
for _i, _name in enumerate(
    (
        "ifeq",
        "ifne",
        "iflt",
        "ifge",
        "ifgt",
        "ifle",
        "if_icmpeq",
        "if_icmpne",
        "if_icmplt",
        "if_icmpge",
        "if_icmpgt",
        "if_icmple",
        "if_acmpeq",
        "if_acmpne",
    )
):
    _op(0x99 + _i, _name, "s2")
_op(0xA7, "goto", "s2")
_op(0xA8, "jsr", "s2")
_op(0xA9, "ret", "local")
_op(0xAA, "tableswitch", "switch")
_op(0xAB, "lookupswitch", "switch")
for _i, _name in enumerate(("ireturn", "lreturn", "freturn", "dreturn", "areturn", "return")):
    _op(0xAC + _i, _name)
for _i, _name in enumerate(("getstatic", "putstatic", "getfield", "putfield", "invokevirtual", "invokespecial", "invokestatic")):
    _op(0xB2 + _i, _name, "cp2")
_op(0xB9, "invokeinterface", "invokeinterface")
_op(0xBA, "invokedynamic", "invokedynamic")
_op(0xBB, "new", "cp2")
_op(0xBC, "newarray", "newarray")
_op(0xBD, "anewarray", "cp2")
_op(0xBE, "arraylength")
_op(0xBF, "athrow")
_op(0xC0, "checkcast", "cp2")
_op(0xC1, "instanceof", "cp2")
_op(0xC2, "monitorenter")
_op(0xC3, "monitorexit")
_op(0xC4, "wide", "wide")
_op(0xC5, "multianewarray", "multianewarray")
_op(0xC6, "ifnull", "s2")
_op(0xC7, "ifnonnull", "s2")
_op(0xC8, "goto_w", "s4")
_op(0xC9, "jsr_w", "s4")
_op(0xCA, "breakpoint")
_op(0xFE, "impdep1")
_op(0xFF, "impdep2")

ARRAY_TYPES = {
    4: "boolean",
    5: "char",
    6: "float",
    7: "double",
    8: "byte",
    9: "short",
    10: "int",
    11: "long",
}


def _flags(value: int, table: dict[int, str]) -> list[str]:
    return [name for bit, name in table.items() if value & bit]


class ClassFile:
    def __init__(self, data: bytes, label: str = "class file") -> None:
        self.reader = Reader(data, ">", 0, label)
        if self.reader.u32() != 0xCAFEBABE:
            raise FormatError("class-file magic CAFEBABE missing")
        self.minor = self.reader.u16()
        self.major = self.reader.u16()
        self.pool: list[Any] = [None]
        self.pool_text: list[str] = ["<unused>"]
        self.attributes: list[dict[str, Any]] = []

    # -- constant pool ------------------------------------------------------
    def read_pool(self) -> None:
        count = self.reader.u16()
        index = 1
        while index < count:
            tag = self.reader.u8()
            if tag == 1:
                length = self.reader.u16()
                raw = self.reader.read(length)
                text = raw.decode("utf-8", "replace")
                self.pool.append(("Utf8", text))
                self.pool_text.append(text)
            elif tag == 3:
                self.pool.append(("Integer", self.reader.i32()))
                self.pool_text.append(str(self.pool[-1][1]))
            elif tag == 4:
                self.pool.append(("Float", self.reader.f32()))
                self.pool_text.append(str(self.pool[-1][1]))
            elif tag == 5:
                value = self.reader.i64()
                self.pool.append(("Long", value))
                self.pool_text.append(str(value))
                self.pool.append(None)
                self.pool_text.append("<unused>")
                index += 1
            elif tag == 6:
                value = self.reader.f64()
                self.pool.append(("Double", value))
                self.pool_text.append(str(value))
                self.pool.append(None)
                self.pool_text.append("<unused>")
                index += 1
            elif tag in (7, 8, 16, 19, 20):
                names = {7: "Class", 8: "String", 16: "MethodType", 19: "Module", 20: "Package"}
                self.pool.append((names[tag], self.reader.u16()))
                self.pool_text.append(f"{names[tag]} #{self.pool[-1][1]}")
            elif tag in (9, 10, 11, 12, 17, 18):
                names = {
                    9: "Fieldref",
                    10: "Methodref",
                    11: "InterfaceMethodref",
                    12: "NameAndType",
                    17: "Dynamic",
                    18: "InvokeDynamic",
                }
                first = self.reader.u16()
                second = self.reader.u16()
                self.pool.append((names[tag], (first, second)))
                self.pool_text.append(f"{names[tag]} #{first}.#{second}")
            elif tag == 15:
                kind = self.reader.u8()
                reference = self.reader.u16()
                self.pool.append(("MethodHandle", (kind, reference)))
                self.pool_text.append(f"MethodHandle kind={kind} #{reference}")
            else:
                raise FormatError(f"unknown constant-pool tag {tag} at index {index}")
            index += 1

    def utf8(self, index: int) -> str:
        try:
            entry = self.pool[index]
        except IndexError:
            return f"<bad #{index}>"
        if entry and entry[0] == "Utf8":
            return entry[1]
        return f"<#{index}>"

    def class_name(self, index: int) -> str:
        if index == 0:
            return ""
        try:
            entry = self.pool[index]
        except IndexError:
            return f"<bad #{index}>"
        if entry and entry[0] == "Class":
            return self.utf8(entry[1])
        return self.utf8(index)

    def describe_constant(self, index: int) -> str:
        try:
            entry = self.pool[index]
        except IndexError:
            return f"<bad #{index}>"
        if entry is None:
            return f"<bad #{index}>"
        tag, value = entry
        if tag == "Utf8":
            return shorten(value, 90)
        if tag in ("Integer", "Float", "Long", "Double"):
            return f"{tag} {value}"
        if tag == "Class":
            return f"class {self.utf8(value)}"
        if tag == "String":
            return f'String "{shorten(self.utf8(value), 80)}"'
        if tag == "MethodType":
            return f"MethodType {self.utf8(value)}"
        if tag in ("Fieldref", "Methodref", "InterfaceMethodref"):
            owner = self.class_name(value[0])
            name, desc = self._name_and_type(value[1])
            return f"{tag} {owner}.{name}:{desc}"
        if tag == "NameAndType":
            name, desc = self._name_and_type(index)
            return f"NameAndType {name}:{desc}"
        if tag == "MethodHandle":
            kind, ref = value
            return f"MethodHandle kind={kind} -> {self.describe_constant(ref)}"
        if tag in ("InvokeDynamic", "Dynamic"):
            return f"{tag} bootstrap #{value[0]} {self._name_and_type(value[1])}"
        if tag in ("Module", "Package"):
            return f"{tag} {self.utf8(value)}"
        return f"{tag} {value}"

    def _name_and_type(self, index: int) -> tuple[str, str]:
        try:
            entry = self.pool[index]
        except IndexError:
            return f"<bad #{index}>", ""
        if entry and entry[0] == "NameAndType":
            return self.utf8(entry[1][0]), self.utf8(entry[1][1])
        return self.utf8(index), ""

    # -- attributes ---------------------------------------------------------
    def read_attributes(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        count = self.reader.u16()
        for _ in range(count):
            name_index = self.reader.u16()
            length = self.reader.u32()
            raw = self.reader.read(length)
            items.append(
                {
                    "name": self.utf8(name_index),
                    "length": length,
                    "raw": raw,
                }
            )
        return items

    # -- members ------------------------------------------------------------
    def read_members(self, kind: str) -> list[dict[str, Any]]:
        members: list[dict[str, Any]] = []
        count = self.reader.u16()
        for _ in range(count):
            access = self.reader.u16()
            name = self.utf8(self.reader.u16())
            descriptor = self.utf8(self.reader.u16())
            attributes = self.read_attributes()
            entry = {
                "access_flags": access,
                "flags": _flags(access, METHOD_FLAGS if kind == "method" else FIELD_FLAGS),
                "name": name,
                "descriptor": descriptor,
                "attributes": [
                    {"name": attribute["name"], "length": attribute["length"]}
                    for attribute in attributes
                ],
            }
            if kind == "method":
                entry["code"] = _decode_code(self, attributes)
            else:
                for attribute in attributes:
                    if attribute["name"] == "ConstantValue" and len(attribute["raw"]) == 2:
                        constant = int.from_bytes(attribute["raw"], "big")
                        entry["constant"] = self.describe_constant(constant)
                    elif attribute["name"] == "Signature" and len(attribute["raw"]) == 2:
                        entry["signature"] = self.utf8(int.from_bytes(attribute["raw"], "big"))
            if kind == "field":
                entry["type"] = _descriptor_to_java(descriptor)
            members.append(entry)
        return members


def _descriptor_to_java(descriptor: str) -> str:
    primitives = {
        "V": "void",
        "Z": "boolean",
        "B": "byte",
        "C": "char",
        "S": "short",
        "I": "int",
        "J": "long",
        "F": "float",
        "D": "double",
    }
    if descriptor in primitives:
        return primitives[descriptor]
    if descriptor.startswith("["):
        return _descriptor_to_java(descriptor[1:]) + "[]"
    if descriptor.startswith("L") and descriptor.endswith(";"):
        return descriptor[1:-1].replace("/", ".")
    return descriptor


def _split_descriptor_params(params: str) -> list[str]:
    parts: list[str] = []
    index = 0
    while index < len(params):
        start = index
        while index < len(params) and params[index] == "[":
            index += 1
        if index >= len(params):
            parts.append(params[start:])
            break
        if params[index] == "L":
            end = params.find(";", index)
            index = len(params) if end < 0 else end + 1
        else:
            index += 1
        parts.append(params[start:index])
    return parts


def _method_signature(name: str, descriptor: str) -> str:
    if not descriptor.startswith("("):
        return f"{name}({descriptor})"
    head, _, tail = descriptor.partition(")")
    result = tail or "V"
    parameters = [_descriptor_to_java(item) for item in _split_descriptor_params(head[1:])]
    return f"{_descriptor_to_java(result)} {name}({', '.join(parameters)})"


def _decode_code(clazz: ClassFile, attributes: list[dict[str, Any]]) -> dict[str, Any] | None:
    for attribute in attributes:
        if attribute["name"] != "Code":
            continue
        reader = Reader(attribute["raw"], ">", 0, "Code attribute")
        max_stack = reader.u16()
        max_locals = reader.u16()
        code_length = reader.u32()
        code = reader.read(code_length)
        handlers: list[dict[str, Any]] = []
        handler_count = reader.u16()
        for _ in range(handler_count):
            handlers.append(
                {
                    "start_pc": reader.u16(),
                    "end_pc": reader.u16(),
                    "handler_pc": reader.u16(),
                    "catch_type": clazz.class_name(reader.u16()) or "any",
                }
            )
        inner: list[dict[str, Any]] = []
        for _ in range(reader.u16()):
            inner_name = clazz.utf8(reader.u16())
            inner_length = reader.u32()
            inner.append({"name": inner_name, "length": inner_length, "raw": reader.read(inner_length)})
        line_numbers: list[dict[str, int]] = []
        local_variables: list[dict[str, Any]] = []
        for item in inner:
            if item["name"] == "LineNumberTable":
                sub = Reader(item["raw"], ">", 0, "LineNumberTable")
                for _ in range(sub.u16()):
                    line_numbers.append({"start_pc": sub.u16(), "line": sub.u16()})
            elif item["name"] == "LocalVariableTable":
                sub = Reader(item["raw"], ">", 0, "LocalVariableTable")
                for _ in range(sub.u16()):
                    start = sub.u16()
                    length = sub.u16()
                    name = clazz.utf8(sub.u16())
                    signature = clazz.utf8(sub.u16())
                    slot = sub.u16()
                    local_variables.append(
                        {
                            "start_pc": start,
                            "length": length,
                            "name": name,
                            "type": _descriptor_to_java(signature),
                            "slot": slot,
                        }
                    )
        instructions, notes = _disassemble(clazz, code)
        return {
            "max_stack": max_stack,
            "max_locals": max_locals,
            "code_length": code_length,
            "bytecode_sha256": hashlib.sha256(code).hexdigest(),
            "instructions": instructions,
            "disassembly": notes,
            "exception_table": handlers,
            "line_numbers": line_numbers,
            "local_variables": local_variables,
        }
    return None


def _read_s4(code: bytes, pos: int) -> int:
    return int.from_bytes(code[pos : pos + 4], "big", signed=True)


def _disassemble(clazz: ClassFile, code: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    instructions: list[dict[str, Any]] = []
    lines: list[str] = []
    pos = 0
    size = len(code)
    while pos < size:
        start = pos
        opcode = code[pos]
        pos += 1
        name, kind = OPCODES.get(opcode, (f"op_{opcode:02x}", ""))
        operands = ""
        extra: list[str] = []
        try:
            if kind == "":
                pass
            elif kind == "s1":
                value = int.from_bytes(code[pos : pos + 1], "big", signed=True)
                pos += 1
                operands = f"{value}"
            elif kind == "cp1":
                index = code[pos]
                pos += 1
                operands = f"#{index}"
                extra.append(clazz.describe_constant(index))
            elif kind == "cp2":
                index = int.from_bytes(code[pos : pos + 2], "big")
                pos += 2
                operands = f"#{index}"
                extra.append(clazz.describe_constant(index))
            elif kind == "s2":
                delta = int.from_bytes(code[pos : pos + 2], "big", signed=True)
                target = start + delta
                pos += 2
                operands = f"{target}"
                extra.append(f"branch to {target}")
            elif kind == "s4":
                delta = _read_s4(code, pos)
                target = start + delta
                pos += 4
                operands = f"{target}"
                extra.append(f"branch to {target}")
            elif kind == "local":
                slot = code[pos]
                pos += 1
                operands = f"{slot}"
            elif kind == "iinc":
                slot = code[pos]
                amount = int.from_bytes(code[pos + 1 : pos + 2], "big", signed=True)
                pos += 2
                operands = f"{slot}, {amount}"
            elif kind == "newarray":
                array_type = code[pos]
                pos += 1
                operands = f"{array_type}"
                extra.append(ARRAY_TYPES.get(array_type, "?"))
            elif kind == "multianewarray":
                index = int.from_bytes(code[pos : pos + 2], "big")
                dimensions = code[pos + 2]
                pos += 3
                operands = f"#{index}, {dimensions}"
                extra.append(clazz.describe_constant(index))
            elif kind == "invokeinterface":
                index = int.from_bytes(code[pos : pos + 2], "big")
                count = code[pos + 2]
                pos += 4
                operands = f"#{index}, {count}"
                extra.append(clazz.describe_constant(index))
            elif kind == "invokedynamic":
                index = int.from_bytes(code[pos : pos + 2], "big")
                pos += 4
                operands = f"#{index}"
                extra.append(clazz.describe_constant(index))
            elif kind == "switch":
                pad = (4 - (pos % 4)) % 4
                pos += pad
                default = _read_s4(code, pos)
                pos += 4
                if name == "tableswitch":
                    low = _read_s4(code, pos)
                    high = _read_s4(code, pos + 4)
                    pos += 8
                    count = max(0, high - low + 1)
                    pairs = []
                    for offset in range(count):
                        target = start + _read_s4(code, pos)
                        pos += 4
                        pairs.append(f"{low + offset}->{target}")
                    operands = f"default {start + default}"
                    extra.append(", ".join(pairs) or "no cases")
                else:
                    pairs_count = _read_s4(code, pos)
                    pos += 4
                    pairs = []
                    for _ in range(max(0, pairs_count)):
                        match = _read_s4(code, pos)
                        target = start + _read_s4(code, pos + 4)
                        pos += 8
                        pairs.append(f"{match}->{target}")
                    operands = f"default {start + default}"
                    extra.append(", ".join(pairs) or "no pairs")
            elif kind == "wide":
                widened = code[pos]
                pos += 1
                wide_name = OPCODES.get(widened, (f"op_{widened:02x}", ""))[0]
                name = f"wide {wide_name}"
                if widened == 0x84:
                    slot = int.from_bytes(code[pos : pos + 2], "big")
                    amount = int.from_bytes(code[pos + 2 : pos + 4], "big", signed=True)
                    pos += 4
                    operands = f"{slot}, {amount}"
                else:
                    slot = int.from_bytes(code[pos : pos + 2], "big")
                    pos += 2
                    operands = f"{slot}"
            else:
                extra.append(f"unsupported operand kind {kind}")
        except IndexError:
            extra.append("truncated instruction")
            pos = min(size, pos + 1)

        comment = f"  // {', '.join(item for item in extra if item)}" if extra else ""
        line = f"{start:6d}: {name:<16}{operands}{comment}"
        lines.append(line)
        instructions.append(
            {
                "offset": start,
                "opcode": opcode,
                "mnemonic": name,
                "operands": operands,
                "resolved": [item for item in extra if item],
                "length": max(1, pos - start),
            }
        )
        if pos <= start:
            pos = start + 1
    return instructions, lines


def analyze(ctx: Context) -> Report:
    data = bytes(ctx.data[: ctx.size])
    clazz = ClassFile(data, os.path.basename(ctx.path))
    clazz.read_pool()
    ctx.stage(f"constant pool: {len(clazz.pool) - 1} entries")
    access = clazz.reader.u16()
    this_class = clazz.reader.u16()
    super_class = clazz.reader.u16()
    interface_count = clazz.reader.u16()
    interfaces = [clazz.class_name(clazz.reader.u16()) for _ in range(interface_count)]
    fields = clazz.read_members("field")
    methods = clazz.read_members("method")
    attributes = clazz.read_attributes()

    class_name = clazz.class_name(this_class)
    major_value = clazz.major
    minor_value = clazz.minor
    ctx.stage(f"members: {len(fields)} fields, {len(methods)} methods")

    report = Report(kind="java-class", label=f"Java class {class_name}")
    report.summary.update(
        {
            "class": class_name,
            "super": clazz.class_name(super_class) or "(none)",
            "interfaces": len(interfaces),
            "fields": len(fields),
            "methods": len(methods),
            "class_file_version": f"{major_value}.{minor_value} (Java {MAJOR_TO_RELEASE.get(major_value, '?')})",
            "flags": ", ".join(_flags(access, CLASS_FLAGS)) or "(none)",
        }
    )

    pool_section = report.section("Constant pool")
    for index in range(1, len(clazz.pool)):
        if clazz.pool[index] is None:
            continue
        pool_section.add(f"{index:5d} = {clazz.pool[index][0]:<18} {clazz.describe_constant(index)}")

    class_section = report.section("Class")
    class_section.add(f"flags        {', '.join(_flags(access, CLASS_FLAGS)) or '(none)'}")
    class_section.add(f"this         {class_name}")
    class_section.add(f"super        {clazz.class_name(super_class) or '(none)'}")
    if interfaces:
        class_section.add("interfaces   " + ", ".join(interfaces))
    for attribute in attributes:
        if attribute["name"] == "SourceFile" and len(attribute["raw"]) == 2:
            class_section.add(f"SourceFile   {clazz.utf8(int.from_bytes(attribute['raw'], 'big'))}")
        elif attribute["name"] == "Signature" and len(attribute["raw"]) == 2:
            class_section.add(f"Signature    {clazz.utf8(int.from_bytes(attribute['raw'], 'big'))}")
        else:
            class_section.add(f"attribute    {attribute['name']} ({attribute['length']} bytes)")

    field_section = report.section("Fields")
    for field in fields:
        field_section.add(
            f"{field['type']:<30} {field['name']:<28} {', '.join(field['flags']) or ''}".rstrip()
        )
        if "constant" in field:
            field_section.add(f"    constant: {field['constant']}")
    if not fields:
        field_section.add("(no declared fields)")

    method_section = report.section("Methods")
    dump: list[str] = [
        "# javap-style disassembly",
        f"# artifact : {ctx.path}",
        f"# sha256   : {ctx.sha256}",
        f"# class    : {class_name}",
        f"# version  : {major_value}.{minor_value}",
        "",
        f"{' '.join(name.lower().replace('acc_', '') for name in _flags(access, CLASS_FLAGS)).strip()} class {class_name}"
        + (f" extends {clazz.class_name(super_class)}" if super_class else ""),
        "{",
    ]
    for method in methods:
        signature = _method_signature(method["name"], method["descriptor"])
        flags = " ".join(name.lower().replace("acc_", "") for name in method["flags"])
        method_section.add(f"{signature}    flags={flags or '-'}")
        dump.append(f"  {flags} {signature};")
        dump.append(f"    descriptor: {method['descriptor']}")
        code = method.get("code")
        if code is None:
            dump.append("    (no Code attribute)")
            dump.append("")
            continue
        dump.append(f"    Code: stack={code['max_stack']}, locals={code['max_locals']}")
        dump.extend("      " + line for line in code["disassembly"])
        if code["exception_table"]:
            dump.append("      Exception table:")
            for handler in code["exception_table"]:
                dump.append(
                    f"        {handler['start_pc']:>6} {handler['end_pc']:>6} {handler['handler_pc']:>6} "
                    f"Class {handler['catch_type']}"
                )
        if code["line_numbers"]:
            dump.append("      LineNumberTable:")
            for entry in code["line_numbers"]:
                dump.append(f"        line {entry['line']}: {entry['start_pc']}")
        if code["local_variables"]:
            dump.append("      LocalVariableTable:")
            for entry in code["local_variables"]:
                dump.append(
                    f"        {entry['slot']:>3}  {entry['name']:<24} {entry['type']}"
                )
        dump.append("")
        method_section.add(
            f"    bytecode {code['code_length']} bytes, {len(code['instructions'])} instructions, "
            f"stack={code['max_stack']}, locals={code['max_locals']}"
        )
    dump.append("}")
    report.payload = {
        "class_name": class_name,
        "super_class": clazz.class_name(super_class),
        "interfaces": interfaces,
        "access_flags": access,
        "flags": _flags(access, CLASS_FLAGS),
        "class_file_version": {"major": major_value, "minor": minor_value, "release": MAJOR_TO_RELEASE.get(major_value)},
        "constant_pool_count": len(clazz.pool) - 1,
        "fields": fields,
        "methods": methods,
        "class_attributes": [
            {"name": attribute["name"], "length": attribute["length"]} for attribute in attributes
        ],
    }
    report.coverage = {
        "status": "complete",
        "examined": len(methods),
        "total": len(methods),
        "exhausted": True,
    }

    package_path = class_name.replace(".", "/")
    ctx.add_artifact(f"sources/{package_path}.javap.txt", "\n".join(dump), kind="disassembly")

    source_path = None
    if ctx.options.source:
        from .java_src import JavaEmitter

        ctx.stage("reconstructing Java source from bytecode")
        emitter = JavaEmitter(clazz, ctx.path, ctx.sha256)
        try:
            java_text = emitter.emit(access, class_name, clazz.class_name(super_class), interfaces, fields, methods)
        except FormatError as exc:
            ctx.limit(f"Java reconstruction stopped early: {exc.message}")
            java_text = ""
        if java_text:
            source_path = f"sources/java/{class_name.replace('.', '/')}.java"
            ctx.stage(f"Java source: {source_path}")
            if ctx.add_artifact(source_path, java_text, kind="source"):
                report.payload["source"] = {"language": "java", "files": [source_path]}
                source_section = report.section("Recovered Java source")
                source_section.add(source_path)
                ctx.observe("Java source was reconstructed from bytecode; verify it against the javap listing.")
    else:
        ctx.limit("Java source reconstruction was disabled with --no-source.")

    report.next_steps.append("Open the .javap.txt artifact for the complete member and bytecode listing.")
    report.next_steps.append("Local javap/jadx are not required; both are optional external engines.")
    return report
