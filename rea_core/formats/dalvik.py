"""Dalvik executable (DEX) reader with smali-style method disassembly.

Implemented from the published DEX layout: id tables, class definitions, class
data, code items and the Dalvik instruction formats. Nothing is executed and no
Android tooling is required.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Any

from ..context import Context
from ..errors import FormatError
from ..report import Report
from ..util import Reader, human_bytes, human_int, shorten

MAX_CLASSES = 100_000
MAX_INSTRUCTIONS = 2_000_000

ACCESS_FLAGS = {
    0x0001: "public",
    0x0002: "private",
    0x0004: "protected",
    0x0008: "static",
    0x0010: "final",
    0x0020: "synchronized",
    0x0040: "volatile",
    0x0080: "transient",
    0x0100: "native",
    0x0200: "interface",
    0x0400: "abstract",
    0x0800: "strict",
    0x1000: "synthetic",
    0x2000: "annotation",
    0x4000: "enum",
    0x10000: "constructor",
    0x20000: "declared-synchronized",
}

# format -> number of 16-bit code units
FORMAT_SIZES = {
    "10x": 1,
    "12x": 1,
    "11n": 1,
    "11x": 1,
    "10t": 1,
    "20t": 2,
    "22x": 2,
    "21t": 2,
    "21s": 2,
    "21h": 2,
    "21c": 2,
    "23x": 2,
    "22b": 2,
    "22t": 2,
    "22s": 2,
    "22c": 2,
    "32x": 3,
    "30t": 3,
    "31i": 3,
    "31t": 3,
    "31c": 3,
    "35c": 3,
    "3rc": 3,
    "45cc": 4,
    "4rcc": 4,
    "51l": 5,
}

OPCODES: dict[int, tuple[str, str]] = {}


def _op(code: int, name: str, fmt: str) -> None:
    OPCODES[code] = (name, fmt)


_op(0x00, "nop", "10x")
_op(0x01, "move", "12x")
_op(0x02, "move/from16", "22x")
_op(0x03, "move/16", "32x")
_op(0x04, "move-wide", "12x")
_op(0x05, "move-wide/from16", "22x")
_op(0x06, "move-wide/16", "32x")
_op(0x07, "move-object", "12x")
_op(0x08, "move-object/from16", "22x")
_op(0x09, "move-object/16", "32x")
_op(0x0A, "move-result", "11x")
_op(0x0B, "move-result-wide", "11x")
_op(0x0C, "move-result-object", "11x")
_op(0x0D, "move-exception", "11x")
_op(0x0E, "return-void", "10x")
_op(0x0F, "return", "11x")
_op(0x10, "return-wide", "11x")
_op(0x11, "return-object", "11x")
_op(0x12, "const/4", "11n")
_op(0x13, "const/16", "21s")
_op(0x14, "const", "31i")
_op(0x15, "const/high16", "21h")
_op(0x16, "const-wide/16", "21s")
_op(0x17, "const-wide/32", "31i")
_op(0x18, "const-wide", "51l")
_op(0x19, "const-wide/high16", "21h")
_op(0x1A, "const-string", "21c")
_op(0x1B, "const-string/jumbo", "31c")
_op(0x1C, "const-class", "21c")
_op(0x1D, "monitor-enter", "11x")
_op(0x1E, "monitor-exit", "11x")
_op(0x1F, "check-cast", "21c")
_op(0x20, "instance-of", "22c")
_op(0x21, "array-length", "12x")
_op(0x22, "new-instance", "21c")
_op(0x23, "new-array", "22c")
_op(0x24, "filled-new-array", "35c")
_op(0x25, "filled-new-array/range", "3rc")
_op(0x26, "fill-array-data", "31t")
_op(0x27, "throw", "11x")
_op(0x28, "goto", "10t")
_op(0x29, "goto/16", "20t")
_op(0x2A, "goto/32", "30t")
_op(0x2B, "packed-switch", "31t")
_op(0x2C, "sparse-switch", "31t")
_op(0x2D, "cmpl-float", "23x")
_op(0x2E, "cmpg-float", "23x")
_op(0x2F, "cmpl-double", "23x")
_op(0x30, "cmpg-double", "23x")
_op(0x31, "cmp-long", "23x")
for _i, _name in enumerate(("if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le")):
    _op(0x32 + _i, _name, "22t")
for _i, _name in enumerate(("if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez")):
    _op(0x38 + _i, _name, "21t")
for _i, _name in enumerate(
    (
        "aget",
        "aget-wide",
        "aget-object",
        "aget-boolean",
        "aget-byte",
        "aget-char",
        "aget-short",
        "aput",
        "aput-wide",
        "aput-object",
        "aput-boolean",
        "aput-byte",
        "aput-char",
        "aput-short",
    )
):
    _op(0x44 + _i, _name, "23x")
for _i, _name in enumerate(
    (
        "iget",
        "iget-wide",
        "iget-object",
        "iget-boolean",
        "iget-byte",
        "iget-char",
        "iget-short",
        "iput",
        "iput-wide",
        "iput-object",
        "iput-boolean",
        "iput-byte",
        "iput-char",
        "iput-short",
    )
):
    _op(0x52 + _i, _name, "22c")
for _i, _name in enumerate(
    (
        "sget",
        "sget-wide",
        "sget-object",
        "sget-boolean",
        "sget-byte",
        "sget-char",
        "sget-short",
        "sput",
        "sput-wide",
        "sput-object",
        "sput-boolean",
        "sput-byte",
        "sput-char",
        "sput-short",
    )
):
    _op(0x60 + _i, _name, "21c")
for _i, _name in enumerate(("invoke-virtual", "invoke-super", "invoke-direct", "invoke-static", "invoke-interface")):
    _op(0x6E + _i, _name, "35c")
for _i, _name in enumerate(
    ("invoke-virtual/range", "invoke-super/range", "invoke-direct/range", "invoke-static/range", "invoke-interface/range")
):
    _op(0x74 + _i, _name, "3rc")
for _i, _name in enumerate(
    (
        "neg-int",
        "not-int",
        "neg-long",
        "not-long",
        "neg-float",
        "neg-double",
        "int-to-long",
        "int-to-float",
        "int-to-double",
        "long-to-int",
        "long-to-float",
        "long-to-double",
        "float-to-int",
        "float-to-long",
        "float-to-double",
        "double-to-int",
        "double-to-long",
        "double-to-float",
        "int-to-byte",
        "int-to-char",
        "int-to-short",
    )
):
    _op(0x7B + _i, _name, "12x")
BINOP_NAMES = (
    "add-int",
    "sub-int",
    "mul-int",
    "div-int",
    "rem-int",
    "and-int",
    "or-int",
    "xor-int",
    "shl-int",
    "shr-int",
    "ushr-int",
    "add-long",
    "sub-long",
    "mul-long",
    "div-long",
    "rem-long",
    "and-long",
    "or-long",
    "xor-long",
    "shl-long",
    "shr-long",
    "ushr-long",
    "add-float",
    "sub-float",
    "mul-float",
    "div-float",
    "rem-float",
    "add-double",
    "sub-double",
    "mul-double",
    "div-double",
    "rem-double",
)
for _i, _name in enumerate(BINOP_NAMES):
    _op(0x90 + _i, _name, "23x")
    _op(0xB0 + _i, f"{_name}/2addr", "12x")
for _i, _name in enumerate(
    ("add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16", "rem-int/lit16", "and-int/lit16", "or-int/lit16", "xor-int/lit16")
):
    _op(0xD0 + _i, _name, "22s")
for _i, _name in enumerate(
    (
        "add-int/lit8",
        "rsub-int/lit8",
        "mul-int/lit8",
        "div-int/lit8",
        "rem-int/lit8",
        "and-int/lit8",
        "or-int/lit8",
        "xor-int/lit8",
        "shl-int/lit8",
        "shr-int/lit8",
        "ushr-int/lit8",
    )
):
    _op(0xD8 + _i, _name, "22b")
_op(0xFA, "invoke-polymorphic", "45cc")
_op(0xFB, "invoke-polymorphic/range", "4rcc")
_op(0xFC, "invoke-custom", "35c")
_op(0xFD, "invoke-custom/range", "3rc")
_op(0xFE, "const-method-handle", "21c")
_op(0xFF, "const-method-type", "21c")


def _decode_mutf8(raw: bytes) -> str:
    """Decode Modified UTF-8, which encodes NUL as two bytes and surrogates directly."""
    units: list[int] = []
    index = 0
    length = len(raw)
    while index < length:
        byte = raw[index]
        if byte < 0x80:
            units.append(byte)
            index += 1
        elif (byte & 0xE0) == 0xC0 and index + 1 < length:
            units.append(((byte & 0x1F) << 6) | (raw[index + 1] & 0x3F))
            index += 2
        elif (byte & 0xF0) == 0xE0 and index + 2 < length:
            units.append(((byte & 0x0F) << 12) | ((raw[index + 1] & 0x3F) << 6) | (raw[index + 2] & 0x3F))
            index += 3
        else:
            units.append(0xFFFD)
            index += 1
    data = b"".join(unit.to_bytes(2, "little") for unit in units)
    return data.decode("utf-16-le", "replace")


@dataclass
class DexFacts:
    label: str
    version: str
    checksum_ok: bool
    file_size: int
    string_count: int
    type_count: int
    method_count: int
    field_count: int
    classes: list[dict[str, Any]] = field(default_factory=list)
    smali: list[tuple[str, str]] = field(default_factory=list)
    instructions: int = 0
    truncated: bool = False
    limitations: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "classes": len(self.classes),
            "methods": self.method_count,
            "fields": self.field_count,
            "strings": self.string_count,
            "instructions": self.instructions,
        }


class Dex:
    def __init__(self, data: bytes, label: str) -> None:
        self.data = data
        self.label = label
        self.reader = Reader(data, "<", 0, label)
        if data[:4] != b"dex\n":
            raise FormatError("DEX magic missing")
        self.version = data[4:7].decode("latin-1")
        checksum = data[8:12]
        signature = data[12:32]
        if hashlib.sha1(data[32:]).digest() != signature:
            self.signature_ok = False
        else:
            self.signature_ok = True
        import zlib

        self.checksum_ok = (int.from_bytes(data[8:12], "little") & 0xFFFFFFFF) == (zlib.adler32(data[12:]) & 0xFFFFFFFF)
        reader = self.reader
        reader.seek(32)
        self.file_size = reader.u32()
        self.header_size = reader.u32()
        reader.u32()  # endian tag
        self.link_size = reader.u32()
        self.link_off = reader.u32()
        self.map_off = reader.u32()
        self.string_ids_size = reader.u32()
        self.string_ids_off = reader.u32()
        self.type_ids_size = reader.u32()
        self.type_ids_off = reader.u32()
        self.proto_ids_size = reader.u32()
        self.proto_ids_off = reader.u32()
        self.field_ids_size = reader.u32()
        self.field_ids_off = reader.u32()
        self.method_ids_size = reader.u32()
        self.method_ids_off = reader.u32()
        self.class_defs_size = reader.u32()
        self.class_defs_off = reader.u32()
        self.data_size = reader.u32()
        self.data_off = reader.u32()
        self.strings = self._read_strings()
        self.types = self._read_types()
        self._methods = self._read_method_ids()
        self._fields = self._read_field_ids()

    # -- id tables ----------------------------------------------------------
    def _read_strings(self) -> list[str]:
        strings: list[str] = []
        for index in range(self.string_ids_size):
            offset = Reader(self.data, "<", self.string_ids_off + index * 4).u32()
            sub = Reader(self.data, "<", offset, "string_data")
            try:
                sub.uleb()
                start = sub.pos
                end = start
                while end < len(self.data) and self.data[end] != 0:
                    end += 1
                strings.append(_decode_mutf8(self.data[start:end]))
            except FormatError:
                strings.append(f"<string {index}>")
        return strings

    def _read_types(self) -> list[str]:
        types: list[str] = []
        for index in range(self.type_ids_size):
            descriptor_index = Reader(self.data, "<", self.type_ids_off + index * 4).u32()
            types.append(self.string(descriptor_index))
        return types

    def _read_proto(self, index: int) -> tuple[str, str]:
        reader = Reader(self.data, "<", self.proto_ids_off + index * 12)
        reader.u32()  # shorty
        return_type = reader.u32()
        parameters_off = reader.u32()
        params: list[str] = []
        if parameters_off:
            sub = Reader(self.data, "<", parameters_off)
            size = sub.u32()
            for _ in range(size):
                params.append(self.type(sub.u16()))
        return self.type(return_type), "".join(params)

    def _read_method_ids(self) -> list[dict[str, Any]]:
        methods: list[dict[str, Any]] = []
        for index in range(self.method_ids_size):
            reader = Reader(self.data, "<", self.method_ids_off + index * 8)
            class_idx = reader.u16()
            proto_idx = reader.u16()
            name_idx = reader.u32()
            methods.append(
                {
                    "class": self.type(class_idx),
                    "proto": proto_idx,
                    "name": self.string(name_idx),
                }
            )
        return methods

    def _read_field_ids(self) -> list[dict[str, Any]]:
        fields: list[dict[str, Any]] = []
        for index in range(self.field_ids_size):
            reader = Reader(self.data, "<", self.field_ids_off + index * 8)
            class_idx = reader.u16()
            type_idx = reader.u16()
            name_idx = reader.u32()
            fields.append({"class": self.type(class_idx), "type": self.type(type_idx), "name": self.string(name_idx)})
        return fields

    def string(self, index: int) -> str:
        return self.strings[index] if 0 <= index < len(self.strings) else f"<string {index}>"

    def type(self, index: int) -> str:
        return self.types[index] if 0 <= index < len(self.types) else f"<type {index}>"

    def field(self, index: int) -> str:
        if not 0 <= index < len(self._fields):
            return f"<field {index}>"
        item = self._fields[index]
        return f"{item['class']}->{item['name']}:{item['type']}"

    def method(self, index: int) -> str:
        if not 0 <= index < len(self._methods):
            return f"<method {index}>"
        item = self._methods[index]
        returns, parameters = self._read_proto(item["proto"])
        return f"{item['class']}->{item['name']}({parameters}){returns}"

    def method_descriptor(self, index: int) -> tuple[str, str, str, str]:
        if not 0 <= index < len(self._methods):
            return f"<class {index}>", f"<method {index}>", "", ""
        item = self._methods[index]
        returns, parameters = self._read_proto(item["proto"])
        return item["class"], item["name"], parameters, returns

    # -- class data ---------------------------------------------------------
    def classes(self, max_classes: int, disassemble: bool) -> DexFacts:
        facts = DexFacts(
            label=self.label,
            version=self.version,
            checksum_ok=self.checksum_ok,
            file_size=self.file_size,
            string_count=self.string_ids_size,
            type_count=self.type_ids_size,
            method_count=self.method_ids_size,
            field_count=self.field_ids_size,
        )
        if not self.signature_ok:
            facts.limitations.append("The DEX SHA-1 signature does not match the payload bytes.")
        if not self.checksum_ok:
            facts.limitations.append("The DEX Adler-32 checksum does not match the payload bytes.")
        if self.file_size != len(self.data):
            facts.limitations.append(
                f"The header declares {human_int(self.file_size)} bytes but the reader holds {human_int(len(self.data))}."
            )

        total = min(self.class_defs_size, max_classes)
        if self.class_defs_size > max_classes:
            facts.truncated = True
            facts.limitations.append(
                f"Only the first {max_classes} of {human_int(self.class_defs_size)} classes were decompiled."
            )

        for index in range(total):
            entry = self._class(index, disassemble)
            facts.classes.append(entry["summary"])
            if entry["smali"] is not None:
                facts.smali.append((entry["path"], entry["smali"]))
            facts.instructions += entry["instructions"]
            if facts.instructions > MAX_INSTRUCTIONS:
                facts.limitations.append("Instruction budget reached; later method bodies were not disassembled.")
                break
        return facts

    def _class(self, index: int, disassemble: bool) -> dict[str, Any]:
        reader = Reader(self.data, "<", self.class_defs_off + index * 32)
        class_idx = reader.u32()
        access = reader.u32()
        super_idx = reader.u32()
        interfaces_off = reader.u32()
        source_idx = reader.u32()
        reader.u32()  # annotations_off
        class_data_off = reader.u32()
        reader.u32()  # static_values_off

        descriptor = self.type(class_idx)
        super_descriptor = self.type(super_idx) if super_idx != 0xFFFFFFFF else None
        source_file = self.string(source_idx) if source_idx != 0xFFFFFFFF else None
        interfaces: list[str] = []
        if interfaces_off:
            sub = Reader(self.data, "<", interfaces_off)
            for _ in range(sub.u32()):
                interfaces.append(self.type(sub.u32()))

        fields: list[dict[str, Any]] = []
        methods: list[dict[str, Any]] = []
        instructions = 0
        header_lines: list[str] = []
        method_lines: list[str] = []
        flags = [name for bit, name in ACCESS_FLAGS.items() if access & bit]
        header_lines.append(f".class {' '.join(flags)} {descriptor}")
        if super_descriptor:
            header_lines.append(f".super {super_descriptor}")
        else:
            header_lines.append(".super <none>")
        if source_file:
            header_lines.append(f'.source "{source_file}"')
        for interface in interfaces:
            header_lines.append(f".implements {interface}")
        header_lines.append("")

        if class_data_off:
            data = Reader(self.data, "<", class_data_off)
            static_fields = data.uleb()
            instance_fields = data.uleb()
            direct_methods = data.uleb()
            virtual_methods = data.uleb()

            field_index = 0
            for count, static in ((static_fields, True), (instance_fields, False)):
                field_index = 0
                bucket: list[dict[str, Any]] = []
                for _ in range(min(count, 65536)):
                    field_index += data.uleb()
                    field_flags = data.uleb()
                    item = self._fields[field_index] if field_index < len(self._fields) else None
                    if item is None:
                        continue
                    bucket.append(
                        {
                            "name": item["name"],
                            "type": item["type"],
                            "flags": [name for bit, name in ACCESS_FLAGS.items() if field_flags & bit],
                            "static": static,
                        }
                    )
                fields.extend(bucket)

            method_index = 0
            for count, direct in ((direct_methods, True), (virtual_methods, False)):
                method_index = 0
                if count:
                    method_lines.append("# direct methods" if direct else "# virtual methods")
                for _ in range(min(count, 200_000)):
                    method_index += data.uleb()
                    method_flags = data.uleb()
                    code_off = data.uleb()
                    klass, name, params, returns = self.method_descriptor(method_index)
                    method_flags_list = [flag for bit, flag in ACCESS_FLAGS.items() if method_flags & bit]
                    methods.append(
                        {
                            "class": klass,
                            "name": name,
                            "parameters": params,
                            "returns": returns,
                            "flags": method_flags_list,
                            "code_offset": code_off,
                            "direct": direct,
                        }
                    )
                    method_lines.append(f".method {' '.join(method_flags_list)} {name}({params}){returns}")
                    if code_off and disassemble:
                        body, used = self._code(code_off)
                        instructions += used
                        method_lines.extend("    " + line for line in body)
                    elif code_off:
                        method_lines.append("    # code body not disassembled (--no-disassembly)")
                    method_lines.append(".end method")
                    method_lines.append("")

        field_lines: list[str] = []
        for item in fields:
            field_lines.append(f".field {' '.join(item['flags'])} {item['name']}:{item['type']}")

        smali: str | None = None
        if disassemble:
            smali = "\n".join(
                [f"# smali recovered from dex {self.version}", "# class " + descriptor]
                + header_lines
                + field_lines
                + [""]
                + method_lines
            )

        relative = descriptor
        if relative.startswith("L") and relative.endswith(";"):
            relative = relative[1:-1]
        summary = {
            "descriptor": descriptor,
            "super": super_descriptor,
            "interfaces": interfaces,
            "source_file": source_file,
            "access_flags": access,
            "flags": flags,
            "fields": fields,
            "methods": [
                {
                    "name": item["name"],
                    "parameters": item["parameters"],
                    "returns": item["returns"],
                    "flags": item["flags"],
                    "code_offset": item["code_offset"],
                }
                for item in methods
            ],
            "path": f"sources/{relative}.smali",
        }
        return {"summary": summary, "smali": smali, "path": f"sources/{relative}.smali", "instructions": instructions}

    # -- code ---------------------------------------------------------------
    def _code(self, offset: int) -> tuple[list[str], int]:
        reader = Reader(self.data, "<", offset, "code_item")
        registers = reader.u16()
        ins = reader.u16()
        reader.u16()  # outs
        tries_size = reader.u16()
        reader.u32()  # debug_info_off
        insns_size = reader.u32()
        insns = Reader(self.data, "<", reader.pos, "insns")
        insns_start = insns.pos
        param_base = registers - ins
        lines: list[str] = [f".registers {registers}"]
        count = 0
        while insns.pos - insns_start < insns_size * 2:
            start = insns.pos // 2
            unit = insns.u16()
            opcode = unit & 0xFF
            info = OPCODES.get(opcode)
            if info is None:
                lines.append(f"    # unsupported opcode 0x{opcode:02x} at code unit {start}")
                break
            name, fmt = info
            size = FORMAT_SIZES[fmt]
            rest = [unit] + [insns.u16() for _ in range(size - 1)]
            rendered = _render(name, fmt, rest, self, param_base)
            lines.append(rendered)
            count += 1
            if count > 200_000:
                break
        if tries_size:
            lines.append(f"    # {tries_size} try/catch block(s) present")
        return lines, count


def _reg(index: int, param_base: int) -> str:
    if index >= param_base >= 0:
        return f"p{index - param_base}"
    return f"v{index}"


def _signed(value: int, bits: int) -> int:
    if value & (1 << (bits - 1)):
        return value - (1 << bits)
    return value


def _render(name: str, fmt: str, units: list[int], dex: Dex, param_base: int) -> str:
    unit0 = units[0]
    a = (unit0 >> 8) & 0xF
    b = (unit0 >> 12) & 0xF
    aa = (unit0 >> 8) & 0xFF

    def reg(value: int) -> str:
        return _reg(value, param_base)

    if fmt == "10x":
        return name
    if fmt == "12x":
        return f"{name} {reg(a)}, {reg(b)}"
    if fmt == "11n":
        return f"{name} {reg(a)}, #{_signed(b, 4)}"
    if fmt == "11x":
        return f"{name} {reg(aa)}"
    if fmt == "10t":
        return f"{name} :label_{_signed(aa, 8)}"
    if fmt == "20t":
        return f"{name} :label_{_signed(units[1], 16)}"
    if fmt == "22x":
        return f"{name} {reg(aa)}, {reg(units[1])}"
    if fmt == "21t":
        return f"{name} {reg(aa)}, :label_{_signed(units[1], 16)}"
    if fmt == "21s":
        return f"{name} {reg(aa)}, #{_signed(units[1], 16)}"
    if fmt == "21h":
        shift = 16 if name.startswith("const/high16") else 48
        return f"{name} {reg(aa)}, #0x{(_signed(units[1], 16) << shift) & 0xFFFFFFFFFFFFFFFF:x}"
    if fmt == "21c":
        if name in ("const-string", "const-string/jumbo"):
            return f'{name} {reg(aa)}, "{_escape(dex.string(units[1]))}"'
        if name == "const-class":
            return f"{name} {reg(aa)}, {dex.type(units[1])}"
        if "sget" in name or "sput" in name:
            return f"{name} {reg(aa)}, {dex.field(units[1])}"
        if name in ("const-method-handle", "const-method-type"):
            return f"{name} {reg(aa)}, {dex.string(units[1]) if name.endswith('type') else dex.field(units[1])}"
        return f"{name} {reg(aa)}, {dex.type(units[1])}"
    if fmt == "23x":
        return f"{name} {reg(aa)}, {reg(units[1] & 0xFF)}, {reg(units[1] >> 8)}"
    if fmt == "22b":
        return f"{name} {reg(aa)}, {reg(units[1] & 0xFF)}, #{_signed(units[1] >> 8, 8)}"
    if fmt == "22t":
        return f"{name} {reg(a)}, {reg(b)}, :label_{_signed(units[1], 16)}"
    if fmt == "22s":
        return f"{name} {reg(a)}, {reg(b)}, #{_signed(units[1], 16)}"
    if fmt == "22c":
        if name.startswith(("iget", "iput")):
            return f"{name} {reg(a)}, {reg(b)}, {dex.field(units[1])}"
        if name in ("instance-of", "new-array"):
            return f"{name} {reg(a)}, {reg(b)}, {dex.type(units[1])}"
        return f"{name} {reg(a)}, {reg(b)}, {dex.method(units[1])}"
    if fmt == "32x":
        return f"{name} {reg(units[1])}, {reg(units[2])}"
    if fmt == "30t":
        target = (units[1] | (units[2] << 16)) & 0xFFFFFFFF
        return f"{name} :label_{_signed(target, 32)}"
    if fmt == "31i":
        value = units[1] | (units[2] << 16)
        return f"{name} {reg(aa)}, #{_signed(value, 32)}"
    if fmt == "31t":
        value = units[1] | (units[2] << 16)
        return f"{name} {reg(aa)}, :label_{_signed(value, 32)}"
    if fmt == "31c":
        value = units[1] | (units[2] << 16)
        if "string" in name:
            return f'{name} {reg(aa)}, "{_escape(dex.string(value))}"'
        return f"{name} {reg(aa)}, {dex.type(value)}"
    if fmt == "51l":
        value = 0
        for index in range(4):
            value |= units[1 + index] << (16 * index)
        return f"{name} {reg(aa)}, #0x{value & 0xFFFFFFFFFFFFFFFF:x}L"
    if fmt in ("35c", "45cc"):
        count = a
        registers = [units[1] & 0xF, (units[1] >> 4) & 0xF, (units[1] >> 8) & 0xF, (units[1] >> 12) & 0xF, b]
        used = ", ".join(reg(value) for value in registers[:count])
        return f"{name} {{{used}}}, {dex.method(units[2])}"
    if fmt in ("3rc", "4rcc"):
        count = aa
        first = units[2]
        used = ", ".join(reg(first + offset) for offset in range(count))
        return f"{name} {{{used}}}, {dex.method(units[1])}"
    return f"{name} # raw {units}"


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")


def parse_dex(data: bytes, label: str, max_classes: int = MAX_CLASSES, disassemble: bool = True) -> DexFacts:
    dex = Dex(bytes(data), label)
    return dex.classes(max_classes=max_classes, disassemble=disassemble)


def _java_skeletons(
    facts: DexFacts,
    smali_texts: dict[str, str] | None = None,
    origin: str = "",
) -> list[tuple[str, str]]:
    """Emit one Java file per class, lifting bodies when the smali is available."""
    from .dex_java import render_java_class
    from .sourcegen import java_type, sanitize_identifier, split_descriptors, JAVA_KEYWORDS

    smali_texts = smali_texts or {}
    files: list[tuple[str, str]] = []
    for entry in facts.classes:
        descriptor = entry["descriptor"]
        if not (descriptor.startswith("L") and descriptor.endswith(";")):
            continue
        internal = descriptor[1:-1]
        java_path = f"sources/java/{internal}.java"
        smali_text = smali_texts.get(f"sources/{internal}.smali")
        if smali_text:
            try:
                files.append((java_path, render_java_class(entry, smali_text, origin or facts.label)))
                continue
            except Exception:
                pass
        package = internal.rsplit("/", 1)[0].replace("/", ".") if "/" in internal else ""
        simple = internal.rsplit("/", 1)[-1].rsplit("$", 1)[-1]
        simple = sanitize_identifier(simple, JAVA_KEYWORDS, "Class")
        flags = set(entry.get("flags") or [])
        modifiers = []
        if "public" in flags:
            modifiers.append("public")
        if "final" in flags:
            modifiers.append("final")
        if "abstract" in flags or "interface" in flags:
            modifiers.append("abstract")
        kind = "interface" if "interface" in flags else "class"
        header = " ".join(modifiers) + f" {kind} {simple}"
        super_descriptor = entry.get("super") or "Ljava/lang/Object;"
        if super_descriptor and super_descriptor != "Ljava/lang/Object;":
            header += " extends " + java_type(super_descriptor)
        interfaces = [java_type(item) for item in entry.get("interfaces") or []]
        if interfaces:
            header += " implements " + ", ".join(interfaces)
        lines = [
            f"// Recovered Java skeleton for {descriptor}",
            "// Bodies live in the smali artifact; this file preserves exact signatures.",
            "",
        ]
        if package:
            lines.append(f"package {package};")
            lines.append("")
        lines.append(header)
        lines.append("{")
        for field in entry.get("fields") or []:
            field_modifiers = ["public" if "public" in field.get("flags", []) else "private"]
            if "static" in field.get("flags", []):
                field_modifiers.append("static")
            if "final" in field.get("flags", []):
                field_modifiers.append("final")
            field_type = java_type(field.get("type", "I"))
            field_name = sanitize_identifier(field.get("name", "field"), JAVA_KEYWORDS, "field")
            lines.append(f"    {' '.join(field_modifiers)} {field_type} {field_name};")
        if entry.get("fields") and entry.get("methods"):
            lines.append("")
        smali_path = f"../{internal}.smali"
        for method in entry.get("methods") or []:
            method_flags = set(method.get("flags") or [])
            method_modifiers = []
            if "public" in method_flags:
                method_modifiers.append("public")
            elif "private" in method_flags:
                method_modifiers.append("private")
            elif "protected" in method_flags:
                method_modifiers.append("protected")
            if "static" in method_flags:
                method_modifiers.append("static")
            if "final" in method_flags:
                method_modifiers.append("final")
            if "abstract" in method_flags:
                method_modifiers.append("abstract")
            if "native" in method_flags:
                method_modifiers.append("native")
            name = method.get("name", "method")
            parameters = split_descriptors(method.get("parameters", ""))
            params = ", ".join(
                f"{java_type(item)} p{index}" for index, item in enumerate(parameters)
            )
            returns = java_type(method.get("returns", "V"))
            java_name = sanitize_identifier(name, JAVA_KEYWORDS, "method")
            signature = f"{' '.join(method_modifiers)} {returns} {java_name}({params})"
            if "abstract" in method_flags or "native" in method_flags or method.get("code_offset", 0) == 0:
                lines.append(f"    {signature};")
                continue
            lines.append(f"    {signature}")
            lines.append("    {")
            lines.append(f"        // body: see {smali_path}")
            lines.append("    }")
            lines.append("")
        lines.append("}")
        files.append((f"sources/java/{internal}.java", "\n".join(lines).rstrip() + "\n"))
    return files

def analyze(ctx: Context) -> Report:
    facts = parse_dex(
        bytes(ctx.data[: ctx.size]),
        os.path.basename(ctx.path),
        max_classes=min(ctx.options.max_items, MAX_CLASSES),
        disassemble=ctx.options.disassemble,
    )
    report = Report(kind="dex", label=f"Dalvik executable (DEX {facts.version})")
    ctx.stage(f"dex {facts.version}: {facts.string_count} strings, {facts.method_count} methods")
    report.summary.update(facts.summary())
    report.summary.update(
        {
            "file_size": human_bytes(facts.file_size),
            "checksum_ok": facts.checksum_ok,
        }
    )
    for limitation in facts.limitations:
        ctx.limit(limitation)

    class_section = report.section("Classes")
    for item in facts.classes[:200]:
        class_section.add(
            f"{item['descriptor']:<56} methods={len(item['methods']):<4} fields={len(item['fields'])}"
        )
    if len(facts.classes) > 200:
        class_section.add(f"... {len(facts.classes) - 200} more")

    for path, text in facts.smali:
        ctx.add_artifact(path, text, kind="disassembly")

    source_files: list[str] = []
    if ctx.options.source:
        ctx.stage("lifting Java method bodies from Dalvik registers")
        smali_texts = {path: text for path, text in facts.smali}
        for path, text in _java_skeletons(facts, smali_texts, ctx.path):
            if ctx.add_artifact(path, text, kind="source"):
                source_files.append(path)
        if source_files:
            source_section = report.section("Recovered Java sources")
            source_section.add(f"{len(source_files)} file(s) lifted from Dalvik; smali kept beside them")
            ctx.stage(f"Java sources: {len(source_files)} file(s)")
            for path in source_files[:60]:
                source_section.add(path)
            ctx.limit(
                "Lifted Java bodies cover straight-line code, branches and common opcodes; "
                "unusual control flow stays in goto form. A local jadx adds higher fidelity."
            )
    else:
        ctx.limit("Java source emission was disabled with --no-source.")

    if ctx.options.source and ctx.options.engine != "none":
        from .. import engines as engine_module

        engine = engine_module.discover().find("jadx")
        if engine:
            files, error = engine_module.run_source_engine(
                [engine.path, "-d", "{out}", "--no-res", "-q", ctx.path], ".java"
            )
            if error:
                ctx.limit(f"The local jadx engine produced no Java output: {error}")
            else:
                added = 0
                for relative, text in files:
                    if ctx.add_artifact(f"sources/jadx/{relative}", text, kind="source"):
                        added += 1
                if added:
                    ctx.observe(f"{added} Java file(s) came from the local jadx engine.")
                    report.section("External Java sources (local jadx)").add(f"{added} file(s) under sources/jadx/")

    report.payload = {
        "version": facts.version,
        "checksum_ok": facts.checksum_ok,
        "file_size": facts.file_size,
        "counts": {
            "strings": facts.string_count,
            "types": facts.type_count,
            "methods": facts.method_count,
            "fields": facts.field_count,
            "classes": len(facts.classes),
            "instructions": facts.instructions,
        },
        "classes": facts.classes,
        "source": {"language": "java", "files": source_files, "bodies": "smali"},
    }
    report.coverage = {
        "status": "partial" if facts.truncated else "complete",
        "examined": len(facts.classes),
        "total": len(facts.classes) + (1 if facts.truncated else 0),
        "exhausted": not facts.truncated,
    }
    report.next_steps.append("Open sources/<package>/<Class>.smali for the decoded method bodies.")
    report.next_steps.append("Java lifting is built in; a local jadx adds higher fidelity.")
    return report
