"""Managed (.NET) assembly reader: ECMA-335 metadata, signatures and CIL.

The reader walks the PE/CLI headers, metadata heaps and tables without loading
or executing the assembly, then renders each method body as IL. Type and member
names, signatures and tokens come straight from metadata.
"""

from __future__ import annotations

import hashlib
import os
import struct
from typing import Any

from ..context import Context
from ..errors import FormatError
from ..report import Report
from ..util import Reader, human_bytes, human_int, shorten

# ---------------------------------------------------------------------------
# metadata tables
# ---------------------------------------------------------------------------

CODED_INDEXES: dict[str, tuple[int, tuple[int, ...]]] = {
    "TypeDefOrRef": (2, (2, 1, 27)),
    "HasConstant": (2, (4, 8, 23)),
    "HasCustomAttribute": (5, (6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43)),
    "HasFieldMarshal": (1, (4, 8)),
    "HasDeclSecurity": (2, (2, 6, 32)),
    "MemberRefParent": (3, (2, 1, 26, 6, 27)),
    "HasSemantics": (1, (20, 23)),
    "MethodDefOrRef": (1, (6, 10)),
    "MemberForwarded": (1, (4, 6)),
    "Implementation": (2, (38, 35, 39)),
    "CustomAttributeType": (3, (6, 10)),
    "ResolutionScope": (2, (0, 26, 35, 1)),
    "TypeOrMethodDef": (1, (2, 6)),
}

S = "str"
G = "guid"
B = "blob"

TABLE_SCHEMAS: dict[int, tuple[str, tuple[tuple[str, Any], ...]]] = {
    0: ("Module", (("Generation", "u16"), ("Name", S), ("Mvid", G), ("EncId", G), ("EncBaseId", G))),
    1: ("TypeRef", (("ResolutionScope", "coded:ResolutionScope"), ("Name", S), ("Namespace", S))),
    2: (
        "TypeDef",
        (
            ("Flags", "u32"),
            ("Name", S),
            ("Namespace", S),
            ("Extends", "coded:TypeDefOrRef"),
            ("FieldList", "idx:4"),
            ("MethodList", "idx:6"),
        ),
    ),
    3: ("FieldPtr", (("Field", "idx:4"),)),
    4: ("Field", (("Flags", "u16"), ("Name", S), ("Signature", B))),
    5: ("MethodPtr", (("Method", "idx:6"),)),
    6: (
        "MethodDef",
        (
            ("RVA", "u32"),
            ("ImplFlags", "u16"),
            ("Flags", "u16"),
            ("Name", S),
            ("Signature", B),
            ("ParamList", "idx:8"),
        ),
    ),
    7: ("ParamPtr", (("Param", "idx:8"),)),
    8: ("Param", (("Flags", "u16"), ("Sequence", "u16"), ("Name", S))),
    9: ("InterfaceImpl", (("Class", "idx:2"), ("Interface", "coded:TypeDefOrRef"))),
    10: ("MemberRef", (("Class", "coded:MemberRefParent"), ("Name", S), ("Signature", B))),
    11: ("Constant", (("Type", "u8"), ("Padding", "u8"), ("Parent", "coded:HasConstant"), ("Value", B))),
    12: ("CustomAttribute", (("Parent", "coded:HasCustomAttribute"), ("Type", "coded:CustomAttributeType"), ("Value", B))),
    13: ("FieldMarshal", (("Parent", "coded:HasFieldMarshal"), ("NativeType", B))),
    14: ("DeclSecurity", (("Action", "u16"), ("Parent", "coded:HasDeclSecurity"), ("PermissionSet", B))),
    15: ("ClassLayout", (("PackingSize", "u16"), ("ClassSize", "u32"), ("Parent", "idx:2"))),
    16: ("FieldLayout", (("Offset", "u32"), ("Field", "idx:4"))),
    17: ("StandAloneSig", (("Signature", B),)),
    18: ("EventMap", (("Parent", "idx:2"), ("EventList", "idx:20"))),
    19: ("EventPtr", (("Event", "idx:20"),)),
    20: ("Event", (("EventFlags", "u16"), ("Name", S), ("EventType", "coded:TypeDefOrRef"))),
    21: ("PropertyMap", (("Parent", "idx:2"), ("PropertyList", "idx:23"))),
    22: ("PropertyPtr", (("Property", "idx:23"),)),
    23: ("Property", (("Flags", "u16"), ("Name", S), ("Type", B))),
    24: ("MethodSemantics", (("Semantics", "u16"), ("Method", "idx:6"), ("Association", "coded:HasSemantics"))),
    25: ("MethodImpl", (("Class", "idx:2"), ("MethodBody", "coded:MethodDefOrRef"), ("MethodDeclaration", "coded:MethodDefOrRef"))),
    26: ("ModuleRef", (("Name", S),)),
    27: ("TypeSpec", (("Signature", B),)),
    28: ("ImplMap", (("MappingFlags", "u16"), ("MemberForwarded", "coded:MemberForwarded"), ("ImportName", S), ("ImportScope", "idx:26"))),
    29: ("FieldRVA", (("RVA", "u32"), ("Field", "idx:4"))),
    30: ("EncLog", (("Token", "u32"), ("FuncCode", "u32"))),
    31: ("EncMap", (("Token", "u32"),)),
    32: (
        "Assembly",
        (
            ("HashAlgId", "u32"),
            ("MajorVersion", "u16"),
            ("MinorVersion", "u16"),
            ("BuildNumber", "u16"),
            ("RevisionNumber", "u16"),
            ("Flags", "u32"),
            ("PublicKey", B),
            ("Name", S),
            ("Culture", S),
        ),
    ),
    33: ("AssemblyProcessor", (("Processor", "u32"),)),
    34: ("AssemblyOS", (("OSPlatformID", "u32"), ("OSMajorVersion", "u32"), ("OSMinorVersion", "u32"))),
    35: (
        "AssemblyRef",
        (
            ("MajorVersion", "u16"),
            ("MinorVersion", "u16"),
            ("BuildNumber", "u16"),
            ("RevisionNumber", "u16"),
            ("Flags", "u32"),
            ("PublicKeyOrToken", B),
            ("Name", S),
            ("Culture", S),
            ("HashValue", B),
        ),
    ),
    36: ("AssemblyRefProcessor", (("Processor", "u32"), ("AssemblyRef", "idx:35"))),
    37: ("AssemblyRefOS", (("OSPlatformId", "u32"), ("OSMajorVersion", "u32"), ("OSMinorVersion", "u32"), ("AssemblyRef", "idx:35"))),
    38: ("File", (("Flags", "u32"), ("Name", S), ("HashValue", B))),
    39: ("ExportedType", (("Flags", "u32"), ("TypeDefId", "u32"), ("TypeName", S), ("TypeNamespace", S), ("Implementation", "coded:Implementation"))),
    40: ("ManifestResource", (("Offset", "u32"), ("Flags", "u32"), ("Name", S), ("Implementation", "coded:Implementation"))),
    41: ("NestedClass", (("NestedClass", "idx:2"), ("EnclosingClass", "idx:2"))),
    42: ("GenericParam", (("Number", "u16"), ("Flags", "u16"), ("Owner", "coded:TypeOrMethodDef"), ("Name", S))),
    43: ("MethodSpec", (("Method", "coded:MethodDefOrRef"), ("Instantiation", B))),
    44: ("GenericParamConstraint", (("Owner", "idx:42"), ("Constraint", "coded:TypeDefOrRef"))),
}

TABLE_NAMES = {index: schema[0] for index, schema in TABLE_SCHEMAS.items()}

# ---------------------------------------------------------------------------
# CIL opcodes
# ---------------------------------------------------------------------------

IL_OPS: dict[int, tuple[str, str]] = {}


def _il(code: int, name: str, operand: str = "none") -> None:
    IL_OPS[code] = (name, operand)


for _code, _name in (
    (0x00, "nop"),
    (0x01, "break"),
    (0x02, "ldarg.0"),
    (0x03, "ldarg.1"),
    (0x04, "ldarg.2"),
    (0x05, "ldarg.3"),
    (0x06, "ldloc.0"),
    (0x07, "ldloc.1"),
    (0x08, "ldloc.2"),
    (0x09, "ldloc.3"),
    (0x0A, "stloc.0"),
    (0x0B, "stloc.1"),
    (0x0C, "stloc.2"),
    (0x0D, "stloc.3"),
    (0x0E, "ldarg.s"),
    (0x0F, "ldarga.s"),
    (0x10, "starg.s"),
    (0x11, "ldloc.s"),
    (0x12, "ldloca.s"),
    (0x13, "stloc.s"),
    (0x14, "ldnull"),
    (0x15, "ldc.i4.m1"),
    (0x16, "ldc.i4.0"),
    (0x17, "ldc.i4.1"),
    (0x18, "ldc.i4.2"),
    (0x19, "ldc.i4.3"),
    (0x1A, "ldc.i4.4"),
    (0x1B, "ldc.i4.5"),
    (0x1C, "ldc.i4.6"),
    (0x1D, "ldc.i4.7"),
    (0x1E, "ldc.i4.8"),
    (0x1F, "ldc.i4.s"),
    (0x20, "ldc.i4"),
    (0x21, "ldc.i8"),
    (0x22, "ldc.r4"),
    (0x23, "ldc.r8"),
    (0x25, "dup"),
    (0x26, "pop"),
    (0x27, "jmp"),
    (0x28, "call"),
    (0x29, "calli"),
    (0x2A, "ret"),
    (0x2B, "br.s"),
    (0x2C, "brfalse.s"),
    (0x2D, "brtrue.s"),
    (0x2E, "beq.s"),
    (0x2F, "bge.s"),
    (0x30, "bgt.s"),
    (0x31, "ble.s"),
    (0x32, "blt.s"),
    (0x33, "bne.un.s"),
    (0x34, "bge.un.s"),
    (0x35, "bgt.un.s"),
    (0x36, "ble.un.s"),
    (0x37, "blt.un.s"),
    (0x38, "br"),
    (0x39, "brfalse"),
    (0x3A, "brtrue"),
    (0x3B, "beq"),
    (0x3C, "bge"),
    (0x3D, "bgt"),
    (0x3E, "ble"),
    (0x3F, "blt"),
    (0x40, "bne.un"),
    (0x41, "bge.un"),
    (0x42, "bgt.un"),
    (0x43, "ble.un"),
    (0x44, "blt.un"),
    (0x45, "switch"),
    (0x46, "ldind.i1"),
    (0x47, "ldind.u1"),
    (0x48, "ldind.i2"),
    (0x49, "ldind.u2"),
    (0x4A, "ldind.i4"),
    (0x4B, "ldind.u4"),
    (0x4C, "ldind.i8"),
    (0x4D, "ldind.i"),
    (0x4E, "ldind.r4"),
    (0x4F, "ldind.r8"),
    (0x50, "ldind.ref"),
    (0x51, "stind.ref"),
    (0x52, "stind.i1"),
    (0x53, "stind.i2"),
    (0x54, "stind.i4"),
    (0x55, "stind.i8"),
    (0x56, "stind.r4"),
    (0x57, "stind.r8"),
    (0x58, "add"),
    (0x59, "sub"),
    (0x5A, "mul"),
    (0x5B, "div"),
    (0x5C, "div.un"),
    (0x5D, "rem"),
    (0x5E, "rem.un"),
    (0x5F, "and"),
    (0x60, "or"),
    (0x61, "xor"),
    (0x62, "shl"),
    (0x63, "shr"),
    (0x64, "shr.un"),
    (0x65, "neg"),
    (0x66, "not"),
    (0x67, "conv.i1"),
    (0x68, "conv.i2"),
    (0x69, "conv.i4"),
    (0x6A, "conv.i8"),
    (0x6B, "conv.r4"),
    (0x6C, "conv.r8"),
    (0x6D, "conv.u4"),
    (0x6E, "conv.u8"),
    (0x6F, "callvirt"),
    (0x70, "cpobj"),
    (0x71, "ldobj"),
    (0x72, "ldstr"),
    (0x73, "newobj"),
    (0x74, "castclass"),
    (0x75, "isinst"),
    (0x76, "conv.r.un"),
    (0x79, "unbox"),
    (0x7A, "throw"),
    (0x7B, "ldfld"),
    (0x7C, "ldflda"),
    (0x7D, "stfld"),
    (0x7E, "ldsfld"),
    (0x7F, "ldsflda"),
    (0x80, "stsfld"),
    (0x81, "stobj"),
    (0x82, "conv.ovf.i1.un"),
    (0x83, "conv.ovf.i2.un"),
    (0x84, "conv.ovf.i4.un"),
    (0x85, "conv.ovf.i8.un"),
    (0x86, "conv.ovf.u1.un"),
    (0x87, "conv.ovf.u2.un"),
    (0x88, "conv.ovf.u4.un"),
    (0x89, "conv.ovf.u8.un"),
    (0x8A, "conv.ovf.i.un"),
    (0x8B, "conv.ovf.u.un"),
    (0x8C, "box"),
    (0x8D, "newarr"),
    (0x8E, "ldlen"),
    (0x8F, "ldelema"),
    (0x90, "ldelem.i1"),
    (0x91, "ldelem.u1"),
    (0x92, "ldelem.i2"),
    (0x93, "ldelem.u2"),
    (0x94, "ldelem.i4"),
    (0x95, "ldelem.u4"),
    (0x96, "ldelem.i8"),
    (0x97, "ldelem.i"),
    (0x98, "ldelem.r4"),
    (0x99, "ldelem.r8"),
    (0x9A, "ldelem.ref"),
    (0x9B, "stelem.i"),
    (0x9C, "stelem.i1"),
    (0x9D, "stelem.i2"),
    (0x9E, "stelem.i4"),
    (0x9F, "stelem.i8"),
    (0xA0, "stelem.r4"),
    (0xA1, "stelem.r8"),
    (0xA2, "stelem.ref"),
    (0xA3, "ldelem"),
    (0xA4, "stelem"),
    (0xA5, "unbox.any"),
    (0xB3, "conv.ovf.i1"),
    (0xB4, "conv.ovf.u1"),
    (0xB5, "conv.ovf.i2"),
    (0xB6, "conv.ovf.u2"),
    (0xB7, "conv.ovf.i4"),
    (0xB8, "conv.ovf.u4"),
    (0xB9, "conv.ovf.i8"),
    (0xBA, "conv.ovf.u8"),
    (0xC2, "refanyval"),
    (0xC3, "ckfinite"),
    (0xC6, "mkrefany"),
    (0xD0, "ldtoken"),
    (0xD1, "conv.u2"),
    (0xD2, "conv.u1"),
    (0xD3, "conv.i"),
    (0xD4, "conv.ovf.i"),
    (0xD5, "conv.ovf.u"),
    (0xD6, "add.ovf"),
    (0xD7, "add.ovf.un"),
    (0xD8, "mul.ovf"),
    (0xD9, "mul.ovf.un"),
    (0xDA, "sub.ovf"),
    (0xDB, "sub.ovf.un"),
    (0xDC, "endfinally"),
    (0xDD, "leave"),
    (0xDE, "leave.s"),
    (0xDF, "stind.i"),
    (0xE0, "conv.u"),
):
    _il(_code, _name)

for _code, _name, _operand in (
    (0x0E, "ldarg.s", "var1"),
    (0x0F, "ldarga.s", "var1"),
    (0x10, "starg.s", "var1"),
    (0x11, "ldloc.s", "var1"),
    (0x12, "ldloca.s", "var1"),
    (0x13, "stloc.s", "var1"),
    (0x1F, "ldc.i4.s", "i1"),
    (0x20, "ldc.i4", "i4"),
    (0x21, "ldc.i8", "i8"),
    (0x22, "ldc.r4", "r4"),
    (0x23, "ldc.r8", "r8"),
    (0x27, "jmp", "tok"),
    (0x28, "call", "tok"),
    (0x29, "calli", "tok"),
    (0x2B, "br.s", "br1"),
    (0x2C, "brfalse.s", "br1"),
    (0x2D, "brtrue.s", "br1"),
    (0x2E, "beq.s", "br1"),
    (0x2F, "bge.s", "br1"),
    (0x30, "bgt.s", "br1"),
    (0x31, "ble.s", "br1"),
    (0x32, "blt.s", "br1"),
    (0x33, "bne.un.s", "br1"),
    (0x34, "bge.un.s", "br1"),
    (0x35, "bgt.un.s", "br1"),
    (0x36, "ble.un.s", "br1"),
    (0x37, "blt.un.s", "br1"),
    (0x38, "br", "br4"),
    (0x39, "brfalse", "br4"),
    (0x3A, "brtrue", "br4"),
    (0x3B, "beq", "br4"),
    (0x3C, "bge", "br4"),
    (0x3D, "bgt", "br4"),
    (0x3E, "ble", "br4"),
    (0x3F, "blt", "br4"),
    (0x40, "bne.un", "br4"),
    (0x41, "bge.un", "br4"),
    (0x42, "bgt.un", "br4"),
    (0x43, "ble.un", "br4"),
    (0x44, "blt.un", "br4"),
    (0x45, "switch", "switch"),
    (0x6F, "callvirt", "tok"),
    (0x70, "cpobj", "tok"),
    (0x71, "ldobj", "tok"),
    (0x72, "ldstr", "tok"),
    (0x73, "newobj", "tok"),
    (0x74, "castclass", "tok"),
    (0x75, "isinst", "tok"),
    (0x79, "unbox", "tok"),
    (0x7B, "ldfld", "tok"),
    (0x7C, "ldflda", "tok"),
    (0x7D, "stfld", "tok"),
    (0x7E, "ldsfld", "tok"),
    (0x7F, "ldsflda", "tok"),
    (0x80, "stsfld", "tok"),
    (0x81, "stobj", "tok"),
    (0x8C, "box", "tok"),
    (0x8D, "newarr", "tok"),
    (0x8F, "ldelema", "tok"),
    (0xA3, "ldelem", "tok"),
    (0xA4, "stelem", "tok"),
    (0xA5, "unbox.any", "tok"),
    (0xD0, "ldtoken", "tok"),
    (0xDD, "leave", "br4"),
    (0xDE, "leave.s", "br1"),
):
    _il(_code, _name, _operand)

IL_OPS_2BYTE = {
    0x00: ("arglist", "none"),
    0x01: ("ceq", "none"),
    0x02: ("cgt", "none"),
    0x03: ("cgt.un", "none"),
    0x04: ("clt", "none"),
    0x05: ("clt.un", "none"),
    0x06: ("ldftn", "tok"),
    0x07: ("ldvirtftn", "tok"),
    0x09: ("ldarg", "var2"),
    0x0A: ("ldarga", "var2"),
    0x0B: ("starg", "var2"),
    0x0C: ("ldloc", "var2"),
    0x0D: ("ldloca", "var2"),
    0x0E: ("stloc", "var2"),
    0x0F: ("localloc", "none"),
    0x11: ("endfilter", "none"),
    0x12: ("unaligned.", "u1"),
    0x13: ("volatile.", "none"),
    0x14: ("tail.", "none"),
    0x15: ("initobj", "tok"),
    0x16: ("constrained.", "tok"),
    0x17: ("cpblk", "none"),
    0x18: ("initblk", "none"),
    0x19: ("no.", "u1"),
    0x1A: ("rethrow", "none"),
    0x1C: ("sizeof", "tok"),
    0x1D: ("refanytype", "none"),
    0x1E: ("readonly.", "none"),
}

TYPE_ACCESS = {
    0: "notpublic",
    1: "public",
    2: "nested public",
    3: "nested private",
    4: "nested family",
    5: "nested assembly",
    6: "nested famandassem",
    7: "nested famorassem",
}

MEMBER_ACCESS = {0: "privatescope", 1: "private", 2: "famandassem", 3: "assembly", 4: "family", 5: "famorassem", 6: "public"}

TYPE_FLAGS = {
    0x00000020: "interface",
    0x00000080: "abstract",
    0x00000100: "sealed",
    0x00000400: "specialname",
    0x00000800: "rtspecialname",
    0x00001000: "import",
    0x00002000: "serializable",
    0x00004000: "windowsruntime",
    0x00100000: "beforefieldinit",
}

METHOD_FLAGS = {
    0x0008: "unmanagedexport",
    0x0010: "static",
    0x0020: "final",
    0x0040: "virtual",
    0x0080: "hidebysig",
    0x0100: "newslot",
    0x0200: "checkaccessonoverride",
    0x0400: "abstract",
    0x0800: "specialname",
    0x1000: "rtspecialname",
    0x2000: "pinvokeimpl",
    0x4000: "hassecurity",
}

FIELD_FLAGS = {
    0x0010: "static",
    0x0020: "initonly",
    0x0040: "literal",
    0x0080: "notserialized",
    0x0100: "hasfieldrva",
    0x0200: "specialname",
    0x0400: "rtspecialname",
    0x1000: "hasfieldmarshal",
    0x2000: "pinvokeimpl",
    0x8000: "hasdefault",
}


def _flag_names(value: int, table: dict[int, str]) -> list[str]:
    names = [name for bit, name in table.items() if value & bit]
    return list(dict.fromkeys(names))


def _type_flags(value: int) -> list[str]:
    names = [TYPE_ACCESS.get(value & 0x07, "")] + _flag_names(value, TYPE_FLAGS)
    return [name for name in names if name]


def _member_flags(value: int, table: dict[int, str]) -> list[str]:
    names = [MEMBER_ACCESS.get(value & 0x07, "")] + _flag_names(value, table)
    return [name for name in names if name]


# ---------------------------------------------------------------------------
# PE image
# ---------------------------------------------------------------------------


class PeImage:
    def __init__(self, data: bytes, label: str) -> None:
        self.data = data
        self.label = label
        reader = Reader(data, "<", 0, label)
        if reader.read(2) != b"MZ":
            raise FormatError("DOS magic missing")
        reader.seek(0x3C)
        pe_offset = reader.u32()
        reader.seek(pe_offset)
        if reader.read(4) != b"PE\x00\x00":
            raise FormatError("PE signature missing")
        self.machine = reader.u16()
        self.section_count = reader.u16()
        reader.u32()
        reader.u32()
        reader.u32()
        optional_size = reader.u16()
        self.characteristics = reader.u16()
        optional_start = reader.pos
        magic = reader.u16()
        self.pe32_plus = magic == 0x20B
        reader.u8()  # major linker version
        reader.u8()  # minor linker version
        reader.u32()  # size of code
        reader.u32()  # size of initialized data
        reader.u32()  # size of uninitialized data
        self.entry_rva = reader.u32()
        reader.u32()  # base of code
        if not self.pe32_plus:
            reader.u32()  # base of data (PE32 only)
        if self.pe32_plus:
            reader.u64()  # image base
        else:
            reader.u32()  # image base
        reader.u32()  # section alignment
        reader.u32()  # file alignment
        reader.u16()  # major OS version
        reader.u16()  # minor OS version
        reader.u16()  # major image version
        reader.u16()  # minor image version
        reader.u16()  # major subsystem version
        reader.u16()  # minor subsystem version
        reader.u32()  # win32 version value
        reader.u32()  # size of image
        reader.u32()  # size of headers
        reader.u32()  # checksum
        self.subsystem = reader.u16()
        reader.u16()  # DLL characteristics
        if self.pe32_plus:
            for _ in range(4):
                reader.u64()
        else:
            for _ in range(4):
                reader.u32()
        reader.u32()  # loader flags
        reader.u32()  # number of directories
        self.directories: list[tuple[int, int]] = []
        for _ in range(16):
            rva = reader.u32()
            size = reader.u32()
            self.directories.append((rva, size))
        reader.seek(optional_start + optional_size)
        self.sections: list[dict[str, Any]] = []
        for _ in range(self.section_count):
            name = reader.read(8).rstrip(b"\x00").decode("latin-1")
            virtual_size = reader.u32()
            virtual_address = reader.u32()
            raw_size = reader.u32()
            raw_pointer = reader.u32()
            reader.u32()  # pointer to relocations
            reader.u32()  # pointer to line numbers
            reader.u16()  # number of relocations
            reader.u16()  # number of line numbers
            characteristics = reader.u32()
            self.sections.append(
                {
                    "name": name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "raw_pointer": raw_pointer,
                    "characteristics": characteristics,
                }
            )

    def rva_to_offset(self, rva: int) -> int:
        for section in self.sections:
            start = section["virtual_address"]
            span = max(section["virtual_size"], section["raw_size"])
            if start <= rva < start + span:
                delta = rva - start
                if delta >= section["raw_size"]:
                    return 0
                return section["raw_pointer"] + delta
        return 0

    def read_at_rva(self, rva: int, size: int) -> bytes:
        offset = self.rva_to_offset(rva)
        if offset <= 0 or offset + size > len(self.data):
            raise FormatError(f"RVA 0x{rva:x} maps outside the file")
        return self.data[offset : offset + size]


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class Metadata:
    def __init__(self, data: bytes, pe: PeImage) -> None:
        self.data = data
        self.pe = pe
        cli_rva, cli_size = pe.directories[14]
        if cli_rva == 0:
            raise FormatError("the PE image has no CLI header (not a managed assembly)")
        cli = Reader(pe.read_at_rva(cli_rva, 0x48), "<", 0, "CLI header")
        cli.u32()
        self.runtime_major = cli.u16()
        self.runtime_minor = cli.u16()
        metadata_rva = cli.u32()
        metadata_size = cli.u32()
        self.cli_flags = cli.u32()
        self.entry_point = cli.u32()
        self.resources_rva = cli.u32()
        self.resources_size = cli.u32()
        self.strong_name_rva = cli.u32()
        self.strong_name_size = cli.u32()

        self.root = Reader(pe.read_at_rva(metadata_rva, metadata_size), "<", 0, "metadata root")
        if self.root.read(4) != b"BSJB":
            raise FormatError("metadata signature BSJB missing")
        self.root.u16()
        self.root.u16()
        self.root.u32()
        version_length = self.root.u32()
        raw_version = self.root.read(version_length)
        self.version_string = raw_version.split(b"\x00")[0].decode("latin-1", "replace")
        self.root.u16()  # metadata flags
        stream_count = self.root.u16()
        streams: dict[str, tuple[int, int]] = {}
        for _ in range(stream_count):
            offset = self.root.u32()
            size = self.root.u32()
            name_bytes = bytearray()
            while True:
                byte = self.root.u8()
                if byte == 0:
                    break
                name_bytes.append(byte)
            while self.root.pos % 4:
                self.root.u8()
            name = name_bytes.decode("latin-1", "replace")
            streams[name] = (offset, size)
        if "#~" not in streams and "#-" not in streams:
            raise FormatError("metadata tables stream (#~) is missing")
        self.streams = streams
        table_key = "#~" if "#~" in streams else "#-"
        self.tables_offset, self.tables_size = streams[table_key]
        self.tables_data = self.root.data[self.tables_offset : self.tables_offset + self.tables_size]
        self._read_tables_header()
        self._rows: dict[int, list[dict[str, Any]]] = {}

    def _read_tables_header(self) -> None:
        reader = Reader(self.tables_data, "<", 0, "tables stream")
        reader.u32()
        self.major = reader.u8()
        self.minor = reader.u8()
        heap_sizes = reader.u8()
        reader.u8()
        self.valid = reader.u64()
        self.sorted = reader.u64()
        self.row_counts: dict[int, int] = {}
        for index in range(64):
            if self.valid & (1 << index):
                self.row_counts[index] = reader.u32()
        self.heap_sizes = heap_sizes
        self.rows_start = reader.pos
        self.string_size = 4 if heap_sizes & 0x01 else 2
        self.guid_size = 4 if heap_sizes & 0x02 else 2
        self.blob_size = 4 if heap_sizes & 0x04 else 2
        self._row_size_cache: dict[int, int] = {}
        self._row_offsets: dict[int, list[int]] = {}
        self._compute_layout()

    def _index_size(self, table: int) -> int:
        return 4 if self.row_counts.get(table, 0) > 0xFFFF else 2

    def _coded_size(self, name: str) -> int:
        bits, tables = CODED_INDEXES[name]
        largest = max(self.row_counts.get(table, 0) for table in tables)
        return 4 if largest >= (1 << (16 - bits)) else 2

    def _column_size(self, kind: Any) -> int:
        if kind == "u8":
            return 1
        if kind == "u16":
            return 2
        if kind == "u32":
            return 4
        if kind == "str":
            return self.string_size
        if kind == "guid":
            return self.guid_size
        if kind == "blob":
            return self.blob_size
        if isinstance(kind, str) and kind.startswith("idx:"):
            return self._index_size(int(kind[4:]))
        if isinstance(kind, str) and kind.startswith("coded:"):
            return self._coded_size(kind[6:])
        raise FormatError(f"unknown metadata column kind {kind!r}")

    def _compute_layout(self) -> None:
        offset = self.rows_start
        for table in sorted(self.row_counts):
            schema = TABLE_SCHEMAS.get(table)
            if schema is None:
                raise FormatError(f"unsupported metadata table {table}")
            row_size = sum(self._column_size(kind) for _, kind in schema[1])
            self._row_size_cache[table] = row_size
            self._row_offsets[table] = [offset + row_size * index for index in range(self.row_counts[table])]
            offset += row_size * self.row_counts[table]

    def rows(self, table: int) -> list[dict[str, Any]]:
        if table in self._rows:
            return self._rows[table]
        schema = TABLE_SCHEMAS[table]
        offsets = self._row_offsets.get(table, [])
        result: list[dict[str, Any]] = []
        for offset in offsets:
            reader = Reader(self.tables_data, "<", offset, f"table {schema[0]}")
            row: dict[str, Any] = {}
            for name, kind in schema[1]:
                if kind == "u8":
                    row[name] = reader.u8()
                elif kind == "u16":
                    row[name] = reader.u16()
                elif kind == "u32":
                    row[name] = reader.u32()
                elif kind in ("str", "guid", "blob"):
                    row[name] = reader.uint(self._column_size(kind))
                elif isinstance(kind, str) and kind.startswith("idx:"):
                    row[name] = reader.uint(self._index_size(int(kind[4:])))
                elif isinstance(kind, str) and kind.startswith("coded:"):
                    row[name] = reader.uint(self._coded_size(kind[6:]))
            result.append(row)
        self._rows[table] = result
        return result

    def row(self, table: int, index: int) -> dict[str, Any] | None:
        rows = self.rows(table)
        if 1 <= index <= len(rows):
            return rows[index - 1]
        return None

    # -- heaps --------------------------------------------------------------
    def string(self, index: int) -> str:
        if index == 0:
            return ""
        offset, size = self.streams.get("#Strings", (0, 0))
        base = offset + index
        end = base
        while end < offset + size and self.root.data[end] != 0:
            end += 1
        return bytes(self.root.data[base:end]).decode("utf-8", "replace")

    def blob(self, index: int) -> bytes:
        if index == 0:
            return b""
        offset, size = self.streams.get("#Blob", (0, 0))
        if offset == 0:
            return b""
        position = offset + index
        if position >= offset + size:
            return b""
        first = self.root.data[position]
        if first & 0x80 == 0:
            length, cursor = first, position + 1
        elif first & 0xC0 == 0x80:
            length = ((first & 0x3F) << 8) | self.root.data[position + 1]
            cursor = position + 2
        else:
            length = ((first & 0x1F) << 24) | (self.root.data[position + 1] << 16) | (self.root.data[position + 2] << 8) | self.root.data[position + 3]
            cursor = position + 4
        return bytes(self.root.data[cursor : cursor + length])

    def user_string(self, token: int) -> str:
        index = token & 0x00FFFFFF
        offset, size = self.streams.get("#US", (0, 0))
        if offset == 0:
            return ""
        position = offset + index
        if position >= offset + size:
            return ""
        first = self.root.data[position]
        if first & 0x80 == 0:
            length, cursor = first, position + 1
        elif first & 0xC0 == 0x80:
            length = ((first & 0x3F) << 8) | self.root.data[position + 1]
            cursor = position + 2
        else:
            length = ((first & 0x1F) << 24) | (self.root.data[position + 1] << 16) | (self.root.data[position + 2] << 8) | self.root.data[position + 3]
            cursor = position + 4
        raw = bytes(self.root.data[cursor : cursor + max(0, length - 1)])
        return raw.decode("utf-16-le", "replace")

    def guid(self, index: int) -> str:
        offset, size = self.streams.get("#GUID", (0, 0))
        if offset == 0 or index == 0:
            return ""
        position = offset + (index - 1) * 16
        if position + 16 > offset + size:
            return ""
        raw = bytes(self.root.data[position : position + 16])
        return (
            raw[3::-1].hex() + "-" + raw[5:3:-1].hex() + "-" + raw[7:5:-1].hex() + "-" + raw[8:10].hex() + "-" + raw[10:].hex()
        )

    # -- coded tokens -------------------------------------------------------
    def decode_coded(self, value: int, name: str) -> tuple[int, int]:
        bits, tables = CODED_INDEXES[name]
        tag = value & ((1 << bits) - 1)
        index = value >> bits
        table = tables[tag] if tag < len(tables) else 0
        return table, index

    def resolve_token(self, token: int) -> str:
        table = (token >> 24) & 0xFF
        index = token & 0x00FFFFFF
        if token >> 24 == 0x70:
            return '"' + self.user_string(token).replace('"', '\\"') + '"'
        if table == 0x02:
            return self.type_name(2, index)
        if table == 0x01:
            return self.type_name(1, index)
        if table == 0x1B:
            return self.type_spec_name(index)
        if table == 0x0A:
            return self.member_ref(index)
        if table == 0x06:
            return self.method_name(index)
        if table == 0x04:
            return self.field_name(index)
        if table == 0x2B:
            spec = self.row(43, index)
            if spec:
                return self.resolve_token(self.coded_token("MethodDefOrRef", spec["Method"]))
            return f"<methodspec 0x{index:x}>"
        if table == 0x11:
            return "<signature>"
        return f"<token 0x{token:08x}>"

    def coded_token(self, name: str, value: int) -> int:
        table, index = self.decode_coded(value, name)
        return (table << 24) | index

    # -- names --------------------------------------------------------------
    def type_name(self, table: int, index: int) -> str:
        row = self.row(table, index)
        if not row:
            return f"<type {table}:{index}>"
        namespace = self.string(row.get("Namespace", 0))
        name = self.string(row.get("Name", 0))
        if table == 2:
            name = self._nested_name(index, name)
        prefix = f"{namespace}." if namespace else ""
        return prefix + name

    def _nested_name(self, index: int, name: str) -> str:
        for row in self.rows(41):
            if row["NestedClass"] == index:
                parent = self.type_name(2, row["EnclosingClass"])
                return f"{parent}/{name}"
        return name

    def type_spec_name(self, index: int) -> str:
        row = self.row(27, index)
        if not row:
            return f"<typespec {index}>"
        text, _ = self.parse_type(self.blob(row["Signature"]), 0)
        return text

    def method_name(self, index: int) -> str:
        row = self.row(6, index)
        if not row:
            return f"<method {index}>"
        returns, _, parameters = self.method_signature_text(self.blob(row["Signature"]))
        return f"{returns} {self.string(row['Name'])}({', '.join(parameters)})"

    def field_name(self, index: int) -> str:
        row = self.row(4, index)
        if not row:
            return f"<field {index}>"
        field_type, _ = self.parse_field_signature(self.blob(row["Signature"]))
        return f"{field_type} {self.string(row['Name'])}"

    def member_ref(self, index: int) -> str:
        row = self.row(10, index)
        if not row:
            return f"<memberref {index}>"
        table, owner_index = self.decode_coded(row["Class"], "MemberRefParent")
        owner = self.type_name(table, owner_index) if table in (1, 2) else (
            self.type_spec_name(owner_index) if table == 27 else f"<module {owner_index}>"
        )
        name = self.string(row["Name"])
        signature = self.blob(row["Signature"])
        if signature and signature[0] != 0x06:
            returns, _, parameters = self.method_signature_text(signature)
            return f"{returns} {owner}::{name}({', '.join(parameters)})"
        field_type, _ = self.parse_field_signature(signature)
        return f"{field_type} {owner}::{name}"

    # -- structured references for source emitters -------------------------
    def method_signature_parts(self, blob: bytes) -> tuple[str, list[str], bool, int]:
        """Return (returns, parameter types, has_this, generic parameter count)."""
        if not blob:
            return "void", [], False, 0
        call = blob[0]
        pos = 1
        generic = 0
        if call & 0x10:
            generic, pos = self._compressed(blob, pos)
        count, pos = self._compressed(blob, pos)
        try:
            returns, pos = self.parse_type(blob, pos)
        except FormatError:
            return "void", [], bool(call & 0x20), generic
        parameters: list[str] = []
        for _ in range(count):
            try:
                parameter, pos = self.parse_type(blob, pos)
            except FormatError:
                break
            parameters.append(parameter)
        return returns, parameters, bool(call & 0x20), generic

    def field_ref(self, token: int) -> dict[str, Any]:
        """Resolve a field token to owner, name and type."""
        table = (token >> 24) & 0xFF
        index = token & 0x00FFFFFF
        if table == 0x04:
            row = self.row(4, index)
            if row:
                field_type, _ = self.parse_field_signature(self.blob(row["Signature"]))
                return {"owner": None, "name": self.string(row["Name"]), "type": field_type, "table": table, "index": index}
        if table == 0x0A:
            row = self.row(10, index)
            if row:
                owner_table, owner_index = self.decode_coded(row["Class"], "MemberRefParent")
                owner = self.type_name(owner_table, owner_index) if owner_table in (1, 2) else None
                field_type, _ = self.parse_field_signature(self.blob(row["Signature"]))
                return {"owner": owner, "name": self.string(row["Name"]), "type": field_type, "table": table, "index": index}
        return {"owner": None, "name": f"field_{index:x}", "type": "object", "table": table, "index": index}

    def method_ref(self, token: int) -> dict[str, Any]:
        """Resolve a method token to owner, name, signature and calling convention."""
        table = (token >> 24) & 0xFF
        index = token & 0x00FFFFFF
        if table == 0x2B:
            spec = self.row(43, index)
            if spec:
                return self.method_ref(self.coded_token("MethodDefOrRef", spec["Method"]))
        if table == 0x06:
            row = self.row(6, index)
            if row:
                returns, parameters, has_this, _ = self.method_signature_parts(self.blob(row["Signature"]))
                return {
                    "owner": None,
                    "name": self.string(row["Name"]),
                    "returns": returns,
                    "params": parameters,
                    "has_this": has_this,
                    "table": table,
                    "index": index,
                }
        if table == 0x0A:
            row = self.row(10, index)
            if row:
                owner_table, owner_index = self.decode_coded(row["Class"], "MemberRefParent")
                owner = self.type_name(owner_table, owner_index) if owner_table in (1, 2) else (
                    self.type_spec_name(owner_index) if owner_table == 27 else None
                )
                returns, parameters, has_this, _ = self.method_signature_parts(self.blob(row["Signature"]))
                return {
                    "owner": owner,
                    "name": self.string(row["Name"]),
                    "returns": returns,
                    "params": parameters,
                    "has_this": has_this,
                    "table": table,
                    "index": index,
                }
        return {
            "owner": None,
            "name": f"method_{index:x}",
            "returns": "void",
            "params": [],
            "has_this": False,
            "table": table,
            "index": index,
        }

    # -- signatures ---------------------------------------------------------
    ELEMENT_NAMES = {
        0x01: "void",
        0x02: "bool",
        0x03: "char",
        0x04: "int8",
        0x05: "uint8",
        0x06: "int16",
        0x07: "uint16",
        0x08: "int32",
        0x09: "uint32",
        0x0A: "int64",
        0x0B: "uint64",
        0x0C: "float32",
        0x0D: "float64",
        0x0E: "string",
        0x16: "typedref",
        0x18: "intptr",
        0x19: "uintptr",
        0x1C: "object",
    }

    def _compressed(self, blob: bytes, pos: int) -> tuple[int, int]:
        if pos >= len(blob):
            raise FormatError("signature ended early")
        first = blob[pos]
        if first & 0x80 == 0:
            return first, pos + 1
        if first & 0xC0 == 0x80:
            return ((first & 0x3F) << 8) | blob[pos + 1], pos + 2
        return ((first & 0x1F) << 24) | (blob[pos + 1] << 16) | (blob[pos + 2] << 8) | blob[pos + 3], pos + 4

    def _type_def_or_ref(self, value: int) -> str:
        table, index = self.decode_coded(value, "TypeDefOrRef")
        if table in (1, 2):
            return self.type_name(table, index)
        if table == 27:
            return self.type_spec_name(index)
        return f"<type {value}>"

    def parse_type(self, blob: bytes, pos: int) -> tuple[str, int]:
        if pos >= len(blob):
            return "?", pos
        element = blob[pos]
        pos += 1
        guard = 0
        while element in (0x1F, 0x20) and guard < 16:  # custom modifiers
            guard += 1
            _, pos = self._compressed(blob, pos)
            if pos >= len(blob):
                return "?", pos
            element = blob[pos]
            pos += 1
        if element in self.ELEMENT_NAMES:
            return self.ELEMENT_NAMES[element], pos
        if element in (0x11, 0x12):  # valuetype / class
            value, pos = self._compressed(blob, pos)
            name = self._type_def_or_ref(value)
            if element == 0x12 and name.startswith("System."):
                return name, pos
            return name, pos
        if element == 0x0F:  # pointer
            inner, pos = self.parse_type(blob, pos)
            return inner + "*", pos
        if element == 0x10:  # byref
            inner, pos = self.parse_type(blob, pos)
            return inner + "&", pos
        if element == 0x13 or element == 0x1E:
            number, pos = self._compressed(blob, pos)
            prefix = "!" if element == 0x13 else "!!"
            return f"{prefix}{number}", pos
        if element == 0x14:  # array
            inner, pos = self.parse_type(blob, pos)
            rank, pos = self._compressed(blob, pos)
            sizes_count, pos = self._compressed(blob, pos)
            for _ in range(sizes_count):
                _, pos = self._compressed(blob, pos)
            bounds_count, pos = self._compressed(blob, pos)
            for _ in range(bounds_count):
                _, pos = self._compressed(blob, pos)
            return f"{inner}[{',' * max(0, rank - 1)}]", pos
        if element == 0x15:  # generic instantiation
            inner, pos = self.parse_type(blob, pos)
            count, pos = self._compressed(blob, pos)
            arguments = []
            for _ in range(count):
                argument, pos = self.parse_type(blob, pos)
                arguments.append(argument)
            return f"{inner}<{', '.join(arguments)}>", pos
        if element == 0x1D:  # szarray
            inner, pos = self.parse_type(blob, pos)
            return inner + "[]", pos
        if element == 0x1B:  # function pointer
            _, _, _, pos = self.parse_method_signature(blob, pos, nested=True)
            return "method_ptr", pos
        if element == 0x45:  # pinned
            return self.parse_type(blob, pos)
        if element == 0x41:  # sentinel
            return self.parse_type(blob, pos)
        if element == 0x21:
            inner, pos = self.parse_type(blob, pos)
            return inner, pos
        return f"<etype 0x{element:02x}>", pos

    def parse_method_signature(self, blob: bytes, pos: int = 0, nested: bool = False) -> tuple[str, str, list[str], int]:
        if pos >= len(blob):
            return "?", "", [], pos
        call = blob[pos]
        pos += 1
        generic = 0
        if call & 0x10:
            generic, pos = self._compressed(blob, pos)
        count, pos = self._compressed(blob, pos)
        returns, pos = self.parse_type(blob, pos)
        parameters: list[str] = []
        for _ in range(count):
            parameter, pos = self.parse_type(blob, pos)
            parameters.append(parameter)
        return returns, "", parameters, pos

    def parse_field_signature(self, blob: bytes) -> tuple[str, str]:
        if len(blob) < 2:
            return "?", "?"
        pos = 1
        text, _ = self.parse_type(blob, pos)
        return text, text

    def method_signature_text(self, blob: bytes) -> tuple[str, str, list[str]]:
        returns, _, parameters, _ = self.parse_method_signature(blob)
        return returns, "", parameters

    # -- IL -----------------------------------------------------------------
    def method_body(self, rva: int) -> dict[str, Any] | None:
        if rva == 0:
            return None
        offset = self.pe.rva_to_offset(rva)
        if offset <= 0:
            return None
        reader = Reader(self.pe.data, "<", offset, "method body")
        first = reader.u8()
        kind = first & 0x03
        if kind == 0x02:
            size = first >> 2
            code = reader.read(size)
            return {"max_stack": 8, "local_sig": 0, "code": code, "offset": offset + 1, "fat": False}
        if kind == 0x03:
            flags = first | (reader.u8() << 8)
            max_stack = reader.u16()
            code_size = reader.u32()
            local_sig = reader.u32()
            if code_size == 0 or code_size > 16 * 1024 * 1024:
                return None
            code = reader.read(code_size)
            more = 0
            if flags & 0x08:
                more = reader.u32()
            return {
                "max_stack": max_stack,
                "local_sig": local_sig,
                "code": code,
                "offset": reader.pos,
                "fat": True,
                "more_sections": more,
            }
        return None

    def body_is_il(self, rva: int) -> bool:
        """Cheap probe used to explain skipped bodies in evidence."""
        if rva == 0:
            return False
        offset = self.pe.rva_to_offset(rva)
        if offset <= 0 or offset + 2 > len(self.pe.data):
            return False
        first = self.pe.data[offset]
        kind = first & 0x03
        if kind == 0x02:
            return True
        if kind == 0x03:
            return (first | (self.pe.data[offset + 1] << 8)) >> 12 in (2, 3)
        return False

    def local_types(self, token: int) -> list[str]:
        if token == 0:
            return []
        table = (token >> 24) & 0xFF
        index = token & 0x00FFFFFF
        if table != 0x11:
            return []
        row = self.row(17, index)
        if not row:
            return []
        blob = self.blob(row["Signature"])
        types: list[str] = []
        try:
            pos = 1
            count, pos = self._compressed(blob, pos)
            for _ in range(count):
                text, pos = self.parse_type(blob, pos)
                types.append(text)
        except FormatError:
            return types
        return types

    def disassemble(self, body: dict[str, Any]) -> list[str]:
        code = body["code"]
        reader = Reader(code, "<", 0, "IL")
        lines: list[str] = []
        while reader.remaining > 0:
            offset = reader.pos
            opcode = reader.u8()
            if opcode == 0xFE:
                second = reader.u8()
                name, operand = IL_OPS_2BYTE.get(second, (f"fe_{second:02x}", "none"))
            else:
                name, operand = IL_OPS.get(opcode, (f"op_{opcode:02x}", "none"))
            text = ""
            if operand == "none":
                pass
            elif operand == "i1":
                text = f" {reader.i8()}"
            elif operand == "u1":
                text = f" {reader.u8()}"
            elif operand == "i4":
                text = f" {reader.i32()}"
            elif operand == "i8":
                text = f" {reader.i64()}"
            elif operand == "r4":
                text = f" {reader.f32():g}"
            elif operand == "r8":
                text = f" {reader.f64():g}"
            elif operand == "br1":
                delta = reader.i8()
                text = f" IL_{offset + 1 + delta:04x}"
            elif operand == "br4":
                delta = reader.i32()
                text = f" IL_{offset + 5 + delta:04x}"
            elif operand == "switch":
                count = reader.u32()
                targets = [f"IL_{offset + 5 + 4 * count + reader.i32():04x}" for _ in range(count)]
                text = " (" + ", ".join(targets) + ")" if targets else " ()"
            elif operand in ("tok", "var2"):
                if operand == "var2":
                    text = f" {reader.u16()}"
                else:
                    token = reader.u32()
                    try:
                        text = f" {self.resolve_token(token)}"
                    except FormatError:
                        text = f" <token 0x{token:08x}>"
            elif operand == "var1":
                text = f" {reader.u8()}"
            if reader.remaining < 0:
                break
            lines.append(f"    IL_{offset:04x}: {name}{text}")
        return lines


# ---------------------------------------------------------------------------
# analysis
# ---------------------------------------------------------------------------


def _public_key_token(public_key: bytes) -> str:
    if not public_key:
        return "neutral"
    digest = hashlib.sha1(public_key).digest()
    return digest[-8:][::-1].hex()


def analyze(ctx: Context) -> Report:
    data = bytes(ctx.data[: ctx.size])
    pe = PeImage(data, os.path.basename(ctx.path))
    metadata = Metadata(data, pe)

    assembly = metadata.row(32, 1)
    module = metadata.row(0, 1)
    assembly_name = metadata.string(assembly["Name"]) if assembly else (
        metadata.string(module["Name"]) if module else "(unknown)"
    )
    report = Report(kind="dotnet", label=f".NET assembly {assembly_name}")

    type_rows = metadata.rows(2)
    method_rows = metadata.rows(6)
    field_rows = metadata.rows(4)
    type_refs = metadata.rows(1)
    member_refs = metadata.rows(10)
    assembly_refs = metadata.rows(35)
    ctx.stage(f"metadata: {len(type_rows)} types, {len(method_rows)} methods, {len(field_rows)} fields")
    ctx.stage(f"references: {len(type_refs)} type refs, {len(member_refs)} member refs, {len(assembly_refs)} assemblies")

    report.summary.update(
        {
            "assembly": assembly_name,
            "version": (
                f"{assembly['MajorVersion']}.{assembly['MinorVersion']}.{assembly['BuildNumber']}.{assembly['RevisionNumber']}"
                if assembly
                else "n/a"
            ),
            "module": metadata.string(module["Name"]) if module else "(none)",
            "mvid": metadata.guid(module["Mvid"]) if module else "(none)",
            "runtime": f"{metadata.runtime_major}.{metadata.runtime_minor}",
            "metadata": metadata.version_string,
            "types": len(type_rows),
            "methods": len(method_rows),
            "fields": len(field_rows),
            "type_refs": len(type_refs),
            "member_refs": len(member_refs),
            "assembly_refs": len(assembly_refs),
            "entry_point": f"0x{metadata.entry_point:08x}" if metadata.entry_point else "(none)",
            "size": human_bytes(ctx.size),
        }
    )

    identity = report.section("Assembly identity")
    identity.add(f"name          {assembly_name}")
    if assembly:
        identity.add(
            "version       "
            f"{assembly['MajorVersion']}.{assembly['MinorVersion']}.{assembly['BuildNumber']}.{assembly['RevisionNumber']}"
        )
        identity.add(f"culture       {metadata.string(assembly['Culture']) or 'neutral'}")
        public_key = metadata.blob(assembly["PublicKey"])
        identity.add(f"public key    {len(public_key)} bytes, token {_public_key_token(public_key)}")
        identity.add(f"flags         0x{assembly['Flags']:08x}")
    if module:
        identity.add(f"module        {metadata.string(module['Name'])}")
        identity.add(f"mvid          {metadata.guid(module['Mvid'])}")
    identity.add(f"runtime       {metadata.runtime_major}.{metadata.runtime_minor} ({metadata.version_string})")
    identity.add(f"streams       {', '.join(sorted(metadata.streams))}")
    identity.add(
        "tables        "
        + ", ".join(f"{TABLE_NAMES.get(table, table)}={count}" for table, count in sorted(metadata.row_counts.items())[:24])
    )

    if assembly_refs:
        ref_section = report.section("Referenced assemblies")
        for row in assembly_refs[:200]:
            name = metadata.string(row["Name"])
            version = f"{row['MajorVersion']}.{row['MinorVersion']}.{row['BuildNumber']}.{row['RevisionNumber']}"
            token = metadata.blob(row["PublicKeyOrToken"])
            ref_section.add(f"{name:<40} {version:<14} token={token[-8:][::-1].hex() if token else 'none'}")

    # Build method and field ownership from TypeDef row ranges.
    type_entries: list[dict[str, Any]] = []
    for index, row in enumerate(type_rows, start=1):
        field_start = row["FieldList"]
        field_end = type_rows[index]["FieldList"] if index < len(type_rows) else len(field_rows) + 1
        method_start = row["MethodList"]
        method_end = type_rows[index]["MethodList"] if index < len(type_rows) else len(method_rows) + 1
        fields = [field_rows[i - 1] for i in range(field_start, min(field_end, len(field_rows) + 1))]
        methods = [method_rows[i - 1] for i in range(method_start, min(method_end, len(method_rows) + 1))]
        type_entries.append(
            {
                "row": row,
                "index": index,
                "name": metadata.type_name(2, index),
                "fields": fields,
                "methods": methods,
                "field_range": [field_start, field_end - 1],
                "method_range": [method_start, method_end - 1],
            }
        )

    type_section = report.section("Types")
    for entry in type_entries[:300]:
        row = entry["row"]
        flags = " ".join(_type_flags(row["Flags"])) or "-"
        base = metadata._type_def_or_ref(row["Extends"]) if row["Extends"] else "(none)"
        type_section.add(f"{entry['name']:<60} {flags:<28} : {base}")
        type_section.add(f"    methods={len(entry['methods'])} fields={len(entry['fields'])}")
    if len(type_entries) > 300:
        type_section.add(f"... {len(type_entries) - 300} more types")

    exported = []
    for row in metadata.rows(39):
        exported.append(
            {
                "name": (metadata.string(row["TypeNamespace"]) + "." if row["TypeNamespace"] else "") + metadata.string(row["TypeName"]),
                "flags": row["Flags"],
            }
        )

    resources = []
    for row in metadata.rows(40):
        resources.append({"name": metadata.string(row["Name"]), "offset": row["Offset"], "flags": row["Flags"]})
    if resources:
        report.section("Resources").lines.extend(f"{item['name']} @0x{item['offset']:x}" for item in resources[:100])

    user_strings = 0
    offset, size = metadata.streams.get("#US", (0, 0))
    if offset:
        cursor = 0
        while cursor < size - 1:
            first = metadata.root.data[offset + cursor]
            if first & 0x80 == 0:
                length, advance = first, 1
            elif first & 0xC0 == 0x80:
                length, advance = ((first & 0x3F) << 8) | metadata.root.data[offset + cursor + 1], 2
            else:
                length, advance = (
                    ((first & 0x1F) << 24)
                    | (metadata.root.data[offset + cursor + 1] << 16)
                    | (metadata.root.data[offset + cursor + 2] << 8)
                    | metadata.root.data[offset + cursor + 3],
                    4,
                )
            if length == 0:
                cursor += advance
                continue
            user_strings += 1
            cursor += advance + length
    report.summary["user_strings"] = user_strings

    # IL listing
    il_lines: list[str] = [
        f"// .NET assembly: {assembly_name}",
        f"// sha256: {ctx.sha256}",
        f"// runtime: {metadata.runtime_major}.{metadata.runtime_minor} ({metadata.version_string})",
        "",
    ]
    decompiled_methods = 0
    skipped_bodies = 0
    il_failures = 0
    ctx.stage("rendering CIL method bodies")
    method_limit = min(ctx.options.max_items, len(method_rows))
    per_type_counts: dict[str, int] = {}
    for entry in type_entries:
        row = entry["row"]
        type_name = entry["name"]
        flags = " ".join(_type_flags(row["Flags"]))
        base = metadata._type_def_or_ref(row["Extends"]) if row["Extends"] else "System.Object"
        il_lines.append(f".class {flags} {type_name} extends {base}")
        il_lines.append("{")
        for field in entry["fields"]:
            field_flags = " ".join(_member_flags(field["Flags"], FIELD_FLAGS))
            field_type, _ = metadata.parse_field_signature(metadata.blob(field["Signature"]))
            il_lines.append(f"  .field {field_flags} {field_type} {metadata.string(field['Name'])}")
        for method in entry["methods"]:
            if decompiled_methods >= method_limit:
                il_lines.append("  // method budget reached")
                break
            returns, _, parameters = metadata.method_signature_text(metadata.blob(method["Signature"]))
            method_flags = " ".join(_member_flags(method["Flags"], METHOD_FLAGS))
            signature = f"{returns} {metadata.string(method['Name'])}({', '.join(parameters)})"
            il_lines.append(f"  .method {method_flags} {signature} cil managed")
            il_lines.append("  {")
            try:
                body = metadata.method_body(method["RVA"])
            except FormatError:
                body = None
            if body is None:
                if method["RVA"]:
                    skipped_bodies += 1
                il_lines.append("    // no IL body (abstract, extern, native or precompiled)")
                il_lines.append("  }")
                il_lines.append("")
                continue
            locals_list = metadata.local_types(body.get("local_sig", 0))
            if locals_list:
                declared = ", ".join(f"{index}: {name}" for index, name in enumerate(locals_list))
                il_lines.append(f"    .locals init ({declared})")
            il_lines.append(f"    .maxstack {body['max_stack']}")
            try:
                il_lines.extend(metadata.disassemble(body))
            except FormatError as exc:
                il_failures += 1
                il_lines.append(f"    // IL decode stopped: {exc.message}")
            il_lines.append("  }")
            il_lines.append("")
            decompiled_methods += 1
            per_type_counts[type_name] = per_type_counts.get(type_name, 0) + 1
        il_lines.append("}")
        il_lines.append("")

    method_section = report.section("Method bodies")
    method_section.add(f"{decompiled_methods} of {len(method_rows)} method bodies rendered as IL")
    for name, count in list(per_type_counts.items())[:80]:
        method_section.add(f"{name:<60} {count} method(s)")
    if len(per_type_counts) > 80:
        method_section.add(f"... {len(per_type_counts) - 80} more types")

    if ctx.options.disassemble and decompiled_methods:
        ctx.add_artifact("sources/assembly.il", "\n".join(il_lines), kind="il")
    elif not ctx.options.disassemble:
        ctx.limit("IL rendering was disabled with --no-disassembly.")

    source_files: list[str] = []
    source_methods = 0
    if ctx.options.source:
        from .csharp import CSharpEmitter

        ctx.stage("reconstructing C# source from IL")
        emitter = CSharpEmitter(
            metadata,
            ctx.path,
            ctx.sha256,
            max_methods=min(max(ctx.options.max_items * 4, 500), 20000),
        )
        try:
            files = emitter.emit(type_entries)
        except FormatError as exc:
            ctx.limit(f"C# reconstruction stopped early: {exc.message}")
            files = []
        for path, text in files:
            if ctx.add_artifact(path, text, kind="source"):
                source_files.append(path)
        source_methods = emitter.emitted_methods
        ctx.stage(f"C#: {len(source_files)} file(s), {source_methods} method body/bodies")
        if source_files:
            source_section = report.section("Recovered C# source")
            source_section.add(f"{len(source_files)} file(s), {emitter.emitted_methods} method body/bodies")
            for path in source_files[:80]:
                source_section.add(path)
            if len(source_files) > 80:
                source_section.add(f"... {len(source_files) - 80} more")
            ctx.observe("C# files were reconstructed from IL; verify them against the IL listing before reuse.")
    else:
        ctx.limit("C# source reconstruction was disabled with --no-source.")

    external_sources: list[str] = []
    if ctx.options.source and ctx.options.engine != "none":
        from .. import engines as engine_module

        engine = engine_module.discover().find("ilspycmd")
        if engine:
            files, error = engine_module.run_source_engine([engine.path, ctx.path, "-o", "{out}"], ".cs")
            if error:
                ctx.limit(f"The local ilspycmd engine produced no C# output: {error}")
            else:
                for relative, text in files:
                    path = f"sources/csharp-external/{relative}"
                    if ctx.add_artifact(path, text, kind="source"):
                        external_sources.append(path)
                if external_sources:
                    ctx.observe(f"{len(external_sources)} C# file(s) came from the local ilspycmd engine.")
                    source_files.extend(external_sources)

    if skipped_bodies:
        ctx.limit(
            f"{skipped_bodies} method(s) carry a body RVA that is not a plain IL header "
            "(native, ReadyToRun or runtime-provided); they are listed but not decompiled."
        )
    if il_failures:
        ctx.limit(f"{il_failures} method body/bodies stopped decoding at a truncated or unsupported instruction.")

    report.payload = {
        "assembly": {
            "name": assembly_name,
            "version": report.summary.get("version"),
            "culture": metadata.string(assembly["Culture"]) if assembly else "",
            "public_key_token": _public_key_token(metadata.blob(assembly["PublicKey"])) if assembly else "neutral",
            "module": metadata.string(module["Name"]) if module else None,
            "mvid": metadata.guid(module["Mvid"]) if module else None,
            "runtime": f"{metadata.runtime_major}.{metadata.runtime_minor}",
            "metadata_version": metadata.version_string,
            "entry_point": metadata.entry_point,
            "table_counts": {TABLE_NAMES.get(key, str(key)): value for key, value in metadata.row_counts.items()},
        },
        "types": [
            {
                "name": entry["name"],
                "flags": _type_flags(entry["row"]["Flags"]),
                "methods": len(entry["methods"]),
                "fields": len(entry["fields"]),
            }
            for entry in type_entries
        ],
        "references": [
            {
                "name": metadata.string(row["Name"]),
                "version": f"{row['MajorVersion']}.{row['MinorVersion']}.{row['BuildNumber']}.{row['RevisionNumber']}",
            }
            for row in assembly_refs
        ],
        "exported_types": exported,
        "resources": resources,
        "user_strings": user_strings,
        "decompiled_methods": decompiled_methods,
        "method_total": len(method_rows),
        "source": {
            "language": "csharp",
            "files": source_files,
            "methods": source_methods,
            "external": external_sources,
        },
    }
    complete = decompiled_methods >= len(method_rows)
    report.coverage = {
        "status": "complete" if complete else "partial",
        "examined": decompiled_methods,
        "total": len(method_rows),
        "exhausted": decompiled_methods >= len(method_rows),
    }
    ctx.limit(
        "Method bodies are rendered as IL, not recompiled to C#. Native implementations "
        "marked 'internalcall' have no IL body to recover."
    )
    report.next_steps.append("Open sources/assembly.il for the full type and method IL listing.")
    report.next_steps.append("C# source recovery requires a local ilspycmd; this build never downloads it.")
    return report
