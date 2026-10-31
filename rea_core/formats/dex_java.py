"""Dalvik to Java source lifting.

The smali listing is parsed back into instructions, registers are typed from
their uses, and statements are emitted as Java. Methods with branches use a
labelled state machine (``__pc`` plus ``switch``) so the result stays valid
Java. Anything the lifter cannot express keeps an explicit comment.
"""

from __future__ import annotations

import re
from typing import Any

from .sourcegen import JAVA_KEYWORDS, java_type, sanitize_identifier, split_descriptors

REG_RE = re.compile(r"\b([vp]\d+)\b")
BRANCH_RE = re.compile(r":label_(-?\d+)")
FIELD_RE = re.compile(r"(L[^;]+;|\[[^\s;,]+)->([^:]+):(\S+)\s*$")
METHOD_RE = re.compile(r"(L[^;]+;|\[[^\s;,]+)->([^(]+)\((.*)\)(\S+)\s*$")

BIN_OPS = {
    "add-int": "+",
    "sub-int": "-",
    "mul-int": "*",
    "div-int": "/",
    "rem-int": "%",
    "and-int": "&",
    "or-int": "|",
    "xor-int": "^",
    "shl-int": "<<",
    "shr-int": ">>",
    "ushr-int": ">>>",
    "add-long": "+",
    "sub-long": "-",
    "mul-long": "*",
    "div-long": "/",
    "rem-long": "%",
    "and-long": "&",
    "or-long": "|",
    "xor-long": "^",
    "shl-long": "<<",
    "shr-long": ">>",
    "ushr-long": ">>>",
    "add-float": "+",
    "sub-float": "-",
    "mul-float": "*",
    "div-float": "/",
    "rem-float": "%",
    "add-double": "+",
    "sub-double": "-",
    "mul-double": "*",
    "div-double": "/",
    "rem-double": "%",
}

UNARY_OPS = {"neg-int": "-", "not-int": "~", "neg-long": "-", "not-long": "~", "neg-float": "-", "neg-double": "-"}

CASTS = {
    "int-to-long": "long",
    "int-to-float": "float",
    "int-to-double": "double",
    "long-to-int": "int",
    "long-to-float": "float",
    "long-to-double": "double",
    "float-to-int": "int",
    "float-to-long": "long",
    "float-to-double": "double",
    "double-to-int": "int",
    "double-to-long": "long",
    "double-to-float": "float",
    "int-to-byte": "byte",
    "int-to-char": "char",
    "int-to-short": "short",
}

IF_OPS = {"if-eq": "==", "if-ne": "!=", "if-lt": "<", "if-ge": ">=", "if-gt": ">", "if-le": "<="}
IFZ_OPS = {"if-eqz": "==", "if-nez": "!=", "if-ltz": "<", "if-gez": ">=", "if-gtz": ">", "if-lez": "<="}

PRIMITIVES = {
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
    "Z": "boolean",
    "B": "byte",
    "S": "short",
    "C": "char",
    "V": "void",
}

DEFAULTS = {
    "int": "0",
    "long": "0L",
    "float": "0f",
    "double": "0d",
    "short": "(short)0",
    "byte": "(byte)0",
    "char": "'\\0'",
    "boolean": "false",
}

MODIFIERS = {
    "public": "public",
    "private": "private",
    "protected": "protected",
    "static": "static",
    "final": "final",
    "abstract": "abstract",
    "native": "native",
    "synchronized": "synchronized",
    "constructor": "",
    "declared-synchronized": "synchronized",
}


def descriptor_to_java(descriptor: str) -> str:
    if descriptor in PRIMITIVES:
        return PRIMITIVES[descriptor]
    return java_type(descriptor)


def _default_for(java: str) -> str:
    if java in DEFAULTS:
        return DEFAULTS[java]
    return "null"


def _split_instruction(line: str) -> tuple[str, str]:
    parts = line.strip().split(None, 1)
    return parts[0], parts[1] if len(parts) > 1 else ""


def _method_key(name: str, parameters: str, returns: str) -> str:
    return f"{name}|{parameters}|{returns}"


class SmaliClass:
    """One smali class file split into its methods."""

    def __init__(self, text: str) -> None:
        self.header: list[str] = []
        self.fields: list[str] = []
        self.methods: dict[str, list[list[str]]] = {}
        self._parse(text)

    def _parse(self, text: str) -> None:
        current: list[str] | None = None
        signature: tuple[str, str, str] | None = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith(".method "):
                header = line[len(".method ") :]
                before, _, descriptor = header.partition("(")
                name = before.split()[-1]
                parameters, _, tail = descriptor.partition(")")
                returns = tail
                signature = (name, parameters, returns)
                current = []
                continue
            if line.startswith(".end method"):
                if signature is not None and current is not None:
                    self.methods.setdefault(_method_key(*signature), []).append(current)
                current = None
                signature = None
                continue
            if current is not None:
                if line.startswith((".registers", ".param", ".line", ".local", ".end local", ".prologue", ".source")):
                    continue
                current.append(line)
                continue
            if line.startswith(".field"):
                self.fields.append(line)
            elif line.startswith((".class", ".super", ".source", ".implements")):
                self.header.append(line)

    def body_for(self, name: str, parameters: str, returns: str) -> list[str] | None:
        bucket = self.methods.get(_method_key(name, parameters, returns))
        if not bucket:
            return None
        return bucket.pop(0)


class JavaLifter:
    def __init__(self, smali: SmaliClass) -> None:
        self.smali = smali

    # -- method body --------------------------------------------------------
    def lift(self, name: str, parameters: str, returns: str) -> list[str] | None:
        instructions = self.smali.body_for(name, parameters, returns)
        if instructions is None:
            return None
        if not instructions:
            return ["        // empty body"]

        param_descriptors = split_descriptors(parameters)
        targets = self._targets(instructions)
        types = self._infer(instructions, returns)
        referenced = sorted(
            {
                register
                for line in instructions
                for register in REG_RE.findall(_split_instruction(line)[1])
                if register.startswith("v")
            },
            key=lambda item: int(item[1:]),
        )
        has_branch = any(
            _split_instruction(line)[0].startswith(("if-", "goto", "packed-switch", "sparse-switch")) for line in instructions
        )
        lines: list[str] = []
        for register in referenced:
            java = types.get(register, "Object")
            if java == "Object":
                lines.append(f"        Object {register} = null;")
            else:
                lines.append(f"        {java} {register} = {_default_for(java)};")
        if referenced:
            lines.append("")
        if has_branch:
            lines.append("        int __pc = 0;")
            lines.append("        while (true)")
            lines.append("        {")
            lines.append("            switch (__pc)")
            lines.append("            {")

        indent = "                    " if has_branch else "        "
        case_open = False
        last_action = ""
        pending_result: str | None = None
        pending_type: str | None = None
        pending_new: dict[str, str] = {}

        def open_case(offset: int) -> None:
            nonlocal case_open
            if has_branch and not case_open:
                lines.append(f"                case {offset}:")
                case_open = True

        def close_case() -> None:
            nonlocal case_open
            if has_branch and case_open:
                if not (last_action.endswith("continue;") or last_action.startswith(("return", "throw"))):
                    lines.append(indent + "break;")
            case_open = False

        def emit(text: str, action: str = "") -> None:
            nonlocal last_action
            lines.append(indent + text)
            last_action = action or text

        for index, line in enumerate(instructions):
            mnemonic, operands = _split_instruction(line)
            if has_branch and index > 0 and index in targets:
                close_case()
            open_case(index)
            registers = REG_RE.findall(operands)
            if mnemonic in ("nop", "monitor-enter", "monitor-exit", "fill-array-data", "check-cast"):
                if mnemonic == "check-cast" and registers:
                    emit(f"{registers[0]} = (({java_type(operands.rsplit(', ', 1)[-1])}) {registers[0]});")
                continue
            if mnemonic.startswith("move") and not mnemonic.startswith("move-result"):
                if len(registers) >= 2:
                    emit(f"{registers[0]} = {registers[1]};")
                    types.setdefault(registers[0], types.get(registers[1], "Object"))
            elif mnemonic.startswith("const-string"):
                emit(f"{registers[0]} = {operands.split(', ', 1)[-1]};")
            elif mnemonic.startswith("const-wide"):
                value = operands.split(", ", 1)[-1].replace("L", "").replace("0x", "0x")
                emit(f"{registers[0]} = {value}L;")
            elif mnemonic.startswith("const"):
                emit(f"{registers[0]} = {operands.split(', ', 1)[-1]};")
            elif mnemonic.startswith("move-result"):
                if registers and pending_result is not None:
                    emit(f"{registers[0]} = {pending_result};")
                    if pending_type:
                        types[registers[0]] = pending_type
                    pending_result = None
                    pending_type = None
            elif mnemonic == "new-instance":
                owner = java_type(operands.rsplit(", ", 1)[-1])
                pending_new[registers[0]] = owner
                types.setdefault(registers[0], owner)
            elif mnemonic == "new-array":
                parts = operands.split(", ")
                emit(f"{registers[0]} = new {java_type(parts[-1])}[{parts[1]}];")
            elif mnemonic.startswith("invoke-"):
                pending_result, pending_type = self._invoke(mnemonic, operands, pending_new, emit)
            elif mnemonic in ("iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte", "iget-char", "iget-short"):
                field = FIELD_RE.search(operands)
                if field and len(registers) >= 2:
                    emit(f"{registers[0]} = {registers[1]}.{sanitize_identifier(field.group(2), JAVA_KEYWORDS, 'field')};")
                    types.setdefault(registers[0], descriptor_to_java(field.group(3)))
            elif mnemonic in ("iput", "iput-wide", "iput-object", "iput-boolean", "iput-byte", "iput-char", "iput-short"):
                field = FIELD_RE.search(operands)
                if field and len(registers) >= 2:
                    emit(f"{registers[1]}.{sanitize_identifier(field.group(2), JAVA_KEYWORDS, 'field')} = {registers[0]};")
            elif mnemonic in ("sget", "sget-wide", "sget-object", "sget-boolean", "sget-byte", "sget-char", "sget-short"):
                field = FIELD_RE.search(operands)
                if field and registers:
                    emit(
                        f"{registers[0]} = {java_type(field.group(1))}.{sanitize_identifier(field.group(2), JAVA_KEYWORDS, 'field')};"
                    )
                    types.setdefault(registers[0], descriptor_to_java(field.group(3)))
            elif mnemonic in ("sput", "sput-wide", "sput-object", "sput-boolean", "sput-byte", "sput-char", "sput-short"):
                field = FIELD_RE.search(operands)
                if field and registers:
                    emit(
                        f"{java_type(field.group(1))}.{sanitize_identifier(field.group(2), JAVA_KEYWORDS, 'field')} = {registers[0]};"
                    )
            elif mnemonic in BIN_OPS:
                if len(registers) >= 3:
                    emit(f"{registers[0]} = ({registers[1]} {BIN_OPS[mnemonic]} {registers[2]});")
            elif mnemonic.endswith("/2addr") and mnemonic[:-6] in BIN_OPS:
                if len(registers) >= 2:
                    emit(f"{registers[0]} = ({registers[0]} {BIN_OPS[mnemonic[:-6]]} {registers[1]});")
            elif "/lit" in mnemonic and mnemonic.split("/lit")[0] in BIN_OPS:
                if len(registers) >= 2:
                    emit(f"{registers[0]} = ({registers[1]} {BIN_OPS[mnemonic.split('/lit')[0]]} {operands.rsplit(', ', 1)[-1]});")
            elif mnemonic in UNARY_OPS:
                if len(registers) >= 2:
                    emit(f"{registers[0]} = ({UNARY_OPS[mnemonic]}{registers[1]});")
            elif mnemonic in CASTS:
                if len(registers) >= 2:
                    emit(f"{registers[0]} = (({CASTS[mnemonic]}) {registers[1]});")
            elif mnemonic in ("cmp-long", "cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double"):
                if len(registers) >= 3:
                    emit(
                        f"{registers[0]} = (({registers[1]} > {registers[2]}) ? 1 : (({registers[1]} == {registers[2]}) ? 0 : -1));"
                    )
            elif mnemonic == "array-length":
                if len(registers) >= 2:
                    emit(f"{registers[0]} = {registers[1]}.length;")
            elif mnemonic in ("aget", "aget-wide", "aget-object", "aget-boolean", "aget-byte", "aget-char", "aget-short"):
                if len(registers) >= 3:
                    emit(f"{registers[0]} = {registers[1]}[{registers[2]}];")
            elif mnemonic in ("aput", "aput-wide", "aput-object", "aput-boolean", "aput-byte", "aput-char", "aput-short"):
                if len(registers) >= 3:
                    emit(f"{registers[1]}[{registers[2]}] = {registers[0]};")
            elif mnemonic == "instance-of":
                if len(registers) >= 2:
                    emit(f"{registers[0]} = ({registers[1]} instanceof {java_type(operands.rsplit(', ', 1)[-1])});")
            elif mnemonic == "throw":
                emit(f"throw {registers[0]};", "throw")
            elif mnemonic == "return-void":
                emit("return;", "return")
            elif mnemonic in ("return", "return-wide", "return-object"):
                value = registers[0] if registers else "null"
                emit(f"return {value};", "return")
            elif mnemonic in IF_OPS:
                if has_branch and len(registers) >= 2:
                    emit(
                        f"if ({registers[0]} {IF_OPS[mnemonic]} {registers[1]}) {{ __pc = {self._target(operands, index)}; continue; }}",
                        "continue;",
                    )
            elif mnemonic in IFZ_OPS:
                if has_branch and registers:
                    emit(
                        f"if ({registers[0]} {IFZ_OPS[mnemonic]} 0) {{ __pc = {self._target(operands, index)}; continue; }}",
                        "continue;",
                    )
            elif mnemonic in ("goto", "goto/16", "goto/32"):
                if has_branch:
                    emit(f"__pc = {self._target(operands, index)}; continue;", "continue;")
            elif mnemonic in ("packed-switch", "sparse-switch"):
                emit("// switch table not expanded")
            elif mnemonic == "move-exception":
                emit(f"{registers[0]} = __caught;")
            else:
                emit(f"// {mnemonic} {operands}".rstrip())

        if pending_new:
            for register, owner in pending_new.items():
                lines.append(indent + f"{register} = new {owner}();")

        if has_branch:
            if case_open:
                lines.append(indent + "break;")
            lines.append("                default:")
            lines.append("                    return;")
            lines.append("            }")
            lines.append("        }")
        return lines

    # -- helpers ------------------------------------------------------------
    def _parse_invoke(self, operands: str) -> tuple[list[str], list[str], str, str] | None:
        if "}, " not in operands:
            return None
        register_text, target = operands.split("}, ", 1)
        match = METHOD_RE.search(target)
        if not match:
            return None
        registers = REG_RE.findall(register_text)
        params = [descriptor_to_java(item) for item in split_descriptors(match.group(3))]
        return registers, params, descriptor_to_java(match.group(4)), java_type(match.group(1))

    def _infer(self, instructions: list[str], returns: str) -> dict[str, str]:
        types: dict[str, str] = {}
        for _ in range(3):
            last_return: str | None = None
            for line in instructions:
                mnemonic, operands = _split_instruction(line)
                registers = REG_RE.findall(operands)
                if mnemonic.startswith("invoke-"):
                    parsed = self._parse_invoke(operands)
                    last_return = parsed[2] if parsed else None
                    if parsed:
                        call_registers, param_types, _ret, _owner = parsed
                        argument_registers = call_registers if mnemonic.startswith("invoke-static") else call_registers[1:]
                        for register, java_type_name in zip(argument_registers, param_types):
                            if java_type_name not in ("Object", "void"):
                                types.setdefault(register, java_type_name)
                    continue
                if mnemonic.startswith("move-result"):
                    if registers and last_return and last_return != "void":
                        types[registers[0]] = last_return
                    continue
                if not registers:
                    continue
                destination = registers[0]
                if mnemonic.startswith("move") and len(registers) >= 2:
                    if registers[1] in types:
                        types.setdefault(destination, types[registers[1]])
                elif mnemonic.startswith("const-string"):
                    types[destination] = "String"
                elif mnemonic.startswith("const-wide"):
                    types[destination] = "long"
                elif mnemonic.startswith("const"):
                    types[destination] = "int"
                elif mnemonic == "new-instance":
                    types[destination] = java_type(operands.rsplit(", ", 1)[-1])
                elif mnemonic == "new-array":
                    types[destination] = java_type(operands.rsplit(", ", 1)[-1])
                elif mnemonic.startswith(("iget", "sget")):
                    field = FIELD_RE.search(operands)
                    if field:
                        types[destination] = descriptor_to_java(field.group(3))
                elif mnemonic.startswith("iput"):
                    field = FIELD_RE.search(operands)
                    if field:
                        types.setdefault(destination, descriptor_to_java(field.group(3)))
                elif mnemonic in BIN_OPS or mnemonic.endswith("/2addr") or "/lit" in mnemonic:
                    kind = mnemonic.split("/")[0].split("-")[-1]
                    types[destination] = {"int": "int", "long": "long", "float": "float", "double": "double"}.get(kind, "int")
                elif mnemonic in CASTS:
                    types[destination] = CASTS[mnemonic]
                elif mnemonic == "array-length":
                    types[destination] = "int"
                elif mnemonic == "instance-of":
                    types[destination] = "boolean"
                elif mnemonic in ("aget", "aget-boolean", "aget-byte", "aget-char", "aget-short"):
                    types[destination] = "int"
                elif mnemonic == "aget-wide":
                    types[destination] = "long"
                elif mnemonic == "aget-object":
                    types[destination] = "Object"
                elif mnemonic in ("return", "return-wide", "return-object") and returns in PRIMITIVES and returns != "V":
                    types.setdefault(destination, PRIMITIVES[returns])
        return types

    @staticmethod
    def _target(operands: str, index: int) -> int:
        match = BRANCH_RE.search(operands)
        return index + int(match.group(1)) if match else index + 1

    @staticmethod
    def _targets(instructions: list[str]) -> set[int]:
        targets: set[int] = set()
        for index, line in enumerate(instructions):
            mnemonic, operands = _split_instruction(line)
            if mnemonic.startswith(("if-", "goto")):
                match = BRANCH_RE.search(operands)
                if match:
                    targets.add(index + int(match.group(1)))
        return targets

    def _invoke(self, mnemonic: str, operands: str, pending_new: dict[str, str], emit) -> tuple[str | None, str | None]:
        if "}, " not in operands:
            emit(f"// {mnemonic} {operands}".rstrip())
            return None, None
        register_text, target = operands.split("}, ", 1)
        registers = REG_RE.findall(register_text)
        match = METHOD_RE.search(target)
        if not match:
            emit(f"// {mnemonic} {target}".rstrip())
            return None, None
        owner = java_type(match.group(1))
        raw_name = match.group(2)
        name = sanitize_identifier(raw_name, JAVA_KEYWORDS, "method")
        params = split_descriptors(match.group(3))
        returns = match.group(4)
        is_static = mnemonic in ("invoke-static", "invoke-static/range")
        receiver = registers[0] if registers and not is_static else None
        args = registers[1:] if receiver else registers
        if raw_name == "<init>":
            if receiver:
                owner = pending_new.pop(receiver, owner)
                emit(f"{receiver} = new {owner}({', '.join(registers[1:])});")
            return None, None
        call = f"{name}({', '.join(args)})"
        expression = f"{owner}.{call}" if is_static else f"{receiver}.{call}" if receiver else call
        if returns == "V":
            emit(f"{expression};")
            return None, None
        return expression, descriptor_to_java(returns)


def render_java_class(entry: dict[str, Any], smali_text: str, origin: str) -> str:
    """Render one complete .java file from a DEX class summary plus its smali."""
    smali = SmaliClass(smali_text)
    lifter = JavaLifter(smali)
    descriptor = entry["descriptor"]
    internal = descriptor[1:-1] if descriptor.startswith("L") and descriptor.endswith(";") else descriptor
    simple = sanitize_identifier(internal.rsplit("/", 1)[-1].rsplit("$", 1)[-1], JAVA_KEYWORDS, "Class")
    package = internal.rsplit("/", 1)[0].replace("/", ".") if "/" in internal else ""
    flags = set(entry.get("flags") or [])
    modifiers = []
    if "public" in flags:
        modifiers.append("public")
    if "final" in flags:
        modifiers.append("final")
    if "abstract" in flags or "interface" in flags:
        modifiers.append("abstract")
    kind = "interface" if "interface" in flags else "class"
    header = (" ".join(modifiers) + f" {kind} {simple}").strip()
    super_descriptor = entry.get("super")
    if super_descriptor and super_descriptor != "Ljava/lang/Object;":
        header += " extends " + java_type(super_descriptor)
    interfaces = [java_type(item) for item in entry.get("interfaces") or []]
    if interfaces:
        header += " implements " + ", ".join(interfaces)

    lines = [
        f"// Recovered Java source for {descriptor}",
        f"// Origin: {origin}",
        "// Method bodies are lifted from Dalvik registers; verify against the smali listing.",
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
        if "volatile" in field.get("flags", []):
            field_modifiers.append("volatile")
        if "transient" in field.get("flags", []):
            field_modifiers.append("transient")
        field_type = java_type(field.get("type", "I"))
        field_name = sanitize_identifier(field.get("name", "field"), JAVA_KEYWORDS, "field")
        lines.append(f"    {' '.join(field_modifiers)} {field_type} {field_name};")
    if entry.get("fields") and entry.get("methods"):
        lines.append("")
    for method in entry.get("methods") or []:
        method_flags = set(method.get("flags") or [])
        method_modifiers = [
            item for item in ("public", "private", "protected", "static", "final", "abstract", "native", "synchronized") if item in method_flags
        ]
        parameters = split_descriptors(method.get("parameters", ""))
        params = ", ".join(f"{java_type(item)} p{index}" for index, item in enumerate(parameters))
        returns = java_type(method.get("returns", "V"))
        name = method.get("name", "method")
        if name == "<init>":
            signature = f"{' '.join(method_modifiers)} {simple}({params})"
        elif name == "<clinit>":
            body = lifter.lift(name, method.get("parameters", ""), method.get("returns", "V")) or []
            lines.append("    static")
            lines.append("    {")
            lines.extend(body)
            lines.append("    }")
            lines.append("")
            continue
        else:
            java_name = sanitize_identifier(name, JAVA_KEYWORDS, "method")
            signature = f"{' '.join(method_modifiers)} {returns} {java_name}({params})"
        if "abstract" in method_flags or "native" in method_flags or method.get("code_offset", 0) == 0:
            lines.append(f"    {signature};")
            continue
        body = lifter.lift(name, method.get("parameters", ""), method.get("returns", "V"))
        if body is None:
            body = ["        // body only in the smali listing"]
        lines.append(f"    {signature}")
        lines.append("    {")
        lines.extend(body)
        lines.append("    }")
        lines.append("")
    lines.append("}")
    return "\n".join(lines).rstrip() + "\n"
