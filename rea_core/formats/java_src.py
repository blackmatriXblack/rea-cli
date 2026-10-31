"""Java source reconstruction from class files.

Straight-line methods become ordinary Java statements. Methods with branches
become a labelled state machine (``__pc`` + ``switch``) so the recovered
control flow stays valid Java even when it is irreducible.
"""

from __future__ import annotations

import re
from typing import Any

from .java_class import OPCODES, ClassFile, _descriptor_to_java, _flags, METHOD_FLAGS, FIELD_FLAGS, CLASS_FLAGS
from .sourcegen import JAVA_KEYWORDS, escape_java, java_type, sanitize_identifier, source_header

BINOPS = {
    "iadd": "+",
    "ladd": "+",
    "fadd": "+",
    "dadd": "+",
    "isub": "-",
    "lsub": "-",
    "fsub": "-",
    "dsub": "-",
    "imul": "*",
    "lmul": "*",
    "fmul": "*",
    "dmul": "*",
    "idiv": "/",
    "ldiv": "/",
    "fdiv": "/",
    "ddiv": "/",
    "irem": "%",
    "lrem": "%",
    "frem": "%",
    "drem": "%",
    "iand": "&",
    "land": "&",
    "ior": "|",
    "lor": "|",
    "ixor": "^",
    "lxor": "^",
    "ishl": "<<",
    "lshl": "<<",
    "ishr": ">>",
    "lshr": ">>",
    "iushr": ">>>",
    "lushr": ">>>",
}

CONDITIONS = {
    "ifeq": "== 0",
    "ifne": "!= 0",
    "iflt": "< 0",
    "ifge": ">= 0",
    "ifgt": "> 0",
    "ifle": "<= 0",
    "ifnull": "== null",
    "ifnonnull": "!= null",
}

COMPARISONS = {
    "if_icmpeq": "==",
    "if_icmpne": "!=",
    "if_icmplt": "<",
    "if_icmpge": ">=",
    "if_icmpgt": ">",
    "if_icmple": "<=",
    "if_acmpeq": "==",
    "if_acmpne": "!=",
}

LOADS = {"iload": "int", "lload": "long", "fload": "float", "dload": "double", "aload": "Object"}
STORES = {"istore": "int", "lstore": "long", "fstore": "float", "dstore": "double", "astore": "Object"}
DEFAULTS = {"int": "0", "long": "0L", "float": "0f", "double": "0d", "boolean": "false", "char": "'\\0'", "byte": "0", "short": "0"}


def _cp(operands: str) -> int | None:
    match = re.search(r"#(\d+)", operands)
    return int(match.group(1)) if match else None


def _number(operands: str) -> int | None:
    match = re.match(r"\s*(-?\d+)", operands or "")
    return int(match.group(1)) if match else None


class JavaEmitter:
    def __init__(self, clazz: ClassFile, artifact: str, sha256: str) -> None:
        self.clazz = clazz
        self.artifact = artifact
        self.sha256 = sha256
        self.class_name = ""
        self.super_name = ""

    # -- public -------------------------------------------------------------
    def emit(self, access: int, class_name: str, super_name: str, interfaces: list[str], fields: list, methods: list) -> str:
        self.class_name = class_name
        self.super_name = super_name
        simple = class_name.rsplit("/", 1)[-1].rsplit(".", 1)[-1]
        package = class_name.rsplit("/", 1)[0].replace("/", ".") if "/" in class_name else ""
        lines = source_header("Java", self.artifact, self.sha256, f"class {class_name}")
        if package:
            lines.append(f"package {package};")
            lines.append("")
        modifiers: list[str] = []
        if access & 0x0001:
            modifiers.append("public")
        else:
            modifiers.append("")
        if access & 0x0010:
            modifiers.append("final")
        if access & 0x0400:
            modifiers.append("abstract")
        kind = "interface" if access & 0x0200 else "class"
        header = " ".join(item for item in modifiers if item) + f" {kind} {simple}"
        if super_name and not super_name.endswith("java/lang/Object"):
            header += f" extends {super_name.replace('/', '.')}"
        if interfaces:
            header += " implements " + ", ".join(item.replace("/", ".") for item in interfaces)
        lines.append(header)
        lines.append("{")
        for field in fields:
            lines.append("    " + self._field(field))
        if fields and methods:
            lines.append("")
        for method in methods:
            lines.extend(self._method(method))
            lines.append("")
        lines.append("}")
        return "\n".join(lines).rstrip() + "\n"

    # -- members ------------------------------------------------------------
    def _field(self, field: dict[str, Any]) -> str:
        flags = field["access_flags"]
        modifiers = []
        if flags & 0x0001:
            modifiers.append("public")
        elif flags & 0x0002:
            modifiers.append("private")
        elif flags & 0x0004:
            modifiers.append("protected")
        if flags & 0x0008:
            modifiers.append("static")
        if flags & 0x0010:
            modifiers.append("final")
        if flags & 0x0040:
            modifiers.append("volatile")
        if flags & 0x0080:
            modifiers.append("transient")
        text = f"{' '.join(modifiers)} {java_type(field['descriptor'])} {sanitize_identifier(field['name'], JAVA_KEYWORDS, 'field')}"
        if "constant" in field:
            text += f" = {field['constant']}"
        return text.strip() + ";"

    def _method(self, method: dict[str, Any]) -> list[str]:
        flags = method["access_flags"]
        name = method["name"]
        descriptor = method["descriptor"]
        params = self._parameters(method)
        returns = descriptor.partition(")")[2] or "V"
        modifiers = []
        if flags & 0x0001:
            modifiers.append("public")
        elif flags & 0x0002:
            modifiers.append("private")
        elif flags & 0x0004:
            modifiers.append("protected")
        if flags & 0x0008:
            modifiers.append("static")
        if flags & 0x0010:
            modifiers.append("final")
        if flags & 0x0020:
            modifiers.append("synchronized")
        if flags & 0x0400:
            modifiers.append("abstract")
        if flags & 0x0100:
            modifiers.append("native")
        simple = self.class_name.rsplit("/", 1)[-1]
        if name == "<init>":
            signature = f"{' '.join(modifiers)} {simple}({', '.join(params)})"
        elif name == "<clinit>":
            signature = "static"
        else:
            method_name = sanitize_identifier(name, JAVA_KEYWORDS, "method")
            signature = f"{' '.join(modifiers)} {java_type(returns)} {method_name}({', '.join(params)})"
        if method.get("code") is None:
            return ["    " + signature + ";"]
        lines = ["    " + signature, "    {"]
        body = self._body(method)
        lines.extend(body)
        lines.append("    }")
        return lines

    def _parameters(self, method: dict[str, Any]) -> list[str]:
        descriptor = method["descriptor"]
        head = descriptor.partition("(")[2].partition(")")[0]
        types = self._descriptor_types(head)
        names = self._local_names(method)
        result = []
        slot = 0 if (method["access_flags"] & 0x0008) else 1
        for position, descriptor_item in enumerate(types):
            type_name = java_type(descriptor_item)
            name = names.get(slot, f"p{position}")
            result.append(f"{type_name} {sanitize_identifier(name, JAVA_KEYWORDS, f'p{position}')}")
            slot += 2 if descriptor_item in ("J", "D") else 1
        return result

    def _local_names(self, method: dict[str, Any]) -> dict[int, str]:
        names: dict[int, str] = {}
        code = method.get("code") or {}
        for entry in code.get("local_variables", []):
            names.setdefault(entry["slot"], entry["name"])
        return names

    def _local_types(self, method: dict[str, Any]) -> dict[int, str]:
        types: dict[int, str] = {}
        code = method.get("code") or {}
        for entry in code.get("local_variables", []):
            types.setdefault(entry["slot"], entry["type"])
        return types

    # -- body ---------------------------------------------------------------
    def _body(self, method: dict[str, Any]) -> list[str]:
        code = method["code"]
        instructions = code.get("instructions", [])
        is_static = bool(method["access_flags"] & 0x0008)
        descriptor = method["descriptor"].partition("(")[2].partition(")")[0]
        arg_slots = (0 if is_static else 1) + sum(
            2 if item in ("J", "D") else 1 for item in self._descriptor_types(descriptor)
        )
        del arg_slots

        names = self._local_names(method)
        types = self._local_types(method)
        if not is_static:
            names.setdefault(0, "this")
            types.setdefault(0, self.class_name.replace("/", "."))
        parameter_slots: set[int] = set()
        slot = 0 if is_static else 1
        for position, descriptor_item in enumerate(self._descriptor_types(descriptor)):
            parameter_slots.add(slot)
            names.setdefault(slot, f"p{position}")
            types.setdefault(slot, java_type(descriptor_item))
            slot += 2 if descriptor_item in ("J", "D") else 1

        referenced: set[int] = set()
        for instruction in instructions:
            operands = instruction.get("operands", "")
            mnemonic = instruction["mnemonic"]
            if mnemonic.endswith(("load", "store")):
                number = _number(operands)
                if number is not None:
                    referenced.add(number)
            if "_" in mnemonic and mnemonic.split("_")[0] in ("iload", "lload", "fload", "dload", "aload", "istore", "lstore", "fstore", "dstore", "astore"):
                try:
                    referenced.add(int(mnemonic.rsplit("_", 1)[1]))
                except ValueError:
                    pass
        local_slots = sorted(slot for slot in referenced if slot not in parameter_slots and slot != 0)
        declarations = []
        for local in local_slots:
            java_name = sanitize_identifier(names.get(local, f"v{local}"), JAVA_KEYWORDS, f"v{local}")
            local_type = types.get(local, "Object")
            if local_type in DEFAULTS:
                declarations.append(f"        {local_type} {java_name} = {DEFAULTS[local_type]};")
            else:
                declarations.append(f"        {local_type} {java_name} = null;")
        has_branch = any(
            instruction["mnemonic"].startswith(("if", "goto", "tableswitch", "lookupswitch", "jsr"))
            for instruction in instructions
        )

        lines: list[str] = []
        lines.extend(declarations)
        if declarations:
            lines.append("")
        if has_branch:
            lines.append("        int __pc = 0;")
            lines.append("        while (true)")
            lines.append("        {")
            lines.append("            switch (__pc)")
            lines.append("            {")
        stack: list[str] = []
        targets = set()
        for instruction in instructions:
            operands = instruction.get("operands", "")
            mnemonic = instruction["mnemonic"]
            if mnemonic.startswith(("if", "goto")):
                number = _number(operands)
                if number is not None:
                    targets.add(number)
        for entry in code.get("exception_table", []):
            targets.add(entry["handler_pc"])

        stmt_indent = "                    " if has_branch else "        "
        case_started = False
        last_text = ""

        def pop(count: int = 1) -> list[str]:
            if count <= 0:
                return []
            if len(stack) >= count:
                values = stack[-count:]
                del stack[-count:]
                return values
            missing = count - len(stack)
            values = ["null"] * missing + stack
            stack.clear()
            return values

        def push(value: str) -> None:
            stack.append(value)

        def emit(text: str) -> None:
            nonlocal case_started, last_text
            if has_branch and not case_started:
                lines.append(f"                case {instruction['offset']}:")
                case_started = True
            lines.append(stmt_indent + text)
            last_text = text

        def flush_case() -> None:
            nonlocal case_started
            if has_branch and case_started:
                if not (last_text.endswith("continue;") or last_text.endswith("return;") or last_text.startswith("throw")):
                    lines.append(stmt_indent + "break;")
            case_started = False

        previous_offset = None
        for instruction in instructions:
            mnemonic = instruction["mnemonic"]
            operands = instruction.get("operands", "")
            offset = instruction["offset"]
            if has_branch and previous_offset is not None:
                # Start a new case at every branch target.
                if offset in targets:
                    if case_started:
                        lines.append(indent + "// falls through")
                    flush_case()
            previous_offset = offset
            if mnemonic == "nop":
                continue
            if mnemonic in ("return", "return_void"):
                emit("return;")
                flush_case()
                continue
            if mnemonic in ("ireturn", "lreturn", "freturn", "dreturn", "areturn"):
                value = pop()[0] if stack else "null"
                emit(f"return {value};")
                flush_case()
                continue
            if mnemonic in ("aconst_null",):
                push("null")
            elif mnemonic in ("iconst_m1", "iconst_0", "iconst_1", "iconst_2", "iconst_3", "iconst_4", "iconst_5"):
                push(mnemonic[-1] if mnemonic[-1].isdigit() else "-1")
            elif mnemonic in ("lconst_0", "lconst_1"):
                push(mnemonic[-1] + "L")
            elif mnemonic in ("fconst_0", "fconst_1", "fconst_2"):
                push(mnemonic[-1] + "f")
            elif mnemonic in ("dconst_0", "dconst_1"):
                push(mnemonic[-1] + "d")
            elif mnemonic in ("bipush", "sipush"):
                push(str(_number(operands)))
            elif mnemonic in ("ldc", "ldc_w", "ldc2_w"):
                push(self._constant(operands))
            elif mnemonic.startswith(("iload", "lload", "fload", "dload", "aload")):
                push(self._local(name=mnemonic, operands=operands, names=names, prefix=mnemonic.split("_")[0]))
            elif mnemonic.startswith(("istore", "lstore", "fstore", "dstore", "astore")):
                value = pop()[0]
                target = self._local(name=mnemonic, operands=operands, names=names, prefix=mnemonic.split("_")[0])
                emit(f"{target} = {value};")
            elif mnemonic.startswith("iinc"):
                slot_number = _number(operands) or 0
                amount_match = re.search(r",\s*(-?\d+)", operands)
                amount = int(amount_match.group(1)) if amount_match else 0
                target = self._local_raw(slot_number, names)
                emit(f"{target} += {amount};")
            elif mnemonic in BINOPS:
                right = pop()[0]
                left = pop()[0]
                push(f"({left} {BINOPS[mnemonic]} {right})")
            elif mnemonic in ("ineg", "lneg", "fneg", "dneg"):
                push(f"(-{pop()[0]})")
            elif mnemonic in ("i2l", "i2f", "i2d", "l2i", "l2f", "l2d", "f2i", "f2l", "f2d", "d2i", "d2l", "d2f", "i2b", "i2c", "i2s"):
                casts = {"i2l": "long", "i2f": "float", "i2d": "double", "l2i": "int", "l2f": "float", "l2d": "double", "f2i": "int", "f2l": "long", "f2d": "double", "d2i": "int", "d2l": "long", "d2f": "float", "i2b": "byte", "i2c": "char", "i2s": "short"}
                push(f"(({casts[mnemonic]}){pop()[0]})")
            elif mnemonic in ("lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg"):
                right = pop()[0]
                left = pop()[0]
                push(f"(({left} > {right}) ? 1 : (({left} == {right}) ? 0 : -1))")
            elif mnemonic == "iinc":
                pass
            elif mnemonic == "getstatic":
                info = self._field_info(operands)
                push(f"{info['owner']}.{sanitize_identifier(info['name'], JAVA_KEYWORDS, 'field')}")
            elif mnemonic == "putstatic":
                info = self._field_info(operands)
                emit(f"{info['owner']}.{sanitize_identifier(info['name'], JAVA_KEYWORDS, 'field')} = {pop()[0]};")
            elif mnemonic == "getfield":
                info = self._field_info(operands)
                instance = pop()[0]
                push(f"{instance}.{sanitize_identifier(info['name'], JAVA_KEYWORDS, 'field')}")
            elif mnemonic == "putfield":
                info = self._field_info(operands)
                value = pop()[0]
                instance = pop()[0]
                emit(f"{instance}.{sanitize_identifier(info['name'], JAVA_KEYWORDS, 'field')} = {value};")
            elif mnemonic == "new":
                info = self._class_info(operands)
                push(f"@new:{info}")
            elif mnemonic in ("invokevirtual", "invokespecial", "invokestatic", "invokeinterface"):
                self._invoke(mnemonic, operands, stack, pop, push, emit)
            elif mnemonic == "athrow":
                emit(f"throw {pop()[0]};")
            elif mnemonic == "checkcast":
                target = self._class_info(operands)
                push(f"(({target}){pop()[0]})")
            elif mnemonic == "instanceof":
                target = self._class_info(operands)
                push(f"({pop()[0]} instanceof {target})")
            elif mnemonic == "arraylength":
                push(f"{pop()[0]}.length")
            elif mnemonic in ("iaload", "laload", "faload", "daload", "aaload", "baload", "caload", "saload"):
                index = pop()[0]
                array = pop()[0]
                push(f"{array}[{index}]")
            elif mnemonic in ("iastore", "lastore", "fastore", "dastore", "aastore", "bastore", "castore", "sastore"):
                value = pop()[0]
                index = pop()[0]
                array = pop()[0]
                emit(f"{array}[{index}] = {value};")
            elif mnemonic == "anewarray":
                target = self._class_info(operands)
                push(f"new {target}[{pop()[0]}]")
            elif mnemonic == "newarray":
                array_types = {4: "boolean", 5: "char", 6: "float", 7: "double", 8: "byte", 9: "short", 10: "int", 11: "long"}
                kind = array_types.get(_number(operands) or 0, "Object")
                push(f"new {kind}[{pop()[0]}]")
            elif mnemonic == "multianewarray":
                info = self._class_info(operands)
                dimensions = re.search(r",\s*(\d+)", operands)
                count = int(dimensions.group(1)) if dimensions else 1
                sizes = [pop()[0] for _ in range(count)][::-1]
                push(f"new {info}" + "".join(f"[{size}]" for size in sizes))
            elif mnemonic == "dup":
                if stack:
                    push(stack[-1])
            elif mnemonic in ("dup_x1", "dup_x2", "dup2", "dup2_x1", "dup2_x2"):
                if stack:
                    push(stack[-1])
            elif mnemonic == "pop":
                if stack:
                    stack.pop()
            elif mnemonic == "pop2":
                pop(2 if len(stack) > 1 else 1)
            elif mnemonic == "swap":
                if len(stack) >= 2:
                    stack[-1], stack[-2] = stack[-2], stack[-1]
            elif mnemonic in ("goto", "goto_w"):
                target = _number(operands)
                if has_branch and target is not None:
                    emit(f"__pc = {target}; continue;")
                    flush_case()
            elif mnemonic in CONDITIONS:
                condition = pop()[0]
                target = _number(operands)
                if has_branch and target is not None:
                    emit(f"if ({condition} {CONDITIONS[mnemonic]}) {{ __pc = {target}; continue; }}")
                    flush_case()
            elif mnemonic in COMPARISONS:
                right = pop()[0]
                left = pop()[0]
                target = _number(operands)
                if has_branch and target is not None:
                    emit(f"if ({left} {COMPARISONS[mnemonic]} {right}) {{ __pc = {target}; continue; }}")
                    flush_case()
            elif mnemonic in ("tableswitch", "lookupswitch"):
                value = pop()[0]
                emit(f"// {mnemonic} on {value}")
            elif mnemonic in ("monitorenter", "monitorexit"):
                emit(f"// {mnemonic}")
            elif mnemonic in ("wide", "jsr", "jsr_w", "ret", "breakpoint"):
                emit(f"// unsupported: {mnemonic} {operands}")
            elif mnemonic in ("invokedynamic",):
                emit(f"// invokedynamic {operands}")
            elif mnemonic == "return":
                emit("return;")
            elif mnemonic in ("d2f",):
                pass
            else:
                if mnemonic not in ("iinc",):
                    emit(f"// {mnemonic} {operands}".rstrip())

        if has_branch:
            if case_started:
                lines.append(indent + "break;")
            lines.append("                default:")
            lines.append("                    return;")
            lines.append("            }")
            lines.append("        }")
        return lines or ["        // empty body"]

    def _descriptor_types(self, descriptor: str) -> list[str]:
        types: list[str] = []
        index = 0
        while index < len(descriptor):
            if descriptor[index] == "[":
                while index < len(descriptor) and descriptor[index] == "[":
                    index += 1
            if index < len(descriptor) and descriptor[index] == "L":
                end = descriptor.find(";", index)
                index = len(descriptor) if end < 0 else end + 1
            else:
                index += 1
            types.append(descriptor[index - 1] if index - 1 < len(descriptor) else "I")
        return types

    def _local_raw(self, slot: int, names: dict[int, str]) -> str:
        return sanitize_identifier(names.get(slot, f"v{slot}"), JAVA_KEYWORDS, f"v{slot}")

    def _local(self, name: str, operands: str, names: dict[int, str], prefix: str) -> str:
        suffix = name[len(prefix):]
        if suffix.startswith("_"):
            slot = int(suffix[1:])
        else:
            slot = _number(operands) or 0
        return self._local_raw(slot, names)

    def _constant(self, operands: str) -> str:
        index = _cp(operands)
        if index is None:
            return "null"
        entry = self.clazz.pool[index] if 0 <= index < len(self.clazz.pool) else None
        if not entry:
            return "null"
        tag, value = entry
        if tag == "String":
            return '"' + escape_java(self.clazz.utf8(value)) + '"'
        if tag in ("Integer",):
            return str(value)
        if tag == "Long":
            return f"{value}L"
        if tag == "Float":
            return f"{value}f"
        if tag == "Double":
            return f"{value}d"
        if tag == "Class":
            return self.clazz.utf8(value).replace("/", ".") + ".class"
        return "null"

    def _class_info(self, operands: str) -> str:
        index = _cp(operands)
        if index is None:
            return "Object"
        return self.clazz.class_name(index).replace("/", ".")

    def _field_info(self, operands: str) -> dict[str, str]:
        index = _cp(operands)
        if index is None:
            return {"owner": "Object", "name": "field", "type": "Object"}
        entry = self.clazz.pool[index] if 0 <= index < len(self.clazz.pool) else None
        if not entry or entry[0] not in ("Fieldref", "InterfaceMethodref"):
            return {"owner": "Object", "name": "field", "type": "Object"}
        owner = self.clazz.class_name(entry[1][0]).replace("/", ".")
        name, descriptor = self.clazz._name_and_type(entry[1][1])
        return {"owner": owner, "name": name, "type": java_type(descriptor)}

    def _method_info(self, operands: str) -> dict[str, Any]:
        index = _cp(operands)
        if index is None:
            return {"owner": "Object", "name": "method", "descriptor": "()V", "static": False}
        entry = self.clazz.pool[index] if 0 <= index < len(self.clazz.pool) else None
        if not entry or entry[0] not in ("Methodref", "InterfaceMethodref"):
            return {"owner": "Object", "name": "method", "descriptor": "()V", "static": False}
        owner = self.clazz.class_name(entry[1][0]).replace("/", ".")
        name, descriptor = self.clazz._name_and_type(entry[1][1])
        return {"owner": owner, "name": name, "descriptor": descriptor, "static": False}

    def _invoke(self, mnemonic: str, operands: str, stack: list[str], pop, push, emit) -> None:
        info = self._method_info(operands)
        descriptor = info["descriptor"]
        param_types = self._descriptor_types(descriptor.partition("(")[2].partition(")")[0])
        returns = descriptor.partition(")")[2] or "V"
        args = [pop()[0] for _ in range(len(param_types))][::-1]
        if mnemonic == "invokestatic":
            call = f"{info['owner']}.{sanitize_identifier(info['name'], JAVA_KEYWORDS, 'method')}({', '.join(args)})"
        else:
            receiver = pop()[0]
            if receiver.startswith("@new:"):
                owner = receiver[5:]
                call = f"new {owner}({', '.join(args)})"
            elif info["name"] == "<init>":
                target = "super" if info["owner"].replace(".", "/") != self.class_name.replace(".", "/") else "this"
                emit(f"{target}({', '.join(args)});")
                return
            else:
                call = f"{receiver}.{sanitize_identifier(info['name'], JAVA_KEYWORDS, 'method')}({', '.join(args)})"
        if returns == "V":
            emit(f"{call};")
        else:
            push(call)
