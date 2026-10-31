"""Best-effort Python source reconstruction from CPython code objects.

Only straight-line bodies and forward ``if`` blocks are lifted. Loops, exception
handlers and other irreducible flow keep a comment instead of guessed code, so
the artifact never claims more than the bytecode proves.
"""

from __future__ import annotations

import dis
import types
from typing import Any

from .sourcegen import escape_cs as _escape  # noqa: F401  (kept for symmetry with other emitters)

SKIP_OPS = {"RESUME", "CACHE", "NOT_TAKEN", "PRECALL", "COPY_FREE_VARS", "NOP", "MAKE_CELL"}


def _const_repr(value: Any) -> str | None:
    if isinstance(value, types.CodeType):
        return None
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, (int, float, complex, bool)) or value is None:
        return repr(value)
    if isinstance(value, bytes):
        return repr(value)
    if isinstance(value, tuple):
        parts = [_const_repr(item) for item in value]
        if any(part is None for part in parts):
            return None
        return "(" + ", ".join(parts) + ("," if len(parts) == 1 else "") + ")"
    if isinstance(value, frozenset):
        parts = [_const_repr(item) for item in value]
        if any(part is None for part in parts):
            return None
        return "frozenset({" + ", ".join(parts) + "})"
    return None


def signature(code: types.CodeType) -> str:
    positional = code.co_argcount
    positional_only = getattr(code, "co_posonlyargcount", 0)
    keyword_only = code.co_kwonlyargcount
    names = list(code.co_varnames)
    parts: list[str] = []
    used = 0
    for index in range(positional_only):
        parts.append(names[index])
        used += 1
    if positional_only:
        pass
    for index in range(positional_only, positional):
        parts.append(names[index])
        used += 1
    if code.co_flags & 0x04:
        parts.append("*" + (names[positional + keyword_only] if positional + keyword_only < len(names) else "args"))
    for index in range(positional, positional + keyword_only):
        parts.append(names[index])
        used += 1
    if not (code.co_flags & 0x04) and keyword_only:
        parts.append("*")
    if code.co_flags & 0x08:
        varkw_index = positional + keyword_only + (1 if code.co_flags & 0x04 else 0)
        parts.append("**" + (names[varkw_index] if varkw_index < len(names) else "kwargs"))
    return ", ".join(parts)


class BodyLifter:
    def __init__(self, code: types.CodeType) -> None:
        self.code = code
        self.lines: list[tuple[int, str]] = []
        self.stack: list[str] = []
        self.indent = 0
        self.pending: list[int] = []
        self.failed = False
        self.instructions = list(dis.get_instructions(code))
        self.skip_offsets: set[int] = set()

    def lift(self) -> list[tuple[int, str]] | None:
        for_iter_offsets = {instruction.offset for instruction in self.instructions if instruction.opname == "FOR_ITER"}
        for position, instruction in enumerate(self.instructions):
            if instruction.opname in ("SEND", "WITH_EXCEPT_START", "BEFORE_WITH", "SETUP_FINALLY", "SETUP_WITH", "RERAISE", "PUSH_EXC_INFO", "CHECK_EXC_MATCH", "POP_EXCEPT"):
                return None
            if instruction.opname.startswith("JUMP_BACKWARD") or instruction.opname in ("JUMP_ABSOLUTE",):
                if int(instruction.argval) not in for_iter_offsets:
                    return None
            while self.pending and instruction.offset >= self.pending[-1]:
                self.pending.pop()
                self.indent -= 1
            if self.indent < 0:
                self.indent = 0
            if instruction.offset in self.skip_offsets:
                continue
            if instruction.opname == "FOR_ITER":
                if not self.stack or not self.stack[-1].startswith("@iter:"):
                    return None
                source = self.stack[-1][6:]
                variable = "item"
                for candidate in self.instructions[position + 1 : position + 3]:
                    if candidate.opname in ("STORE_FAST", "STORE_NAME", "STORE_GLOBAL", "STORE_DEREF"):
                        variable = str(candidate.argval)
                        self.skip_offsets.add(candidate.offset)
                        break
                self._emit(f"for {variable} in {source}:")
                self.pending.append(int(instruction.argval))
                self.indent += 1
                continue
            if instruction.opname == "GET_ITER":
                expression = self._pop()[0]
                self.stack.append("@iter:" + expression)
                continue
            if instruction.opname in ("END_FOR", "POP_ITER"):
                continue
            if instruction.opname.startswith(("JUMP_BACKWARD", "JUMP_FORWARD")) or instruction.opname in ("JUMP", "JUMP_ABSOLUTE"):
                continue
            self._step(instruction)
            if self.failed:
                return None
        if not self.lines:
            return None
        return [(level, text) for level, text in self.lines if text]

    def _emit(self, text: str) -> None:
        self.lines.append((self.indent, text))

    def _pop(self, count: int = 1) -> list[str]:
        if count <= 0:
            return []
        if len(self.stack) >= count:
            values = self.stack[-count:]
            del self.stack[-count:]
            return values
        values = ["None"] * (count - len(self.stack)) + self.stack
        self.stack.clear()
        return values

    def _step(self, instruction: dis.Instruction) -> None:
        name = instruction.opname
        if name in SKIP_OPS:
            return
        if name in ("LOAD_CONST",):
            if isinstance(instruction.argval, types.CodeType):
                self.stack.append("@code")
                return
            value = _const_repr(instruction.argval)
            if value is None:
                self.failed = True
                return
            self.stack.append(value)
        elif name == "LOAD_SMALL_INT":
            self.stack.append(str(instruction.arg))
        elif name == "LOAD_COMMON_CONSTANT":
            self.stack.append(str(instruction.argrepr))
        elif name in ("LOAD_NAME", "LOAD_GLOBAL", "LOAD_FAST", "LOAD_FAST_BORROW", "LOAD_DEREF", "LOAD_FAST_CHECK", "LOAD_FAST_AND_CLEAR"):
            self.stack.append(str(instruction.argval))
        elif name == "LOAD_FAST_BORROW_LOAD_FAST_BORROW":
            for part in str(instruction.argrepr).split(", "):
                if part:
                    self.stack.append(part)
        elif name == "COPY":
            depth = instruction.arg or 1
            if len(self.stack) >= depth:
                self.stack.append(self.stack[-depth])
        elif name == "SWAP":
            depth = instruction.arg or 1
            if len(self.stack) >= depth:
                self.stack[-1], self.stack[-depth] = self.stack[-depth], self.stack[-1]
        elif name in ("STORE_NAME", "STORE_GLOBAL", "STORE_FAST", "STORE_DEREF"):
            value = self._pop()[0]
            if value.startswith("@function") or value.startswith("@class") or value == "@code":
                return
            self._emit(f"{instruction.argval} = {value}")
        elif name == "LOAD_ATTR":
            value = self._pop()[0]
            attribute = instruction.argrepr.split(" + ")[0].replace("NULL|self + ", "").strip()
            self.stack.append(f"{value}.{attribute}")
        elif name == "STORE_ATTR":
            instance = self._pop()[0]
            value = self._pop()[0]
            self._emit(f"{instance}.{instruction.argval} = {value}")
        elif name == "BINARY_SUBSCR":
            key = self._pop()[0]
            container = self._pop()[0]
            self.stack.append(f"{container}[{key}]")
        elif name == "STORE_SUBSCR":
            key = self._pop()[0]
            container = self._pop()[0]
            value = self._pop()[0]
            self._emit(f"{container}[{key}] = {value}")
        elif name == "BINARY_OP":
            right = self._pop()[0]
            left = self._pop()[0]
            operator = (instruction.argrepr or "+").rstrip("=")
            self.stack.append(f"{left} {operator} {right}".strip())
        elif name == "COMPARE_OP":
            right = self._pop()[0]
            left = self._pop()[0]
            operator = instruction.argrepr
            if "(" in operator and ")" in operator:
                operator = operator[operator.find("(") + 1 : operator.find(")")]
            self.stack.append(f"{left} {operator} {right}")
        elif name == "UNARY_NOT":
            self.stack.append(f"not {self._pop()[0]}")
        elif name == "UNARY_NEGATIVE":
            self.stack.append(f"-{self._pop()[0]}")
        elif name in ("BUILD_LIST", "BUILD_TUPLE", "BUILD_SET"):
            values = self._pop(instruction.arg or 0)
            if name == "BUILD_LIST":
                self.stack.append("[" + ", ".join(values) + "]")
            elif name == "BUILD_SET":
                self.stack.append("{" + ", ".join(values) + "}" if values else "set()")
            else:
                self.stack.append("(" + ", ".join(values) + ("," if len(values) == 1 else "") + ")")
        elif name in ("BUILD_MAP",):
            values = self._pop((instruction.arg or 0) * 2)
            pairs = [f"{values[index]}: {values[index + 1]}" for index in range(0, len(values), 2)]
            self.stack.append("{" + ", ".join(pairs) + "}")
        elif name == "FORMAT_VALUE":
            value = self._pop()[0]
            self.stack.append(f"str({value})")
        elif name == "FORMAT_SIMPLE":
            value = self._pop()[0]
            self.stack.append(f"str({value})")
        elif name == "FORMAT_WITH_SPEC":
            spec = self._pop()[0]
            value = self._pop()[0]
            self.stack.append(f"format({value}, {spec})")
        elif name == "BUILD_STRING":
            values = self._pop(instruction.arg or 0)
            self.stack.append(" + ".join(values) if values else "''")
        elif name == "LIST_APPEND":
            value = self._pop()[0]
            self._emit(f"list.append({value})")
        elif name in ("LIST_EXTEND", "SET_UPDATE", "DICT_UPDATE"):
            value = self._pop()[0]
            self._emit(f"# container update: {value}")
        elif name == "PUSH_NULL":
            self.stack.append("@null")
        elif name == "CALL":
            count = instruction.arg or 0
            arguments = self._pop(count)
            callable_value = self._pop()[0]
            if callable_value == "@null":
                callable_value = self._pop()[0]
            if callable_value == "@buildclass":
                self.stack.append("@class")
                return
            self.stack.append(f"{callable_value}({', '.join(arguments)})")
        elif name == "CALL_FUNCTION_EX":
            kwargs = self._pop()[0] if instruction.arg else None
            arguments = self._pop()[0]
            callable_value = self._pop()[0]
            suffix = f", **{kwargs}" if kwargs else ""
            self.stack.append(f"{callable_value}(*{arguments}{suffix})")
        elif name == "RETURN_VALUE":
            value = self._pop()[0] if self.stack else "None"
            self._emit(f"return {value}")
        elif name == "RETURN_CONST":
            self._emit(f"return {instruction.argrepr}")
        elif name == "POP_TOP":
            value = self._pop()[0]
            if "(" in value:
                self._emit(value)
        elif name in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE", "POP_JUMP_FORWARD_IF_FALSE", "POP_JUMP_FORWARD_IF_TRUE", "POP_JUMP_IF_NONE", "POP_JUMP_IF_NOT_NONE"):
            condition = self._pop()[0]
            if instruction.opname.endswith("TRUE"):
                text = f"not ({condition})"
            elif instruction.opname.endswith("NONE"):
                text = f"{condition} is None" if "NOT" not in instruction.opname else f"{condition} is not None"
            else:
                text = condition
            self._emit(f"if {text}:")
            self.pending.append(int(instruction.argval))
            self.indent += 1
        elif name in ("JUMP_FORWARD", "JUMP"):
            return
        elif name == "IMPORT_NAME":
            fromlist = self._pop()[0] if self.stack else "None"
            self._pop()[0] if self.stack else None
            self.stack.append(f"@import:{instruction.argval}")
        elif name == "IMPORT_FROM":
            module = self.stack[-1] if self.stack else "@import:?"
            if module.startswith("@import:"):
                self.stack.append(f"@from:{module[8:]}:{instruction.argval}")
            else:
                self.stack.append(str(instruction.argval))
        elif name == "MAKE_FUNCTION":
            self._pop(1)
            self.stack.append("@function")
        elif name == "SET_FUNCTION_ATTRIBUTE":
            if self.stack:
                self._pop()
            if self.stack:
                value = self._pop()[0]
                self.stack.append(value if value.startswith("@function") else "@function")
        elif name == "RETURN_GENERATOR":
            self.failed = True
        elif name in ("LOAD_BUILD_CLASS",):
            self.stack.append("@buildclass")
        elif name in ("SETUP_ANNOTATIONS",):
            return
        else:
            self.failed = True


def body_lines(code: types.CodeType, level: int = 1, module_level: bool = False) -> list[str]:
    lifter = BodyLifter(code)
    lifted = lifter.lift()
    if lifted is None:
        return ["    " * level + "pass  # bytecode body not reconstructed (see the .dis.txt artifact)"]
    result: list[str] = []
    for relative, text in lifted:
        if module_level and text.startswith("return"):
            continue
        line = "    " * (level + relative) + text
        if "@import:" in line and "=" in line:
            name = line.split("=")[0].strip()
            module = line.split("@import:", 1)[1].strip()
            line = "    " * (level + relative) + f"import {module}"
        elif "@import:" in line:
            line = line.replace("@import:", "import ")
        if "@from:" in line:
            _, module, name = line.partition("@from:")[2].partition(":")
            line = "    " * (level + relative) + f"from {module} import {name}"
        result.append(line)
    if result and result[-1].strip() == "return None":
        result.pop()
    return result


def emit_module(code: types.CodeType, artifact: str, sha256: str, version: str) -> str:
    lines = [
        f"# Recovered source produced by rea-cli (offline, best effort).",
        f"# Artifact: {artifact}",
    ]
    if sha256:
        lines.append(f"# SHA-256: {sha256}")
    lines.append(f"# Bytecode: CPython {version}; bodies are pattern-lifted, not a rebuild.")
    lines.append("")

    def walk(current: types.CodeType, level: int, owner_is_class: bool = False) -> None:
        if current.co_name in ("__annotate__",):
            return
        is_class = bool(current.co_name != "<module>" and not (current.co_flags & 0x01))
        if current.co_name == "<module>":
            lines.extend(body_lines(current, level, module_level=True))
            nested = [const for const in current.co_consts if isinstance(const, types.CodeType)]
            for child in sorted(nested, key=lambda item: item.co_firstlineno):
                walk(child, level)
            return
        if is_class and not owner_is_class:
            lines.append(f"{'    ' * level}class {current.co_name}:")
            class_body = body_lines(current, level + 1)
            class_body = [line for line in class_body if "pass  # bytecode body" not in line]
            lines.extend(class_body)
            nested = [const for const in current.co_consts if isinstance(const, types.CodeType)]
            for child in sorted(nested, key=lambda item: item.co_firstlineno):
                walk(child, level + 1, owner_is_class=True)
            lines.append("")
            return
        if is_class and owner_is_class:
            # Nested class: keep it as a class, not a method.
            lines.append(f"{'    ' * level}class {current.co_name}:")
            nested = [const for const in current.co_consts if isinstance(const, types.CodeType)]
            for child in sorted(nested, key=lambda item: item.co_firstlineno):
                walk(child, level + 1, owner_is_class=True)
            lines.append("")
            return
        lines.append(f"{'    ' * level}def {current.co_name}({signature(current)}):")
        body = body_lines(current, level + 1)
        lines.extend(body)
        lines.append("")

    walk(code, 0)
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n"
