"""Helpers shared by the source emitters (C#, Java, Python)."""

from __future__ import annotations

import re

CS_TYPES = {
    "void": "void",
    "bool": "bool",
    "char": "char",
    "int8": "sbyte",
    "uint8": "byte",
    "int16": "short",
    "uint16": "ushort",
    "int32": "int",
    "uint32": "uint",
    "int64": "long",
    "uint64": "ulong",
    "float32": "float",
    "float64": "double",
    "string": "string",
    "object": "object",
    "intptr": "IntPtr",
    "uintptr": "UIntPtr",
    "typedref": "TypedReference",
    "method_ptr": "IntPtr",
}

JAVA_TYPES = {
    "V": "void",
    "Z": "boolean",
    "B": "byte",
    "C": "char",
    "S": "short",
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
    "void": "void",
    "boolean": "boolean",
    "byte": "byte",
    "char": "char",
    "short": "short",
    "int": "int",
    "long": "long",
    "float": "float",
    "double": "double",
}

CS_KEYWORDS = {
    "abstract",
    "as",
    "base",
    "bool",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "checked",
    "class",
    "const",
    "continue",
    "decimal",
    "default",
    "delegate",
    "do",
    "double",
    "else",
    "enum",
    "event",
    "explicit",
    "extern",
    "false",
    "finally",
    "fixed",
    "float",
    "for",
    "foreach",
    "goto",
    "if",
    "implicit",
    "in",
    "int",
    "interface",
    "internal",
    "is",
    "lock",
    "long",
    "namespace",
    "new",
    "null",
    "object",
    "operator",
    "out",
    "override",
    "params",
    "private",
    "protected",
    "public",
    "readonly",
    "ref",
    "return",
    "sbyte",
    "sealed",
    "short",
    "sizeof",
    "stackalloc",
    "static",
    "string",
    "struct",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "uint",
    "ulong",
    "unchecked",
    "unsafe",
    "ushort",
    "using",
    "virtual",
    "void",
    "volatile",
    "while",
}

JAVA_KEYWORDS = {
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "try",
    "void",
    "volatile",
    "while",
}

GENERIC_RE = re.compile(r"`\d+")


def cs_type(name: str) -> str:
    """Map one parsed .NET type string to C# spelling."""
    if not name:
        return "object"
    text = name.strip()
    text = re.sub(r"^\[[^\]]*\]", "", text)
    text = text.replace("/", ".")
    text = GENERIC_RE.sub("", text)
    for prefix in ("class ", "valuetype "):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    array_suffix = ""
    while text.endswith(("[]", "*", "&")):
        if text.endswith("[]"):
            array_suffix = "[]" + array_suffix
            text = text[:-2]
        else:
            array_suffix = text[-1] + array_suffix
            text = text[:-1]
    text = text.replace("<>", "_")
    if text in CS_TYPES:
        return CS_TYPES[text] + array_suffix
    if text.startswith("!"):
        return "object" + array_suffix
    if "<" in text and text.endswith(">"):
        head, _, tail = text.partition("<")
        inner = tail[:-1]
        parts = [cs_type(item) for item in _split_generic(inner)]
        return f"{cs_type(head)}<{', '.join(parts)}>" + array_suffix
    return text + array_suffix


def _split_generic(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current = ""
    for char in text:
        if char == "<":
            depth += 1
        elif char == ">":
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
            continue
        current += char
    if current:
        parts.append(current)
    return parts


def java_type(descriptor: str) -> str:
    """Map a JVM field/method descriptor to Java source spelling."""
    if not descriptor:
        return "void"
    text = descriptor
    if text.startswith("("):
        return text
    dimensions = 0
    while text.startswith("["):
        dimensions += 1
        text = text[1:]
    if text in JAVA_TYPES:
        base = JAVA_TYPES[text]
    elif text.startswith("L") and text.endswith(";"):
        base = text[1:-1].replace("/", ".").replace("$", ".")
    else:
        base = "Object"
    return base + "[]" * dimensions


def escape_cs(value: str) -> str:
    result = []
    for char in value:
        if char == "\\":
            result.append("\\\\")
        elif char == '"':
            result.append('\\"')
        elif char == "\n":
            result.append("\\n")
        elif char == "\r":
            result.append("\\r")
        elif char == "\t":
            result.append("\\t")
        elif ord(char) < 0x20:
            result.append(f"\\u{ord(char):04x}")
        else:
            result.append(char)
    return "".join(result)


def escape_java(value: str) -> str:
    return escape_cs(value)


def sanitize_identifier(name: str, keywords: set[str], fallback: str = "member") -> str:
    cleaned = re.sub(r"[^0-9A-Za-z_$]", "_", name or "")
    cleaned = re.sub(r"_{2,}", "_", cleaned).strip("_")
    if not cleaned:
        cleaned = fallback
    if cleaned[0].isdigit():
        cleaned = "_" + cleaned
    if cleaned in keywords:
        cleaned = "@" + cleaned if keywords is CS_KEYWORDS else cleaned + "_"
    return cleaned


def split_top_level(text: str, separator: str = ",") -> list[str]:
    parts: list[str] = []
    depth = 0
    current = ""
    for char in text:
        if char in "<([{":
            depth += 1
        elif char in ">)]}":
            depth -= 1
        if char == separator and depth == 0:
            parts.append(current)
            current = ""
            continue
        current += char
    if current:
        parts.append(current)
    return [part.strip() for part in parts if part.strip()]


def split_descriptors(text: str) -> list[str]:
    """Split a concatenated JVM descriptor list such as ``ILjava/lang/String;``."""
    parts: list[str] = []
    index = 0
    while index < len(text):
        start = index
        while index < len(text) and text[index] == "[":
            index += 1
        if index >= len(text):
            parts.append(text[start:])
            break
        if text[index] == "L":
            end = text.find(";", index)
            index = len(text) if end < 0 else end + 1
        else:
            index += 1
        parts.append(text[start:index])
    return parts


def source_header(kind: str, artifact: str, sha256: str, extra: str = "") -> list[str]:
    lines = [
        f"// Recovered {kind} produced by rea-cli (offline, best effort).",
        f"// Artifact: {artifact}",
    ]
    if sha256:
        lines.append(f"// SHA-256: {sha256}")
    if extra:
        lines.append(f"// {extra}")
    lines.append("// Bodies are reconstructed from bytecode patterns; they are evidence, not a rebuild.")
    lines.append("")
    return lines
