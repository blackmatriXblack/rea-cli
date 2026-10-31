"""Format registry and dispatch for the built-in offline readers."""

from __future__ import annotations

import importlib
from typing import Callable

from ..context import Context
from ..detect import Detection
from ..errors import UnsupportedFormat

#: format id -> (module under ``rea_core.formats``, entry function)
HANDLERS: dict[str, tuple[str, str]] = {
    "python-pyc": ("pyc", "analyze"),
    "java-class": ("java_class", "analyze"),
    "dex": ("dalvik", "analyze"),
    "apk": ("apk", "analyze"),
    "axml": ("apk", "analyze_axml"),
    "dotnet": ("dotnet", "analyze"),
    "wasm": ("wasm", "analyze"),
    "elf": ("native", "analyze"),
    "pe": ("native", "analyze"),
    "macho": ("native", "analyze"),
    "javascript": ("jsapp", "analyze_file"),
    "asar": ("jsapp", "analyze_asar"),
    "zip": ("archive", "analyze"),
    "jar": ("archive", "analyze"),
    "tar": ("archive", "analyze"),
    "gzip": ("archive", "analyze"),
    "bzip2": ("archive", "analyze"),
    "xz": ("archive", "analyze"),
    "7z": ("archive", "analyze"),
    "rar": ("archive", "analyze"),
    "sqlite": ("sqlite_db", "analyze"),
    "beam": ("beam", "analyze"),
    "text": ("blob", "analyze"),
    "json": ("blob", "analyze"),
    "plist": ("blob", "analyze"),
    "blob": ("blob", "analyze"),
    "gguf": ("blob", "analyze"),
    "godot-pck": ("blob", "analyze"),
    "unityfs": ("blob", "analyze"),
}

#: Forced formats for ``inspect-*`` compatibility commands.
COMMAND_FORMATS = {
    "inspect-python-pyc": "python-pyc",
    "inspect-java-class": "java-class",
    "inspect-dex": "dex",
    "inspect-android-package": "apk",
    "inspect-managed-artifact": "dotnet",
    "inspect-managed-members": "dotnet",
    "inspect-wasm-artifact": "wasm",
    "inspect-sqlite-database": "sqlite",
    "inspect-erlang-beam": "beam",
    "analyze-javascript-application": "javascript",
    "inspect-asar-archive": "asar",
}


def resolve(format_id: str) -> Callable[[Context], object]:
    entry = HANDLERS.get(format_id)
    if entry is None:
        raise UnsupportedFormat(
            f"no built-in reader for format '{format_id}'",
            hint="Run 'rea capabilities' for the supported format list.",
        )
    module_name, function_name = entry
    module = importlib.import_module(f".{module_name}", __package__)
    return getattr(module, function_name)


def analyze(ctx: Context, detection: Detection):
    handler = resolve(detection.format)
    return handler(ctx)
