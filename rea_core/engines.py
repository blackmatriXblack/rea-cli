"""Discovery of analysis engines that are already installed on the host.

The policy is deliberately narrow: this CLI only *uses* local executables. It
never downloads, installs, upgrades or vendors a tool, and it refuses remote
inputs before any subprocess or network activity.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Sequence

from .version import DOWNLOAD_POLICY

#: Engine families this CLI can delegate to when the host already provides them.
ENGINE_COMMANDS: dict[str, tuple[str, ...]] = {
    "objdump": ("objdump",),
    "llvm-objdump": ("llvm-objdump",),
    "dumpbin": ("dumpbin",),
    "jadx": ("jadx", "jadx.bat", "jadx-cli"),
    "javap": ("javap",),
    "ilspycmd": ("ilspycmd",),
    "monodis": ("monodis",),
    "wasm2wat": ("wasm2wat",),
    "wasm-objdump": ("wasm-objdump",),
    "rizin": ("rizin",),
    "radare2": ("radare2",),
    "upx": ("upx",),
    "7z": ("7z", "7za"),
    "llvm-readobj": ("llvm-readobj",),
}

ENGINE_PURPOSE = {
    "objdump": "native disassembly (ELF/PE/Mach-O)",
    "llvm-objdump": "native disassembly (LLVM objects)",
    "dumpbin": "PE headers, imports and disassembly",
    "jadx": "Java/Kotlin source recovery from dex",
    "javap": "JVM class disassembly",
    "ilspycmd": "C# source recovery from .NET assemblies",
    "monodis": ".NET IL disassembly",
    "wasm2wat": "WebAssembly text rendering",
    "wasm-objdump": "WebAssembly section dump",
    "rizin": "binary analysis and disassembly",
    "radare2": "binary analysis and disassembly",
    "upx": "packed-binary inspection",
    "7z": "archive listing",
    "llvm-readobj": "object header inspection",
}

MAX_TOOL_OUTPUT = 8 * 1024 * 1024


@dataclass
class Engine:
    name: str
    path: str | None = None
    purpose: str = ""
    version: str | None = None

    @property
    def available(self) -> bool:
        return self.path is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "path": self.path,
            "purpose": self.purpose,
            "version": self.version,
        }


@dataclass
class EngineReport:
    engines: list[Engine] = field(default_factory=list)
    downloads: str = DOWNLOAD_POLICY

    def find(self, name: str) -> Engine | None:
        for engine in self.engines:
            if engine.name == name and engine.available:
                return engine
        return None

    @property
    def available(self) -> list[Engine]:
        return [engine for engine in self.engines if engine.available]

    def to_dict(self) -> dict[str, Any]:
        return {
            "downloads": self.downloads,
            "policy": "local-only; nothing is fetched or installed",
            "available": [engine.to_dict() for engine in self.available],
            "unavailable": [engine.name for engine in self.engines if not engine.available],
        }

    def summary_line(self) -> str:
        names = [engine.name for engine in self.available]
        if not names:
            return "no external engines detected (built-in readers only)"
        return ", ".join(names)


def _version_argv(name: str) -> list[str]:
    if name in ("7z", "7za"):
        return []
    if name == "dumpbin":
        return []
    return ["--version"]


def _safe_version(path: str, name: str) -> str | None:
    argv = _version_argv(name)
    if not argv:
        return None
    try:
        completed = subprocess.run(
            [path, *argv],
            capture_output=True,
            timeout=6,
            check=False,
            text=True,
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = (completed.stdout or completed.stderr or "").strip().splitlines()
    return text[0][:120] if text else None


def discover(probe_versions: bool = False) -> EngineReport:
    """Locate engines already present on ``PATH`` (never installs anything)."""
    report = EngineReport()
    for name, commands in ENGINE_COMMANDS.items():
        resolved = None
        for command in commands:
            found = shutil.which(command)
            if found:
                resolved = found
                break
        engine = Engine(name=name, path=resolved, purpose=ENGINE_PURPOSE.get(name, ""))
        if resolved and probe_versions:
            engine.version = _safe_version(resolved, name)
        report.engines.append(engine)
    return report


def run_tool(argv: Sequence[str], timeout: int = 120) -> tuple[int, str, str]:
    """Run one already-installed tool with bounded output capture."""
    try:
        completed = subprocess.run(
            list(argv),
            capture_output=True,
            timeout=timeout,
            check=False,
            text=True,
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise OSError(f"engine not found: {argv[0]}") from exc
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if len(stdout) > MAX_TOOL_OUTPUT:
        stdout = stdout[:MAX_TOOL_OUTPUT] + "\n[rea: output truncated]\n"
    if len(stderr) > MAX_TOOL_OUTPUT:
        stderr = stderr[:MAX_TOOL_OUTPUT] + "\n[rea: output truncated]\n"
    return completed.returncode, stdout, stderr


def which(name: str) -> str | None:
    return shutil.which(name)


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


MAX_SOURCE_FILES = 1500
MAX_SOURCE_BYTES = 32 * 1024 * 1024


def run_source_engine(command: Sequence[str], suffix: str, timeout: int = 900) -> tuple[list[tuple[str, str]], str | None]:
    """Run a local decompiler that writes files into an output directory.

    ``{out}`` in ``command`` is replaced with a private temporary directory.
    Returns (relative path, text) pairs plus an error message when nothing was
    produced. The engine is never installed or downloaded here.
    """
    with tempfile.TemporaryDirectory(prefix="rea-source-") as workspace:
        argv = [item.replace("{out}", workspace) for item in command]
        try:
            code, stdout, stderr = run_tool(argv, timeout=timeout)
        except OSError as exc:
            return [], str(exc)
        results: list[tuple[str, str]] = []
        total = 0
        for root, _dirs, names in os.walk(workspace):
            for name in sorted(names):
                if not name.lower().endswith(suffix):
                    continue
                full = os.path.join(root, name)
                try:
                    size = os.path.getsize(full)
                    if size > 4 * 1024 * 1024 or total + size > MAX_SOURCE_BYTES:
                        continue
                    with open(full, "r", encoding="utf-8", errors="replace") as handle:
                        text = handle.read()
                except OSError:
                    continue
                relative = os.path.relpath(full, workspace).replace("\\", "/")
                results.append((relative, text))
                total += size
                if len(results) >= MAX_SOURCE_FILES:
                    break
        if not results:
            detail = (stderr or stdout or "").strip().splitlines()
            message = detail[-1][:300] if detail else f"engine exited with {code} and wrote no {suffix} files"
            return [], message
        return results, None
