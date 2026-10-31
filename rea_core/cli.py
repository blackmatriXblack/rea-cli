"""Command-line front end: dispatch, evidence delivery and drag-and-drop flow."""

from __future__ import annotations

import json
import mmap
import os
import re
import sys
import traceback
from dataclasses import dataclass, replace
from typing import Any, Sequence

from . import detect as detection_module
from . import engines as engine_module
from .context import Context, Options
from .errors import (
    InvalidRequest,
    NetworkRefused,
    ReaError,
    UnsupportedFormat,
)
from .formats import COMMAND_FORMATS, analyze as analyze_format
from .report import (
    attach_sections,
    default_out_dir,
    envelope,
    format_elapsed,
    now_ms,
    render,
    strip_internal,
    target_block,
    write_artifacts,
    write_json,
    write_text,
)
from .progress import Progress, events_to_lines
from .util import human_bytes, sha256_file
from .version import DOWNLOAD_POLICY, TOOL_LABEL, VERSION

COMMANDS = (
    "analyze",
    "inspect",
    "decompile",
    "decompile-all",
    "strings",
    "search",
    "hash",
    "compare",
    "evidence",
    "source",
    "shell",
    "doctor",
    "capabilities",
    "providers",
    "version",
    *sorted(COMMAND_FORMATS),
)

URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
MIB = 1024 * 1024
MMAP_THRESHOLD = 8 * MIB


@dataclass
class Invocation:
    command: str
    targets: list[str]
    options: Options
    as_json: bool
    out_dir: str | None
    inline_artifacts: bool
    timings: bool
    verbose: bool
    no_pause: bool
    trace: bool = True
    explicit_command: bool = False
    open_folder: bool = False


def parse_args(argv: Sequence[str]) -> Invocation:
    args = list(argv)
    options = Options()
    as_json = False
    out_dir: str | None = None
    inline_artifacts = False
    timings = False
    verbose = False
    no_pause = False
    trace = True
    explicit_command = False
    open_folder = False
    command: str | None = None
    targets: list[str] = []

    index = 0
    while index < len(args):
        token = args[index]
        if token in ("-h", "--help"):
            raise _HelpRequested()
        if token in ("-V", "--version"):
            raise _VersionRequested()
        if token == "--json":
            as_json = True
        elif token == "--format":
            index += 1
            value = args[index] if index < len(args) else "text"
            if value == "json":
                as_json = True
            elif value == "text":
                as_json = False
            else:
                raise InvalidRequest(f"unsupported output format '{value}'", hint="Use --format text or --format json.")
        elif token in ("--out", "--output", "-o"):
            index += 1
            if index >= len(args):
                raise InvalidRequest(f"{token} requires a directory")
            out_dir = args[index]
        elif token == "--detail":
            index += 1
            value = args[index] if index < len(args) else "complete"
            if value not in ("complete", "summary"):
                raise InvalidRequest("--detail expects 'complete' or 'summary'")
            options.detail = value
        elif token == "--max-strings":
            index += 1
            options.max_strings = _positive_int(args, index, "--max-strings")
        elif token == "--max-items":
            index += 1
            options.max_items = _positive_int(args, index, "--max-items")
        elif token == "--max-artifact-bytes":
            index += 1
            options.max_artifact_bytes = _positive_int(args, index, "--max-artifact-bytes")
        elif token == "--no-disassembly":
            options.disassemble = False
        elif token == "--no-source":
            options.source = False
        elif token == "--no-trace":
            trace = False
        elif token == "--open":
            open_folder = True
        elif token == "--no-engines":
            options.engine = "none"
        elif token == "--engine":
            index += 1
            options.engine = args[index] if index < len(args) else "auto"
        elif token == "--inline-artifacts":
            inline_artifacts = True
        elif token == "--timings":
            timings = True
        elif token in ("--verbose", "-v"):
            verbose = True
        elif token in ("--quiet", "-q"):
            options.quiet = True
        elif token == "--no-pause":
            no_pause = True
        elif token == "--pause":
            options.pause = True
        elif token.startswith("-") and token != "-":
            raise InvalidRequest(f"unknown option '{token}'", hint="Run 'rea --help' for the supported options.")
        elif command is None and token in COMMANDS:
            command = token
            explicit_command = True
        else:
            targets.append(token)
        index += 1

    if command is None:
        command = "analyze"
    return Invocation(
        command=command,
        targets=targets,
        options=options,
        as_json=as_json,
        out_dir=out_dir,
        inline_artifacts=inline_artifacts,
        timings=timings,
        verbose=verbose,
        no_pause=no_pause,
        trace=trace,
        explicit_command=explicit_command,
        open_folder=open_folder,
    )


def _positive_int(args: Sequence[str], index: int, flag: str) -> int:
    if index >= len(args):
        raise InvalidRequest(f"{flag} requires a value")
    try:
        value = int(args[index], 0)
    except ValueError as exc:
        raise InvalidRequest(f"{flag} expects an integer, got '{args[index]}'") from exc
    if value <= 0:
        raise InvalidRequest(f"{flag} expects a positive integer")
    return value


class _HelpRequested(Exception):
    pass


class _VersionRequested(Exception):
    pass


HELP_TEXT = f"""{TOOL_LABEL}
Offline command-line reverse engineering. Drag a file onto the executable, or:

  rea <path>                       analyze + decompile, write results next to the file
  rea analyze <path>               explicit form of the same workflow
  rea inspect <path>               facts only, nothing written unless --out is given
  rea decompile <path>             decompile and write every retained product
  rea decompile-all <path> -o DIR  write every product into DIR
  rea doctor                       local engine inventory (nothing is installed)
  rea capabilities                 supported formats and commands
  rea providers                    alias for doctor
  rea version                      print the version
  rea shell                        interactive shell (stays open, many operations)
  rea strings <path> [pattern]     list printable strings
  rea search <path> <text>         search the artifact's strings
  rea hash <path>                  md5 / sha1 / sha256
  rea compare <a> <b>              compare two artifacts
  rea evidence <evidence.json>     summarize a saved evidence file
  rea source <path> [--open]       analyze and list (optionally open) the source files

Options
  --json                  machine-readable evidence on stdout
  --format text|json      output framing (default: text)
  --out DIR, -o DIR       write evidence.json, report.txt and sources/ into DIR
  --detail complete|summary
  --max-strings N         cap extracted strings (default 4000)
  --max-items N           cap listed items per section (default 2000)
  --max-artifact-bytes N  cap retained decompiled text (default {human_bytes(Options().max_artifact_bytes)})
  --no-disassembly        skip bytecode/IL/WAT listings
  --no-source             skip C#/Java/Python source reconstruction
  --no-engines            never delegate to a local external engine
  --no-trace              hide the live step trace
  --open                  open the output folder after a run (Windows/macOS)
  --inline-artifacts      embed decompiled text in the JSON evidence
  --timings               add a command_ms timing record to the JSON evidence
  --verbose, -v           list every artifact and show tracebacks
  --quiet, -q             suppress the human report summary
  --pause / --no-pause    wait for Enter after a drag-and-drop run
  -h, --help              this text
  -V, --version           print the version

Network policy: downloads = {DOWNLOAD_POLICY}. Remote URLs are refused before any
file, subprocess or network activity, and no engine is ever installed.

Source recovery (best effort, written next to the evidence)
  .NET assemblies   sources/csharp/<Type>.cs          (C# from IL; full C# with local ilspycmd)
  .class / .jar     sources/java/<Class>.java          (Java from JVM bytecode)
  .dex / .apk       <dex>/java/<Class>.java + smali    (full Java with local jadx)
  .pyc              sources/recovered/<module>.py     (straight-line bodies; see .dis.txt)
"""


def capabilities_text() -> str:
    from .formats import HANDLERS

    lines = [TOOL_LABEL, "", "Built-in readers (no downloads, no engines required):"]
    for format_id in sorted(HANDLERS):
        module, function = HANDLERS[format_id]
        lines.append(f"  {format_id:<16} formats/{module}.py::{function}")
    lines.append("")
    lines.append("Commands:")
    for command in COMMANDS:
        forced = COMMAND_FORMATS.get(command)
        suffix = f"  (forces format {forced})" if forced else ""
        lines.append(f"  {command}{suffix}")
    return "\n".join(lines)


def doctor_payload() -> dict[str, Any]:
    report = engine_module.discover(probe_versions=True)
    return {
        "ok": True,
        "tool": {"name": "rea-cli", "version": VERSION, "label": TOOL_LABEL},
        "downloads": DOWNLOAD_POLICY,
        "policy": "Local-only. Missing engines are reported, never installed.",
        "host": {
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "executable": sys.executable,
            "frozen": bool(getattr(sys, "frozen", False)),
        },
        "engines": report.to_dict(),
        "builtin": {
            "python-pyc": "header, marshal graph, bytecode",
            "java-class": "constant pool, members, JVM bytecode",
            "dex / apk": "classes, methods, smali, manifest",
            "dotnet": "metadata, signatures, CIL",
            "wasm": "sections, imports/exports, WAT code",
            "elf / pe / macho": "layout, imports, exports, symbols, strings",
            "javascript / asar": "modules, imports, urls, recovered sources",
            "sqlite": "schema, row counts, samples",
            "archives": "inventory and nested decompilation",
        },
    }


def doctor_text() -> str:
    payload = doctor_payload()
    lines = [
        TOOL_LABEL,
        f"host: {payload['host']['platform']}  python {payload['host']['python']}  frozen={payload['host']['frozen']}",
        f"downloads: {DOWNLOAD_POLICY}",
        "",
        "External engines (already installed on this host):",
    ]
    for engine in payload["engines"]["available"]:
        version = f"  {engine['version']}" if engine["version"] else ""
        lines.append(f"  [ok]   {engine['name']:<14} {engine['path']}{version}")
    missing = payload["engines"]["unavailable"]
    if missing:
        lines.append(f"  [--]   not found: {', '.join(missing)}")
    lines.append("")
    lines.append("Nothing above was downloaded, installed or modified by this CLI.")
    return "\n".join(lines)


def _refuse_remote(target: str) -> None:
    if URL_SCHEME.match(target):
        raise NetworkRefused(
            f"refusing remote target '{target}'",
            hint="This build never downloads. Save the artifact locally and pass its path.",
        )


def _validate_path(target: str) -> str:
    _refuse_remote(target)
    if "\x00" in target:
        raise InvalidRequest("path contains a NUL byte")
    if not target.strip():
        raise InvalidRequest("empty path", hint="Pass an explicit path; an empty string never selects the CWD.")
    absolute = os.path.abspath(os.path.expanduser(target))
    if not os.path.exists(absolute):
        raise InvalidRequest(f"path does not exist: {absolute}")
    return absolute


def _load(path: str) -> tuple[Any, int, str]:
    size = os.path.getsize(path)
    digest = sha256_file(path)
    if size == 0:
        return b"", 0, digest
    if size > MMAP_THRESHOLD:
        with open(path, "rb") as handle:
            return mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ), size, digest
    with open(path, "rb") as handle:
        return handle.read(), size, digest


def _apply_forced_format(invocation: Invocation, det: detection_module.Detection) -> detection_module.Detection:
    forced = COMMAND_FORMATS.get(invocation.command)
    if forced is None or forced == det.format:
        return det
    if forced == "dotnet" and det.format not in ("pe", "dotnet"):
        raise UnsupportedFormat(
            f"{invocation.command} expects a managed PE/CLI assembly, detected {det.label}",
            hint="Use 'rea analyze' for automatic format selection.",
        )
    if forced == "javascript" and det.format not in ("javascript", "text", "json"):
        raise UnsupportedFormat(
            f"{invocation.command} expects JavaScript/ASAR input, detected {det.label}"
        )
    return detection_module.Detection(
        format=forced,
        label=det.label + f" (forced as {forced})",
        by="command",
        container=det.container,
        details=det.details,
    )


def analyze_one(invocation: Invocation, target: str, progress: Progress | None = None) -> tuple[dict[str, Any], Context]:
    absolute = _validate_path(target)
    started = now_ms()
    progress = progress or Progress(enabled=False)
    progress.step(f"checking target {os.path.basename(absolute)}")

    if os.path.isdir(absolute):
        from .formats import jsapp

        data, size, digest = b"", 0, ""
        det = detection_module.Detection("javascript", "JavaScript/Electron application directory", "content", details={"directory": True})
        ctx = Context(path=absolute, data=data, size=size, sha256=digest, options=invocation.options, progress=progress)
        ctx.detection = det
        ctx.stage("scanning the application directory")
        report = jsapp.analyze_directory(ctx, absolute)
        ctx.stage(f"directory digest {ctx.sha256[:16]}..., {ctx.size:,} bytes")
        target_info = {
            "path": absolute,
            "name": os.path.basename(absolute.rstrip("\\/")),
            "size": ctx.size,
            "sha256": ctx.sha256,
            "format_label": det.label,
            "detected_by": "content",
        }
    else:
        data, size, digest = _load(absolute)
        progress.step(f"read {human_bytes(size)} ({size:,} bytes)")
        det = detection_module.detect(absolute, data)
        det = _apply_forced_format(invocation, det)
        ctx = Context(path=absolute, data=data, size=size, sha256=digest, options=invocation.options, progress=progress)
        ctx.detection = det
        ctx.stage(f"sha256 {digest[:16]}...")
        ctx.stage(f"detected {det.label} [{det.format}]")
        progress.step(f"running the {det.format} reader")
        report = analyze_format(ctx, det)
        target_info = target_block(absolute, size, digest, det.label, det.by)
        ctx.stage(f"reader finished: {len(ctx.artifacts)} artifact(s), {len(ctx.limitations)} limitation(s)")

    ctx.stage("collecting the local engine inventory")
    engines = []
    if invocation.options.engine != "none":
        engines = engine_module.discover(probe_versions=False).available
    ctx.stage(f"engines available: {len(engines)}")

    if invocation.options.detail == "summary":
        # Summary delivery keeps the facts and drops the decompiled products.
        ctx.artifacts.clear()
        ctx.artifact_bytes = 0

    if ctx.events:
        process = report.section("Process")
        process.lines.extend(events_to_lines(ctx.events))

    elapsed = format_elapsed(started)
    result = envelope(
        command=invocation.command,
        target=target_info,
        report=report,
        ctx=ctx,
        engines=engines,
        elapsed_ms=elapsed if invocation.timings else None,
    )
    result["detection"] = det.to_dict()
    attach_sections(result, report)
    return result, ctx


def _default_out(invocation: Invocation, target: str) -> str | None:
    if invocation.out_dir:
        return os.path.abspath(os.path.expanduser(invocation.out_dir))
    if invocation.command in ("analyze", "decompile", "decompile-all"):
        return default_out_dir(target)
    return None


def deliver(invocation: Invocation, target: str, result: dict[str, Any], ctx: Context) -> None:
    out_dir = _default_out(invocation, target)
    written: list[str] = []
    evidence_path = None
    report_path = None
    if out_dir:
        try:
            os.makedirs(out_dir, exist_ok=True)
            if ctx.artifacts:
                written = write_artifacts(out_dir, ctx)
                result["output"] = {
                    "directory": out_dir,
                    "sources": written,
                    "files": len(written),
                }
            source_files = [item.path for item in ctx.artifacts if item.kind == "source"]
            if result.get("output") is not None:
                result["output"]["source_files"] = source_files
            if source_files:
                index_lines = [f"{item.size:>10}  {os.path.join(out_dir, item.path)}" for item in ctx.artifacts if item.kind == "source"]
                write_text(
                    os.path.join(out_dir, "SOURCE-INDEX.txt"),
                    f"source files for {target}\n\n" + "\n".join(index_lines) + "\n",
                )
            report_text = render(result, verbose=invocation.verbose)
            report_path = write_text(os.path.join(out_dir, "report.txt"), report_text + "\n")
            evidence = strip_internal(result)
            if invocation.inline_artifacts:
                evidence["inline_artifacts"] = {item.path: item.text for item in ctx.artifacts}
            evidence_path = write_json(os.path.join(out_dir, "evidence.json"), evidence)
        except OSError as error:
            out_dir = None
            written = []
            print(f"warning: results could not be written ({error}); console output only", file=sys.stderr)
            result.pop("output", None)

    if invocation.as_json:
        payload = strip_internal(result)
        if invocation.inline_artifacts:
            payload["inline_artifacts"] = {item.path: item.text for item in ctx.artifacts}
        json.dump(payload, sys.stdout, indent=2, ensure_ascii=True, default=str)
        sys.stdout.write("\n")
        return

    if not invocation.options.quiet:
        print(render(result, verbose=invocation.verbose))
        if out_dir:
            print("")
            print(f"output directory : {out_dir}")
            print(f"report           : {report_path}")
            print(f"evidence         : {evidence_path}")
            if written:
                print(f"decompiled files : {len(written)} written under {out_dir}")
            source_files = [item.path for item in ctx.artifacts if item.kind == "source"]
            if source_files:
                print(f"source files     : {len(source_files)} (see SOURCE-INDEX.txt)")
            print(f"total retained   : {human_bytes(ctx.artifact_bytes)}")
            if invocation.open_folder:
                try:
                    os.startfile(out_dir)  # type: ignore[attr-defined]
                except (AttributeError, OSError):
                    pass


def _run_utility(invocation: Invocation, progress: Progress) -> int:
    from . import tools

    targets = [item for item in invocation.targets if item]
    command = invocation.command
    try:
        if command == "strings":
            if not targets:
                raise InvalidRequest("strings needs a path", hint="rea strings <path> [pattern]")
            return tools.strings(invocation, targets[0], targets[1] if len(targets) > 1 else None, progress)
        if command == "search":
            if len(targets) < 2:
                raise InvalidRequest("search needs a path and a pattern", hint="rea search <path> <text>")
            return tools.search(invocation, targets[0], " ".join(targets[1:]), progress)
        if command == "hash":
            if not targets:
                raise InvalidRequest("hash needs a path", hint="rea hash <path>")
            return tools.digests(invocation, targets[0], progress)
        if command == "compare":
            if len(targets) < 2:
                raise InvalidRequest("compare needs two paths", hint="rea compare <a> <b>")
            return tools.compare(invocation, targets[0], targets[1], progress)
        if command == "evidence":
            if not targets:
                raise InvalidRequest("evidence needs a saved evidence.json", hint="rea evidence <file>")
            return tools.artifact_summary(invocation, progress)
    except ReaError as error:
        if invocation.as_json:
            json.dump(error.to_dict(), sys.stdout, indent=2, ensure_ascii=True)
            sys.stdout.write("\n")
        else:
            print(f"error[{error.code}]: {error.message}", file=sys.stderr)
            if error.hint:
                print(f"hint: {error.hint}", file=sys.stderr)
        return 1
    except Exception as error:  # pragma: no cover - defensive boundary
        print(f"internal error: {type(error).__name__}: {error}", file=sys.stderr)
        if invocation.verbose:
            traceback.print_exc()
        return 70
    return 0


def _print_sources(result: dict[str, Any], ctx: Context) -> None:
    sources = [item.path for item in ctx.artifacts if item.kind == "source"]
    directory = (result.get("output") or {}).get("directory")
    print("")
    if not sources:
        print("source files: 0 (this format produced no source; try a .dll/.exe, .class/.jar, .apk/.dex or .pyc)")
        return
    print(f"source files: {len(sources)}")
    for path in sources[:200]:
        print("  " + (os.path.join(directory, path) if directory else path))
    if len(sources) > 200:
        print(f"  ... {len(sources) - 200} more (see SOURCE-INDEX.txt)")


def run(argv: Sequence[str]) -> int:
    try:
        interactive = sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError):
        interactive = False
    try:
        invocation = parse_args(argv)
    except _HelpRequested:
        print(HELP_TEXT)
        return 0
    except _VersionRequested:
        print(f"rea-cli {VERSION}")
        return 0
    except ReaError as error:
        print(f"error: {error.message}", file=sys.stderr)
        if error.hint:
            print(f"hint : {error.hint}", file=sys.stderr)
        return 2

    if invocation.command == "version":
        print(f"rea-cli {VERSION}")
        return 0
    if invocation.command == "capabilities":
        print(capabilities_text())
        return 0
    if invocation.command in ("doctor", "providers"):
        if invocation.as_json:
            json.dump(doctor_payload(), sys.stdout, indent=2, ensure_ascii=True)
            sys.stdout.write("\n")
        else:
            print(doctor_text())
        return 0

    progress = Progress(enabled=invocation.trace, verbose=invocation.verbose)

    want_sources = invocation.command == "source"
    if want_sources:
        invocation = replace(invocation, command="analyze")

    if invocation.command in ("strings", "search", "hash", "compare", "evidence"):
        return _run_utility(invocation, progress)

    targets = [item for item in invocation.targets if item != ""]
    if invocation.command == "shell":
        from .shell import run_shell

        return run_shell(invocation, progress, targets[0] if targets else None)

    if not targets and interactive:
        try:
            entered = input("Drop a file here (or paste its path) and press Enter: ").strip().strip('"')
        except EOFError:
            entered = ""
        if entered:
            targets = [entered]

    # A bare path (drag and drop, or double click) opens the shell so the window
    # never closes after the analysis finishes.
    if not invocation.explicit_command and interactive and not invocation.no_pause:
        from .shell import run_shell

        return run_shell(invocation, progress, targets[0] if targets else None)

    if not targets:
        print(HELP_TEXT)
        return 0

    exit_code = 0
    for target in targets:
        try:
            result, ctx = analyze_one(invocation, target, progress)
            deliver(invocation, _validate_path(target), result, ctx)
            if want_sources and not invocation.as_json:
                _print_sources(result, ctx)
        except ReaError as error:
            exit_code = 1 if exit_code == 0 else exit_code
            if invocation.as_json:
                json.dump(error.to_dict(), sys.stdout, indent=2, ensure_ascii=True)
                sys.stdout.write("\n")
            else:
                print(f"error[{error.code}]: {error.message}", file=sys.stderr)
                if error.hint:
                    print(f"hint: {error.hint}", file=sys.stderr)
                if getattr(sys, "frozen", False):
                    print("", file=sys.stderr)
        except Exception as error:  # pragma: no cover - defensive boundary
            exit_code = 70
            print(f"internal error: {type(error).__name__}: {error}", file=sys.stderr)
            if invocation.verbose:
                traceback.print_exc()

    pause = invocation.options.pause or (interactive and not invocation.no_pause)
    if pause:
        try:
            input("\nPress Enter to close...")
        except EOFError:
            pass
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    return run(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
