"""Interactive terminal shell so the window stays open and work continues."""

from __future__ import annotations

import dataclasses
import os
import sys
from typing import Any

from . import tools
from .errors import ReaError
from .util import human_bytes
from .version import DOWNLOAD_POLICY, TOOL_LABEL

HELP = """commands
  open <path>            load a new target (analyze + decompile immediately)
  analyze | a            run the full analyze + decompile workflow again
  inspect | i            re-run with summary delivery (facts only)
  decompile | d          rewrite every retained artifact to the output folder
  strings [pattern]      list printable strings, optionally filtered
  search <text>          search the artifact's strings
  hash                   md5 / sha1 / sha256 and size
  evidence <file>        summarize a saved evidence.json
  report | r             print the full human report of the current result
  source [open]          list the recovered source files (optionally open the folder)
  artifacts | ls         list the retained artifacts and their paths
  out [dir]              show or change the output directory
  doctor                 local engine inventory (nothing is installed)
  capabilities           supported formats and commands
  help | h               this text
  quit | q | exit        leave the shell
"""


class Shell:
    def __init__(self, invocation: Any, progress: Any) -> None:
        self.invocation = invocation
        self.progress = progress
        self.target: str | None = None
        self.result: dict[str, Any] | None = None
        self.ctx: Any = None
        self.out_dir: str | None = invocation.out_dir

    # -- entry --------------------------------------------------------------
    def run(self, initial: str | None = None) -> int:
        self._banner()
        if initial:
            try:
                self.load(initial)
            except ReaError as error:
                print(f"error[{error.code}]: {error.message}")
                if error.hint:
                    print(f"hint: {error.hint}")
                initial = None
        if not initial:
            entered = self._ask("target path (or 'quit'): ")
            if entered.lower() in ("quit", "exit", "q", ""):
                return 0
            try:
                self.load(entered.strip('"'))
            except ReaError as error:
                print(f"error[{error.code}]: {error.message}")
                if error.hint:
                    print(f"hint: {error.hint}")
        while True:
            try:
                line = input("rea> ").strip().lstrip("\ufeff")
            except EOFError:
                print("")
                return 0
            except KeyboardInterrupt:
                print("\n(type 'quit' to leave)")
                continue
            if not line:
                continue
            try:
                if not self._dispatch(line):
                    return 0
            except ReaError as error:
                print(f"error[{error.code}]: {error.message}")
                if error.hint:
                    print(f"hint: {error.hint}")
            except KeyboardInterrupt:
                print("\ninterrupted; still in the shell")
            except Exception as error:  # keep the shell alive
                print(f"internal error: {type(error).__name__}: {error}")

    # -- banner / helpers ---------------------------------------------------
    def _banner(self) -> None:
        from . import engines

        print(f"{TOOL_LABEL} - interactive shell")
        print(f"downloads: {DOWNLOAD_POLICY}   engines: {engines.discover().summary_line()}")
        print("Type 'help' for commands, 'quit' to exit.\n")

    def _ask(self, prompt: str) -> str:
        try:
            return input(prompt).strip().lstrip("\ufeff")
        except EOFError:
            return ""
        except KeyboardInterrupt:
            return ""

    def _invocation(self, **changes: Any) -> Any:
        return dataclasses.replace(self.invocation, **changes)

    def _compact(self) -> None:
        if not self.result:
            return
        summary = self.result.get("summary") or {}
        print("")
        print(f"format      {self.result.get('format_label')}")
        for key in list(summary)[:8]:
            print(f"{key:<22}{summary[key]}")
        artifacts = self.result.get("artifacts") or []
        total = sum(item.get("bytes", 0) for item in artifacts)
        print(f"artifacts   {len(artifacts)} ({human_bytes(total)})")
        source_count = len([item for item in (self.ctx.artifacts if self.ctx else []) if item.kind == "source"])
        if source_count:
            print(f"source      {source_count} file(s) - type 'source' to list them")
        output = self.result.get("output") or {}
        if output.get("directory"):
            print(f"output      {output['directory']}")
        print(f"evidence    {self.result.get('evidence_id')}")
        print("Type 'report' for the full text, 'artifacts' to list files.\n")

    # -- operations ---------------------------------------------------------
    def load(self, target: str, command: str = "analyze") -> None:
        from . import cli

        invocation = self._invocation(command=command, out_dir=self.out_dir)
        self.progress.banner(f"analyzing {os.path.basename(target)}")
        result, ctx = cli.analyze_one(invocation, target, self.progress)
        self.target = target
        self.result = result
        self.ctx = ctx
        quiet_before = invocation.options.quiet
        invocation.options.quiet = True
        try:
            cli.deliver(invocation, os.path.abspath(os.path.expanduser(target)), result, ctx)
        finally:
            invocation.options.quiet = quiet_before
        output = result.get("output") or {}
        if output.get("directory"):
            self.out_dir = output["directory"]
        self._compact()

    @staticmethod
    def result_format_hint(result: dict[str, Any]) -> str:
        return f"{result.get('format_label')} | evidence {result.get('evidence_id')}"


    def _dispatch(self, line: str) -> bool:
        from . import cli

        parts = line.split()
        command = parts[0].lower()
        rest = parts[1:]
        if command in ("quit", "exit", "q"):
            return False
        if command in ("help", "h", "?"):
            print(HELP)
            return True
        if command in ("open", "o"):
            if not rest:
                print("usage: open <path>")
                return True
            self.load(" ".join(rest).strip('"'))
            return True
        if command in ("analyze", "a"):
            self._require_target()
            self.load(self.target, "analyze")
            return True
        if command in ("inspect", "i"):
            self._require_target()
            previous = self.invocation.options.detail
            self.invocation.options.detail = "summary"
            try:
                self.load(self.target, "inspect")
            finally:
                self.invocation.options.detail = previous
            return True
        if command in ("decompile", "d"):
            self._require_target()
            self.load(self.target, "decompile")
            return True
        if command in ("strings", "s"):
            self._require_target()
            tools.strings(self._invocation(as_json=False), self.target, rest[0] if rest else None, self.progress)
            return True
        if command in ("search", "g", "find"):
            self._require_target()
            if not rest:
                print("usage: search <text>")
                return True
            tools.search(self._invocation(as_json=False), self.target, " ".join(rest), self.progress)
            return True
        if command in ("hash", "sha256", "digest"):
            self._require_target()
            tools.digests(self._invocation(as_json=False), self.target, self.progress)
            return True
        if command in ("evidence", "ev"):
            if not rest:
                print("usage: evidence <evidence.json>")
                return True
            tools.artifact_summary(self._invocation(as_json=False, targets=[rest[0]]), self.progress)
            return True
        if command in ("report", "r"):
            if not self.result:
                print("no result yet; use 'open <path>'")
                return True
            print(cli.render(self.result, verbose=True))
            return True
        if command in ("artifacts", "ls"):
            self._list_artifacts()
            return True
        if command in ("source", "src"):
            self._list_sources(open_folder=bool(rest) and rest[0].lower() == "open")
            return True
        if command == "out":
            if rest:
                self.out_dir = os.path.abspath(os.path.expanduser(" ".join(rest)))
                print(f"output directory: {self.out_dir}")
            else:
                print(f"output directory: {self.out_dir or '(default next to the target)'}")
            return True
        if command == "doctor":
            print(cli.doctor_text())
            return True
        if command in ("capabilities", "caps"):
            print(cli.capabilities_text())
            return True
        if command == "compare":
            if len(rest) < 2:
                print("usage: compare <a> <b>")
                return True
            tools.compare(self._invocation(as_json=False), rest[0], rest[1], self.progress)
            return True
        print(f"unknown command '{command}'; type 'help'")
        return True

    def _require_target(self) -> None:
        if not self.target:
            raise ReaError("no target loaded", hint="Use 'open <path>' first.")

    def _list_sources(self, open_folder: bool = False) -> None:
        if not self.ctx:
            print("no target loaded")
            return
        sources = [item for item in self.ctx.artifacts if item.kind == "source"]
        directory = (self.result or {}).get("output", {}).get("directory")
        if not sources:
            print("no source files were produced for this target")
            return
        print(f"source files: {len(sources)}")
        for item in sources:
            print("  " + (os.path.join(directory, item.path) if directory else item.path))
        if open_folder and directory:
            try:
                os.startfile(directory)  # type: ignore[attr-defined]
            except (AttributeError, OSError):
                pass

    def _list_artifacts(self) -> None:
        if not self.ctx or not self.ctx.artifacts:
            print("no artifacts retained")
            return
        output = (self.result or {}).get("output") or {}
        directory = output.get("directory")
        for item in self.ctx.artifacts:
            location = os.path.join(directory, item.path) if directory else item.path
            print(f"{item.size:>10}  {location}")
        print(f"{len(self.ctx.artifacts)} artifact(s), {human_bytes(self.ctx.artifact_bytes)}")


def run_shell(invocation: Any, progress: Any, initial: str | None = None) -> int:
    return Shell(invocation, progress).run(initial)
