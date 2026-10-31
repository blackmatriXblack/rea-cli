"""Live operation tracing for the terminal.

Every stage the CLI performs is printed with a relative timestamp and recorded
in the evidence, so the process stays visible during a run and afterwards in
`report.txt` and `evidence.json`.
"""

from __future__ import annotations

import sys
import time
from typing import Any, TextIO

BAR = "-" * 72


class Progress:
    """Prints stage lines and keeps the same events for evidence."""

    def __init__(self, enabled: bool = True, stream: TextIO | None = None, verbose: bool = False) -> None:
        self.enabled = enabled
        self.verbose = verbose
        self.stream = stream or sys.stderr
        self.started = time.perf_counter()

    def elapsed(self) -> float:
        return time.perf_counter() - self.started

    def step(self, message: str, detail: str | None = None) -> None:
        if not self.enabled:
            return
        try:
            self.stream.write(f"[{self.elapsed():8.3f}s] {message}\n")
            if detail and self.verbose:
                for line in str(detail).splitlines():
                    self.stream.write(f"           | {line}\n")
            self.stream.flush()
        except (OSError, ValueError):
            self.enabled = False

    def banner(self, title: str, subtitle: str = "") -> None:
        if not self.enabled:
            return
        try:
            self.stream.write(f"\n{BAR}\n{title}\n")
            if subtitle:
                self.stream.write(subtitle + "\n")
            self.stream.write(BAR + "\n")
            self.stream.flush()
        except (OSError, ValueError):
            self.enabled = False

    def finish(self, message: str = "done") -> None:
        self.step(f"{message} ({self.elapsed():.3f}s elapsed)")


def events_to_lines(events: list[dict[str, Any]]) -> list[str]:
    """Render recorded stages for the saved report."""
    lines: list[str] = []
    for event in events:
        milliseconds = event.get("ms", 0)
        lines.append(f"{milliseconds:>8} ms  {event.get('message', '')}")
    return lines
