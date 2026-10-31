"""Analysis context passed to every format reader."""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from typing import Any

from .errors import LimitError

#: Default ceiling for retained decompiled text. Artifacts keep streaming to
#: disk until this budget is exhausted, then the reader records a limitation.
DEFAULT_ARTIFACT_BUDGET = 96 * 1024 * 1024


@dataclass
class Options:
    detail: str = "complete"
    max_strings: int = 4000
    max_artifact_bytes: int = DEFAULT_ARTIFACT_BUDGET
    max_items: int = 2000
    disassemble: bool = True
    source: bool = True
    include_hex: bool = True
    engine: str = "auto"
    quiet: bool = False
    pause: bool = False


@dataclass
class Artifact:
    """One decompiled text product destined for the output directory."""

    path: str
    text: str
    kind: str = "source"

    @property
    def size(self) -> int:
        return len(self.text.encode("utf-8", "replace"))


@dataclass
class Context:
    path: str
    data: Any
    size: int
    sha256: str
    options: Options
    detection: Any = None
    progress: Any = None
    started: float = field(default_factory=time.perf_counter)
    events: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    artifact_bytes: int = 0
    truncated_artifacts: int = 0

    # -- evidence helpers ---------------------------------------------------
    def limit(self, message: str) -> None:
        if message not in self.limitations:
            self.limitations.append(message)

    def stage(self, message: str) -> None:
        """Record and display one operation step."""
        milliseconds = int((time.perf_counter() - self.started) * 1000)
        self.events.append({"ms": milliseconds, "message": message})
        if self.progress is not None:
            self.progress.step(message)

    def observe(self, message: str) -> None:
        self.observations.append(message)

    def add_artifact(self, path: str, text: str, kind: str = "source") -> bool:
        """Retain one decompiled product, honouring the artifact budget."""
        rel = path.replace("\\", "/").lstrip("/")
        encoded = text.encode("utf-8", "replace")
        if self.artifact_bytes + len(encoded) > self.options.max_artifact_bytes:
            self.truncated_artifacts += 1
            self.limit(
                "Artifact budget reached; later decompiled files were not written. "
                f"Raise --max-artifact-bytes (current {self.options.max_artifact_bytes})."
            )
            return False
        self.artifact_bytes += len(encoded)
        self.artifacts.append(Artifact(rel, text, kind))
        return True

    @property
    def artifact_names(self) -> list[str]:
        return [item.path for item in self.artifacts]

    # -- address helpers ----------------------------------------------------
    def u16(self, offset: int, endian: str = "<") -> int:
        return struct.unpack_from(endian + "H", self.data, offset)[0]

    def u32(self, offset: int, endian: str = "<") -> int:
        return struct.unpack_from(endian + "I", self.data, offset)[0]

    def u64(self, offset: int, endian: str = "<") -> int:
        return struct.unpack_from(endian + "Q", self.data, offset)[0]

    def require_artifacts(self) -> None:
        if self.options.detail == "summary" and self.artifacts:
            raise LimitError("Summary detail cannot retain decompiled artifacts")

    @property
    def format_id(self) -> str:
        return getattr(self.detection, "format", "blob")


def format_size(value: int) -> str:
    return f"{value:,}"


class ChildContext:
    """Borrowed context that re-roots artifacts under one container prefix.

    Nested readers (a class inside a JAR, a binary inside a gzip stream) get a
    view of the same limits and evidence lists, while their products land in a
    dedicated subdirectory of the parent output.
    """

    def __init__(
        self,
        parent: Context,
        *,
        path: str,
        data: Any,
        sha256: str = "",
        prefix: str = "",
        detection: Any = None,
    ) -> None:
        self.parent = parent
        self.path = path
        self.data = data
        self.size = len(data)
        self.sha256 = sha256
        self.prefix = prefix.strip("/")
        self.detection = detection
        self.options = parent.options

    @property
    def artifacts(self) -> list[Artifact]:
        return self.parent.artifacts

    @property
    def limitations(self) -> list[str]:
        return self.parent.limitations

    @property
    def observations(self) -> list[str]:
        return self.parent.observations

    @property
    def format_id(self) -> str:
        return getattr(self.detection, "format", "blob")

    def limit(self, message: str) -> None:
        self.parent.limit(message)

    def stage(self, message: str) -> None:
        self.parent.stage(message)

    def observe(self, message: str) -> None:
        self.parent.observe(message)

    def add_artifact(self, path: str, text: str, kind: str = "source") -> bool:
        relative = path.replace("\\", "/").lstrip("/")
        if relative.startswith("sources/"):
            relative = relative[len("sources/") :]
        target = f"{self.prefix}/{relative}" if self.prefix else f"sources/{relative}"
        return self.parent.add_artifact(target, text, kind)

    def require_artifacts(self) -> None:
        self.parent.require_artifacts()


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path
