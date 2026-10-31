"""Evidence envelope construction, human rendering and artifact writing."""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from .context import Context
from .errors import InvalidRequest
from .util import human_bytes, human_int
from .version import DOWNLOAD_POLICY, ENGINE_KIND, ENGINE_NAME, TOOL_LABEL, VERSION

RULE_WIDTH = 78


@dataclass
class Section:
    title: str
    lines: list[str] = field(default_factory=list)

    def add(self, line: str = "") -> "Section":
        self.lines.append(line)
        return self


@dataclass
class Report:
    """Format-specific evidence: a human projection plus structured facts."""

    kind: str
    label: str
    summary: dict[str, Any] = field(default_factory=dict)
    sections: list[Section] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, Any] = field(default_factory=dict)
    next_steps: list[str] = field(default_factory=list)

    def section(self, title: str) -> Section:
        section = Section(title)
        self.sections.append(section)
        return section

    def finish(self, examined: int | None = None, total: int | None = None) -> dict[str, Any]:
        if self.coverage:
            return self.coverage
        coverage: dict[str, Any] = {"status": "complete"}
        if examined is not None:
            coverage["examined"] = examined
        if total is not None:
            coverage["total"] = total
        if examined is not None and total is not None:
            coverage["exhausted"] = examined >= total
            coverage["status"] = "complete" if examined >= total else "partial"
        return coverage


def target_block(path: str, size: int, sha256: str, label: str, by: str) -> dict[str, Any]:
    return {
        "path": path,
        "name": os.path.basename(path),
        "size": size,
        "sha256": sha256,
        "format_label": label,
        "detected_by": by,
    }


def evidence_id(sha256: str, kind: str, command: str) -> str:
    seed = f"{sha256}:{kind}:{command}".encode("utf-8")
    return "ev_" + hashlib.sha256(seed).hexdigest()[:24]


def envelope(
    *,
    command: str,
    target: dict[str, Any],
    report: Report,
    ctx: Context,
    engines: Iterable[Any] = (),
    elapsed_ms: int | None = None,
) -> dict[str, Any]:
    artifacts = [
        {"path": item.path, "bytes": item.size, "kind": item.kind}
        for item in ctx.artifacts
    ]
    payload: dict[str, Any] = {
        "ok": True,
        "tool": {"name": "rea-cli", "version": VERSION, "label": TOOL_LABEL},
        "command": command,
        "engine": {
            "name": ENGINE_NAME,
            "kind": ENGINE_KIND,
            "downloads": DOWNLOAD_POLICY,
            "external": [engine.to_dict() for engine in engines],
        },
        "evidence_id": evidence_id(target["sha256"], report.kind, command),
        "target": target,
        "format": report.kind,
        "format_label": report.label,
        "summary": report.summary,
        "normalized_result": report.payload,
        "coverage": report.coverage or report.finish(),
        "limitations": list(ctx.limitations),
        "observations": list(ctx.observations),
        "trace": list(getattr(ctx, "events", [])),
        "artifacts": artifacts,
        "next_steps": report.next_steps,
    }
    if elapsed_ms is not None:
        payload["timings"] = {"command_ms": elapsed_ms}
    return payload


def _kv_rows(items: Iterable[tuple[str, Any]], width: int = 22) -> list[str]:
    rows: list[str] = []
    for key, value in items:
        if value is None or value == "":
            continue
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
        rows.append(f"  {key:<{width}}{text}")
    return rows


def render(result: dict[str, Any], *, verbose: bool = False) -> str:
    """Render the human projection of one completed evidence record."""
    target = result["target"]
    lines: list[str] = []
    lines.append(f"{TOOL_LABEL} {VERSION}")
    lines.append(
        f"engine: {ENGINE_NAME} ({ENGINE_KIND})   downloads: {DOWNLOAD_POLICY}   "
        f"evidence: {result['evidence_id']}"
    )
    lines.append("=" * RULE_WIDTH)
    lines.append(f"{'TARGET':<12}{target['path']}")
    lines.append(f"{'FORMAT':<12}{result['format_label']}")
    lines.append(f"{'SIZE':<12}{human_bytes(target['size'])} ({human_int(target['size'])} bytes)")
    lines.append(f"{'SHA-256':<12}{target['sha256']}")
    lines.append(f"{'COMMAND':<12}{result['command']}")

    summary = result.get("summary") or {}
    if summary:
        lines.append("")
        lines.append("-- Overview " + "-" * (RULE_WIDTH - 12))
        lines.extend(_kv_rows(summary.items()))

    for entry in result.get("_sections", []):
        title = entry["title"]
        body = entry["lines"]
        if not body:
            continue
        lines.append("")
        lines.append(f"-- {title} " + "-" * max(3, RULE_WIDTH - len(title) - 4))
        lines.extend("  " + line if line else "" for line in body)

    artifacts = result.get("artifacts") or []
    lines.append("")
    lines.append("-- Decompiled artifacts " + "-" * (RULE_WIDTH - 24))
    if not artifacts:
        lines.append("  (none retained for this artifact)")
    else:
        total = sum(item["bytes"] for item in artifacts)
        lines.append(f"  {len(artifacts)} files, {human_bytes(total)}")
        shown = artifacts if verbose else artifacts[:40]
        for item in shown:
            lines.append(f"  {human_bytes(item['bytes']):>10}  {item['path']}")
        if len(artifacts) > len(shown):
            lines.append(f"  ... {len(artifacts) - len(shown)} more (use --verbose or open the report file)")

    limitations = result.get("limitations") or []
    if limitations:
        lines.append("")
        lines.append("-- Limitations " + "-" * (RULE_WIDTH - 16))
        for item in limitations:
            lines.append(f"  - {item}")

    next_steps = result.get("next_steps") or []
    if next_steps:
        lines.append("")
        lines.append("-- Next steps " + "-" * (RULE_WIDTH - 15))
        for item in next_steps:
            lines.append(f"  - {item}")

    coverage = result.get("coverage") or {}
    if coverage:
        parts = [f"{key}={value}" for key, value in coverage.items()]
        lines.append("")
        lines.append("coverage: " + ", ".join(parts))
    return "\n".join(lines)


def attach_sections(result: dict[str, Any], report: Report, *, max_lines: int = 400) -> dict[str, Any]:
    """Copy report sections into the JSON envelope as a human projection."""
    result["_sections"] = [
        {
            "title": section.title,
            "lines": section.lines[:max_lines],
        }
        for section in report.sections
        if section.lines
    ]
    return result


def strip_internal(result: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in result.items() if not key.startswith("_")}


def safe_join(base: str, relative: str) -> str:
    rel = relative.replace("\\", "/").lstrip("/")
    parts = [part for part in rel.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise InvalidRequest(f"refusing to write outside the output directory: {relative}")
    if not parts:
        raise InvalidRequest("empty artifact path")
    return os.path.join(base, *parts)


def write_artifacts(out_dir: str, ctx: Context) -> list[str]:
    written: list[str] = []
    for artifact in ctx.artifacts:
        destination = safe_join(out_dir, artifact.path)
        os.makedirs(os.path.dirname(destination) or out_dir, exist_ok=True)
        with open(destination, "w", encoding="utf-8", errors="replace", newline="\n") as handle:
            handle.write(artifact.text)
        written.append(destination)
    return written


def write_text(path: str, text: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="replace", newline="\n") as handle:
        handle.write(text)
    return path


def write_json(path: str, payload: dict[str, Any]) -> str:
    text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    return write_text(path, text + ("\n" if not text.endswith("\n") else ""))


def default_out_dir(target_path: str) -> str:
    stem = os.path.basename(target_path.rstrip("\\/")) or "artifact"
    return os.path.join(os.path.dirname(os.path.abspath(target_path)), stem + ".rea")


def now_ms() -> int:
    return int(time.perf_counter() * 1000)


def format_elapsed(start_ms: int) -> int:
    return max(0, now_ms() - start_ms)
