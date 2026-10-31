"""Small standalone terminal utilities: strings, search, hash and compare."""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

from . import detect as detection_module
from .errors import InvalidRequest, ReaError
from .util import human_bytes, printable_strings, sha256_file


def _validate(path: str) -> str:
    if "\x00" in path:
        raise InvalidRequest("path contains a NUL byte")
    absolute = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(absolute):
        raise InvalidRequest(f"path does not exist: {absolute}")
    return absolute


def _read(path: str, limit: int = 512 * 1024 * 1024) -> bytes:
    with open(path, "rb") as handle:
        return handle.read(limit)


def _print_json(payload: dict[str, Any]) -> None:
    import sys

    json.dump(payload, sys.stdout, indent=2, ensure_ascii=True, default=str)
    sys.stdout.write("\n")


def _emit(invocation: Any, payload: dict[str, Any], lines: list[str]) -> None:
    if getattr(invocation, "as_json", False):
        _print_json(payload)
    else:
        print("\n".join(lines))


def strings(invocation: Any, target: str, pattern: str | None, progress: Any) -> int:
    path = _validate(target)
    progress.step(f"opening {os.path.basename(path)}")
    data = _read(path)
    progress.step(f"scanning {human_bytes(len(data))} for printable strings")
    items = printable_strings(data, min_len=4, limit=200_000, max_bytes=64 * 1024 * 1024)
    if pattern:
        try:
            matcher = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise InvalidRequest(f"invalid pattern: {exc}") from exc
        items = [item for item in items if matcher.search(item["text"])]
    progress.step(f"{len(items)} string(s) matched")
    payload = {
        "ok": True,
        "command": "strings",
        "target": {"path": path, "size": len(data), "sha256": sha256_file(path)},
        "pattern": pattern,
        "count": len(items),
        "strings": items[:50000],
    }
    lines = [
        f"strings in {path}",
        f"pattern : {pattern or '(none)'}",
        f"count   : {len(items)}",
        "",
    ]
    for item in items[:2000]:
        lines.append(f"0x{item['offset']:08x}  {item['text'][:200]}")
    if len(items) > 2000:
        lines.append(f"... {len(items) - 2000} more (use --json for the full list)")
    _emit(invocation, payload, lines)
    return 0


def search(invocation: Any, target: str, pattern: str | None, progress: Any) -> int:
    path = _validate(target)
    if not pattern:
        raise InvalidRequest("search needs a pattern", hint="rea search <path> <text>")
    progress.step(f"searching {os.path.basename(path)} for {pattern!r}")
    data = _read(path)
    det = detection_module.detect(path, data)
    matches: list[dict[str, Any]] = []
    for item in printable_strings(data, min_len=3, limit=200_000, max_bytes=64 * 1024 * 1024):
        if pattern.lower() in item["text"].lower():
            matches.append({"kind": "string", "offset": item["offset"], "text": item["text"][:400]})
        if len(matches) >= 20000:
            break
    progress.step(f"{len(matches)} hit(s) in raw strings; format {det.format}")
    payload = {
        "ok": True,
        "command": "search",
        "target": {"path": path, "size": len(data), "sha256": sha256_file(path), "format": det.format},
        "pattern": pattern,
        "count": len(matches),
        "matches": matches,
    }
    lines = [f"search {pattern!r} in {path}", f"format: {det.label}", f"hits  : {len(matches)}", ""]
    for item in matches[:1000]:
        lines.append(f"0x{item['offset']:08x}  {item['text']}")
    if len(matches) > 1000:
        lines.append(f"... {len(matches) - 1000} more (use --json)")
    if not matches:
        lines.append("no match; try `rea strings <path>` to inspect the string table")
    _emit(invocation, payload, lines)
    return 0


def digests(invocation: Any, target: str, progress: Any) -> int:
    path = _validate(target)
    if os.path.isdir(path):
        raise InvalidRequest("hash expects a file, not a directory")
    progress.step(f"hashing {os.path.basename(path)}")
    size = os.path.getsize(path)
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    payload = {
        "ok": True,
        "command": "hash",
        "target": {"path": path, "size": size},
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }
    lines = [
        f"path   {path}",
        f"size   {human_bytes(size)} ({size:,} bytes)",
        f"md5    {payload['md5']}",
        f"sha1   {payload['sha1']}",
        f"sha256 {payload['sha256']}",
    ]
    _emit(invocation, payload, lines)
    return 0


def compare(invocation: Any, first: str, second: str, progress: Any) -> int:
    from . import cli

    left = _validate(first)
    right = _validate(second)
    progress.step(f"analyzing {os.path.basename(left)} (summary)")
    result_a, _ctx_a = cli.analyze_one(invocation, left, progress)
    progress.step(f"analyzing {os.path.basename(right)} (summary)")
    result_b, _ctx_b = cli.analyze_one(invocation, right, progress)
    summary_a = result_a.get("summary") or {}
    summary_b = result_b.get("summary") or {}
    keys = sorted(set(summary_a) | set(summary_b))
    differences = []
    for key in keys:
        value_a = summary_a.get(key)
        value_b = summary_b.get(key)
        if value_a != value_b:
            differences.append({"field": key, "first": value_a, "second": value_b})
    payload = {
        "ok": True,
        "command": "compare",
        "first": result_a["target"],
        "second": result_b["target"],
        "format": [result_a["format"], result_b["format"]],
        "identical_bytes": result_a["target"]["sha256"] == result_b["target"]["sha256"],
        "differences": differences,
    }
    lines = [
        "compare",
        f"  A {result_a['target']['path']}",
        f"  B {result_b['target']['path']}",
        f"  formats     {result_a['format']} / {result_b['format']}",
        f"  same bytes  {payload['identical_bytes']}",
        "",
        f"{'field':<28}{'A':<34}{'B'}",
    ]
    def show(value: Any) -> str:
        return "-" if value is None else str(value)

    for item in differences[:200]:
        first = show(item["first"])[:32]
        second = show(item["second"])[:32]
        lines.append(f"{item['field']:<28}{first:<34}{second}")
    if not differences:
        lines.append("(no summary field differs)")
    _emit(invocation, payload, lines)
    return 0


def artifact_summary(invocation: Any, progress: Any) -> int:
    """Print the summary of a saved evidence.json file."""
    target = invocation.targets[0]
    path = _validate(target)
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        try:
            evidence = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ReaError(f"{path} is not valid evidence JSON: {exc}") from exc
    progress.step("reading saved evidence")
    summary = evidence.get("summary") or {}
    lines = [
        f"evidence {path}",
        f"  command  {evidence.get('command')}",
        f"  format   {evidence.get('format')}",
        f"  evidence {evidence.get('evidence_id')}",
        "",
    ]
    for key, value in summary.items():
        lines.append(f"  {key:<22}{value}")
    artifacts = evidence.get("artifacts") or []
    if artifacts:
        lines.append("")
        lines.append(f"  artifacts ({len(artifacts)}):")
        for item in artifacts[:60]:
            lines.append(f"    {item.get('path')}  ({item.get('bytes')} bytes)")
    limitations = evidence.get("limitations") or []
    if limitations:
        lines.append("")
        for item in limitations:
            lines.append(f"  ! {item}")
    if getattr(invocation, "as_json", False):
        _print_json(evidence)
    else:
        print("\n".join(lines))
    return 0
