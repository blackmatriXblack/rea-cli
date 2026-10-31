"""Smoke runner for every fixture and format, with tracebacks on failure."""

from __future__ import annotations

import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rea_core import cli  # noqa: E402


SOURCE_EXPECTATIONS = {
    "Sample.class": ".java",
    "sample.jar": ".java",
    "sample.apk": ".java",
    "sample.dex": ".java",
    "sample_module.pyc": ".py",
}


def check(path: str, args: list[str] | None = None) -> bool:
    invocation = cli.parse_args((args or []) + [path])
    try:
        result, ctx = cli.analyze_one(invocation, path)
    except Exception:
        print(f"FAIL {os.path.basename(path)}")
        traceback.print_exc()
        return False
    name = os.path.basename(path)
    expected = SOURCE_EXPECTATIONS.get(name)
    sources = [item.path for item in ctx.artifacts if item.kind == "source"]
    if expected and not any(item.endswith(expected) for item in sources):
        print(f"FAIL {name}: no {expected} source artifact was produced")
        return False
    print(
        f"OK   {name:<24} format={result['format']:<12} "
        f"artifacts={len(ctx.artifacts):<3} sources={len(sources):<3} limitations={len(ctx.limitations)}"
    )
    return True


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    fixtures = os.path.join(root, "fixtures")
    targets = [
        "sample_module.wasm",
        "sample_image.elf",
        "sample_image.macho",
        "Sample.class",
        "sample.dex",
        "AndroidManifest.bin",
        "sample.asar",
        "sample.jar",
        "sample.apk",
        "sample.db",
        "sample.js",
        "notes.txt",
        "blob.bin",
        "sample_module.pyc",
    ]
    failures = 0
    for name in targets:
        path = os.path.join(fixtures, name)
        if not os.path.exists(path):
            print(f"SKIP {name} (missing)")
            continue
        failures += 0 if check(path) else 1

    extra = [item for item in sys.argv[1:] if os.path.exists(item)]
    for path in extra:
        failures += 0 if check(path) else 1

    print(f"\n{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
