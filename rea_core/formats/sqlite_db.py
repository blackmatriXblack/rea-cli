"""SQLite database reader: schema, columns, indexes and bounded sample rows."""

from __future__ import annotations

import os
import sqlite3
from typing import Any

from ..context import Context
from ..errors import FormatError
from ..report import Report
from ..util import human_bytes, shorten

MAX_TABLES = 500
SAMPLE_ROWS = 3


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _open_readonly(path: str) -> sqlite3.Connection:
    uri = "file:" + path.replace("\\", "/").replace("?", "%3f").replace("#", "%23") + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.text_factory = lambda raw: raw.decode("utf-8", "replace")
    return connection


def analyze(ctx: Context) -> Report:
    report = Report(kind="sqlite", label="SQLite database")
    header = bytes(ctx.data[:16])
    if header != b"SQLite format 3\x00":
        raise FormatError("SQLite header missing")

    page_size = int.from_bytes(bytes(ctx.data[16:18]), "big")
    write_version = ctx.data[18]
    read_version = ctx.data[19]
    change_counter = int.from_bytes(bytes(ctx.data[24:28]), "big")
    page_count = int.from_bytes(bytes(ctx.data[28:32]), "big")
    encoding = int.from_bytes(bytes(ctx.data[56:60]), "big")
    encoding_name = {1: "utf-8", 2: "utf-16le", 3: "utf-16be"}.get(encoding, str(encoding))

    report.summary.update(
        {
            "page_size": page_size,
            "pages": page_count,
            "encoding": encoding_name,
            "write_version": write_version,
            "read_version": read_version,
            "change_counter": change_counter,
        }
    )

    if os.path.exists(ctx.path + "-wal"):
        ctx.limit(
            "A write-ahead log is present next to the database; rows committed only to the WAL "
            "may be absent from this read-only snapshot."
        )

    try:
        connection = _open_readonly(ctx.path)
    except sqlite3.Error as exc:
        raise FormatError(f"SQLite could not open the file read-only: {exc}") from exc

    schema_rows: list[tuple[str, str, str]] = []
    tables: list[dict[str, Any]] = []
    try:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE type IN ('table','view','index','trigger') "
            "ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'view' THEN 1 WHEN 'index' THEN 2 ELSE 3 END, name"
        )
        entries = cursor.fetchall()
        ctx.stage(f"schema: {len(entries)} object(s)")
        schema_dump: list[str] = [f"-- schema of {os.path.basename(ctx.path)}", ""]
        for kind, name, table, sql in entries:
            schema_rows.append((kind, name, sql or ""))
            if sql:
                schema_dump.append(sql.rstrip(";") + ";")
                schema_dump.append("")
        for kind, name, table, sql in entries:
            if kind not in ("table", "view"):
                continue
            if len(tables) >= MAX_TABLES:
                ctx.limit(f"Only the first {MAX_TABLES} tables were inspected.")
                break
            entry: dict[str, Any] = {"name": name, "kind": kind, "sql": sql}
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {_quote(name)}")
                entry["rows"] = int(cursor.fetchone()[0])
            except sqlite3.Error as exc:
                entry["rows"] = None
                entry["rows_error"] = str(exc)
            try:
                cursor.execute(f"PRAGMA table_info({_quote(name)})")
                entry["columns"] = [
                    {"name": row[1], "type": row[2], "notnull": bool(row[3]), "pk": bool(row[5])}
                    for row in cursor.fetchall()
                ]
            except sqlite3.Error:
                entry["columns"] = []
            if kind == "table":
                try:
                    cursor.execute(f"SELECT * FROM {_quote(name)} LIMIT {SAMPLE_ROWS}")
                    rows = cursor.fetchall()
                    entry["sample"] = [
                        [shorten(value, 80) if value is not None else None for value in row] for row in rows
                    ]
                    schema_dump.append(f"-- {name}: {entry.get('rows')} row(s), sample:")
                    for row in entry["sample"]:
                        schema_dump.append("-- " + " | ".join("NULL" if value is None else str(value) for value in row))
                    schema_dump.append("")
                except sqlite3.Error:
                    entry["sample"] = []
            tables.append(entry)
    except sqlite3.Error as exc:
        ctx.limit(f"SQLite schema inspection stopped early: {exc}")
    finally:
        connection.close()

    table_section = report.section("Tables and views")
    for entry in tables:
        columns = ", ".join(column["name"] for column in entry.get("columns", [])[:12])
        table_section.add(f"{entry['kind']:<6} {entry['name']:<32} rows={entry.get('rows')}  [{columns}]")

    schema_section = report.section("Schema")
    for kind, name, sql in schema_rows:
        schema_section.add(f"{kind:<8} {name}")

    stem = os.path.splitext(os.path.basename(ctx.path))[0] or "database"
    ctx.add_artifact(f"sources/{stem}.schema.sql", "\n".join(schema_dump), kind="schema")

    report.payload = {
        "header": {
            "page_size": page_size,
            "page_count": page_count,
            "encoding": encoding_name,
            "write_version": write_version,
            "read_version": read_version,
        },
        "objects": [{"type": kind, "name": name, "sql": sql} for kind, name, sql in schema_rows],
        "tables": tables,
        "database_size": human_bytes(ctx.size),
    }
    complete = len(tables) < MAX_TABLES
    report.coverage = {
        "status": "complete" if complete else "partial",
        "examined": len(tables),
        "total": sum(1 for kind, _, _ in schema_rows if kind in ("table", "view")),
        "exhausted": complete,
    }
    report.next_steps.append("Open the .schema.sql artifact for CREATE statements and sample rows.")
    return report
