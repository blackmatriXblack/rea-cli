"""Deterministic, self-contained fixtures for the offline readers.

Every fixture is assembled from bytes so the suite runs without compilers,
SDKs or network access. Run: python tests/make_fixtures.py
"""

from __future__ import annotations

import json
import os
import sqlite3
import struct
import sys
import zipfile
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "fixtures")


def u8(value: int) -> bytes:
    return struct.pack("<B", value)


def u16(value: int) -> bytes:
    return struct.pack("<H", value)


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def write(name: str, data: bytes) -> str:
    path = os.path.join(OUT, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


# ---------------------------------------------------------------------------
# WebAssembly
# ---------------------------------------------------------------------------


def wasm_module() -> bytes:
    type_section = bytes([0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F])
    func_section = bytes([0x01, 0x00])
    export_name = b"add"
    export_section = bytes([0x01, len(export_name)]) + export_name + bytes([0x00, 0x00])
    body = bytes([0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B])
    code_section = bytes([0x01, len(body)]) + body
    module = b"\x00asm" + u32(1)
    for section_id, payload in ((1, type_section), (3, func_section), (7, export_section), (10, code_section)):
        module += bytes([section_id]) + bytes([len(payload)]) + payload
    return module


# ---------------------------------------------------------------------------
# ELF (x86-64, one PT_LOAD and three sections)
# ---------------------------------------------------------------------------


def elf_image() -> bytes:
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text = bytes([0x55, 0x48, 0x89, 0xE5, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x5D, 0xC3])
    ehsize = 64
    phoff = ehsize
    phentsize = 56
    phnum = 1
    text_offset = phoff + phentsize * phnum
    shstrtab_offset = text_offset + len(text)
    shoff = shstrtab_offset + len(shstrtab)
    shentsize = 64
    shnum = 3
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    struct.pack_into("<HHI", header, 16, 2, 62, 1)
    struct.pack_into("<QQQ", header, 24, 0x401000, phoff, shoff)
    struct.pack_into("<IHHHHHH", header, 48, 0, ehsize, phentsize, phnum, shentsize, shnum, 2)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, text_offset + len(text), text_offset + len(text), 0x1000)
    sections = bytearray()
    sections += struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sections += struct.pack("<IIQQQQIIQQ", 1, 1, 0x6, 0x401000, text_offset, len(text), 0, 0, 16, 0)
    sections += struct.pack("<IIQQQQIIQQ", 7, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0)
    return bytes(header) + phdr + text + shstrtab + bytes(sections)


# ---------------------------------------------------------------------------
# Mach-O (x86-64, one segment, LC_MAIN)
# ---------------------------------------------------------------------------


def macho_image() -> bytes:
    commands = bytearray()
    segment = bytearray()
    segment += struct.pack("<II", 0x19, 72 + 80)
    segment += b"__TEXT".ljust(16, b"\x00")
    segment += struct.pack("<QQQQiiII", 0x100000000, 0x1000, 0, 0, 7, 5, 1, 0)
    section = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", 0x100000F60, 11, 0xF60, 4, 0, 0, 0x80000400, 0, 0, 0)
    segment += section
    commands += segment
    commands += struct.pack("<IIQQ", 0x28, 24, 0x100000F60, 0)
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 2, len(commands), 0x00200085, 0)
    return header + bytes(commands)


# ---------------------------------------------------------------------------
# Java class (one class, two methods)
# ---------------------------------------------------------------------------


class ConstantPoolBuilder:
    def __init__(self) -> None:
        self.entries: list[bytes] = []
        self.index: dict[str, int] = {}

    def utf8(self, text: str) -> int:
        key = "u:" + text
        if key in self.index:
            return self.index[key]
        raw = text.encode("utf-8")
        self.entries.append(b"\x01" + struct.pack(">H", len(raw)) + raw)
        self.index[key] = len(self.entries)
        return self.index[key]

    def cls(self, name: str) -> int:
        key = "c:" + name
        if key in self.index:
            return self.index[key]
        name_index = self.utf8(name)
        self.entries.append(b"\x07" + struct.pack(">H", name_index))
        self.index[key] = len(self.entries)
        return self.index[key]

    def ref(self, kind: int, owner: str, name: str, descriptor: str) -> int:
        key = f"r:{kind}:{owner}:{name}:{descriptor}"
        if key in self.index:
            return self.index[key]
        owner_index = self.cls(owner)
        name_index = self.utf8(name)
        descriptor_index = self.utf8(descriptor)
        self.entries.append(b"\x0c" + struct.pack(">HH", name_index, descriptor_index))
        name_and_type = len(self.entries)
        self.entries.append(bytes([kind]) + struct.pack(">HH", owner_index, name_and_type))
        self.index[key] = len(self.entries)
        return self.index[key]

    def to_bytes(self) -> bytes:
        return struct.pack(">H", len(self.entries) + 1) + b"".join(self.entries)


def java_class() -> bytes:
    pool = ConstantPoolBuilder()
    this_class = pool.cls("demo/Hello")
    super_class = pool.cls("java/lang/Object")
    init_ref = pool.ref(10, "java/lang/Object", "<init>", "()V")
    code_name = pool.utf8("Code")
    source_name = pool.utf8("SourceFile")
    source_value = pool.utf8("Hello.java")
    name_index = pool.utf8("add")

    init_code = bytes([0x2A, 0xB7, 0x00, init_ref & 0xFF, 0xB1])
    add_code = bytes([0x1A, 0x1B, 0x60, 0xAC])

    def method(access: int, name: int, descriptor: int, code: bytes, stack: int, locals: int) -> bytes:
        attribute = (
            struct.pack(">HIHHI", code_name, 12 + len(code), stack, locals, len(code))
            + code
            + struct.pack(">HH", 0, 0)
        )
        return struct.pack(">HHHH", access, name, descriptor, 1) + attribute

    methods = b""
    methods += method(0x0001, pool.utf8("<init>"), pool.utf8("()V"), init_code, 1, 1)
    methods += method(0x0009, name_index, pool.utf8("(II)I"), add_code, 2, 2)

    source_attribute = struct.pack(">HIH", source_name, 2, source_value)
    body = b""
    body += struct.pack(">HHH", 0x0021, this_class, super_class)
    body += struct.pack(">H", 0)
    body += struct.pack(">H", 0)
    body += struct.pack(">H", 2) + methods
    body += struct.pack(">H", 1) + source_attribute
    return struct.pack(">IHH", 0xCAFEBABE, 0, 52) + pool.to_bytes() + body


# ---------------------------------------------------------------------------
# DEX (one class, one static method)
# ---------------------------------------------------------------------------


def dex_file() -> bytes:
    strings = ["Ldemo/Hello;", "Ljava/lang/Object;", "I", "V", "add", "III", "demo/Hello.java"]
    string_ids_offset = 0x70
    type_ids_offset = string_ids_offset + 4 * len(strings)
    proto_ids_offset = type_ids_offset + 4 * 4
    method_ids_offset = proto_ids_offset + 12
    class_defs_offset = method_ids_offset + 8
    data_start = class_defs_offset + 32

    string_data = bytearray()
    string_offsets = []
    for text in strings:
        string_offsets.append(data_start + len(string_data))
        raw = text.encode("utf-8")
        string_data += bytes([len(text)]) + raw + b"\x00"
    while len(string_data) % 4:
        string_data += b"\x00"

    type_list_offset = data_start + len(string_data)
    type_list = u32(2) + u16(2) + u16(2)  # two int parameters
    while len(type_list) % 4:
        type_list += b"\x00"

    code_offset = type_list_offset + len(type_list)
    insns = [0x0090, 0x0201, 0x000F]  # add-int v0, p0, p1 ; return v0
    code_item = (
        u16(3)
        + u16(2)
        + u16(0)
        + u16(0)
        + u32(0)
        + u32(len(insns))
        + b"".join(u16(item) for item in insns)
    )

    class_data_offset = code_offset + len(code_item)
    class_data = bytes([0, 0, 1, 0, 0, 0x09, 0])  # 1 direct method, idx diff 0, public|static, code at delta
    # Replace the code offset with a uleb128 delta from the class_data position.
    class_data = bytes([0, 0, 1, 0, 0, 0x09]) + uleb(code_offset)

    header_size = 0x70
    file_size = class_data_offset + len(class_data)
    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, header_size)
    struct.pack_into("<I", header, 40, 0x12345678)
    struct.pack_into("<II", header, 44, 0, 0)
    struct.pack_into("<I", header, 52, 0)
    struct.pack_into("<II", header, 56, len(strings), string_ids_offset)
    struct.pack_into("<II", header, 64, 4, type_ids_offset)
    struct.pack_into("<II", header, 72, 1, proto_ids_offset)
    struct.pack_into("<II", header, 80, 0, 0)
    struct.pack_into("<II", header, 88, 1, method_ids_offset)
    struct.pack_into("<II", header, 96, 1, class_defs_offset)
    struct.pack_into("<II", header, 104, file_size - data_start, data_start)

    string_ids = b"".join(u32(offset) for offset in string_offsets)
    type_ids = b"".join(u32(index) for index in (0, 1, 2, 3))
    proto_ids = u32(5) + u32(2) + u32(type_list_offset)
    method_ids = u16(0) + u16(0) + u32(4)
    class_def = u32(0) + u32(0x0001) + u32(1) + u32(0) + u32(6) + u32(0) + u32(class_data_offset) + u32(0)

    payload = (
        bytes(header)
        + string_ids
        + type_ids
        + proto_ids
        + method_ids
        + class_def
        + bytes(string_data)
        + type_list
        + code_item
        + class_data
    )
    assert len(payload) == file_size, (len(payload), file_size)
    signature = __import__("hashlib").sha1(payload[32:]).digest()
    checksum = zlib.adler32(signature + payload[32:]) & 0xFFFFFFFF
    result = bytearray(payload)
    result[12:32] = signature
    struct.pack_into("<I", result, 8, checksum)
    return bytes(result)


def uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


# ---------------------------------------------------------------------------
# Android binary XML
# ---------------------------------------------------------------------------


def axml_manifest() -> bytes:
    strings = [
        "versionCode",
        "name",
        "exported",
        "package",
        "com.demo.offline",
        "manifest",
        "application",
        "activity",
        ".MainActivity",
        "1",
        "true",
        "android",
        "http://schemas.android.com/apk/res/android",
    ]

    data = bytearray()
    offsets = []
    for text in strings:
        offsets.append(len(data))
        raw = text.encode("utf-8")
        # UTF-8 AXML strings carry the UTF-16 length, then the UTF-8 byte length.
        data += bytes([len(text), len(raw)]) + raw + b"\x00"
    while len(data) % 4:
        data += b"\x00"

    pool_header_size = 28
    strings_start = pool_header_size + 4 * len(strings)
    pool_size = strings_start + len(data)
    pool = bytearray()
    pool += struct.pack("<HHI", 0x0001, pool_header_size, pool_size)
    pool += struct.pack("<IIIII", len(strings), 0, 0x100, strings_start, 0)
    for offset in offsets:
        pool += struct.pack("<I", offset)
    pool += data

    resource_map = struct.pack("<HHI", 0x0180, 8, 8 + 4 * 3) + struct.pack("<III", 0x0101021B, 0x01010003, 0x01010010)

    def start_namespace(prefix: int, uri: int) -> bytes:
        return struct.pack("<HHIIIII", 0x0100, 16, 24, 1, 0xFFFFFFFF, prefix, uri)

    def end_namespace(prefix: int, uri: int) -> bytes:
        return struct.pack("<HHIIIII", 0x0101, 16, 24, 1, 0xFFFFFFFF, prefix, uri)

    def start_element(name: int, attributes: list[tuple[int, int, int, int, int]]) -> bytes:
        size = 36 + 20 * len(attributes)
        out = bytearray(
            struct.pack(
                "<HHIIIIIHHHHHH",
                0x0102,
                16,
                size,
                1,
                0xFFFFFFFF,
                0xFFFFFFFF,
                name,
                20,
                20,
                len(attributes),
                0,
                0,
                0,
            )
        )
        for key, raw_value, value_type, value, flags in attributes:
            out += struct.pack(
                "<IIIHBBI",
                flags & 0xFFFFFFFF,
                key,
                raw_value & 0xFFFFFFFF,
                8,
                0,
                value_type,
                value & 0xFFFFFFFF,
            )
        return bytes(out)

    def end_element(name: int) -> bytes:
        return struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, name)

    body = bytearray()
    android = 12
    body += start_namespace(11, android)
    body += start_element(5, [(3, 4, 0x03, 4, -1), (0, 9, 0x10, 1, android)])
    body += start_element(6, [(1, 3, 0x03, 3, android), (2, 10, 0x12, -1, android)])
    body += start_element(7, [(1, 8, 0x03, 8, android), (2, 10, 0x12, -1, android)])
    body += end_element(7)
    body += end_element(6)
    body += end_element(5)
    body += end_namespace(11, android)

    total = 8 + len(pool) + len(resource_map) + len(body)
    header = struct.pack("<HHI", 0x0003, 8, total)
    return header + bytes(pool) + resource_map + bytes(body)


# ---------------------------------------------------------------------------
# ASAR / JAR / ZIP / SQLite / JS
# ---------------------------------------------------------------------------


def asar_archive() -> bytes:
    files = {
        "package.json": json.dumps({"name": "demo-app", "main": "main.js", "version": "1.0.0"}).encode(),
        "main.js": (
            b'const {app,BrowserWindow}=require("electron");'
            b"const path=require('path');"
            b"function createWindow(){const w=new BrowserWindow({width:800,webPreferences:{nodeIntegration:true}});"
            b'w.loadURL("https://example.com/demo?x=1");}'
            b"app.whenReady().then(createWindow);"
        ),
        "renderer.js": b'const x=1;function boot(){console.log("boot",x);}boot();',
    }
    tree = {"files": {}}
    payload = bytearray()
    for name, content in files.items():
        tree["files"][name] = {"size": len(content), "offset": str(len(payload))}
        payload += content
    header = json.dumps(tree).encode()
    return u32(len(header)) + u32(len(payload)) + header + bytes(payload)


def jar_archive() -> bytes:
    buffer = __import__("io").BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nMain-Class: demo.Hello\r\n\r\n")
        archive.writestr("demo/Hello.class", java_class())
        archive.writestr("demo/config.properties", "mode=offline\nengine=builtin\n")
    return buffer.getvalue()


def apk_archive() -> bytes:
    buffer = __import__("io").BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", axml_manifest())
        archive.writestr("classes.dex", dex_file())
        archive.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 60)
        archive.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF" + b"\x00" * 60)
        archive.writestr("META-INF/CERT.RSA", b"\x30\x82" + b"\x00" * 32)
    return buffer.getvalue()


def sqlite_database(path: str) -> None:
    for suffix in ("", "-wal", "-shm"):
        candidate = path + suffix
        if os.path.exists(candidate):
            os.remove(candidate)
    connection = sqlite3.connect(path)
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT)")
    cursor.execute("CREATE INDEX notes_title ON notes(title)")
    cursor.execute("INSERT INTO notes (title, body) VALUES ('first', 'offline fixture')")
    cursor.execute("INSERT INTO notes (title, body) VALUES ('second', 'no downloads')")
    connection.commit()
    connection.close()


def javascript_bundle() -> bytes:
    return (
        b'const fs=require("fs");const https=require("https");'
        b'function load(p){return fs.readFileSync(p,"utf8");}'
        b'class Loader{constructor(root){this.root=root;}}'
        b'const endpoint="https://api.example.com/v1/items?limit=50";'
        b"module.exports={load,Loader,endpoint};\n"
        b"//# sourceMappingURL=data:application/json;base64,"
        + __import__("base64").b64encode(
            json.dumps({"version": 3, "sources": ["src/loader.ts"], "names": [], "mappings": "AAAA"}).encode()
        )
    )


def javascript_app(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    files = {
        "package.json": json.dumps({"name": "fixture-app", "version": "0.1.0", "main": "main.js"}, indent=2),
        "main.js": (
            "const {app, BrowserWindow, ipcMain} = require('electron');\n"
            "const path = require('path');\n\n"
            "function createWindow() {\n"
            "  const win = new BrowserWindow({width: 1024, webPreferences: {preload: path.join(__dirname, 'preload.js')}});\n"
            "  win.loadFile('index.html');\n"
            "}\n\n"
            "ipcMain.handle('ping', () => 'pong');\n"
            "app.whenReady().then(createWindow);\n"
        ),
        "preload.js": (
            "const {contextBridge, ipcRenderer} = require('electron');\n"
            "contextBridge.exposeInMainWorld('api', {ping: () => ipcRenderer.invoke('ping')});\n"
        ),
        "bundle.min.js": (
            '!function(){var a=require("fs"),b="https://cdn.example.com/app.bundle.js";'
            'function c(d){return a.readFileSync(d,"utf8")}window.boot=function(){return c(b)}}();'
        ),
        "index.html": "<!doctype html><title>fixture</title><script src=\"bundle.min.js\"></script>\n",
    }
    for name, content in files.items():
        with open(os.path.join(path, name), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    write("sample_module.wasm", wasm_module())
    write("sample_image.elf", elf_image())
    write("sample_image.macho", macho_image())
    write("Sample.class", java_class())
    write("sample.dex", dex_file())
    write("AndroidManifest.bin", axml_manifest())
    write("sample.asar", asar_archive())
    write("sample.jar", jar_archive())
    write("sample.apk", apk_archive())
    write("sample.js", javascript_bundle())
    write("notes.txt", b"REA offline fixture: this text file is inspected, not decompiled.\n")
    write("blob.bin", bytes(range(256)) * 4)
    sqlite_database(os.path.join(OUT, "sample.db"))
    javascript_app(os.path.join(OUT, "jsapp"))
    print(f"fixtures written to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
