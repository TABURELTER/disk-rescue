#!/usr/bin/env python3
"""Build offline Windows release artifacts using only Python's standard library.

Run from any directory: python scripts/build.py
No downloads, local device access, user logs or machine-specific paths are used.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import zipfile


ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
ZIP_TIME = (2026, 1, 1, 0, 0, 0)
RELEASE_NAME = "DiskRescue-win-x64.zip"
ARCHIVE_PATH = re.compile(
    r"^(tsk|photorec)/[A-Za-z0-9_-][A-Za-z0-9_.-]*(/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*$"
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8-sig").replace("\r\n", "\n")


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def release_zip(files: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, ZIP_TIME)
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return stream.getvalue()


def validate_engines(data: bytes) -> dict[str, str]:
    hashes = {}
    seen = set()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for entry in archive.infolist():
            name = entry.filename
            if not ARCHIVE_PATH.fullmatch(name) or name.lower() in seen:
                raise ValueError(f"Unsafe or duplicate engine archive entry: {name!r}")
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError(f"Symlinks are not allowed in engine archive: {name!r}")
            seen.add(name.lower())
            hashes[name] = digest(archive.read(entry))
    required = {
        "tsk/mmls.exe", "tsk/fsstat.exe", "tsk/fls.exe", "tsk/icat.exe",
        "photorec/photorec_win.exe",
    }
    if not required.issubset(hashes):
        raise ValueError("Engine archive is incomplete: " + ", ".join(sorted(required - hashes.keys())))
    return hashes


def build() -> dict[str, str]:
    required = [
        "assets/engines.zip", "src/Recover-Disk.template.ps1", "src/DiskRescueNative.cs",
        "src/ScanLog.ps1", "src/FilesystemTools.ps1", "src/SessionTools.ps1",
        "START.cmd", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md",
    ]
    for name in required:
        file = ROOT / name
        if not file.is_file() or file.is_symlink():
            raise ValueError(f"Required regular file is missing: {name}")

    version_path = ROOT / "VERSION"
    version = read_text("VERSION").strip() if version_path.is_file() else "2.1.0"
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version):
        raise ValueError("VERSION must contain a semantic version, for example 2.1.0")

    engine = (ROOT / "assets/engines.zip").read_bytes()
    engine_hashes = validate_engines(engine)
    source = read_text("src/Recover-Disk.template.ps1")
    native = read_text("src/DiskRescueNative.cs").rstrip("\n")
    replacements = {
        "__VERSION__": version,
        "__ENGINE_HASH__": digest(engine),
        "__LOG_PARSER__": read_text("src/ScanLog.ps1").rstrip("\n"),
        "__NATIVE_READER__": "$NativeSource = @'\n" + native + "\n'@",
        "__FILESYSTEM_TOOLS__": read_text("src/FilesystemTools.ps1").rstrip("\n"),
        "__SESSION_TOOLS__": read_text("src/SessionTools.ps1").rstrip("\n"),
    }
    for marker, content in replacements.items():
        if source.count(marker) != 1:
            raise ValueError(f"Expected exactly one source marker: {marker}")
        source = source.replace(marker, content)
    if "LogBase64" in source or "__LOG__" in source:
        raise ValueError("Embedded personal scan logs are prohibited")
    if re.search(r"__(?:VERSION|ENGINE_HASH|LOG_PARSER|NATIVE_READER|FILESYSTEM_TOOLS|SESSION_TOOLS)__", source):
        raise ValueError("Unexpanded source markers")
    encoded = base64.b64encode(engine).decode("ascii")
    payload = "\n".join(encoded[i:i + 120] for i in range(0, len(encoded), 120))
    source += "\n<# DISK_RESCUE_ENGINE_BASE64\n" + payload + "\n#>\n"
    # A BOM is intentional: Windows PowerShell 5.1 otherwise treats UTF-8 as ANSI.
    script = source.encode("utf-8-sig")
    inputs = {name: digest((ROOT / name).read_bytes()) for name in sorted(required)}
    build_info = {
        "version": version,
        "platform": "windows-x64",
        "engines": {"photorec": "7.2", "sleuthkit": "4.15.0"},
        "embedded_engines_sha256": digest(engine),
        "script_sha256": digest(script),
        "inputs_sha256": inputs,
        "engine_files_sha256": engine_hashes,
        "scan_logs_bundled": False,
        "source_urls": [
            "https://www.cgsecurity.org/testdisk-7.2.win64.zip",
            "https://www.cgsecurity.org/testdisk-7.2.tar.bz2",
            "https://github.com/sleuthkit/sleuthkit/releases/tag/sleuthkit-4.15.0",
        ],
    }
    patches = ROOT / "tools/manifest-patches/utf8-manifest-patches.json"
    if patches.is_file():
        build_info["tsk_unicode_manifest_patches"] = json.loads(patches.read_text(encoding="utf-8-sig"))
    info = json_bytes(build_info)
    files = {
        "Recover-Disk.ps1": script,
        "START.cmd": (ROOT / "START.cmd").read_bytes(),
        "README.md": (ROOT / "README.md").read_bytes(),
        "LICENSE": (ROOT / "LICENSE").read_bytes(),
        "THIRD_PARTY_NOTICES.md": (ROOT / "THIRD_PARTY_NOTICES.md").read_bytes(),
        "BUILD-INFO.json": info,
    }
    archive = release_zip(files)
    artifacts = {
        "Recover-Disk.ps1": script,
        RELEASE_NAME: archive,
        "BUILD-INFO.json": info,
    }
    sums = {name: digest(data) for name, data in sorted(artifacts.items())}
    artifacts["SHA256SUMS.json"] = json_bytes(sums)
    artifacts["SHA256SUMS.txt"] = "".join(f"{value}  {name}\n" for name, value in sums.items()).encode("ascii")
    DIST.mkdir(exist_ok=True)
    for name, data in artifacts.items():
        (DIST / name).write_bytes(data)
    with zipfile.ZipFile(DIST / RELEASE_NAME) as archive_check:
        if archive_check.testzip() is not None:
            raise ValueError("Generated release archive failed its CRC test")
        if digest(archive_check.read("Recover-Disk.ps1")) != sums["Recover-Disk.ps1"]:
            raise ValueError("Release script hash mismatch")
    return sums


if __name__ == "__main__":
    try:
        print(json.dumps({"version": "built", "sha256": build()}, indent=2))
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"Build failed: {error}", file=sys.stderr)
        raise SystemExit(1)
