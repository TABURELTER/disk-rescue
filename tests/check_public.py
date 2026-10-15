"""Reject private scan data/credentials and verify the public release package."""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile


TEXT_SUFFIXES = {
    ".ps1", ".py", ".cs", ".md", ".txt", ".json", ".yml", ".yaml",
    ".cmd", ".bat", ".sh", ".html", ".xml", ".ini", ".cfg", ".toml",
}
# Rules use general shapes, never a real person's username or device serial.
RULES = {
    "absolute Windows profile path": re.compile(r"[a-z]:[\\/]Users[\\/][^\\/\s\"'<>]+", re.I),
    "embedded private scan variable": re.compile(r"\$LogBase64\s*=", re.I),
    "literal USB device serial": re.compile(r"usbstor#[^\r\n]*#[a-z0-9]{12,}&\d+#", re.I),
    "credential token": re.compile(r"(?:gh[pousr]_[a-zA-Z0-9]{30,}|github_pat_[a-zA-Z0-9_]{30,}|AKIA[A-Z0-9]{16})"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
ENGINE_MARKER = "<# DISK_RESCUE_ENGINE_BASE64"
PACKED_RUNTIME = re.compile(r"(?m)^" + re.escape(ENGINE_MARKER)
                            + r"\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n#>")


def inspect_text(label: str, data: bytes, failures: list[str]) -> None:
    text = data.decode("utf-8-sig", errors="replace")
    packed_match = PACKED_RUNTIME.search(text)
    # Inspect runtime archive contents after decoding. Random base64 characters
    # can resemble credential prefixes and are not executable script text.
    searchable = PACKED_RUNTIME.sub("<embedded runtime archive>", text)
    for reason, pattern in RULES.items():
        if pattern.search(searchable):
            # Never echo the sensitive match into CI logs.
            failures.append(f"{label}: {reason}")
    if packed_match:
        encoded = packed_match.group(1)
        try:
            packed = base64.b64decode("".join(encoded.split()), validate=True)
            inspect_zip(label + ":embedded-engine", packed, failures)
        except (ValueError, zipfile.BadZipFile) as error:
            failures.append(f"{label}: invalid embedded runtime ({type(error).__name__})")


def inspect_zip(label: str, data: bytes, failures: list[str], depth: int = 0) -> None:
    if depth > 3:
        failures.append(f"{label}: unexpectedly nested archive")
        return
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if archive.testzip() is not None:
            failures.append(f"{label}: corrupt ZIP member")
        for member in archive.infolist():
            if member.is_dir():
                continue
            path = Path(member.filename)
            if path.is_absolute() or ".." in path.parts:
                failures.append(f"{label}: unsafe ZIP member path")
            # Fixtures are constructed at test time; no disk data belongs in a release.
            if path.suffix.lower() in {".img", ".dd", ".raw", ".partial", ".log"}:
                failures.append(f"{label}:{member.filename}: disk image or runtime log")
            if path.suffix.lower() in TEXT_SUFFIXES:
                inspect_text(label + ":" + member.filename, archive.read(member), failures)
            elif path.suffix.lower() == ".zip":
                inspect_zip(label + ":" + member.filename, archive.read(member), failures, depth + 1)


def check_sources(root: Path, failures: list[str]) -> int:
    count = 0
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part in {".git", "dist", "__pycache__", ".pytest_cache"} for part in relative.parts):
            continue
        if not path.is_file():
            continue
        count += 1
        if path.suffix.lower() in {".img", ".dd", ".raw", ".partial", ".log"}:
            failures.append(f"{relative}: disk image or runtime log committed")
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {"LICENSE", "VERSION", ".gitignore"}:
            inspect_text(str(relative), path.read_bytes(), failures)
        elif path.suffix.lower() == ".zip":
            inspect_zip(str(relative), path.read_bytes(), failures)
    return count


def check_dist(root: Path, dist: Path, failures: list[str]) -> None:
    hashes = json.loads((dist / "SHA256SUMS.json").read_text(encoding="utf-8-sig"))
    assert isinstance(hashes, dict) and hashes, "Empty checksum manifest"
    for name, expected in hashes.items():
        assert Path(name).name == name, "Manifest filename must be a plain basename"
        path = dist / name
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert re.fullmatch(r"[0-9a-f]{64}", expected), f"Invalid hash for {name}"
        assert actual == expected, f"Checksum mismatch: {name}"
    for required in ("Recover-Disk.ps1", "DiskRescue-win-x64.zip", "BUILD-INFO.json"):
        assert required in hashes, f"Missing release checksum: {required}"
    txt = (dist / "SHA256SUMS.txt").read_text(encoding="utf-8-sig")
    for name, expected in hashes.items():
        assert f"{expected}  {name}" in txt, f"Text checksum missing: {name}"
    script = (dist / "Recover-Disk.ps1").read_bytes()
    inspect_text("dist/Recover-Disk.ps1", script, failures)
    assert PACKED_RUNTIME.search(script.decode("utf-8-sig")), "Standalone script lacks embedded runtime"
    inspect_zip("dist/DiskRescue-win-x64.zip", (dist / "DiskRescue-win-x64.zip").read_bytes(), failures)
    with zipfile.ZipFile(dist / "DiskRescue-win-x64.zip") as archive:
        assert archive.read("Recover-Disk.ps1") == script, "ZIP script differs from standalone script"
        assert "START.cmd" in archive.namelist(), "Release launcher missing"
        assert "README.md" in archive.namelist(), "Release instructions missing"
    build = json.loads((dist / "BUILD-INFO.json").read_text(encoding="utf-8-sig"))
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    assert build["version"] == version, "Build version differs from VERSION"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--dist", type=Path, help="Also inspect the built release directory")
    args = parser.parse_args()
    failures: list[str] = []
    count = check_sources(args.root.resolve(strict=True), failures)
    if args.dist:
        check_dist(args.root.resolve(), args.dist.resolve(strict=True), failures)
    if failures:
        raise SystemExit("Public-file checks failed:\n" + "\n".join(sorted(set(failures))))
    print(f"Public-file checks passed ({count} source files; archives and embedded runtime inspected).")


if __name__ == "__main__":
    main()
