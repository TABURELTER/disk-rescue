#!/usr/bin/env python3
"""Copy four official TSK EXEs and add a UTF-8 activeCodePage manifest.

Windows only. Usage: python tools/manifest-patches/apply.py INPUT_BIN NEW_OUTPUT
Input binaries are read, never changed. Output files must not already exist.
Hashes are checked against the recorded official and patched executable hashes.
"""

from pathlib import Path
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import shutil
import xml.etree.ElementTree as ET


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_bin", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Windows resource update APIs are required")
    inputs = args.input_bin.resolve(strict=True)
    output = args.output.resolve()
    if output == inputs or output.exists():
        parser.error("Choose a NEW output directory distinct from the input directory")
    records = json.loads((Path(__file__).parent / "utf8-manifest-patches.json").read_text(encoding="utf-8"))
    for record in records:
        original = inputs / record["name"]
        if not original.is_file() or original.is_symlink() or sha256(original) != record["original_sha256"]:
            raise ValueError("Original executable hash mismatch: " + record["name"])

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LoadLibraryExW.argtypes = (wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD)
    kernel.LoadLibraryExW.restype = wintypes.HMODULE
    kernel.FindResourceW.argtypes = (wintypes.HMODULE, wintypes.LPCWSTR, wintypes.LPCWSTR)
    kernel.FindResourceW.restype = wintypes.HANDLE
    kernel.LoadResource.argtypes = (wintypes.HMODULE, wintypes.HANDLE)
    kernel.LoadResource.restype = wintypes.HANDLE
    kernel.LockResource.argtypes = (wintypes.HANDLE,)
    kernel.LockResource.restype = wintypes.LPVOID
    kernel.SizeofResource.argtypes = (wintypes.HMODULE, wintypes.HANDLE)
    kernel.SizeofResource.restype = wintypes.DWORD
    kernel.FreeLibrary.argtypes = (wintypes.HMODULE,)
    kernel.BeginUpdateResourceW.argtypes = (wintypes.LPCWSTR, wintypes.BOOL)
    kernel.BeginUpdateResourceW.restype = wintypes.HANDLE
    kernel.UpdateResourceW.argtypes = (wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.WORD, wintypes.LPVOID, wintypes.DWORD)
    kernel.UpdateResourceW.restype = wintypes.BOOL
    kernel.EndUpdateResourceW.argtypes = (wintypes.HANDLE, wintypes.BOOL)
    kernel.EndUpdateResourceW.restype = wintypes.BOOL
    resource_type = ctypes.cast(ctypes.c_void_p(24), wintypes.LPCWSTR)
    resource_name = ctypes.cast(ctypes.c_void_p(1), wintypes.LPCWSTR)
    addition = '<application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings><activeCodePage xmlns="http://schemas.microsoft.com/SMI/2019/WindowsSettings">UTF-8</activeCodePage></windowsSettings></application>'
    output.mkdir(parents=True)
    for record in records:
        path = output / record["name"]
        with path.open("xb") as target, (inputs / record["name"]).open("rb") as source:
            shutil.copyfileobj(source, target)
        handle = kernel.LoadLibraryExW(str(path), None, 2)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            resource = kernel.FindResourceW(handle, resource_name, resource_type)
            if not resource:
                raise ctypes.WinError(ctypes.get_last_error())
            length = kernel.SizeofResource(handle, resource)
            blob = kernel.LockResource(kernel.LoadResource(handle, resource))
            manifest = ctypes.string_at(blob, length).decode("utf-8-sig").rstrip("\0")
        finally:
            kernel.FreeLibrary(handle)
        if "activeCodePage" in manifest or "</assembly>" not in manifest:
            raise ValueError("Unexpected original manifest: " + record["name"])
        manifest = manifest.replace("</assembly>", addition + "</assembly>")
        ET.fromstring(manifest)
        encoded = manifest.encode("utf-8")
        update = kernel.BeginUpdateResourceW(str(path), False)
        if not update:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(encoded)
        if not kernel.UpdateResourceW(update, resource_type, resource_name, 1033, buffer, len(encoded)):
            code = ctypes.get_last_error()
            kernel.EndUpdateResourceW(update, True)
            raise ctypes.WinError(code)
        if not kernel.EndUpdateResourceW(update, False):
            raise ctypes.WinError(ctypes.get_last_error())
        if sha256(path) != record["patched_sha256"]:
            raise ValueError("Patched executable hash mismatch: " + record["name"])
        print(record["name"] + ": verified")


if __name__ == "__main__":
    main()
