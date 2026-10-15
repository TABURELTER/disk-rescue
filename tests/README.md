# Verification

Run from the repository root with Python 3.11 or later:

```powershell
python tests/check_public.py
python scripts/build.py
python tests/check_public.py --dist dist
python tests/smoke.py --report dist/TEST-RESULTS.json
```

The application smoke checks require 64-bit Windows 10 1903 or later and Windows
PowerShell 5.1 (the default) or PowerShell 7 (`--shell pwsh.exe`). They generate
temporary synthetic FAT16, FAT32 and exFAT filesystems. Expected names, directory
structure, zero-length files and fragmented payloads are checked byte for byte.
The original image hashes must remain unchanged. Additional checks exercise deep
scan without an MBR, malformed-name isolation, refusal to reuse an existing output
directory, log parsing as data, and exiting the terminal menu.

These checks never open physical disks, mount filesystems or modify real user
data. They verify these specific cases; they do not prove that every damaged
filesystem or physical device can be recovered. NTFS, hardware failures and raw
device access are not covered by this portable synthetic suite.

Fixture layout references: [Microsoft FAT specification](https://download.microsoft.com/download/1/6/1/161BA512-40E2-4CC9-843A-923143F3456C/fatgen103.doc)
and [Microsoft exFAT specification](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification).
