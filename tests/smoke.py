"""Exercise the built application using synthetic image files only.

No physical disk handle, mount, format, or repair operation is used. Fixtures are
generated independently of the exporter; expected paths and bytes are known.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

import fixtures


def sha(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--script", type=Path, default=Path("dist/Recover-Disk.ps1"))
    parser.add_argument("--shell", default="powershell.exe")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    script = args.script.resolve(strict=True)
    results = []

    with tempfile.TemporaryDirectory(prefix="disk-rescue-tests-") as temporary:
        root = Path(temporary)

        def run(name: str, parameters: list[str], *, success: bool = True,
                input_text: str | None = None) -> subprocess.CompletedProcess:
            command = [args.shell, "-NoProfile", "-ExecutionPolicy", "Bypass",
                       "-File", str(script), *parameters]
            started = time.monotonic()
            process = subprocess.run(command, input=input_text, capture_output=True,
                                     text=True, encoding="utf-8", errors="replace",
                                     timeout=240)
            expected = process.returncode == 0 if success else process.returncode != 0
            if not expected:
                raise AssertionError(f"{name}: exit {process.returncode}\n"
                                     f"{process.stdout}\n{process.stderr}")
            results.append({"case": name, "passed": True,
                            "seconds": round(time.monotonic() - started, 3)})
            print(f"PASS {name}", flush=True)
            return process

        def recover(name: str, image: bytes, *, offset: int = 0,
                    payloads: dict[str, bytes] | None = None,
                    preserve_paths: bool = True) -> tuple[Path, Path]:
            image_path = root / (name + ".img")
            image_path.write_bytes(image)
            original = sha(image_path)
            destination = root / (name + "-output")
            parameters = ["-Action", "Recover", "-ImagePath", str(image_path),
                          "-OutputDirectory", str(destination), "-Offset", str(offset)]
            run(name, parameters)
            assert sha(image_path) == original, f"{name}: input image changed"
            exports = list(destination.glob("recovered-tree-*/files"))
            assert len(exports) == 1, f"{name}: missing or ambiguous export"
            files_root = exports[0]
            expected = payloads if payloads is not None else fixtures.FILES
            if preserve_paths:
                for relative, payload in expected.items():
                    recovered = files_root / relative
                    assert recovered.is_file(), f"{name}: missing {relative}"
                    assert recovered.read_bytes() == payload, f"{name}: corrupt {relative}"
            else:
                # Malformed names must be renamed into ordinary, distinct files.
                # Compare a multiset so duplicate content cannot hide data loss.
                actual = sorted(sha(path) for path in files_root.rglob("*") if path.is_file())
                expected_hashes = sorted(hashlib.sha256(data).hexdigest()
                                         for data in expected.values())
                assert actual == expected_hashes, f"{name}: lost or duplicated payload"
                assert not (root / "escape.txt").exists(), "Traversal escaped output"
                assert not (destination / "escape.txt").exists(), "Traversal escaped files root"
                for recovered in files_root.rglob("*"):
                    assert recovered.resolve().is_relative_to(files_root.resolve())
                    assert not recovered.is_symlink(), "Export created a link"
            return image_path, destination

        recover("fat16-unicode-fragmented", fixtures.make_fat(16))
        fat32 = fixtures.mbr_wrapper(fixtures.make_fat(32), 0x0C)
        image, output = recover("fat32-mbr-nested", fat32, offset=2048)
        before = {str(path.relative_to(output)): sha(path)
                  for path in output.rglob("*") if path.is_file()}
        run("existing-output-refused", ["-Action", "Recover", "-ImagePath", str(image),
                                       "-OutputDirectory", str(output), "-Offset", "2048"],
            success=False)
        after = {str(path.relative_to(output)): sha(path)
                 for path in output.rglob("*") if path.is_file()}
        assert before == after, "Existing output files changed after refusal"

        exfat = fixtures.make_exfat()
        recover("exfat-unicode-fragmented", exfat)
        damaged = fixtures.mbr_wrapper(exfat, 0x07)
        damaged[:512] = bytes(512)
        damaged_path = root / "damaged-partition-table.img"
        damaged_path.write_bytes(damaged)
        original = sha(damaged_path)
        scan_output = root / "deep-scan-output"
        run("deep-scan-without-mbr", ["-Action", "Scan", "-DeepScan", "-ImagePath",
                                     str(damaged_path), "-OutputDirectory", str(scan_output)])
        volumes = json.loads((scan_output / "volumes.json").read_text(encoding="utf-8-sig"))
        if isinstance(volumes, dict):
            volumes = [volumes]
        assert any(item["Offset"] == 2048 and item["Type"] == "exFAT" for item in volumes)
        assert sha(damaged_path) == original, "Deep scan changed image"

        adversarial, additional = fixtures.make_adversarial_fat16()
        recover("malformed-name-isolation", adversarial,
                payloads=fixtures.FILES | additional, preserve_paths=False)

        # This is deliberately synthetic input, including text that would be an
        # instruction if evaluated. Analyze must parse it strictly as log data.
        log = root / "synthetic-scan.txt"
        sentinel = root / "injection-was-executed"
        synthetic_text = (
            "[devscan]\n"
            "scan_dev=1:0:11:-1:0x1:512:32768:"
            "\\\\?\\usbstor#disk&ven_fixture&prod_test&rev_1#FIXTURE01&0#{00000000}\n"
            'scan_range="0x0-0x1000000"\n'
            '[rawscan]\nft[jpg.]=!"1;synthetic"\n'
            f"$null = New-Item -ItemType File -LiteralPath '{sentinel}'\n"
        )
        log.write_text(synthetic_text, encoding="utf-8")
        run("analyze-log-as-data", ["-Action", "Analyze", "-LogPath", str(log)])
        assert not sentinel.exists(), "Log text was evaluated"
        run("analyze-requires-log", ["-Action", "Analyze"], success=False)
        run("menu-exit", [], input_text="0\n")

    report = {"passed": True, "physical_devices_opened": False, "cases": results}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"All {len(results)} image-only application checks passed.")


if __name__ == "__main__":
    main()
