#!/usr/bin/env python3
"""Independently verify a finished JZ08 engineering ZIP, without device I/O.

This is a *second* verification pass: it reads bytes back from the ZIP, not
the paths used by the packager. Passing does not establish bootability.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

REQUIRED = {
    "images/boot.img",
    "images/system.img",
    "images/kernel-from-boot.bin",
    "images/initramfs-kernel.bin",
    "images/initrd.cpio",
    "images/RAM_ONLY_INITRAMFS_CANDIDATE.img",
    "images/msm8916-generic-jz08-3000-nkv.dtb",
    "audit/JZ08_PACKAGES.manifest",
    "audit/JZ08_BUILD_AUDIT.json",
    "audit/JZ08_ROOTFS_RUNTIME_AUDIT.json",
    "audit/JZ08_ROOTFS_CONTENTS_STATUS.txt",
    "audit/JZ08_INITRAMFS_CPIO_AUDIT.json",
    "README_FIRST_RU.txt",
    "MANIFEST.json",
    "SHA256SUMS",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def require(condition, reason):
    if not condition:
        raise ValueError("JZ08 ZIP VERIFICATION FAILED: " + reason)


def verify(archive_path: Path, checksum_path: Path, report_path: Path):
    require(archive_path.is_file(), "archive absent")
    require(checksum_path.is_file(), "external SHA256 absent")
    require(report_path.is_file(), "external verification report absent")
    outer = hashlib.sha256()
    with archive_path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            outer.update(block)
    digest = outer.hexdigest()
    expected_external = f"{digest}  {archive_path.name}"
    require(checksum_path.read_text().strip() == expected_external,
            "external SHA256SUMS does not match archive")
    report = json.loads(report_path.read_text())
    require(report.get("status") == "ARCHIVE_VERIFIED_NOT_FLASHABLE"
            and report.get("flash_allowed") is False
            and report.get("hardware_tested") is False
            and report.get("full_device_boot_ready") is False
            and report.get("sha256") == digest
            and report.get("archive") == archive_path.name,
            "external verification report inconsistent")

    with zipfile.ZipFile(archive_path, "r") as zf:
        infos = zf.infolist()
        names = [entry.filename for entry in infos]
        require(len(names) == len(set(names)), "duplicate ZIP entries")
        require(set(names) == REQUIRED, "required ZIP member missing or unexpected")
        require(all(not entry.is_dir() and not entry.flag_bits & 1
                    for entry in infos), "directory or encrypted ZIP entry")
        require(zf.testzip() is None, "ZIP CRC failed")
        manifest = json.loads(zf.read("MANIFEST.json"))
        require(manifest.get("board") == "JZ08-3000-NKV 1.0"
                and manifest.get("status") == "NOT_FLASHABLE"
                and manifest.get("flash_allowed") is False
                and manifest.get("hardware_tested") is False
                and manifest.get("full_device_boot_ready") is False
                and isinstance(manifest.get("boot_blockers"), list)
                and manifest["boot_blockers"],
                "unsafe or incomplete embedded manifest")
        entries = manifest.get("files")
        require(isinstance(entries, dict)
                and set(entries) == REQUIRED - {"MANIFEST.json", "SHA256SUMS", "README_FIRST_RU.txt"},
                "embedded manifest missing binary/audit entries")

        lines = zf.read("SHA256SUMS").decode("ascii").splitlines()
        checksums = {}
        for line in lines:
            require(len(line) >= 67 and line[64:66] == "  ",
                    "invalid SHA256SUMS line")
            hexdigest, name = line[:64], line[66:]
            require(bool(HEX64.fullmatch(hexdigest))
                    and name in REQUIRED and name != "SHA256SUMS"
                    and name not in checksums, "invalid or duplicate checksum entry")
            checksums[name] = hexdigest
        require(set(checksums) == REQUIRED - {"SHA256SUMS"},
                "SHA256SUMS does not cover every member")
        for name in sorted(REQUIRED - {"SHA256SUMS"}):
            sha = hashlib.sha256()
            length = 0
            with zf.open(name) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    sha.update(block)
                    length += len(block)
            require(length > 0, "empty ZIP member: " + name)
            require(sha.hexdigest() == checksums[name],
                    "ZIP content differs from SHA256SUMS: " + name)
            if name in entries:
                record = entries[name]
                require(isinstance(record, dict)
                        and record.get("sha256") == sha.hexdigest()
                        and record.get("bytes") == length,
                        "manifest hash/length mismatch: " + name)
        require(report.get("members") == len(names),
                "external verification member count mismatch")
    return {"status": "INDEPENDENT_ZIP_CONTENT_VERIFIED_NOT_BOOT_PROOF",
            "archive": archive_path.name, "sha256": digest,
            "members": len(REQUIRED), "flash_allowed": False,
            "hardware_tested": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--sha256", required=True, type=Path)
    parser.add_argument("--verification", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.archive, args.sha256, args.verification), indent=2))


if __name__ == "__main__":
    main()
