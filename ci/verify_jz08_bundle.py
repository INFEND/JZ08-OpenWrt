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





def require_kernel_appended_dtb(kernel_path, expected_dtb):
    """Prove that the *bootable kernel payload* carries this exact JZ08 DTB.

    OpenWrt's pinned msm89xx image recipe is kernel-bin | gzip | append-dtb.
    Merely shipping a separate correct DTB does not prove that the bootloader
    will pass that DTB to Linux. This checks gzip integrity and exact trailer
    bytes; it does NOT prove the bootloader's RAM address or Linux handoff.
    """
    import zlib

    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    uncompressed = 0
    trailer = bytearray()
    with kernel_path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            if decompressor.eof:
                trailer.extend(block)
                continue
            try:
                decoded = decompressor.decompress(block)
            except zlib.error as exc:
                raise ValueError(
                    "JZ08 ZIP VERIFICATION FAILED: corrupt kernel gzip: "
                    + str(exc)) from exc
            uncompressed += len(decoded)
            require(uncompressed <= 256 * 1024 * 1024,
                    "kernel gzip expands beyond offline safety limit")
            if decompressor.eof:
                trailer.extend(decompressor.unused_data)
    require(decompressor.eof and uncompressed > 4096,
            "kernel gzip is incomplete or empty")
    require(bytes(trailer) == expected_dtb,
            "kernel payload does not append the exact published JZ08 DTB")
    return {"gzip_uncompressed_bytes": uncompressed,
            "appended_jz08_dtb_bytes": len(expected_dtb)}



def require_matching_rootfs_audit(actual, claimed):
    """Fail closed if the downloaded rootfs disagrees with its build report."""
    require(actual.get("status") == "OFFLINE_USERSPACE_CHECK_PASS_ONLY"
            and actual.get("flash_allowed") is False
            and actual.get("hardware_tested") is False
            and actual.get("rootfs_executed") is False
            and actual.get("errors") == [],
            "independently extracted rootfs fails runtime checks")
    for field in ("status", "flash_allowed", "hardware_tested",
                  "rootfs_executed", "errors", "required_elf",
                  "required_assets", "observed_paths_not_boot_proof"):
        require(actual.get(field) == claimed.get(field),
                "published runtime audit differs from extracted system.img: " + field)


def verify_actual_rootfs(system_image, claimed_runtime):
    """Re-extract the PUBLISHED system.img, never trusting its audit alone.

    This uses offline userspace tools on an ephemeral GitHub runner; no device
    nodes, eMMC writes, executable payload runs, or network calls are made.
    """
    import shutil
    import subprocess
    import tempfile
    from audit_rootfs_runtime import audit as audit_rootfs

    for command in ("simg2img", "unsquashfs", "sudo"):
        require(shutil.which(command) is not None,
                "independent rootfs audit requires " + command)
    with tempfile.TemporaryDirectory(prefix="jz08-independent-rootfs-") as tmp:
        raw = Path(tmp) / "rootfs.raw"
        extracted = Path(tmp) / "extracted"
        try:
            try:
                subprocess.run(["simg2img", str(system_image), str(raw)],
                               check=True, capture_output=True, timeout=120)
                subprocess.run([
                    "sudo", "-n", "unsquashfs", "-strict-errors",
                    "-no-progress", "-no-xattrs", "-processors", "2",
                    "-dest", str(extracted), str(raw)
                ], check=True, capture_output=True, timeout=180)
            except (OSError, subprocess.CalledProcessError,
                    subprocess.TimeoutExpired) as exc:
                raise ValueError(
                    "JZ08 ZIP VERIFICATION FAILED: independently extracting "
                    "published system.img failed: " + str(exc)) from exc
            actual = audit_rootfs(extracted)
            require_matching_rootfs_audit(actual, claimed_runtime)
        finally:
            # unsquashfs runs as root to preserve special filesystem entries.
            # Only remove the path inside our private, freshly-created temp dir.
            if extracted.exists():
                subprocess.run(["sudo", "-n", "rm", "-rf", "--",
                                str(extracted)], check=True, timeout=60)
    return "INDEPENDENT_PUBLISHED_ROOTFS_CONTENT_VERIFIED_NOT_BOOT_PROOF"


def verify_real_payloads(zf):
    """Independently inspect binary contents, not just self-declared hashes.

    All work is on temporary files extracted from the *downloaded* ZIP.
    Never opens a device or issues a flash/boot command.
    """
    import shutil
    import tempfile

    from audit_initramfs_cpio import audit as audit_cpio
    from check_built_jz08 import (
        MUST_HAVE, android_boot_v0_header_details,
        squashfs_v4_superblock_details,
    )

    payload_names = (
        "images/boot.img",
        "images/system.img",
        "images/kernel-from-boot.bin",
        "images/initramfs-kernel.bin",
        "images/initrd.cpio",
        "images/RAM_ONLY_INITRAMFS_CANDIDATE.img",
        "images/msm8916-generic-jz08-3000-nkv.dtb",
    )
    with tempfile.TemporaryDirectory(prefix="jz08-independent-payload-") as temp:
        paths = {}
        for name in payload_names:
            dest = Path(temp) / name.rsplit("/", 1)[-1]
            with zf.open(name) as source, dest.open("wb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            paths[name] = dest

        boot = paths["images/boot.img"]
        candidate = paths["images/RAM_ONLY_INITRAMFS_CANDIDATE.img"]
        kernel = paths["images/kernel-from-boot.bin"]
        initramfs_kernel = paths["images/initramfs-kernel.bin"]
        boot_header = android_boot_v0_header_details(boot)
        ram_header = android_boot_v0_header_details(candidate)
        require(boot_header["valid"] and boot_header["ramdisk_size"] == 0,
                "invalid or unexpected ordinary Android boot image")
        require(ram_header["valid"] and ram_header["ramdisk_size"] == 0,
                "invalid RAM-only candidate Android boot header")
        require(boot_header["kernel_size"] == kernel.stat().st_size,
                "ordinary boot kernel length mismatch")
        require(ram_header["kernel_size"] == initramfs_kernel.stat().st_size,
                "RAM-only embedded kernel length mismatch")
        require(initramfs_kernel.open("rb").read(2) == bytes.fromhex("1f8b"),
                "RAM-only embedded kernel is not gzip")
        with candidate.open("rb") as stream:
            stream.seek(64)
            cmdline = stream.read(512).split(bytes([0]), 1)[0]
        require(b"rdinit=/init" in cmdline and b"root=" not in cmdline,
                "RAM-only candidate contains unsafe or missing boot arguments")

        def boot_kernel_sha(path, header):
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                stream.seek(header["page_size"])
                remaining = header["kernel_size"]
                while remaining:
                    block = stream.read(min(1024 * 1024, remaining))
                    require(bool(block), "truncated Android boot kernel")
                    digest.update(block)
                    remaining -= len(block)
            return digest.hexdigest()

        def file_sha(path):
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            return digest.hexdigest()

        require(boot_kernel_sha(boot, boot_header) == file_sha(kernel),
                "ordinary boot kernel payload differs from exported kernel")
        require(boot_kernel_sha(candidate, ram_header) == file_sha(initramfs_kernel),
                "RAM-only boot kernel differs from embedded initramfs kernel")

        dtb = paths["images/msm8916-generic-jz08-3000-nkv.dtb"]
        dtb_data = dtb.read_bytes()
        require(len(dtb_data) >= 1024 and dtb_data[:4] == bytes.fromhex("d00dfeed")
                and 40 <= int.from_bytes(dtb_data[4:8], "big") <= len(dtb_data)
                and b"xarkon,jz08-3000-nkv" + bytes([0]) in dtb_data,
                "compiled DTB does not identify JZ08")
        # A separately published DTB is insufficient for this image recipe.
        # Verify the actual gzip payloads carry the same JZ08 DTB bytes.
        require_kernel_appended_dtb(kernel, dtb_data)
        require_kernel_appended_dtb(initramfs_kernel, dtb_data)
        system = paths["images/system.img"]
        require(squashfs_v4_superblock_details(system)["valid"] is True,
                "system.img sparse/SquashFS structure invalid")

        cpio = paths["images/initrd.cpio"]
        actual_cpio = audit_cpio(cpio)
        claimed_cpio = json.loads(zf.read("audit/JZ08_INITRAMFS_CPIO_AUDIT.json"))
        for field in ("status", "archive_sha256", "archive_bytes", "entries",
                      "required_paths", "flash_allowed", "hardware_tested",
                      "linux_init_executed"):
            require(claimed_cpio.get(field) == actual_cpio[field],
                    "embedded initramfs audit differs from actual CPIO: " + field)

        packages = {
            row.split(" - ", 1)[0]
            for row in zf.read("audit/JZ08_PACKAGES.manifest").decode("utf-8").splitlines()
            if " - " in row
        }
        require(MUST_HAVE.issubset(packages),
                "published package manifest lacks mandatory JZ08 components")
        build = json.loads(zf.read("audit/JZ08_BUILD_AUDIT.json"))
        require(build.get("status") == "BUILD_CHECKS_PASS_ONLY"
                and build.get("flash_allowed") is False
                and build.get("hardware_tested") is False
                and build.get("errors") == []
                and set(build.get("required_packages", [])) <= packages
                and set(build.get("found_packages", [])) == packages,
                "published build audit inconsistent with actual package manifest")
        require(any(row.get("verified_fdt_compatible") is True
                    and row.get("sha256") == file_sha(dtb)
                    for row in build.get("dtb", [])),
                "published DTB differs from build audit")
        images = build.get("build_images", [])
        for suffix, path in (("boot.img", boot), ("system.img", system)):
            require(sum(row.get("path", "").endswith(suffix)
                        and row.get("sha256") == file_sha(path)
                        and row.get("header_verified") is True
                        for row in images) == 1,
                    "published image differs from build audit: " + suffix)

        runtime = json.loads(zf.read("audit/JZ08_ROOTFS_RUNTIME_AUDIT.json"))
        require(runtime.get("status") == "OFFLINE_USERSPACE_CHECK_PASS_ONLY"
                and runtime.get("flash_allowed") is False
                and runtime.get("errors") == []
                and runtime.get("required_elf")
                and all(row.get("valid") is True
                        for row in runtime["required_elf"].values())
                and runtime.get("required_assets")
                and all(row.get("valid") is True and row.get("size", 0) > 0
                        for row in runtime["required_assets"].values()),
                "published runtime audit does not confirm AArch64 and Russian LuCI")
        require(all(runtime.get("observed_paths_not_boot_proof", {}).get(name, {}).get("present") is True
                    for name in ("/sbin/procd", "/usr/sbin/uhttpd",
                                 "/usr/sbin/ModemManager", "/usr/sbin/rmtfs",
                                 "/www/cgi-bin/luci")),
                "published runtime audit lacks required services")
        verify_actual_rootfs(system, runtime)
    return "INDEPENDENT_REAL_PAYLOAD_AND_ROOTFS_CONTENT_VERIFIED_NOT_BOOT_PROOF"


def verify(archive_path: Path, checksum_path: Path, report_path: Path, inspect_payloads=True):
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
        if inspect_payloads:
            verify_real_payloads(zf)
    return {"status": "INDEPENDENT_ZIP_CONTENT_VERIFIED_NOT_BOOT_PROOF",
            "archive": archive_path.name, "sha256": digest,
            "members": len(REQUIRED), "flash_allowed": False,
            "hardware_tested": False,
            "real_payloads_inspected": bool(inspect_payloads),
            "kernel_appended_jz08_dtb_verified": bool(inspect_payloads),
            "rootfs_contents_rechecked": bool(inspect_payloads)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--sha256", required=True, type=Path)
    parser.add_argument("--verification", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.archive, args.sha256, args.verification), indent=2))


if __name__ == "__main__":
    main()
