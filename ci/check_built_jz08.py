#!/usr/bin/env python3
"""Reject misleading green CI builds with missing modem/router functionality.
Diagnostic verification only; does not produce flashable images.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys

MUST_HAVE = {
    "kernel", "base-files", "procd", "busybox", "luci", "luci-base",
    "luci-i18n-base-ru", "modemmanager", "rmtfs", "kmod-qcom-rproc-modem",
    "kmod-qcom-rproc-wcnss", "kmod-wcn36xx", "kmod-usb-gadget-ncm",
    "uhttpd", "configs-mifi"
}

def squashfs_v4_superblock_details(path):
    """Report safe SquashFS metadata and every failed structural check.

    This does not certify filesystem contents or device compatibility.
    """
    size = path.stat().st_size
    with path.open("rb") as stream:
        sb = stream.read(96)
    details = {"file_size": size, "superblock_size": len(sb)}
    if len(sb) != 96:
        details.update(valid=False, failed_checks=["superblock_length"])
        return details
    details.update({
        "magic": sb[:4].hex(),
        "inode_count": int.from_bytes(sb[4:8], "little"),
        "block_size": int.from_bytes(sb[12:16], "little"),
        "major": int.from_bytes(sb[28:30], "little"),
        "minor": int.from_bytes(sb[30:32], "little"),
        "bytes_used": int.from_bytes(sb[40:48], "little"),
    })
    block_size = details["block_size"]
    checks = {
        "magic": details["magic"] == "3aff26ed",
        "inodes": details["inode_count"] > 0,
        "block_size_range": 4096 <= block_size <= 1048576,
        "block_size_power_of_two": block_size > 0 and (block_size & (block_size - 1)) == 0,
        "squashfs_v4": (details["major"], details["minor"]) == (4, 0),
        "bytes_used_range": 4096 <= details["bytes_used"] <= size,
    }
    details["failed_checks"] = [name for name, passed in checks.items() if not passed]
    details["valid"] = not details["failed_checks"]
    return details


def squashfs_v4_superblock_valid(path):
    """Retain the simple predicate for offline tests and callers."""
    return squashfs_v4_superblock_details(path)["valid"]

def check(source, log, root):
    errors = []
    text = log.read_text(errors="replace")
    critical = [x.strip() for x in text.splitlines() if "error: recursive dependency detected" in x.lower()]
    if critical:
        errors.append(f"{len(critical)} Kconfig recursive dependency errors")
    manifests = list((root / "bin/targets").rglob("*jz08*.manifest"))
    if len(manifests) != 1:
        errors.append(f"expected exactly 1 JZ08 package manifest, found {len(manifests)}")
    packages = set()
    if manifests:
        for row in manifests[0].read_text(errors="replace").splitlines():
            if " - " in row: packages.add(row.split(" - ", 1)[0])
        absent = MUST_HAVE.difference(packages)
        if absent:
            errors.append("missing required packages: " + ", ".join(sorted(absent)))
    kconfig = (root / ".config").read_text(errors="replace")
    if "CONFIG_TARGET_msm89xx_msm8916_DEVICE_generic-jz08-3000-nkv=y" not in kconfig:
        errors.append("selected target is not generic-jz08-3000-nkv")
    # OpenWrt image.mk produces image-<DEVICE_DTS>.dtb in KDIR. The kernel
    # may also produce a plain <DEVICE_DTS>.dtb. Accept only exact JZ08 names
    # and validate the FDT magic and board compatible string.
    dtb_basename = "msm8916-generic-jz08-3000-nkv.dtb"
    allowed_names = {dtb_basename, "image-" + dtb_basename}
    dtbs = [p for p in (root / "build_dir").rglob("*jz08*.dtb")
            if p.name in allowed_names]
    verified_dtbs = []
    for p in dtbs:
        data = p.read_bytes()
        if (len(data) >= 1024 and data[:4] == bytes.fromhex("d00dfeed")
                and int.from_bytes(data[4:8], "big") <= len(data)
                and b"xarkon,jz08-3000-nkv\x00" in data):
            verified_dtbs.append(p)
    if not verified_dtbs:
        errors.append("no compiled JZ08 DTB with valid FDT header and board compatible")
    # Validate actual JZ08 boot and rootfs build products, not just Kconfig.
    # These remain on the ephemeral CI runner and are NEVER uploaded.
    images = []
    for suffix, magic in (("boot.img", b"ANDROID!"),
                          ("system.img", bytes.fromhex("3aff26ed"))):
        matches = [p for p in (root / "bin/targets").rglob("*jz08*" + suffix)
                   if p.is_file()]
        if len(matches) != 1:
            errors.append(f"expected exactly one JZ08 {suffix}, found {len(matches)}")
        for p in matches:
            with p.open("rb") as f:
                header = f.read(len(magic))
            valid = header == magic and p.stat().st_size > 4096
            if not valid:
                errors.append(f"JZ08 {suffix} is missing its expected image header")
            superblock = None
            if suffix == "system.img":
                superblock = squashfs_v4_superblock_details(p)
                if not superblock["valid"]:
                    errors.append(
                        "JZ08 system.img has invalid or inconsistent SquashFS superblock "
                        "(failed checks: " + ", ".join(superblock["failed_checks"]) + ")"
                    )
                valid = valid and superblock["valid"]
            image_record = {
                "path": p.relative_to(root).as_posix(),
                "size": p.stat().st_size,
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                "header_verified": valid,
                "published": False,
            }
            if superblock is not None:
                image_record["squashfs_superblock"] = superblock
            images.append(image_record)
    if "DEVICE_DTS := msm8916-generic-jz08-3000-nkv" not in (
            source / "board/msm8916.mk.append").read_text():
        errors.append("JZ08 image profile does not select the JZ08 DTB")
    report = {
        "board": "JZ08-3000-NKV 1.0",
        "status": "BUILD_CHECKS_PASS_ONLY" if not errors else "REJECTED_DEVELOPMENT_BUILD",
        "hardware_tested": False,
        "flash_allowed": False,
        "required_packages": sorted(MUST_HAVE),
        "found_packages": sorted(packages),
        "dtb": [{"path":p.relative_to(root).as_posix(), "size":p.stat().st_size,
                 "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                 "verified_fdt_compatible": p in verified_dtbs}
                for p in dtbs[:10]],
        "build_images": images,
        "errors": errors,
    }
    out = source / "output/JZ08_BUILD_AUDIT.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({k:v for k,v in report.items() if k!="found_packages"}, indent=2, ensure_ascii=False))
    if errors:
        raise SystemExit(1)

if __name__ == "__main__":
    a=argparse.ArgumentParser()
    a.add_argument("--source", type=pathlib.Path, required=True)
    a.add_argument("--build-log", type=pathlib.Path, required=True)
    a.add_argument("--openwrt", type=pathlib.Path, required=True)
    args=a.parse_args()
    check(args.source.resolve(), args.build_log.resolve(), args.openwrt.resolve())
