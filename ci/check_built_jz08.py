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

def _squashfs_metadata(sb, logical_size):
    """Validate the SquashFS superblock against the decoded filesystem size."""
    details = {"file_size": logical_size, "superblock_size": len(sb)}
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
        "magic": details["magic"] == "68737173",  # hsqs, SquashFS LE
        "inodes": details["inode_count"] > 0,
        "block_size_range": 4096 <= block_size <= 1048576,
        "block_size_power_of_two": block_size > 0 and (block_size & (block_size - 1)) == 0,
        "squashfs_v4": (details["major"], details["minor"]) == (4, 0),
        "bytes_used_range": 96 <= details["bytes_used"] <= logical_size,
    }
    details["failed_checks"] = [name for name, passed in checks.items() if not passed]
    details["valid"] = not details["failed_checks"]
    return details


def squashfs_v4_superblock_details(path):
    """Accept raw SquashFS or a structurally valid Android sparse SquashFS.

    Android sparse starts with 3aff26ed; this is NOT the SquashFS magic.
    Parse every chunk and validate the decoded superblock and logical bounds.
    No device I/O and no flash image publication.
    """
    import struct

    size = path.stat().st_size
    with path.open("rb") as stream:
        first = stream.read(28)
        if first[:4] != bytes.fromhex("3aff26ed"):
            return {"container": "raw", **_squashfs_metadata(first + stream.read(68), size)}
        details = {"container": "android_sparse", "file_size": size}
        failed = []
        if len(first) != 28:
            return {**details, "valid": False, "failed_checks": ["sparse_header_length"]}
        magic, major, minor, file_hdr_sz, chunk_hdr_sz, block_sz, total_blks, total_chunks, checksum = struct.unpack("<I4H4I", first)
        details.update(sparse_major=major, sparse_minor=minor, sparse_block_size=block_sz,
                       sparse_blocks=total_blks, sparse_chunks=total_chunks,
                       expanded_size=total_blks * block_sz)
        if major != 1 or minor != 0 or file_hdr_sz < 28 or chunk_hdr_sz < 12 or file_hdr_sz > size:
            failed.append("sparse_header")
        if block_sz < 4096 or block_sz > 1048576 or block_sz & (block_sz - 1):
            failed.append("sparse_block_size")
        if total_blks == 0 or total_chunks == 0 or total_chunks > 1000000:
            failed.append("sparse_dimensions")
        if failed:
            return {**details, "valid": False, "failed_checks": failed}
        stream.seek(file_hdr_sz)
        logical_blocks = 0
        first_sb = None
        raw_ranges = []
        for index in range(total_chunks):
            hdr = stream.read(chunk_hdr_sz)
            if len(hdr) != chunk_hdr_sz:
                failed.append("truncated_chunk_header")
                break
            chunk_type, reserved, blocks, chunk_total = struct.unpack("<2H2I", hdr[:12])
            payload = chunk_total - chunk_hdr_sz
            if chunk_total < chunk_hdr_sz or blocks > total_blks - logical_blocks:
                failed.append("invalid_chunk_bounds")
                break
            if chunk_type == 0xCAC1:  # RAW
                expected = blocks * block_sz
            elif chunk_type == 0xCAC2:  # FILL
                expected = 4
            elif chunk_type == 0xCAC3:  # DONT_CARE
                expected = 0
            elif chunk_type == 0xCAC4:  # CRC32
                expected = 4
                if blocks != 0:
                    failed.append("invalid_crc_chunk")
            else:
                failed.append("unknown_chunk_type")
                break
            if payload != expected or stream.tell() + payload > size:
                failed.append("invalid_chunk_size")
                break
            if chunk_type == 0xCAC1 and blocks:
                if logical_blocks == 0 and first_sb is None:
                    first_sb = stream.read(96)
                    if len(first_sb) != 96:
                        failed.append("truncated_squashfs_superblock")
                        break
                    stream.seek(-96, 1)
                raw_ranges.append((logical_blocks * block_sz, (logical_blocks + blocks) * block_sz))
            stream.seek(payload, 1)
            if chunk_type != 0xCAC4:
                logical_blocks += blocks
        if logical_blocks != total_blks:
            failed.append("sparse_block_count")
        if stream.tell() != size:
            failed.append("sparse_trailing_or_truncated_data")
        if first_sb is None:
            failed.append("missing_raw_squashfs_superblock")
            sb = _squashfs_metadata(b"", total_blks * block_sz)
        else:
            sb = _squashfs_metadata(first_sb, total_blks * block_sz)
        if not sb["valid"]:
            failed.extend("squashfs_" + check for check in sb["failed_checks"])
        # Every filesystem byte must be backed by RAW data, not an unallocated hole.
        used = sb.get("bytes_used", 0)
        if used and used <= total_blks * block_sz:
            covered = 0
            for begin, end in raw_ranges:
                if begin > covered:
                    break
                covered = max(covered, end)
                if covered >= used:
                    break
            if covered < used:
                failed.append("squashfs_unallocated_data")
        details.update(squashfs_superblock=sb, failed_checks=failed, valid=not failed)
        return details


def squashfs_v4_superblock_valid(path):
    """Retain the predicate for offline tests and callers."""
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
                          ("system.img", None)):
        matches = [p for p in (root / "bin/targets").rglob("*jz08*" + suffix)
                   if p.is_file()]
        if len(matches) != 1:
            errors.append(f"expected exactly one JZ08 {suffix}, found {len(matches)}")
        for p in matches:
            with p.open("rb") as f:
                header = f.read(len(magic) if magic is not None else 4)
            valid = (header == magic if magic is not None else True) and p.stat().st_size > 4096
            if not valid:
                errors.append(f"JZ08 {suffix} is missing its expected image header")
            superblock = None
            if suffix == "system.img":
                superblock = squashfs_v4_superblock_details(p)
                if not superblock["valid"]:
                    errors.append(
                        "JZ08 system.img has invalid or inconsistent SquashFS superblock/sparse container "
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
