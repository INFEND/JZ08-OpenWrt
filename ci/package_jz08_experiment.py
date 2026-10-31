#!/usr/bin/env python3
"""Build a self-auditing, NON-FLASHABLE JZ08 inspection bundle.

Only reads locally compiled files. Never accesses a device or partition.
The archive is for engineering inspection, NOT a validated boot procedure.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import zipfile

from check_built_jz08 import android_boot_v0_header_details, squashfs_v4_superblock_details

BOARD = "JZ08-3000-NKV 1.0"
BUNDLE_NAME = "JZ08_EXPERIMENTAL_INSPECTION_NOT_FLASHABLE.zip"
REQUIRED_OBSERVED = (
    "/sbin/procd", "/usr/sbin/uhttpd", "/usr/sbin/ModemManager",
    "/usr/sbin/rmtfs", "/www/cgi-bin/luci",
)
WARNING = """JZ08-3000-NKV 1.0 | ЭКСПЕРИМЕНТАЛЬНЫЙ КОМПЛЕКТ
СТАТУС: NOT FLASHABLE / НЕ ПРОШИВАТЬ!

Этот архив содержит реальные результаты сборки для анализа: boot.img,
system.img (Android sparse SquashFS), JZ08 DTB, ядро из boot.img,
а также отдельный RAM_ONLY_INITRAMFS_CANDIDATE.img со встроенной
файловой системой OpenWrt (без обращения к разделам eMMC).
Проверены структура файлов, SHA-256, пакеты и содержимое rootfs.
Это НЕ доказательство успешной загрузки на устройстве.

КРИТИЧЕСКИЙ БЛОКЕР: CMDLINE использует
root=PARTLABEL=jz08-unconfigured-rootfs, такого проверенного rootfs-раздела
на заводской GPT нет. Обычный boot.img имеет пустой ramdisk и не
предназначен для загрузки системы. Отдельный RAM-only кандидат собран
с rdinit=/init, но его загрузка через LK2ND на JZ08 ещё не доказана.

Не выполнять команды записи через Fastboot, EDL, rawprogram, замену GPT или
запись в eMMC. p14 на JZ08 = modemst2 (модемные данные), а не rootfs.
Не применять чужие скрипты generic-mf68e.

Для первого испытания полной системы ещё требуется подтвердить безопасный
RAM-only запуск кандидата и параметры загрузчика, прежде чем выполнять
какие-либо команды на физическом устройстве.
Не подтверждены RAM-адреса, GPIO/LCD, Wi-Fi и LTE на физической плате.
Образы внутри предназначены для инженерной проверки и сравнения.
"""


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def required(condition, message):
    if not condition:
        raise ValueError("JZ08 bundle REJECTED: " + message)


def confined(root, relative):
    root = root.resolve(strict=True)
    path = (root / relative).resolve(strict=True)
    required(path.is_relative_to(root), "path outside OpenWrt tree")
    required(path.is_file(), "missing build file: " + relative)
    return path


def assemble(source, openwrt):
    output = source / "output"
    audit = json.loads((output / "JZ08_BUILD_AUDIT.json").read_text())
    runtime = json.loads((output / "JZ08_ROOTFS_RUNTIME_AUDIT.json").read_text())
    required(audit["status"] == "BUILD_CHECKS_PASS_ONLY" and not audit["errors"],
             "compiled-image audit did not pass")
    required(audit["flash_allowed"] is False and audit["hardware_tested"] is False,
             "unsafe or misleading build status")
    required(runtime["status"] == "OFFLINE_USERSPACE_CHECK_PASS_ONLY"
             and not runtime["errors"] and runtime["flash_allowed"] is False,
             "extracted rootfs runtime audit did not pass")
    for entry in runtime["required_elf"].values():
        required(entry.get("valid") is True, "required AArch64 ELF invalid")
    required(runtime["required_assets"], "Russian LuCI assets not audited")
    for entry in runtime["required_assets"].values():
        required(entry.get("valid") is True and entry.get("size", 0) > 0,
                 "Russian LuCI catalog missing or empty")
    for name in REQUIRED_OBSERVED:
        required(runtime["observed_paths_not_boot_proof"][name]["present"] is True,
                 "rootfs service missing: " + name)
    required(set(audit["required_packages"]).issubset(audit["found_packages"]),
             "required packages absent from manifest")
    required("root=PARTLABEL=jz08-unconfigured-rootfs" in
             (source / "board/msm8916.mk.append").read_text(),
             "unsafe assumption: rootfs partition changed without review")

    images = audit["build_images"]
    required(len(images) == 2, "expected exactly boot.img and system.img")
    files = {}
    for suffix, arcname in (("boot.img", "images/boot.img"),
                            ("system.img", "images/system.img")):
        matches = [row for row in images if row["path"].endswith(suffix)]
        required(len(matches) == 1, "missing or duplicate " + suffix)
        row = matches[0]
        path = confined(openwrt, row["path"])
        required(row["header_verified"] is True and row["size"] == path.stat().st_size
                 and row["sha256"] == sha256(path), "image audit mismatch: " + suffix)
        details = (android_boot_v0_header_details(path) if suffix == "boot.img"
                   else squashfs_v4_superblock_details(path))
        required(details["valid"] is True, "invalid image: " + suffix)
        files[arcname] = path

    dtbs = [row for row in audit["dtb"] if row["verified_fdt_compatible"] is True]
    required(len(dtbs) == 1, "expected exactly one verified JZ08 DTB")
    dtb = dtbs[0]
    dtb_path = confined(openwrt, dtb["path"])
    required(dtb["sha256"] == sha256(dtb_path) and
             dtb_path.name == "image-msm8916-generic-jz08-3000-nkv.dtb",
             "JZ08 DTB mismatch")
    files["images/msm8916-generic-jz08-3000-nkv.dtb"] = dtb_path

    # A RAM-only initramfs is mandatory; an eMMC-root boot.img is insufficient.
    initramfs_matches = list(
        (openwrt / "bin/targets/msm89xx/msm8916").glob("*jz08*initramfs-kernel.bin"))
    required(len(initramfs_matches) == 1, "expected one JZ08 embedded initramfs kernel")
    initramfs = initramfs_matches[0]
    required(initramfs.stat().st_size > 4096 and
             initramfs.open("rb").read(2) == b"\x1f\x8b",
             "initramfs kernel is missing gzip header")
    files["images/initramfs-kernel.bin"] = initramfs
    candidate = output / "JZ08_RAM_ONLY_INITRAMFS_CANDIDATE.img"
    required(candidate.is_file(), "RAM-only Android boot candidate missing")
    candidate_header = android_boot_v0_header_details(candidate)
    required(candidate_header["valid"] and candidate_header["ramdisk_size"] == 0
             and candidate_header["kernel_size"] == initramfs.stat().st_size,
             "RAM-only Android boot candidate invalid")
    with candidate.open("rb") as stream:
        stream.seek(64)
        cmdline = stream.read(512).split(b"\x00", 1)[0]
    required(b"rdinit=/init" in cmdline and b"root=" not in cmdline,
             "RAM-only candidate has unsafe rootfs command line")
    files["images/RAM_ONLY_INITRAMFS_CANDIDATE.img"] = candidate

    manifests = list((openwrt / "bin/targets/msm89xx/msm8916").glob("*jz08*.manifest"))
    required(len(manifests) == 1, "expected one JZ08 package manifest")
    files["audit/JZ08_PACKAGES.manifest"] = manifests[0]
    files["audit/JZ08_BUILD_AUDIT.json"] = output / "JZ08_BUILD_AUDIT.json"
    files["audit/JZ08_ROOTFS_RUNTIME_AUDIT.json"] = output / "JZ08_ROOTFS_RUNTIME_AUDIT.json"
    files["audit/JZ08_ROOTFS_CONTENTS_STATUS.txt"] = output / "JZ08_ROOTFS_CONTENTS_STATUS.txt"

    boot = files["images/boot.img"]
    boot_header = android_boot_v0_header_details(boot)
    required(boot_header["ramdisk_size"] == 0, "unexpected ramdisk: review boot procedure")
    with tempfile.TemporaryDirectory(prefix="jz08-bundle-") as tmp:
        kernel = Path(tmp) / "kernel-from-boot.bin"
        with boot.open("rb") as stream, kernel.open("wb") as dest:
            stream.seek(boot_header["page_size"])
            remaining = boot_header["kernel_size"]
            while remaining:
                block = stream.read(min(1024 * 1024, remaining))
                required(bool(block), "truncated boot kernel payload")
                dest.write(block)
                remaining -= len(block)
        files["images/kernel-from-boot.bin"] = kernel
        for name, path in files.items():
            required(path.is_file() and path.stat().st_size > 0,
                     "required bundle member missing: " + name)

        records = {name: {"sha256": sha256(path), "bytes": path.stat().st_size}
                   for name, path in sorted(files.items())}
        metadata = {
            "board": BOARD, "status": "NOT_FLASHABLE",
            "flash_allowed": False, "hardware_tested": False,
            "full_device_boot_ready": False,
            "boot_blockers": [
                "root=PARTLABEL=jz08-unconfigured-rootfs does not identify a verified OEM partition",
                "ordinary boot.img has no ramdisk; RAM-only initramfs candidate is untested",
                "RAM loading addresses and LK2ND Linux handoff not validated",
                "LCD GPIO/controller and LTE/Wi-Fi hardware operation unverified",
            ],
            "files": records,
        }
        text_members = {
            "README_FIRST_RU.txt": WARNING.encode("utf-8"),
            "MANIFEST.json": (json.dumps(metadata, indent=2, ensure_ascii=False) + "\n").encode(),
        }
        sums = [(entry["sha256"], name) for name, entry in records.items()]
        sums.extend((hashlib.sha256(content).hexdigest(), name)
                    for name, content in text_members.items())
        text_members["SHA256SUMS"] = "".join(
            "{}  {}\n".format(digest, name) for digest, name in sorted(sums, key=lambda x: x[1])
        ).encode()
        target = output / BUNDLE_NAME
        temporary = output / (BUNDLE_NAME + ".tmp")
        try:
            with zipfile.ZipFile(temporary, "w", allowZip64=True) as archive:
                for name, path in sorted(files.items()):
                    archive.write(path, name, compress_type=zipfile.ZIP_STORED)
                for name, content in sorted(text_members.items()):
                    archive.writestr(name, content, compress_type=zipfile.ZIP_DEFLATED)
            with zipfile.ZipFile(temporary) as archive:
                required(archive.testzip() is None, "ZIP CRC failure")
                expected = set(files) | set(text_members)
                required(set(archive.namelist()) == expected, "archive member mismatch")
                for name, entry in records.items():
                    digest = hashlib.sha256()
                    with archive.open(name) as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(chunk)
                    required(digest.hexdigest() == entry["sha256"],
                             "ZIP member hash mismatch: " + name)
                for name, content in text_members.items():
                    required(archive.read(name) == content, "ZIP text member mismatch")
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
        digest = sha256(target)
        (output / (BUNDLE_NAME + ".sha256")).write_text(
            "{}  {}\n".format(digest, BUNDLE_NAME))
        (output / "JZ08_BUNDLE_VERIFICATION.json").write_text(
            json.dumps({"status": "ARCHIVE_VERIFIED_NOT_FLASHABLE",
                        "archive": BUNDLE_NAME, "sha256": digest,
                        "members": len(files) + len(text_members),
                        "flash_allowed": False, "hardware_tested": False,
                        "full_device_boot_ready": False}, indent=2) + "\n")
        print("PASS: verified JZ08 engineering inspection bundle:", target)
        print("NOT FLASHABLE: no verified full-system RAM-only boot path")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--openwrt", type=Path, required=True)
    args = parser.parse_args()
    assemble(args.source.resolve(), args.openwrt.resolve())
