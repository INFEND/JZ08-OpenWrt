#!/usr/bin/env python3
"""Strict, read-only inspection of OpenWrt initrd.cpio (newc format)."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath

REGULAR = 0o100000
SYMLINK = 0o120000
TYPE_MASK = 0o170000

REQUIRED = (
    "init", "sbin/init", "bin/busybox", "sbin/procd",
    "usr/sbin/ModemManager", "usr/sbin/rmtfs",
    "usr/sbin/uhttpd", "www/cgi-bin/luci",
    "usr/lib/lua/luci/i18n/base.ru.lmo",
)



EXECUTABLES = frozenset(REQUIRED) - {"usr/lib/lua/luci/i18n/base.ru.lmo"}
FORBIDDEN_FILES = frozenset((
    "lib/preinit/79-format-rootfs-data",
    "etc/init.d/msm-firmware-dumper",
    "usr/bin/msm-firmware-dumper",
))
FORBIDDEN_AUTOSTART = frozenset((
    "rmtfs", "msm-firmware-dumper", "fstab", "gpio_switch", "led",
    "battery-monitor", "usb-gadget", "qrtrns", "modemmanager",
))


def resolve_member(records, name):
    """Resolve symlinks inside CPIO, never against the host filesystem."""
    pending = list(PurePosixPath(name).parts)
    components = []
    links = 0
    while pending:
        component = pending.pop(0)
        if component in ("", "."):
            continue
        if component == "..":
            if not components:
                raise ValueError("initramfs symlink escapes archive root: " + name)
            components.pop()
            continue
        candidate = "/".join(components + [component])
        record = records.get(candidate)
        if record and (record["mode"] & TYPE_MASK) == SYMLINK:
            links += 1
            if links > 40:
                raise ValueError("initramfs symlink loop: " + name)
            target = record["target"]
            if target.startswith("/"):
                components = []
            pending = target.split("/") + pending
        else:
            components.append(component)
    return records.get("/".join(components))


def require_real_required_members(records):
    for name in REQUIRED:
        record = resolve_member(records, name)
        if record is None or (record["mode"] & TYPE_MASK) != REGULAR:
            raise ValueError("required initramfs path is not a regular file: " + name)
        if record["size"] == 0:
            raise ValueError("required initramfs file is empty: " + name)
        if name in EXECUTABLES and not record["mode"] & 0o111:
            raise ValueError("required initramfs executable lacks execute bit: " + name)


def reject_known_storage_mutators(records):
    # Startup directory aliases can hide services under unrelated CPIO paths.
    # OpenWrt expects literal /etc and /etc/rc.d directories, never symlinks.
    for directory in ("etc", "etc/rc.d"):
        entry = records.get(directory)
        if entry and (entry["mode"] & TYPE_MASK) == SYMLINK:
            raise ValueError("unsafe startup directory symlink in initramfs: " + directory)
    for name in FORBIDDEN_FILES:
        # Parent directories may themselves be symlinks (for example,
        # lib/preinit -> /unsafe-preinit). Inspect the resolved path, not
        # only the literal CPIO entry name.
        if resolve_member(records, name) is not None:
            raise ValueError("unsafe OEM storage component in initramfs: " + name)
    for name, record in records.items():
        if not name.startswith("etc/rc.d/S"):
            continue
        link = name.rsplit("/", 1)[-1]
        if len(link) < 4 or not link[1:3].isdigit():
            continue
        service = link[3:]
        target = record.get("target", "").rsplit("/", 1)[-1]
        # Follow aliases rather than trusting only the immediate link name.
        # A service may be hidden behind /etc/init.d/alias -> modemmanager.
        resolved = resolve_member(records, name)
        alias_to_forbidden = resolved is not None and any(
            resolved is resolve_member(records, "etc/init.d/" + forbidden)
            for forbidden in FORBIDDEN_AUTOSTART
        )
        if (service in FORBIDDEN_AUTOSTART or target in FORBIDDEN_AUTOSTART
                or alias_to_forbidden):
            raise ValueError("unsafe unverified hardware/storage service autostart in initramfs: " + name)


def align4(value):
    return (value + 3) & ~3


def audit(path):
    total = path.stat().st_size
    records = {}
    with path.open("rb") as stream:
        while True:
            start = stream.tell()
            if start + 110 > total:
                raise ValueError("missing or truncated cpio TRAILER!!!")
            header = stream.read(110)
            if header[:6] not in (b"070701", b"070702"):
                raise ValueError("invalid newc header at offset {}".format(start))
            try:
                fields = [int(header[6 + i * 8:14 + i * 8], 16)
                          for i in range(13)]
            except ValueError as exc:
                raise ValueError("malformed newc ASCII header") from exc
            mode, filesize, namesize = fields[1], fields[6], fields[11]
            if not 1 <= namesize <= 4096 or filesize > total:
                raise ValueError("invalid cpio member size")
            raw_name = stream.read(namesize)
            if (len(raw_name) != namesize or not raw_name.endswith(b"\x00")
                    or b"\x00" in raw_name[:-1]):
                raise ValueError("invalid cpio filename")
            try:
                name = raw_name[:-1].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("non-UTF8 cpio filename") from exc
            data_start = align4(stream.tell())
            data_end = data_start + filesize
            if data_end > total:
                raise ValueError("cpio member exceeds archive")
            if name == "TRAILER!!!":
                if filesize != 0:
                    raise ValueError("invalid cpio trailer")
                # Linux accepts zero padding after the final newc trailer,
                # but a second archive or hidden nonzero payload must not
                # evade the published initramfs content audit.
                stream.seek(align4(data_end))
                if stream.tell() > total:
                    raise ValueError("invalid cpio trailer padding")
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    if chunk.strip(b"\x00"):
                        raise ValueError("nonzero data after cpio trailer")
                break
            # Kernel/VFS path lookup treats repeated separators and interior
            # dot components as aliases. Reject noncanonical member names so
            # forbidden OEM startup paths cannot bypass exact-name checks.
            # A single leading "./" is accepted for common newc producers.
            if name.startswith("./"):
                name = name[2:]
            parts = PurePosixPath(name).parts
            if (not name or name.startswith("/") or ".." in parts
                    or PurePosixPath(name).as_posix() != name):
                raise ValueError("unsafe or noncanonical cpio path")
            if name in records:
                raise ValueError("duplicate cpio path: " + name)
            record = {"size": filesize, "mode": mode}
            if (mode & TYPE_MASK) == SYMLINK:
                if not 1 <= filesize <= 4096:
                    raise ValueError("invalid cpio symlink size: " + name)
                stream.seek(data_start)
                raw_target = stream.read(filesize)
                # Linux gen_init_cpio may store a single terminal NUL.
                # Reject embedded NULs, but accept this canonical encoding.
                if raw_target.endswith(b"\x00"):
                    raw_target = raw_target[:-1]
                if not raw_target or b"\x00" in raw_target:
                    raise ValueError("invalid cpio symlink target: " + name)
                try:
                    record["target"] = raw_target.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ValueError("invalid cpio symlink target: " + name) from exc
            records[name] = record
            stream.seek(align4(data_end))
            if stream.tell() > total:
                raise ValueError("invalid cpio padding")
    missing = sorted(set(REQUIRED) - records.keys())
    if missing:
        raise ValueError("incomplete initramfs: missing={}".format(missing))
    require_real_required_members(records)
    reject_known_storage_mutators(records)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "status": "INITRAMFS_CPIO_CONTENTS_VERIFIED_NOT_BOOT_PROOF",
        "archive_sha256": digest.hexdigest(),
        "archive_bytes": total,
        "entries": len(records),
        "required_paths": list(REQUIRED),
        "flash_allowed": False,
        "hardware_tested": False,
        "linux_init_executed": False,
        "known_dangerous_startup_paths_absent": True,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cpio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.cpio)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("PASS: embedded OpenWrt initramfs CPIO contents verified offline")


if __name__ == "__main__":
    main()
