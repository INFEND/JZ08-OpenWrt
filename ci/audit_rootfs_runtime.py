#!/usr/bin/env python3
"""Offline ELF/userspace inspection of an extracted JZ08 rootfs.

No binary execution, block-device access, firmware publication, or hardware I/O.
Passing this check is NOT evidence that the JZ08 kernel can boot the rootfs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

REQUIRED = ("/sbin/init", "/bin/busybox")
# Pinned LuCI luci.mk installs translations to
# $(LUA_LIBRARYDIR)/luci/i18n, with LUA_LIBRARYDIR=/usr/lib/lua.
# Package manifest presence alone does not prove the Russian catalog exists.
REQUIRED_ASSETS = ("/usr/lib/lua/luci/i18n/base.ru.lmo",)
OBSERVED = (
    "/sbin/procd", "/usr/sbin/uhttpd", "/usr/sbin/ModemManager",
    "/usr/sbin/rmtfs", "/www/cgi-bin/luci",
    "/etc/openwrt_release", "/etc/init.d/network",
)


def resolve_rootfs(root: Path, logical: str) -> Path:
    """Resolve absolute and relative rootfs symlinks WITHOUT following host /."""
    if not logical.startswith("/"):
        raise ValueError("rootfs path must be absolute")
    root = root.resolve(strict=True)
    pending = logical.split("/")
    components = []
    links = 0
    while pending:
        component = pending.pop(0)
        if component in ("", "."):
            continue
        if component == "..":
            if not components:
                raise ValueError("rootfs symlink escapes extraction root")
            components.pop()
            continue
        candidate = root.joinpath(*components, component)
        if candidate.is_symlink():
            links += 1
            if links > 40:
                raise ValueError("rootfs symlink loop or excessive depth")
            target = os.readlink(candidate)
            if target.startswith("/"):
                components = []
            pending = target.split("/") + pending
        else:
            components.append(component)
    return root.joinpath(*components)


def elf_aarch64(path: Path):
    """Inspect ELF64/AArch64 load segments and optional dynamic interpreter."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        header = stream.read(64)
        if (len(header) != 64 or header[:4] != b"\x7fELF"
                or header[4:7] != b"\x02\x01\x01"):
            raise ValueError("not a little-endian ELF64 executable")
        e_type, machine = struct.unpack_from("<HH", header, 16)
        if machine != 183 or e_type not in (2, 3):
            raise ValueError("ELF machine/type is not AArch64 executable/shared")
        phoff = struct.unpack_from("<Q", header, 32)[0]
        phentsize, phnum = struct.unpack_from("<HH", header, 54)
        if not (1 <= phnum <= 128 and 56 <= phentsize <= 128
                and phoff >= 64 and phoff + phentsize * phnum <= size):
            raise ValueError("ELF program header table is missing or truncated")
        load_count = 0
        interpreter = None
        for index in range(phnum):
            stream.seek(phoff + index * phentsize)
            ph = stream.read(56)
            p_type, _, p_offset, _, _, p_filesz, _, _ = struct.unpack("<IIQQQQQQ", ph)
            if p_offset + p_filesz > size:
                raise ValueError("ELF program segment exceeds file")
            if p_type == 1:
                load_count += 1
            if p_type == 3:
                if interpreter is not None or p_filesz < 2 or p_filesz > 4096:
                    raise ValueError("invalid ELF interpreter segment")
                stream.seek(p_offset)
                raw = stream.read(p_filesz)
                if not raw.endswith(b"\x00") or b"\x00" in raw[:-1]:
                    raise ValueError("malformed ELF interpreter path")
                interpreter = raw[:-1].decode("ascii")
                if not interpreter.startswith("/"):
                    raise ValueError("ELF interpreter path must be absolute")
        if load_count == 0:
            raise ValueError("ELF has no loadable segments")
    return {"machine": "AArch64", "elf_class": 64,
            "load_segments": load_count, "interpreter": interpreter}


def audit(root: Path):
    if not root.is_dir():
        raise ValueError("rootfs extraction directory does not exist")
    errors = []
    checked = {}
    for logical in REQUIRED:
        item = {"present": False, "valid": False}
        try:
            path = resolve_rootfs(root, logical)
            if not path.is_file():
                raise ValueError("required executable is absent")
            if not (stat.S_IMODE(path.stat().st_mode) & 0o111):
                raise ValueError("required executable has no execute bit")
            details = elf_aarch64(path)
            interpreter = details["interpreter"]
            if interpreter:
                loader = resolve_rootfs(root, interpreter)
                if not loader.is_file():
                    raise ValueError("dynamic ELF interpreter is missing: " + interpreter)
            item.update(present=True, valid=True,
                        resolved_path="/" + path.relative_to(root.resolve()).as_posix(),
                        size=path.stat().st_size,
                        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                        **details)
        except (OSError, ValueError, UnicodeError) as exc:
            errors.append(logical + ": " + str(exc))
            item["reason"] = str(exc)
        checked[logical] = item
    required_assets = {}
    for logical in REQUIRED_ASSETS:
        item = {"present": False, "valid": False}
        try:
            path = resolve_rootfs(root, logical)
            if not path.is_file():
                raise ValueError("required LuCI translation asset is absent")
            if path.stat().st_size == 0:
                raise ValueError("required LuCI translation asset is empty")
            item.update(present=True, valid=True,
                        size=path.stat().st_size,
                        sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        except (OSError, ValueError) as exc:
            errors.append(logical + ": " + str(exc))
            item["reason"] = str(exc)
        required_assets[logical] = item
    observed = {}
    for logical in OBSERVED:
        try:
            p = resolve_rootfs(root, logical)
            observed[logical] = {"present": p.exists(), "type":
                "file" if p.is_file() else ("directory" if p.is_dir() else "missing")}
        except (OSError, ValueError) as exc:
            observed[logical] = {"present": False, "reason": str(exc)}
    return {
        "status": "OFFLINE_USERSPACE_CHECK_PASS_ONLY" if not errors else "REJECTED_USERSPACE",
        "flash_allowed": False,
        "hardware_tested": False,
        "rootfs_executed": False,
        "required_elf": checked,
        "required_assets": required_assets,
        "observed_paths_not_boot_proof": observed,
        "errors": errors,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print("JZ08 offline rootfs runtime audit:", result["status"])
    for error in result["errors"]:
        print("ERROR:", error)
    if result["errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
