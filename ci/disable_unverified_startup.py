#!/usr/bin/env python3
"""Disable unverified hardware, NV and storage service autostart in the JZ08 RAM candidate.

This edits only pinned build-tree sources, never a device or an OEM partition.
Every expected upstream START value must match exactly, otherwise fail closed.
Installed binaries and manual service control remain available for later validation.
"""
import argparse
from pathlib import Path

STARTUP_SOURCES = {
    "package/base-files/files/etc/init.d/gpio_switch": 94,
    "package/base-files/files/etc/init.d/led": 96,
    "package/system/fstools/files/fstab.init": 11,
    "package/msm8916/configs-mifi/files/battery-monitor.init": 99,
    "package/msm8916/uci-usb-gadget/files/usb-gadget.init": 99,
    "package/msm8916/qrtr/files/qrtrns.init": 60,
    "feeds/packages/net/modemmanager/files/etc/init.d/modemmanager": 70,
}


def disable(openwrt: Path):
    root = openwrt.resolve(strict=True)
    # Preflight all files before writing any: no partial policy on mismatch.
    edits = []
    for relative, priority in STARTUP_SOURCES.items():
        path = root / relative
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("missing or unsafe pinned init source: " + relative)
        content = path.read_text()
        if not content.startswith("#!/bin/sh /etc/rc.common"):
            raise ValueError("unexpected init source format: " + relative)
        lines = content.splitlines(keepends=True)
        old = f"START={priority}"
        indexes = [i for i, line in enumerate(lines) if line.rstrip("\r\n") == old]
        if len(indexes) != 1:
            raise ValueError("pinned startup priority changed: " + relative)
        index = indexes[0]
        lines[index] = lines[index].replace(old, "START=", 1)
        edits.append((path, "".join(lines)))
    for path, content in edits:
        path.write_text(content)
        print("JZ08 RAM-only: autostart disabled:", path.relative_to(root))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--openwrt", required=True, type=Path)
    disable(parser.parse_args().openwrt)
