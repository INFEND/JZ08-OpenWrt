#!/usr/bin/env python3
"""Locate the actual kernel-produced OpenWrt initramfs CPIO, fail closed.

Linux's normal embedded-initramfs build produces usr/initramfs_data.cpio.
OpenWrt's separate-initramfs build produces KERNEL_BUILD_DIR/initrd.cpio.
Never accept an arbitrary cpio found elsewhere in the build tree.
"""
import argparse
from pathlib import Path


def locate(openwrt: Path) -> Path:
    build = openwrt / "build_dir"
    candidates = sorted(set(
        list(build.glob("target-*/linux-msm89xx_msm8916/initrd.cpio"))
        + list(build.glob(
            "target-*/linux-msm89xx_msm8916/linux-*/usr/initramfs_data.cpio"))
    ))
    if len(candidates) != 1:
        raise ValueError(
            "expected exactly one kernel-produced JZ08 initramfs CPIO, "
            f"found {len(candidates)}: {[str(p) for p in candidates]}; "
            "inspect CONFIG_INITRAMFS_SOURCE and kernel build logs"
        )
    path = candidates[0].resolve(strict=True)
    if not path.is_relative_to(build.resolve(strict=True)):
        raise ValueError("CPIO source escapes OpenWrt build directory")
    if not path.is_file() or path.stat().st_size < 110:
        raise ValueError("kernel-produced initramfs CPIO is empty or missing")
    with path.open("rb") as handle:
        if handle.read(6) not in (b"070701", b"070702"):
            raise ValueError("kernel-produced initramfs is not raw newc CPIO")
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--openwrt", type=Path, required=True)
    args = parser.parse_args()
    print(locate(args.openwrt))
