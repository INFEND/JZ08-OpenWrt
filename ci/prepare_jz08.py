#!/usr/bin/env python3
"""Generate a build-only JZ08 profile from pinned upstream sources.
No EDL/USB operations, no flashable artifacts, and no OEM GPT modifications.
"""
import argparse
import difflib
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAKEFILE = "arch/arm64/boot/dts/qcom/Makefile"
DTS = "arch/arm64/boot/dts/qcom/msm8916-generic-jz08-3000-nkv.dts"

def run(upstream: pathlib.Path, openwrt: pathlib.Path):
    target = openwrt / "target/linux/msm89xx"
    if not (target / "patches-6.12/801-arm64-dts-qcom-add-devices-makefile.patch").is_file():
        raise RuntimeError("msm89xx patches are missing")
    mk = target / "image/msm8916.mk"
    text = mk.read_text()
    if "define Device/generic-jz08-3000-nkv" in text:
        raise RuntimeError("unexpected existing JZ08 target")
    addition = (ROOT / "board/msm8916.mk.append").read_text()
    if "root=PARTLABEL=jz08-unconfigured-rootfs" not in addition or "ARTIFACTS :=" not in addition:
        raise RuntimeError("missing no-flash guard in target")
    idx = text.rfind("endif")
    if idx < 0:
        raise RuntimeError("device target Makefile structure changed")
    text = text[:idx] + addition + "\n" + text[idx:]
    mk.write_text(text)

    dts = (ROOT / "board/msm8916-generic-jz08-prototype.dts").read_text()
    if 'status = "disabled"' not in dts:
        raise RuntimeError("prototype LCD is not disabled")
    lines = dts.splitlines(keepends=True)
    # Apply as kernel 6.12 patch. Never enable the prototype LCD.
    new_dts = "".join(difflib.unified_diff([], lines, fromfile="/dev/null", tofile="b/" + DTS))
    if not new_dts:
        raise RuntimeError("DTS patch generation failed")
    context = "dtb-$(CONFIG_ARCH_QCOM)\t+= msm8916-generic-mf68e.dtb"
    addition_line = "dtb-$(CONFIG_ARCH_QCOM)\t+= msm8916-generic-jz08-3000-nkv.dtb"
    mk_patch = "--- a/" + MAKEFILE + "\n+++ b/" + MAKEFILE + "\n"
    mk_patch += "@@ -26 +26,2 @@\n " + context + "\n+" + addition_line + "\n"
    patch = target / "patches-6.12/809-arm64-dts-jz08-prototype.patch"
    patch.write_text(mk_patch + new_dts)
    # Derive an experiment from upstream MF68E package selection while
    # excluding its LCD code and all rootfs/flash recipe assumptions.
    old = (upstream / "diffconfig_mf68e").read_text()
    old = old.replace("CONFIG_TARGET_msm89xx_msm8916_DEVICE_generic-mf68e=y",
                      "CONFIG_TARGET_msm89xx_msm8916_DEVICE_generic-jz08-3000-nkv=y")
    # Explicitly select the router UI and modem packages in addition to the
    # image profile's DEVICE_PACKAGES. Do not silently inherit an incomplete
    # MF68E selection. make defconfig may still reject unmet dependencies:
    # the CI build must detect and report that, never claim a valid image.
    required = ("luci", "luci-base", "luci-i18n-base-ru", "modemmanager")
    removed = ("CONFIG_PACKAGE_router-display=",
               "CONFIG_PACKAGE_kmod-fbtft-gc9107=",
               "CONFIG_PACKAGE_prepare-rootfs-data=",
               "CONFIG_PACKAGE_msm-firmware-dumper=")
    overrides = tuple(f"CONFIG_PACKAGE_{name}=" for name in required) + ("CONFIG_TARGET_ROOTFS_INITRAMFS=",)
    filtered = [
        line for line in old.splitlines()
        if not line.startswith(removed + overrides)
    ]
    filtered.extend(f"CONFIG_PACKAGE_{name}=y" for name in required)
    # Embed userspace in a RAM-only initramfs kernel candidate. This avoids
    # assuming that an OEM eMMC partition contains an OpenWrt rootfs.
    filtered.append("CONFIG_TARGET_ROOTFS_INITRAMFS=y")
    (openwrt / ".config").write_text("\n".join(filtered) + "\n")
    print("JZ08 DEVELOPMENT PROFILE ADDED: NO GPIO ENABLED / NO OEM GPT / NO FLASHING")
    print("Linux patch:",patch)
    print("Rootfs safety marker: jz08-unconfigured-rootfs")

if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("--upstream", type=pathlib.Path, required=True)
    a.add_argument("--openwrt", type=pathlib.Path, required=True)
    args = a.parse_args()
    run(args.upstream.resolve(), args.openwrt.resolve())
