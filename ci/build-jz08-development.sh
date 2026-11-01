#!/usr/bin/env bash
# Compiles MF68E upstream as a JZ08 DEVELOPMENT ONLY. No flashing and no firmware publication.
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/work/reference"
mkdir -p "$WORK" "$ROOT/output"
UP="$WORK/upstream"
OW="$WORK/openwrt"
PIN_UP="c2e2dd5afc6ec4e8be55cfc952a1fce042e681c4"
PIN_OW="46ab9f3f1c0e6ac2a17efa5a3f34e466a0c2d4e0"
echo "JZ08 DEVELOPMENT BUILD ONLY / NO FLASH / NO FIRMWARE UPLOAD"
echo "Experimental source compilation only; device compatibility is UNVERIFIED."
python3 "$ROOT/ci/validate.py"
git init -q "$UP"
git -C "$UP" remote add origin https://github.com/rabbits0209/msm8916-xiaoxun-openwrt.git
git -C "$UP" fetch --depth 1 origin "$PIN_UP"
git -C "$UP" checkout --detach FETCH_HEAD
test "$(git -C "$UP" rev-parse HEAD)" = "$PIN_UP"
git init -q "$OW"
git -C "$OW" remote add origin https://github.com/openwrt/openwrt.git
git -C "$OW" fetch --depth 1 origin "$PIN_OW"
git -C "$OW" checkout --detach FETCH_HEAD
test "$(git -C "$OW" rev-parse HEAD)" = "$PIN_OW"
cp -a "$UP/msm89xx" "$OW/target/linux/msm89xx"
cp -a "$UP/packages" "$OW/package/msm8916"
# Retain rmtfs binary but disable its OEM NV-backed automatic startup.
python3 - "$OW/package/msm8916/rmtfs/files/rmtfs.init" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
if s.count("\nSTART=15\n") != 1:
    raise SystemExit("FATAL: pinned rmtfs init startup policy changed")
p.write_text(s.replace("\nSTART=15\n", "\nSTART=\n", 1))
PY
python3 "$ROOT/ci/prepare_jz08.py" --upstream "$UP" --openwrt "$OW"
# Correct two old directory prefixes in the pinned, public upstream patch.
sed -e 's#a/oopenwrt/#a/#g' -e 's#a/openwrt/#a/#g' -e 's#b/openwrt/#b/#g' "$UP/enable_wcn36xx_mac80211.patch" > "$WORK/wcn36xx.patch"
git -C "$OW" apply --check "$WORK/wcn36xx.patch"
git -C "$OW" apply "$WORK/wcn36xx.patch"
# JZ08 config created by prepare_jz08.py
# Reference output only. Forbid packed GPT/flash-script artifacts even for MF68E.
sed -i 's/ARTIFACTS := squashfs-gpt_both0.bin flash.sh firmware.zip/ARTIFACTS :=/' "$OW/target/linux/msm89xx/image/msm8916.mk"
if grep -q 'ARTIFACTS := squashfs-gpt_both0.bin' "$OW/target/linux/msm89xx/image/msm8916.mk"; then
  echo "Refusing unsafe artifact generator" >&2
  exit 1
fi
# Freeze feeds to the same November 2025-era code as the pinned OpenWrt tree.
# Floating feeds from 2026 caused recursive Kconfig dependencies and missing LuCI.
cat > "$OW/feeds.conf.default" <<'FEEDS'
src-git packages https://github.com/openwrt/packages.git^1e1cc2d13483ee2759712e4d28bc1f347b1e3097
src-git luci https://github.com/openwrt/luci.git^2eac826ea01b7b48dcdd983b1f5ceb9cc77b8f7b
src-git routing https://github.com/openwrt/routing.git^0bf1ec3c3d9459ce8dc6fa7e1b6084518a0b5a55
src-git telephony https://github.com/openwrt/telephony.git^6e2a8b34c5c3c69a17442898eb7cbd4d4d090769
FEEDS
sudo -E bash "$UP/devenv/dependencies.sh"
cd "$OW"
./scripts/feeds update -a
./scripts/feeds install -a
make defconfig > "$WORK/jz08-kconfig.log" 2>&1 || { cat "$WORK/jz08-kconfig.log"; exit 1; }
if grep -Eiq 'error: recursive dependency detected|error: symbol .* depends on' "$WORK/jz08-kconfig.log"; then
  echo "FATAL: Kconfig error even if make defconfig returned zero" >&2
  cat "$WORK/jz08-kconfig.log"
  exit 1
fi
cp "$WORK/jz08-kconfig.log" "$ROOT/output/JZ08_KCONFIG.log.txt"
# Never include the pinned upstream automatic p15 formatter or OEM dumper.
for forbidden in prepare-rootfs-data msm-firmware-dumper; do
  if grep -Fxq "CONFIG_PACKAGE_${forbidden}=y" "$OW/.config"; then
    echo "FATAL: unsafe OEM storage package selected: $forbidden" >&2
    exit 1
  fi
done
grep -Fxq 'CONFIG_TARGET_ROOTFS_INITRAMFS=y' "$OW/.config" || {
  echo "FATAL: embedded initramfs for RAM-only test was deselected" >&2
  exit 1
}
grep -Fxq 'CONFIG_TARGET_msm89xx_msm8916_DEVICE_generic-jz08-3000-nkv=y' "$OW/.config" || {
  echo "FATAL: JZ08 target was deselected by Kconfig" >&2
  exit 1
}
# Fail fast if Kconfig rejects essential UI or modem packages.
python3 - "$OW/.config" "$ROOT/output/JZ08_REQUIRED_CONFIG.txt" <<'PY'
import pathlib, sys
config = pathlib.Path(sys.argv[1]).read_text()
required = ("luci", "luci-base", "luci-i18n-base-ru", "modemmanager")
lines = [f"CONFIG_PACKAGE_{name}=" for name in required]
report = [next((x for x in config.splitlines() if x.startswith(prefix)),
               prefix + "<ABSENT>") for prefix in lines]
pathlib.Path(sys.argv[2]).write_text("\n".join(report) + "\n")
print("Required OpenWrt selections:", *report, sep="\n")
missing = [name for name, row in zip(required, report) if row != f"CONFIG_PACKAGE_{name}=y"]
if missing:
    sys.exit("Kconfig rejected required JZ08 packages: " + ", ".join(missing))
PY
make download -j4
make -j2 || make -j1 V=s
python3 "$ROOT/ci/check_built_jz08.py" --source "$ROOT" --build-log "$ROOT/output/JZ08_KCONFIG.log.txt" --openwrt "$OW"
# Verify actual rootfs contents, not merely the sparse/SquashFS superblock.
# The decoded image exists ONLY on the temporary CI runner and is deleted.
# Do not upload this image, or publish any firmware binary.
echo "Verifying every file in the built JZ08 SquashFS (offline, no flashing)"
ROOTFS_IMAGE="$(find "$OW/bin/targets/msm89xx/msm8916" -maxdepth 1 -type f -name '*jz08*system.img' -print -quit)"
test -n "$ROOTFS_IMAGE" && test -f "$ROOTFS_IMAGE" || {
  echo "FATAL: built JZ08 rootfs image missing for content verification" >&2
  exit 1
}
command -v simg2img >/dev/null || {
  echo "FATAL: simg2img unavailable; cannot verify real rootfs contents" >&2
  exit 1
}
sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends squashfs-tools
ROOTFS_RAW="$(mktemp /tmp/jz08-rootfs-audit.XXXXXXXX.raw)"
ROOTFS_TMP="$(mktemp -d /tmp/jz08-rootfs-files.XXXXXXXX)"
# unsquashfs requires a destination that does not already exist.
# mktemp -d creates the parent, not the extraction destination.
ROOTFS_EXTRACT="$ROOTFS_TMP/rootfs"
# OpenWrt rootfs can contain device nodes. Extract as root on the ephemeral
# CI runner, with strict errors and no persistent extraction artifacts.
# Ubuntu squashfs-tools 4.5 does NOT support the non-existent -test flag.
trap 'sudo -n rm -rf -- "$ROOTFS_TMP"; rm -f -- "$ROOTFS_RAW"' EXIT
simg2img "$ROOTFS_IMAGE" "$ROOTFS_RAW"
if ! sudo -n unsquashfs -strict-errors -no-progress -no-xattrs -processors 2 -dest "$ROOTFS_EXTRACT" "$ROOTFS_RAW" > "$ROOT/output/JZ08_ROOTFS_CONTENTS_TEST.txt" 2>&1; then
  echo "FATAL: real JZ08 SquashFS extraction/content decompression failed" >&2
  tail -n 100 "$ROOT/output/JZ08_ROOTFS_CONTENTS_TEST.txt" >&2
  exit 1
fi
# Confirm the extraction created the expected Linux root tree.
for required in etc bin sbin usr; do
  test -d "$ROOTFS_EXTRACT/$required" || {
    echo "FATAL: extracted rootfs missing /$required" >&2
    exit 1
  }
done
# Check real extracted ARM64 init and BusyBox ELF/loaders; only JSON is retained.
python3 "$ROOT/ci/audit_rootfs_runtime.py" --root "$ROOTFS_EXTRACT" --output "$ROOT/output/JZ08_ROOTFS_RUNTIME_AUDIT.json"
printf 'PASS: real JZ08 Android Sparse decoded and all SquashFS entries extracted\nsource_sha256=%s\nexpanded_bytes=%s\nflash_allowed=false\n' \
  "$(sha256sum "$ROOTFS_IMAGE" | cut -d' ' -f1)" \
  "$(stat -c '%s' "$ROOTFS_RAW")" \
  > "$ROOT/output/JZ08_ROOTFS_CONTENTS_STATUS.txt"
cat "$ROOT/output/JZ08_ROOTFS_CONTENTS_STATUS.txt"
sudo -n rm -rf -- "$ROOTFS_TMP"
rm -f -- "$ROOTFS_RAW"
trap - EXIT
printf 'JZ08_BUILD_VALIDATED_HARDWARE_UNVERIFIED\n%s\n%s\n' "$PIN_UP" "$PIN_OW" > "$ROOT/output/JZ08_DEVELOPMENT_BUILD_STATUS.txt"
# Keep diagnostic manifests only; images are excluded on purpose.
find bin/targets/msm89xx -type f -name '*.manifest' -exec cp '{}' "$ROOT/output/" ';' || true
# Independently inspect the exact cpio embedded by the OpenWrt initramfs build.
# OpenWrt normally embeds Linux usr/initramfs_data.cpio; separate mode uses
# KERNEL_BUILD_DIR/initrd.cpio. Resolve exactly one audited source, never a guess.
INITRAMFS_CPIO="$(python3 "$ROOT/ci/locate_initramfs_cpio.py" --openwrt "$OW")"
echo "Auditing kernel-generated initramfs: $INITRAMFS_CPIO"
python3 "$ROOT/ci/audit_initramfs_cpio.py" --cpio "$INITRAMFS_CPIO" \
  --output "$ROOT/output/JZ08_INITRAMFS_CPIO_AUDIT.json"
# Prepare a separate RAM-only candidate with embedded initramfs and no eMMC root.
# The Android header is unverified on real JZ08/LK2ND; NEVER write this image.
INITRAMFS_KERNEL="$(find "$OW/bin/targets/msm89xx/msm8916" -maxdepth 1 -type f -name '*jz08*initramfs-kernel.bin' -print -quit)"
test -n "$INITRAMFS_KERNEL" && test -s "$INITRAMFS_KERNEL" || {
  echo "FATAL: JZ08 initramfs kernel is missing" >&2
  exit 1
}
command -v mkbootimg >/dev/null || {
  echo "FATAL: mkbootimg unavailable for RAM-only candidate" >&2
  exit 1
}
mkbootimg --kernel "$INITRAMFS_KERNEL" --ramdisk /dev/null \
  --cmdline "earlycon console=ttyMSM0,115200 rdinit=/init" --pagesize 2048 \
  -o "$ROOT/output/JZ08_RAM_ONLY_INITRAMFS_CANDIDATE.img"
# Assemble all verified binaries into one engineering-only archive; no flash scripts.
# Failure to verify any mandatory member fails the entire build.
python3 "$ROOT/ci/package_jz08_experiment.py" --source "$ROOT" --openwrt "$OW"
echo "Build finished. Verified inspection archive produced; NOT FLASHABLE."
