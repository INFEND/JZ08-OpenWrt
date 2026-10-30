#!/usr/bin/env bash
# Compiles MF68E upstream as a REFERENCE ONLY. No flashing and no firmware publication.
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/work/reference"
mkdir -p "$WORK" "$ROOT/output"
UP="$WORK/upstream"
OW="$WORK/openwrt"
PIN_UP="c2e2dd5afc6ec4e8be55cfc952a1fce042e681c4"
PIN_OW="46ab9f3f1c0e6ac2a17efa5a3f34e466a0c2d4e0"
echo "REFERENCE BUILD ONLY / NO FLASH / NO ARTIFACT FIRMWARE UPLOAD"
echo "This is for toolchain checking, not JZ08 compatibility."
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
# Correct two old directory prefixes in the pinned, public upstream patch.
sed -e 's#a/oopenwrt/#a/#g' -e 's#b/openwrt/#b/#g' "$UP/enable_wcn36xx_mac80211.patch" > "$WORK/wcn36xx.patch"
git -C "$OW" apply --check "$WORK/wcn36xx.patch"
git -C "$OW" apply "$WORK/wcn36xx.patch"
cp "$UP/diffconfig_mf68e" "$OW/.config"
# Reference output only. Forbid packed GPT/flash-script artifacts even for MF68E.
sed -i 's/ARTIFACTS := squashfs-gpt_both0.bin flash.sh firmware.zip/ARTIFACTS :=/' "$OW/target/linux/msm89xx/image/msm8916.mk"
if grep -q 'ARTIFACTS := squashfs-gpt_both0.bin' "$OW/target/linux/msm89xx/image/msm8916.mk"; then
  echo "Refusing unsafe artifact generator" >&2
  exit 1
fi
sudo -E bash "$UP/devenv/dependencies.sh"
cd "$OW"
./scripts/feeds update -a
./scripts/feeds install -a
make defconfig
grep -q '^CONFIG_TARGET_msm89xx_msm8916_DEVICE_generic-mf68e=y$' .config
make download -j4
make -j2 || make -j1 V=s
printf 'OPENWRT_REFERENCE_BUILD_SUCCEEDED\n%s\n%s\n' "$PIN_UP" "$PIN_OW" > "$ROOT/output/REFERENCE_BUILD_STATUS.txt"
# Keep diagnostic manifests only; images are excluded on purpose.
find bin/targets/msm89xx -type f -name '*.manifest' -exec cp '{}' "$ROOT/output/" ';' || true
echo "Build finished. Reference results are NOT for flashing on JZ08."
