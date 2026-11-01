"""Offline safeguards for the JZ08 build-only image profile."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("prepare_jz08", ROOT / "ci/prepare_jz08.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class DevelopmentProfile(unittest.TestCase):
    def test_image_profile_is_not_flashable(self):
        text = (ROOT / "board/msm8916.mk.append").read_text()
        self.assertIn("DEVICE_DTS := msm8916-generic-jz08-3000-nkv", text)
        self.assertIn("ARTIFACTS :=", text)
        self.assertIn("root=PARTLABEL=jz08-unconfigured-rootfs", text)
        for pkg in ("luci", "luci-base", "luci-i18n-base-ru", "modemmanager"):
            self.assertIn(pkg, text)
        for forbidden in ("prepare-rootfs-data", "msm-firmware-dumper"):
            self.assertNotIn(forbidden, text)

    def test_rootfs_content_audit_uses_supported_strict_extraction(self):
        script = (ROOT / "ci/build-jz08-development.sh").read_text()
        self.assertNotIn("unsquashfs -test", script)
        self.assertIn("unsquashfs -strict-errors -no-progress -no-xattrs", script)
        self.assertIn('-dest "$ROOTFS_EXTRACT" "$ROOTFS_RAW"', script)
        self.assertIn('simg2img "$ROOTFS_IMAGE" "$ROOTFS_RAW"', script)
        # mktemp -d must create only the parent; unsquashfs -dest must not exist.
        self.assertIn('ROOTFS_TMP="$(mktemp -d /tmp/jz08-rootfs-files.XXXXXXXX)"', script)
        self.assertIn('ROOTFS_EXTRACT="$ROOTFS_TMP/rootfs"', script)
        self.assertIn('trap \'sudo -n rm -rf -- "$ROOTFS_TMP"; rm -f -- "$ROOTFS_RAW"\' EXIT', script)
        self.assertIn('sudo -n rm -rf -- "$ROOTFS_TMP"', script)
        self.assertNotIn('mkdir -p "$ROOTFS_EXTRACT"', script)
        self.assertIn('flash_allowed=false', script)
        self.assertIn(
            '\npython3 "$ROOT/ci/audit_rootfs_runtime.py" --root "$ROOTFS_EXTRACT" '
            '--output "$ROOT/output/JZ08_ROOTFS_RUNTIME_AUDIT.json"\n', script)
        workflow = (ROOT / ".github/workflows/jz08-development.yml").read_text()
        self.assertIn("\n      - ci/audit_rootfs_runtime.py\n", workflow)

    def test_prepare_adds_dtb_patch_and_required_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            up = base / "upstream"
            ow = base / "openwrt"
            target = ow / "target/linux/msm89xx"
            (target / "patches-6.12").mkdir(parents=True)
            (target / "image").mkdir()
            up.mkdir()
            (target / "patches-6.12/801-arm64-dts-qcom-add-devices-makefile.patch").write_text(
                "existing pinned source patch\n")
            (target / "image/msm8916.mk").write_text(
                "ifeq ($(SUBTARGET),msm8916)\nendif\n")
            (up / "diffconfig_mf68e").write_text(
                "CONFIG_TARGET_msm89xx_msm8916_DEVICE_generic-mf68e=y\n"
                "CONFIG_PACKAGE_luci=y\nCONFIG_PACKAGE_modemmanager=y\n"
                "CONFIG_PACKAGE_router-display=y\n"
                "CONFIG_PACKAGE_kmod-fbtft-gc9107=y\n")
            prepare.run(up, ow)
            config = (ow / ".config").read_text()
            for pkg in ("luci", "luci-base", "luci-i18n-base-ru", "modemmanager"):
                self.assertEqual(config.count(f"CONFIG_PACKAGE_{pkg}=y"), 1)
            self.assertIn("CONFIG_TARGET_msm89xx_msm8916_DEVICE_generic-jz08-3000-nkv=y", config)
            self.assertIn("CONFIG_TARGET_ROOTFS_INITRAMFS=y", config)
            self.assertNotIn("CONFIG_PACKAGE_router-display=y", config)
            self.assertNotIn("CONFIG_PACKAGE_prepare-rootfs-data=y", config)
            self.assertNotIn("CONFIG_PACKAGE_msm-firmware-dumper=y", config)
            patch = (target / "patches-6.12/809-arm64-dts-jz08-prototype.patch").read_text()
            self.assertIn("msm8916-generic-jz08-3000-nkv.dtb", patch)
            self.assertIn('status = "disabled"', patch)
            self.assertIn("msm8916-generic-jz08-3000-nkv.dts", patch)


if __name__ == "__main__":
    unittest.main()
