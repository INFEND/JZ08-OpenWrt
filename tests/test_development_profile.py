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
                "existing pinned source patch\\n")
            (target / "image/msm8916.mk").write_text(
                "ifeq ($(SUBTARGET),msm8916)\\nendif\\n")
            (up / "diffconfig_mf68e").write_text(
                "CONFIG_TARGET_msm89xx_msm8916_DEVICE_generic-mf68e=y\\n"
                "CONFIG_PACKAGE_luci=y\\nCONFIG_PACKAGE_modemmanager=y\\n"
                "CONFIG_PACKAGE_router-display=y\\n"
                "CONFIG_PACKAGE_kmod-fbtft-gc9107=y\\n")
            prepare.run(up, ow)
            config = (ow / ".config").read_text()
            for pkg in ("luci", "luci-base", "luci-i18n-base-ru", "modemmanager"):
                self.assertEqual(config.count(f"CONFIG_PACKAGE_{pkg}=y"), 1)
            self.assertIn("CONFIG_TARGET_msm89xx_msm8916_DEVICE_generic-jz08-3000-nkv=y", config)
            self.assertNotIn("CONFIG_PACKAGE_router-display=y", config)
            patch = (target / "patches-6.12/809-arm64-dts-jz08-prototype.patch").read_text()
            self.assertIn("msm8916-generic-jz08-3000-nkv.dtb", patch)
            self.assertIn('status = "disabled"', patch)
            self.assertIn("msm8916-generic-jz08-3000-nkv.dts", patch)


if __name__ == "__main__":
    unittest.main()
