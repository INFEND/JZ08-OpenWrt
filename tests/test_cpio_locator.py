"""Ensure kernel-generated initramfs CPIO is located in both OpenWrt modes."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ci"))
from locate_initramfs_cpio import locate


class LocateInitramfsCpioTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.openwrt = Path(self.tmp.name)
        self.kernel_build = (
            self.openwrt / "build_dir/target-aarch64_generic_musl/"
            "linux-msm89xx_msm8916"
        )
        self.kernel_build.mkdir(parents=True)

    def make_cpio(self, relative):
        path = self.kernel_build / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"070701" + b"0" * 200)
        return path

    def test_normal_embedded_linux_initramfs(self):
        path = self.make_cpio("linux-6.12.52/usr/initramfs_data.cpio")
        self.assertEqual(locate(self.openwrt), path)

    def test_separate_openwrt_initramfs(self):
        path = self.make_cpio("initrd.cpio")
        self.assertEqual(locate(self.openwrt), path)

    def test_missing_cpio_rejected(self):
        with self.assertRaisesRegex(ValueError, "expected exactly one"):
            locate(self.openwrt)

    def test_ambiguous_cpio_rejected(self):
        self.make_cpio("initrd.cpio")
        self.make_cpio("linux-6.12.52/usr/initramfs_data.cpio")
        with self.assertRaisesRegex(ValueError, "found 2"):
            locate(self.openwrt)

    def test_invalid_cpio_rejected(self):
        self.make_cpio("linux-6.12.52/usr/initramfs_data.cpio").write_bytes(
            b"not a cpio" + b"0" * 200
        )
        with self.assertRaisesRegex(ValueError, "not raw newc"):
            locate(self.openwrt)


if __name__ == "__main__":
    unittest.main()
