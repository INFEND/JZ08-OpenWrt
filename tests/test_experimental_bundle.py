"""Fail-closed tests for the unified NOT-FLASHABLE JZ08 inspection bundle."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ci"))
import package_jz08_experiment as bundle


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class EngineeringBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.source = base / "repo"
        self.openwrt = base / "openwrt"
        output = self.source / "output"
        output.mkdir(parents=True)
        board = self.source / "board"
        board.mkdir()
        (board / "msm8916.mk.append").write_text(
            "CMDLINE := root=PARTLABEL=jz08-unconfigured-rootfs\n")
        target = self.openwrt / "bin/targets/msm89xx/msm8916"
        target.mkdir(parents=True)
        boot = target / "openwrt-jz08-boot.img"
        raw_boot = bytearray(8192)
        raw_boot[:8] = b"ANDROID!"
        raw_boot[8:12] = (4096).to_bytes(4, "little")
        raw_boot[36:40] = (2048).to_bytes(4, "little")
        boot.write_bytes(raw_boot)
        system = target / "openwrt-jz08-system.img"
        squash = bytearray(8192)
        squash[:4] = b"hsqs"
        squash[4:8] = (1).to_bytes(4, "little")
        squash[12:16] = (131072).to_bytes(4, "little")
        squash[28:30] = (4).to_bytes(2, "little")
        squash[40:48] = (4096).to_bytes(8, "little")
        system.write_bytes(squash)
        (target / "openwrt-jz08.manifest").write_text("luci - 1\nmodemmanager - 1\n")
        dtb = self.openwrt / (
            "build_dir/target-aarch64_generic_musl/linux-msm89xx_msm8916/"
            "image-msm8916-generic-jz08-3000-nkv.dtb")
        dtb.parent.mkdir(parents=True)
        fdt = bytearray(1024)
        fdt[:4] = bytes.fromhex("d00dfeed")
        fdt[4:8] = (1024).to_bytes(4, "big")
        fdt[64:64 + len(b"xarkon,jz08-3000-nkv\x00")] = b"xarkon,jz08-3000-nkv\x00"
        dtb.write_bytes(fdt)
        initramfs = target / "openwrt-jz08-initramfs-kernel.bin"
        initramfs.write_bytes(b"\x1f\x8b" + bytes(8190))
        candidate = bytearray(2048 + initramfs.stat().st_size)
        candidate[:8] = b"ANDROID!"
        candidate[8:12] = initramfs.stat().st_size.to_bytes(4, "little")
        candidate[36:40] = (2048).to_bytes(4, "little")
        candidate[64:64 + len(b"rdinit=/init")] = b"rdinit=/init"
        (output / "JZ08_RAM_ONLY_INITRAMFS_CANDIDATE.img").write_bytes(candidate)
        self.audit = {
            "status": "BUILD_CHECKS_PASS_ONLY", "errors": [],
            "flash_allowed": False, "hardware_tested": False,
            "required_packages": ["luci", "modemmanager"],
            "found_packages": ["luci", "modemmanager"],
            "build_images": [
                {"path": boot.relative_to(self.openwrt).as_posix(),
                 "size": boot.stat().st_size, "sha256": digest(boot),
                 "header_verified": True},
                {"path": system.relative_to(self.openwrt).as_posix(),
                 "size": system.stat().st_size, "sha256": digest(system),
                 "header_verified": True},
            ],
            "dtb": [{"path": dtb.relative_to(self.openwrt).as_posix(),
                     "sha256": digest(dtb), "verified_fdt_compatible": True}],
        }
        self.runtime = {
            "status": "OFFLINE_USERSPACE_CHECK_PASS_ONLY", "errors": [],
            "flash_allowed": False,
            "required_elf": {"/sbin/init": {"valid": True},
                             "/bin/busybox": {"valid": True}},
            "required_assets": {
                "/usr/lib/lua/luci/i18n/base.ru.lmo": {"valid": True, "size": 100}},
            "observed_paths_not_boot_proof": {
                name: {"present": True} for name in bundle.REQUIRED_OBSERVED},
        }
        self.output = output
        self.save()

    def save(self):
        (self.output / "JZ08_BUILD_AUDIT.json").write_text(json.dumps(self.audit))
        (self.output / "JZ08_ROOTFS_RUNTIME_AUDIT.json").write_text(
            json.dumps(self.runtime))
        (self.output / "JZ08_ROOTFS_CONTENTS_STATUS.txt").write_text("PASS\n")

    def test_complete_bundle_verified_and_not_flashable(self):
        bundle.assemble(self.source, self.openwrt)
        path = self.output / bundle.BUNDLE_NAME
        self.assertTrue(path.is_file())
        with zipfile.ZipFile(path) as archive:
            self.assertIsNone(archive.testzip())
            names = set(archive.namelist())
            for name in ("images/boot.img", "images/system.img",
                         "images/kernel-from-boot.bin",
                         "images/initramfs-kernel.bin",
                         "images/RAM_ONLY_INITRAMFS_CANDIDATE.img",
                         "images/msm8916-generic-jz08-3000-nkv.dtb",
                         "SHA256SUMS", "MANIFEST.json", "README_FIRST_RU.txt"):
                self.assertIn(name, names)
            self.assertEqual(len(archive.read("images/kernel-from-boot.bin")), 4096)
            metadata = json.loads(archive.read("MANIFEST.json"))
            self.assertFalse(metadata["flash_allowed"])
            self.assertFalse(metadata["full_device_boot_ready"])
        self.assertIn(digest(path),
                      (self.output / (bundle.BUNDLE_NAME + ".sha256")).read_text())

    def test_changed_image_rejected(self):
        path = self.openwrt / self.audit["build_images"][0]["path"]
        path.write_bytes(path.read_bytes() + b"tampered")
        with self.assertRaisesRegex(ValueError, "image audit mismatch"):
            bundle.assemble(self.source, self.openwrt)

    def test_missing_initramfs_rejected(self):
        path = next((self.openwrt / "bin/targets/msm89xx/msm8916").glob(
            "*jz08*initramfs-kernel.bin"))
        path.unlink()
        with self.assertRaisesRegex(ValueError, "initramfs kernel"):
            bundle.assemble(self.source, self.openwrt)

    def test_missing_russian_catalog_rejected(self):
        self.runtime["required_assets"].clear()
        self.save()
        with self.assertRaisesRegex(ValueError, "Russian LuCI assets"):
            bundle.assemble(self.source, self.openwrt)

    def test_missing_modem_service_rejected(self):
        self.runtime["observed_paths_not_boot_proof"]["/usr/sbin/ModemManager"]["present"] = False
        self.save()
        with self.assertRaisesRegex(ValueError, "rootfs service missing"):
            bundle.assemble(self.source, self.openwrt)

    def test_changed_root_partition_assumption_rejected(self):
        (self.source / "board/msm8916.mk.append").write_text("CMDLINE := root=/dev/mmcblk0p14\n")
        with self.assertRaisesRegex(ValueError, "rootfs partition changed"):
            bundle.assemble(self.source, self.openwrt)


if __name__ == "__main__":
    unittest.main()
