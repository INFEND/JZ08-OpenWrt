"""Offline regression tests for compiled JZ08 artifact checks (no device access)."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "check_built_jz08", ROOT / "ci/check_built_jz08.py"
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class BuiltImageAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.targets = self.root / "bin/targets/msm89xx/msm8916"
        self.targets.mkdir(parents=True)
        dtbdir = self.root / "build_dir/target-aarch64_generic_musl/linux-msm89xx_msm8916"
        dtbdir.mkdir(parents=True)
        dtb = bytearray(1024)
        dtb[:4] = bytes.fromhex("d00dfeed")
        dtb[4:8] = (1024).to_bytes(4, "big")
        compatible = b"xarkon,jz08-3000-nkv\x00"
        dtb[64:64 + len(compatible)] = compatible
        (dtbdir / "image-msm8916-generic-jz08-3000-nkv.dtb").write_bytes(dtb)
        (self.targets / "openwrt-jz08.manifest").write_text(
            "".join(f"{pkg} - 1.0\n" for pkg in sorted(audit.MUST_HAVE))
        )
        (self.root / ".config").write_text(
            "CONFIG_TARGET_msm89xx_msm8916_DEVICE_generic-jz08-3000-nkv=y\n"
        )
        self.log = self.root / "kconfig.log"
        self.log.write_text("Kconfig passed\n")
        self.boot = self.targets / "openwrt-jz08-boot.img"
        self.system = self.targets / "openwrt-jz08-system.img"
        self.boot.write_bytes(b"ANDROID!" + bytes(4096))
        # Minimal internally consistent SquashFS v4 superblock fixture.
        squashfs = bytearray(4096 + 96)
        squashfs[:4] = b"hsqs"  # SquashFS LE, not Android sparse magic
        squashfs[4:8] = (1).to_bytes(4, "little")  # inode_count
        squashfs[12:16] = (131072).to_bytes(4, "little")  # block_size
        squashfs[28:30] = (4).to_bytes(2, "little")  # s_major
        squashfs[40:48] = (4096).to_bytes(8, "little")  # bytes_used
        self.system.write_bytes(squashfs)

    def run_audit(self):
        with self.assertRaises(SystemExit) as caught:
            audit.check(ROOT, self.log, self.root)
        self.assertEqual(caught.exception.code, 1)
        return json.loads((ROOT / "output/JZ08_BUILD_AUDIT.json").read_text())

    def test_complete_synthetic_build_passes(self):
        audit.check(ROOT, self.log, self.root)
        report = json.loads((ROOT / "output/JZ08_BUILD_AUDIT.json").read_text())
        self.assertEqual(report["status"], "BUILD_CHECKS_PASS_ONLY")
        self.assertEqual(report["errors"], [])
        self.assertFalse(report["flash_allowed"])
        self.assertFalse(report["hardware_tested"])
        self.assertEqual(len(report["build_images"]), 2)
        self.assertTrue(all(x["header_verified"] for x in report["build_images"]))
        self.assertTrue(all(x["published"] is False for x in report["build_images"]))
        self.assertTrue(any(x["verified_fdt_compatible"] for x in report["dtb"]))

    def test_missing_rootfs_is_rejected(self):
        self.system.unlink()
        report = self.run_audit()
        self.assertEqual(report["status"], "REJECTED_DEVELOPMENT_BUILD")
        self.assertTrue(any("system.img" in e for e in report["errors"]))

    def test_invalid_boot_header_is_rejected(self):
        self.boot.write_bytes(b"BROKEN!!" + bytes(4096))
        report = self.run_audit()
        self.assertTrue(any("boot.img" in e and "header" in e for e in report["errors"]))

    def test_invalid_squashfs_version_is_rejected(self):
        image = bytearray(self.system.read_bytes())
        image[28:30] = (3).to_bytes(2, "little")
        self.system.write_bytes(image)
        report = self.run_audit()
        self.assertTrue(any("system.img" in e and "superblock" in e for e in report["errors"]))

    def test_truncated_squashfs_bytes_used_is_rejected(self):
        image = bytearray(self.system.read_bytes())
        image[40:48] = (1000000).to_bytes(8, "little")
        self.system.write_bytes(image)
        report = self.run_audit()
        self.assertTrue(any("system.img" in e and "superblock" in e for e in report["errors"]))

    def test_squashfs_failure_reports_exact_metadata_without_weakening_gate(self):
        image = bytearray(self.system.read_bytes())
        image[40:48] = (1000000).to_bytes(8, "little")
        self.system.write_bytes(image)
        report = self.run_audit()
        self.assertTrue(any("bytes_used_range" in error for error in report["errors"]))
        record = next(x for x in report["build_images"] if x["path"].endswith("system.img"))
        self.assertFalse(record["header_verified"])
        self.assertEqual(record["squashfs_superblock"]["bytes_used"], 1000000)
        self.assertEqual(record["squashfs_superblock"]["file_size"], len(image))
        self.assertEqual(record["squashfs_superblock"]["failed_checks"], ["bytes_used_range"])
        self.assertFalse(record["published"])

    def test_valid_squashfs_reports_structural_fields(self):
        audit.check(ROOT, self.log, self.root)
        report = json.loads((ROOT / "output/JZ08_BUILD_AUDIT.json").read_text())
        record = next(x for x in report["build_images"] if x["path"].endswith("system.img"))
        self.assertTrue(record["squashfs_superblock"]["valid"])
        self.assertEqual(record["squashfs_superblock"]["major"], 4)
        self.assertEqual(record["squashfs_superblock"]["minor"], 0)
        self.assertEqual(record["squashfs_superblock"]["failed_checks"], [])

    def _make_sparse_system(self, *, truncate=False, corrupt_chunk=False, hole=False):
        import struct
        raw = self.system.read_bytes()
        block_size = 4096
        padded = raw + bytes((-len(raw)) % block_size)
        blocks = len(padded) // block_size
        chunks = 2 if hole else 1
        header = struct.pack("<I4H4I", 0xED26FF3A, 1, 0, 28, 12,
                             block_size, blocks + int(hole), chunks, 0)
        chunk = struct.pack("<2H2I", 0xCAC1, 0, blocks,
                            12 + len(padded) + int(corrupt_chunk))
        content = header + chunk + padded
        if hole:
            content += struct.pack("<2H2I", 0xCAC3, 0, 1, 12)
        if truncate:
            content = content[:-1]
        self.system.write_bytes(content)

    def test_android_sparse_squashfs_is_validated(self):
        self._make_sparse_system()
        audit.check(ROOT, self.log, self.root)
        report = json.loads((ROOT / "output/JZ08_BUILD_AUDIT.json").read_text())
        system = next(x for x in report["build_images"] if x["path"].endswith("system.img"))
        self.assertTrue(system["header_verified"])
        self.assertEqual(system["squashfs_superblock"]["container"], "android_sparse")
        self.assertEqual(system["squashfs_superblock"]["squashfs_superblock"]["major"], 4)

    def test_android_sparse_rejects_invalid_inner_squashfs(self):
        raw = bytearray(self.system.read_bytes())
        raw[28:30] = (3).to_bytes(2, "little")
        self.system.write_bytes(raw)
        self._make_sparse_system()
        report = self.run_audit()
        system = next(x for x in report["build_images"] if x["path"].endswith("system.img"))
        self.assertIn("squashfs_squashfs_v4", system["squashfs_superblock"]["failed_checks"])

    def test_truncated_android_sparse_image_is_rejected(self):
        self._make_sparse_system(truncate=True)
        report = self.run_audit()
        system = next(x for x in report["build_images"] if x["path"].endswith("system.img"))
        self.assertIn("invalid_chunk_size", system["squashfs_superblock"]["failed_checks"])

    def test_bad_android_sparse_chunk_length_is_rejected(self):
        self._make_sparse_system(corrupt_chunk=True)
        report = self.run_audit()
        system = next(x for x in report["build_images"] if x["path"].endswith("system.img"))
        self.assertIn("invalid_chunk_size", system["squashfs_superblock"]["failed_checks"])

    def test_sparse_hole_after_filesystem_is_allowed(self):
        self._make_sparse_system(hole=True)
        audit.check(ROOT, self.log, self.root)

    def test_missing_essential_package_is_rejected(self):
        manifest = self.targets / "openwrt-jz08.manifest"
        manifest.write_text(
            "".join(f"{pkg} - 1.0\n" for pkg in sorted(audit.MUST_HAVE - {"rmtfs"}))
        )
        report = self.run_audit()
        self.assertTrue(any("rmtfs" in e for e in report["errors"]))


if __name__ == "__main__":
    unittest.main()
