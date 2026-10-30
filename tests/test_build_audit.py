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
        compatible = b"xarkon,jz08-3000-nkv\\x00"
        dtb[64:64 + len(compatible)] = compatible
        (dtbdir / "image-msm8916-generic-jz08-3000-nkv.dtb").write_bytes(dtb)
        (self.targets / "openwrt-jz08.manifest").write_text(
            "".join(f"{pkg} - 1.0\\n" for pkg in sorted(audit.MUST_HAVE))
        )
        (self.root / ".config").write_text(
            "CONFIG_TARGET_msm89xx_msm8916_DEVICE_generic-jz08-3000-nkv=y\\n"
        )
        self.log = self.root / "kconfig.log"
        self.log.write_text("Kconfig passed\\n")
        self.boot = self.targets / "openwrt-jz08-boot.img"
        self.system = self.targets / "openwrt-jz08-system.img"
        self.boot.write_bytes(b"ANDROID!" + bytes(4096))
        self.system.write_bytes(bytes.fromhex("3aff26ed") + bytes(4096))

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

    def test_missing_essential_package_is_rejected(self):
        manifest = self.targets / "openwrt-jz08.manifest"
        manifest.write_text(
            "".join(f"{pkg} - 1.0\\n" for pkg in sorted(audit.MUST_HAVE - {"rmtfs"}))
        )
        report = self.run_audit()
        self.assertTrue(any("rmtfs" in e for e in report["errors"]))


if __name__ == "__main__":
    unittest.main()
