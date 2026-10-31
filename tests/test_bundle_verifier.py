"""Synthetic, offline tests for independent JZ08 ZIP content verification."""
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ci"))
from verify_jz08_bundle import (REQUIRED, verify, require_matching_rootfs_audit,
                                require_kernel_appended_dtb)


class IndependentBundleVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.archive = base / "JZ08_EXPERIMENTAL_INSPECTION_NOT_FLASHABLE.zip"
        self.sha = base / (self.archive.name + ".sha256")
        self.report = base / "JZ08_BUNDLE_VERIFICATION.json"
        self.members = {
            name: ("synthetic fixture: " + name).encode()
            for name in REQUIRED - {"MANIFEST.json", "SHA256SUMS"}
        }
        self.manifest = {
            "board": "JZ08-3000-NKV 1.0",
            "status": "NOT_FLASHABLE",
            "flash_allowed": False,
            "hardware_tested": False,
            "full_device_boot_ready": False,
            "boot_blockers": ["synthetic test: no hardware validation"],
        }
        self.build()

    def build(self):
        binary = REQUIRED - {"MANIFEST.json", "SHA256SUMS", "README_FIRST_RU.txt"}
        self.manifest["files"] = {
            name: {"sha256": hashlib.sha256(self.members[name]).hexdigest(),
                   "bytes": len(self.members[name])}
            for name in binary if name in self.members
        }
        self.members["MANIFEST.json"] = (
            json.dumps(self.manifest).encode() + b"\n"
        )
        sums = {
            name: hashlib.sha256(content).hexdigest()
            for name, content in self.members.items() if name != "SHA256SUMS"
        }
        self.members["SHA256SUMS"] = "".join(
            f"{value}  {name}\n" for name, value in sorted(sums.items())
        ).encode()
        with zipfile.ZipFile(self.archive, "w") as zf:
            for name, content in sorted(self.members.items()):
                zf.writestr(name, content)
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.sha.write_text(f"{digest}  {self.archive.name}\n")
        self.report.write_text(json.dumps({
            "status": "ARCHIVE_VERIFIED_NOT_FLASHABLE",
            "archive": self.archive.name,
            "sha256": digest,
            "members": len(self.members),
            "flash_allowed": False,
            "hardware_tested": False,
            "full_device_boot_ready": False,
        }))

    def test_kernel_payload_has_exact_appended_board_dtb(self):
        kernel = Path(self.tmp.name) / "kernel.bin"
        board_dtb = bytes.fromhex("d00dfeed") + b"JZ08-BOARD-DTB"
        kernel.write_bytes(gzip.compress(b"K" * 8192) + board_dtb)
        result = require_kernel_appended_dtb(kernel, board_dtb)
        self.assertEqual(result["appended_jz08_dtb_bytes"], len(board_dtb))
        self.assertEqual(result["gzip_uncompressed_bytes"], 8192)

    def test_kernel_payload_rejects_missing_or_wrong_appended_dtb(self):
        kernel = Path(self.tmp.name) / "kernel.bin"
        board_dtb = bytes.fromhex("d00dfeed") + b"JZ08-BOARD-DTB"
        for trailer in (b"", b"WRONG", board_dtb + b"EXTRA"):
            with self.subTest(trailer=trailer):
                kernel.write_bytes(gzip.compress(b"K" * 8192) + trailer)
                with self.assertRaisesRegex(ValueError, "exact published JZ08 DTB"):
                    require_kernel_appended_dtb(kernel, board_dtb)

    def test_kernel_payload_rejects_corrupt_or_truncated_gzip(self):
        kernel = Path(self.tmp.name) / "kernel.bin"
        board_dtb = bytes.fromhex("d00dfeed") + b"JZ08-BOARD-DTB"
        kernel.write_bytes(gzip.compress(b"K" * 8192)[:-8] + board_dtb)
        with self.assertRaises(ValueError):
            require_kernel_appended_dtb(kernel, board_dtb)

    def test_valid_complete_archive(self):
        result = verify(self.archive, self.sha, self.report, inspect_payloads=False)
        self.assertFalse(result["flash_allowed"])
        self.assertEqual(result["members"], len(REQUIRED))

    def test_deep_audit_rejects_synthetic_binaries_even_when_hashes_match(self):
        # Metadata-only validation is insufficient: the payloads here are
        # deliberately synthetic, despite having matching SHA256SUMS.
        with self.assertRaisesRegex(ValueError, "Android boot image"):
            verify(self.archive, self.sha, self.report, inspect_payloads=True)

    def test_missing_required_member(self):
        self.members.pop("images/initrd.cpio")
        self.build()
        with self.assertRaisesRegex(ValueError, "required ZIP member"):
            verify(self.archive, self.sha, self.report, inspect_payloads=False)

    def test_bad_member_checksum(self):
        self.build()
        with zipfile.ZipFile(self.archive, "a") as zf:
            zf.writestr("EXTRA", "bad")
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.sha.write_text(f"{digest}  {self.archive.name}\n")
        report = json.loads(self.report.read_text())
        report["sha256"] = digest
        report["members"] += 1
        self.report.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "required ZIP member"):
            verify(self.archive, self.sha, self.report, inspect_payloads=False)

    def test_modified_member_with_stale_checksums(self):
        self.members["images/initrd.cpio"] = b"changed contents"
        self.build()
        # Keep valid outer hashes but inject an intentionally stale inner sum.
        old = self.members["SHA256SUMS"].decode()
        current = hashlib.sha256(b"changed contents").hexdigest()
        self.members["SHA256SUMS"] = old.replace(current, "0" * 64).encode()
        self.build_with_current_sums()
        with self.assertRaisesRegex(ValueError, "differs from SHA256SUMS"):
            verify(self.archive, self.sha, self.report, inspect_payloads=False)

    def build_with_current_sums(self):
        with zipfile.ZipFile(self.archive, "w") as zf:
            for name, content in sorted(self.members.items()):
                zf.writestr(name, content)
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.sha.write_text(f"{digest}  {self.archive.name}\n")
        report = json.loads(self.report.read_text())
        report["sha256"] = digest
        self.report.write_text(json.dumps(report))

    def test_unsafe_manifest_rejected(self):
        self.manifest["flash_allowed"] = True
        self.build()
        with self.assertRaisesRegex(ValueError, "unsafe or incomplete"):
            verify(self.archive, self.sha, self.report, inspect_payloads=False)

    def test_external_checksum_rejected(self):
        self.sha.write_text("0" * 64 + "  " + self.archive.name + "\n")
        with self.assertRaisesRegex(ValueError, "external SHA256"):
            verify(self.archive, self.sha, self.report, inspect_payloads=False)


    def test_independent_rootfs_audit_must_match_actual_bytes(self):
        actual = {
            "status": "OFFLINE_USERSPACE_CHECK_PASS_ONLY",
            "flash_allowed": False,
            "hardware_tested": False,
            "rootfs_executed": False,
            "errors": [],
            "required_elf": {
                "/sbin/init": {"valid": True, "sha256": "a" * 64}
            },
            "required_assets": {
                "/usr/lib/lua/luci/i18n/base.ru.lmo":
                    {"valid": True, "size": 512, "sha256": "b" * 64}
            },
            "observed_paths_not_boot_proof": {
                "/usr/sbin/ModemManager": {"present": True, "type": "file"}
            },
        }
        require_matching_rootfs_audit(actual, dict(actual))
        import copy
        for section, key, value in (
            ("required_elf", "/sbin/init", {"valid": True, "sha256": "c" * 64}),
            ("required_assets", "/usr/lib/lua/luci/i18n/base.ru.lmo",
             {"valid": True, "size": 512, "sha256": "d" * 64}),
            ("observed_paths_not_boot_proof", "/usr/sbin/ModemManager",
             {"present": False, "type": "missing"}),
        ):
            claimed = copy.deepcopy(actual)
            claimed[section][key] = value
            with self.subTest(section=section), self.assertRaisesRegex(
                    ValueError, "differs from extracted system.img"):
                require_matching_rootfs_audit(actual, claimed)

    def test_independent_rootfs_audit_rejects_failed_actual_rootfs(self):
        actual = {
            "status": "REJECTED_USERSPACE",
            "flash_allowed": False,
            "hardware_tested": False,
            "rootfs_executed": False,
            "errors": ["missing Russian LuCI"],
        }
        with self.assertRaisesRegex(ValueError, "fails runtime checks"):
            require_matching_rootfs_audit(actual, actual)


if __name__ == "__main__":
    unittest.main()
