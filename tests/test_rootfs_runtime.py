"""Synthetic tests for JZ08 rootfs ELF and symlink audit (no device I/O)."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("audit_rootfs_runtime", ROOT / "ci/audit_rootfs_runtime.py")
audit_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_module)


def fake_elf(machine=183, interpreter=None):
    phnum = 2 if interpreter else 1
    payload_offset = 64 + 56 * phnum
    data = bytearray(payload_offset + (len(interpreter) + 1 if interpreter else 0) + 8)
    data[:4] = b"\x7fELF"
    data[4:7] = b"\x02\x01\x01"
    struct.pack_into("<HH", data, 16, 2, machine)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, phnum)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, payload_offset, 0, 0, 8, 8, 4096)
    if interpreter:
        struct.pack_into("<IIQQQQQQ", data, 120, 3, 4, payload_offset, 0, 0,
                         len(interpreter) + 1, len(interpreter) + 1, 1)
        data[payload_offset:payload_offset + len(interpreter) + 1] = interpreter.encode() + b"\x00"
    return bytes(data)


class RootfsRuntimeAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "bin").mkdir()
        (self.root / "sbin").mkdir()
        (self.root / "sbin/procd").write_bytes(fake_elf())
        (self.root / "sbin/procd").chmod(0o755)
        (self.root / "sbin/init").symlink_to("/sbin/procd")
        (self.root / "bin/busybox").write_bytes(fake_elf())
        (self.root / "bin/busybox").chmod(0o755)
        # Real pinned LuCI translation location (not /www/luci-static).
        translation = self.root / "usr/lib/lua/luci/i18n/base.ru.lmo"
        translation.parent.mkdir(parents=True)
        translation.write_bytes(b"synthetic-nonempty-lmo")

    def test_valid_offline_userspace_stays_not_flashable(self):
        report = audit_module.audit(self.root)
        self.assertEqual(report["status"], "OFFLINE_USERSPACE_CHECK_PASS_ONLY")
        self.assertEqual(report["errors"], [])
        self.assertFalse(report["flash_allowed"])
        self.assertFalse(report["hardware_tested"])
        self.assertFalse(report["rootfs_executed"])
        self.assertEqual(report["required_elf"]["/sbin/init"]["resolved_path"], "/sbin/procd")
        self.assertTrue(report["required_assets"]["/usr/lib/lua/luci/i18n/base.ru.lmo"]["valid"])

    def test_missing_russian_translation_rejected(self):
        (self.root / "usr/lib/lua/luci/i18n/base.ru.lmo").unlink()
        report = audit_module.audit(self.root)
        self.assertEqual(report["status"], "REJECTED_USERSPACE")
        self.assertTrue(any("translation asset is absent" in x for x in report["errors"]))
        self.assertFalse(report["flash_allowed"])

    def test_empty_russian_translation_rejected(self):
        (self.root / "usr/lib/lua/luci/i18n/base.ru.lmo").write_bytes(b"")
        report = audit_module.audit(self.root)
        self.assertEqual(report["status"], "REJECTED_USERSPACE")
        self.assertTrue(any("translation asset is empty" in x for x in report["errors"]))

    def test_wrong_architecture_rejected(self):
        (self.root / "bin/busybox").write_bytes(fake_elf(machine=40))
        report = audit_module.audit(self.root)
        self.assertEqual(report["status"], "REJECTED_USERSPACE")
        self.assertTrue(any("AArch64" in x for x in report["errors"]))

    def test_missing_init_rejected(self):
        (self.root / "sbin/init").unlink()
        report = audit_module.audit(self.root)
        self.assertTrue(any("/sbin/init" in x for x in report["errors"]))

    def test_symlink_escape_rejected(self):
        (self.root / "sbin/init").unlink()
        (self.root / "sbin/init").symlink_to("../../../etc/passwd")
        report = audit_module.audit(self.root)
        self.assertTrue(any("escapes" in x for x in report["errors"]))

    def test_nonexecutable_busybox_rejected(self):
        (self.root / "bin/busybox").chmod(0o644)
        report = audit_module.audit(self.root)
        self.assertTrue(any("execute bit" in x for x in report["errors"]))

    def test_oem_preinit_formatter_rejected(self):
        path = self.root / "lib/preinit/79-format-rootfs-data"
        path.parent.mkdir(parents=True)
        path.write_text("mkfs.ext4 -F /dev/mmcblk0p15")
        report = audit_module.audit(self.root)
        self.assertEqual(report["status"], "REJECTED_USERSPACE")
        self.assertFalse(report["known_storage_mutators_absent"])

    def test_rmtfs_autostart_rejected(self):
        path = self.root / "etc/rc.d/S15rmtfs"
        path.parent.mkdir(parents=True)
        path.symlink_to("../init.d/rmtfs")
        report = audit_module.audit(self.root)
        self.assertTrue(any("unsafe OEM/NV service autostart" in x for x in report["errors"]))

    def test_dynamic_loader_must_be_in_rootfs(self):
        (self.root / "bin/busybox").write_bytes(fake_elf(interpreter="/lib/ld-musl-aarch64.so.1"))
        report = audit_module.audit(self.root)
        self.assertTrue(any("interpreter is missing" in x for x in report["errors"]))
        (self.root / "lib").mkdir()
        (self.root / "lib/ld-musl-aarch64.so.1").write_bytes(b"loader")
        report = audit_module.audit(self.root)
        self.assertEqual(report["errors"], [])


if __name__ == "__main__":
    unittest.main()
