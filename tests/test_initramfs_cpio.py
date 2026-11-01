"""Synthetic newc regression tests for RAM-only OpenWrt initramfs audit."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ci"))
import audit_initramfs_cpio as cpio


def newc(name, data=b"ok", mode=0o100755):
    encoded = name.encode() + b"\x00"
    fields = (1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0)
    header = b"070701" + b"".join(("{:08x}".format(n)).encode() for n in fields)
    result = header + encoded
    result += bytes((-len(result)) % 4)
    result += data
    result += bytes((-len(result)) % 4)
    return result


class InitramfsAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "initrd.cpio"

    def write(self, omit=()):
        payload = b"".join(newc(name) for name in cpio.REQUIRED if name not in omit)
        payload += newc("TRAILER!!!", b"", mode=0)
        self.path.write_bytes(payload)

    def test_complete_cpio(self):
        self.write()
        result = cpio.audit(self.path)
        self.assertEqual(result["entries"], len(cpio.REQUIRED))
        self.assertFalse(result["flash_allowed"])
        self.assertFalse(result["linux_init_executed"])

    def test_missing_luci_catalog_fails(self):
        self.write(omit=("usr/lib/lua/luci/i18n/base.ru.lmo",))
        with self.assertRaisesRegex(ValueError, "incomplete initramfs"):
            cpio.audit(self.path)

    def test_directory_named_as_required_executable_fails(self):
        for name in ("init", "usr/sbin/ModemManager", "usr/sbin/rmtfs",
                     "www/cgi-bin/luci"):
            with self.subTest(name=name):
                self.write(omit=(name,))
                payload = self.path.read_bytes()
                payload = newc(name, b"", mode=0o040755) + payload
                self.path.write_bytes(payload)
                with self.assertRaisesRegex(ValueError, "not a regular file"):
                    cpio.audit(self.path)

    def test_required_executable_without_execute_bit_fails(self):
        self.write(omit=("usr/sbin/ModemManager",))
        payload = newc("usr/sbin/ModemManager", b"ELF", mode=0o100644)
        self.path.write_bytes(payload + self.path.read_bytes())
        with self.assertRaisesRegex(ValueError, "execute bit"):
            cpio.audit(self.path)

    def test_valid_required_symlink_to_regular_executable(self):
        self.write(omit=("init",))
        payload = newc("init", b"sbin/init", mode=0o120777)
        self.path.write_bytes(payload + self.path.read_bytes())
        self.assertEqual(cpio.audit(self.path)["entries"], len(cpio.REQUIRED))

    def test_broken_required_symlink_fails(self):
        self.write(omit=("init",))
        payload = newc("init", b"missing/executable", mode=0o120777)
        self.path.write_bytes(payload + self.path.read_bytes())
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            cpio.audit(self.path)

    def test_required_symlink_escape_fails(self):
        self.write(omit=("init",))
        payload = newc("init", b"../outside", mode=0o120777)
        self.path.write_bytes(payload + self.path.read_bytes())
        with self.assertRaisesRegex(ValueError, "escapes archive root"):
            cpio.audit(self.path)

    def test_required_symlink_loop_fails(self):
        self.write(omit=("init",))
        payload = newc("init", b"init", mode=0o120777)
        self.path.write_bytes(payload + self.path.read_bytes())
        with self.assertRaisesRegex(ValueError, "symlink loop"):
            cpio.audit(self.path)

    def test_invalid_magic_fails(self):
        self.write()
        self.path.write_bytes(b"BADBAD" + self.path.read_bytes()[6:])
        with self.assertRaisesRegex(ValueError, "invalid newc header"):
            cpio.audit(self.path)

    def test_truncated_cpio_fails(self):
        self.write()
        self.path.write_bytes(self.path.read_bytes()[:-150])
        with self.assertRaises(ValueError):
            cpio.audit(self.path)


if __name__ == "__main__":
    unittest.main()
