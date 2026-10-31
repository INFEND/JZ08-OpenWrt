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
