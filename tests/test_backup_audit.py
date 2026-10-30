"""Small synthetic GPT images; never use a real IMEI/NV/eMMC in CI."""
import hashlib
import importlib.util
import pathlib
import struct
import sys
import tempfile
import unittest
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("jz08_backup_audit", ROOT / "tools/jz08_backup_audit.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def fixture(path, *, p14="modemst2"):
    sectors = 128
    data = bytearray(sectors * 512)
    data[450] = 0xEE
    data[510:512] = b"\x55\xaa"
    table = bytearray(128 * 128)
    for i in range(1, 28):
        e = bytearray(128)
        e[:16] = bytes([i]) * 16
        e[16:32] = bytes([i + 1]) * 16
        struct.pack_into("<QQ", e, 32, 34 + (i - 1) * 2, 35 + (i - 1) * 2)
        labels = {14: p14, 22: "boot", 23: "system",
                  26: "recovery", 27: "userdata"}
        name = labels.get(i, "p" + str(i)).encode("utf-16-le")
        e[56:56+len(name)] = name
        table[(i - 1) * 128:i * 128] = e
    data[2*512:34*512] = table
    data[95*512:127*512] = table
    crc = zlib.crc32(table) & 0xffffffff
    for here, other, table_lba in [(1, 127, 2), (127, 1, 95)]:
        header = bytearray(audit.HEADER.pack(
            b"EFI PART", 0x00010000, 92, 0, 0, here, other,
            34, 94, b"\x01"*16, table_lba, 128, 128, crc))
        struct.pack_into("<I", header, 16, zlib.crc32(header) & 0xffffffff)
        data[here*512:here*512+len(header)] = header
    path.write_bytes(data)
    return len(data), hashlib.sha256(data).hexdigest()


class BackupAuditor(unittest.TestCase):
    def test_good_dual_gpt_and_sha(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "dummy.img"
            size, sha = fixture(p)
            r = audit.audit_image(p, expected_size=size, expected_sha=sha)
            self.assertEqual(r["status"], "LOCAL_BACKUP_VERIFIED")
            self.assertEqual(r["gpt_partitions"], 27)
            self.assertEqual(r["protected_partition_14"], "modemst2")
            self.assertFalse(r["flash_allowed"])

    def test_reject_wrong_nv_partition(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "dummy.img"
            size, sha = fixture(p, p14="rootfs")
            with self.assertRaisesRegex(audit.AuditError, "p14"):
                audit.audit_image(p, expected_size=size, expected_sha=sha)

    def test_reject_bad_primary_header_crc(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "dummy.img"
            size, sha = fixture(p)
            with p.open("r+b") as f:
                f.seek(512 + 16)
                f.write(b"\x00\x00\x00\x00")
            with self.assertRaisesRegex(audit.AuditError, "header CRC32"):
                audit.audit_image(p, expected_size=size, expected_sha=sha)

    def test_reject_bad_secondary_entries_crc(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "dummy.img"
            size, sha = fixture(p)
            with p.open("r+b") as f:
                f.seek(95*512 + 17)
                f.write(b"\x7f")
            with self.assertRaisesRegex(audit.AuditError, "entries CRC32"):
                audit.audit_image(p, expected_size=size, expected_sha=sha)

    def test_reject_full_sha_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "dummy.img"
            size, sha = fixture(p)
            with self.assertRaisesRegex(audit.AuditError, "SHA256"):
                audit.audit_image(p, expected_size=size, expected_sha="0" * 64)


if __name__ == "__main__":
    unittest.main()
