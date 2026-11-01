"""Negative tests for root JZ08 compatible and FDT structural identity."""
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ci"))
from audit_jz08_fdt import FDTError, verify_jz08_fdt


def fixture(root_compatible=b"xarkon,jz08-3000-nkv\x00qcom,msm8916\x00",
            extra_strings=b"", child_compatible=None):
    names = b"compatible\x00" + extra_strings

    def prop(value):
        return (struct.pack(">III", 3, len(value), 0) + value
                + b"\x00" * ((-len(value)) % 4))

    tree = struct.pack(">I", 1) + b"\x00" * 4 + prop(root_compatible)
    if child_compatible is not None:
        tree += (struct.pack(">I", 1) + b"child\x00\x00\x00"
                 + prop(child_compatible) + struct.pack(">I", 2))
    tree += struct.pack(">II", 2, 9)
    reserve = b"\x00" * 16
    struct_off = 40 + len(reserve)
    strings_off = struct_off + len(tree)
    header = struct.pack(">10I", 0xD00DFEED, strings_off + len(names),
                         struct_off, strings_off, 40, 17, 16, 0,
                         len(names), len(tree))
    return header + reserve + tree + names


class TestJZ08FDTIdentity(unittest.TestCase):
    def test_valid_root_identity(self):
        result = verify_jz08_fdt(fixture())
        self.assertTrue(result["fdt_structure_valid"])
        self.assertIn("xarkon,jz08-3000-nkv", result["root_compatible"])

    def test_reject_string_table_spoof(self):
        data = fixture(root_compatible=b"qcom,msm8916\x00",
                       extra_strings=b"xarkon,jz08-3000-nkv\x00")
        with self.assertRaisesRegex(FDTError, "root compatible"):
            verify_jz08_fdt(data)

    def test_reject_child_node_only_identity(self):
        data = fixture(root_compatible=b"qcom,msm8916\x00",
                       child_compatible=b"xarkon,jz08-3000-nkv\x00")
        with self.assertRaisesRegex(FDTError, "root compatible"):
            verify_jz08_fdt(data)

    def test_reject_corrupt_offsets(self):
        data = bytearray(fixture())
        data[12:16] = struct.pack(">I", 0xFFFFFFFF)
        with self.assertRaises(FDTError):
            verify_jz08_fdt(data)

    def test_reject_truncated_fdt(self):
        with self.assertRaises(FDTError):
            verify_jz08_fdt(fixture()[:-1])

    def test_reject_incomplete_compatible_property(self):
        with self.assertRaises(FDTError):
            verify_jz08_fdt(fixture(root_compatible=b"xarkon,jz08-3000-nkv"))

    def test_reject_duplicate_root_compatible(self):
        data = bytearray(fixture())
        tree_off = 56
        tree_end = struct.unpack_from(">I", data, 8)[0] + struct.unpack_from(">I", data, 36)[0]
        # Rebuild a valid-size tree containing two root compatible properties.
        value = b"xarkon,jz08-3000-nkv\x00"
        prop = (struct.pack(">III", 3, len(value), 0) + value
                + b"\x00" * ((-len(value)) % 4))
        original = fixture(root_compatible=value)
        struct_start = struct.unpack_from(">I", original, 8)[0]
        struct_size = struct.unpack_from(">I", original, 36)[0]
        new_tree = original[struct_start:struct_start + struct_size - 8] + prop + struct.pack(">II", 2, 9)
        strings = b"compatible\x00"
        new_strings_off = struct_start + len(new_tree)
        header = struct.pack(">10I", 0xD00DFEED, new_strings_off + len(strings),
                             struct_start, new_strings_off, 40, 17, 16, 0,
                             len(strings), len(new_tree))
        with self.assertRaisesRegex(FDTError, "duplicate root compatible"):
            verify_jz08_fdt(header + b"\x00" * 16 + new_tree + strings)
