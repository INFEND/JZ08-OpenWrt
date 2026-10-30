import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ci"))
import validate

class Safety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.board = json.loads((ROOT / "board/jz08.json").read_text())
    def test_source_validator(self):
        self.assertEqual(validate.check(), [])
    def test_modem_partition(self):
        self.assertEqual(self.board["oem"]["partition_ids"]["14"], "modemst2")
    def test_emmc_size(self):
        self.assertEqual(self.board["oem"]["sectors"] * 512, 3909091328)
    def test_no_flash(self):
        self.assertFalse(self.board["firmware_flash_allowed"])
        self.assertFalse(self.board["proof"]["linux_init"])
    def test_lcd_undefined(self):
        self.assertIsNone(self.board["lcd"]["confirmed"])
        self.assertFalse(self.board["lcd"]["gpio_roles_verified"])
