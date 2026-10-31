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
    def test_prototype_dts_guard_accepts_current_disabled_spi(self):
        dts = (ROOT / "board/msm8916-generic-jz08-prototype.dts").read_text()
        self.assertEqual(validate.prototype_dts_errors(dts), [])

    def test_prototype_dts_guard_rejects_false_disabled_marker(self):
        dts = (ROOT / "board/msm8916-generic-jz08-prototype.dts").read_text()
        # A random disabled node must not mask an enabled LCD SPI controller.
        changed = dts.replace('status = "disabled";', 'status = "okay";') + (
            '\\n&other_node { status = "disabled"; };\\n'
        )
        self.assertTrue(validate.prototype_dts_errors(changed))

    def test_prototype_dts_guard_rejects_unverified_gpio_and_memory(self):
        dts = (ROOT / "board/msm8916-generic-jz08-prototype.dts").read_text()
        for extra in ('\\n&blsp_spi4 { reset-gpios = <&msmgpio 116 0>; };\\n',
                      '\\n/ { memory@80000000 { reg = <0 0x80000000 0 0x10000000>; }; };\\n'):
            with self.subTest(extra=extra):
                self.assertTrue(validate.prototype_dts_errors(dts + extra))

    def test_prototype_dts_guard_rejects_missing_board_identity(self):
        dts = (ROOT / "board/msm8916-generic-jz08-prototype.dts").read_text()
        self.assertTrue(validate.prototype_dts_errors(
            dts.replace('xarkon,jz08-3000-nkv', 'generic,ufi')))

    def test_lcd_undefined(self):
        self.assertIsNone(self.board["lcd"]["confirmed"])
        self.assertFalse(self.board["lcd"]["gpio_roles_verified"])
