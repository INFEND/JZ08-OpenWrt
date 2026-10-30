import pathlib
import re
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
LCD=ROOT / "drivers/lcd"

class LcdSources(unittest.TestCase):
    def check_panel(self, panel, expected_count, expected_fps):
        c=(LCD / ("fb_jz08_" + panel + ".c")).read_text()
        init=c.split("static int init_display(",1)[1].split("static void set_addr_win(",1)[0]
        commands=re.findall(r"\bwrite_reg\(par,\s*0x[0-9a-fA-F]+",init)
        self.assertEqual(len(commands),expected_count)
        self.assertIn(".fps = " + str(expected_fps),c)
        self.assertNotIn("return -ENODEV",init)
        d=(LCD / ("jz08-" + panel + "-disabled.dts.inc")).read_text()
        self.assertGreaterEqual(d.count('status = "disabled"'),2)
        self.assertIn("spi-max-frequency = <16000000>",d)
        self.assertNotIn('status = "okay"',d)
    def test_st7735s(self):
        self.check_panel("st7735s",19,20)
    def test_nv3023a(self):
        self.check_panel("nv3023a",58,27)
    def test_no_connected_lcd(self):
        d=(ROOT/"board/msm8916-generic-jz08-prototype.dts").read_text()
        self.assertIn('status = "disabled"',d)
