"""Fail-closed regression tests for pinned JZ08 RAM-only service startup policy."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ci"))
from disable_unverified_startup import STARTUP_SOURCES, disable


class StartupPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, priority in STARTUP_SOURCES.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"#!/bin/sh /etc/rc.common\nSTART={priority}\nSTOP=10\n")

    def test_all_unverified_services_are_disabled_without_removing_binaries(self):
        self.assertEqual(len(STARTUP_SOURCES), 7)
        disable(self.root)
        for name in STARTUP_SOURCES:
            self.assertIn("\nSTART=\n", (self.root / name).read_text())
            self.assertIn("\nSTOP=10\n", (self.root / name).read_text())

    def test_changed_upstream_priority_fails_without_partial_edits(self):
        name = "package/base-files/files/etc/init.d/gpio_switch"
        (self.root / name).write_text("#!/bin/sh /etc/rc.common\nSTART=95\n")
        with self.assertRaisesRegex(ValueError, "priority changed"):
            disable(self.root)
        for other, priority in STARTUP_SOURCES.items():
            if other != name:
                self.assertIn(f"START={priority}", (self.root / other).read_text())

    def test_missing_upstream_script_fails_closed(self):
        name = "package/system/fstools/files/fstab.init"
        (self.root / name).unlink()
        with self.assertRaisesRegex(ValueError, "missing or unsafe"):
            disable(self.root)


if __name__ == "__main__":
    unittest.main()
