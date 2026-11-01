"""Do not mistake another phone or stale ADB listing for stock JZ08."""
import sys,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools/termux'))
from postmortem import stock_android

class Postmortem(unittest.TestCase):
    def test_other_phone_never_has_kernel_logs_read(self):
        calls=[]
        def adb(args,timeout):
            calls.append(args)
            output='PHONE\tdevice\n' if args==['devices'] else 'sm8550\nOTHER\nOther_build\n'
            return SimpleNamespace(returncode=0,stdout=output)
        self.assertIsNone(stock_android(adb));self.assertEqual(len(calls),2)
    def test_multiple_targets_stop_before_shell(self):
        def adb(args,timeout):
            self.assertEqual(args,['devices'])
            return SimpleNamespace(returncode=0,stdout='A\tdevice\nB\tdevice\n')
        self.assertIsNone(stock_android(adb))
    def test_verified_stock_reads_diagnostics_and_filters_long_identifiers(self):
        def adb(args,timeout):
            if args==['devices']:out='TARGET\tdevice\nemulator-5554\tdevice\n'
            elif 'getprop ro.board.platform' in args[-1]:out='msm8916\nMIFI\nJZ_MIFI_LCD_COM_20260615\n'
            else:out='bootreason=watchdog\nID=123456789012345\nKernel panic\n'
            return SimpleNamespace(returncode=0,stdout=out)
        r=stock_android(adb);self.assertEqual(r['identity']['platform'],'msm8916')
        self.assertIn('Kernel panic',r['log']);self.assertNotIn('123456789012345',r['log'])

if __name__=='__main__':unittest.main()
