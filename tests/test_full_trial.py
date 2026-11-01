"""Regression tests for actual LK2ND placement and full-rootfs edits."""
import gzip,struct,sys,unittest,urllib.error,io,importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/termux'))
from bootlib import boot_image
from cpio import entries,rewrite,credentials
from httpcheck import fetch_luci

def cpio_one():
    name=b'init\0';body=b'original'
    f=[1,0o100755,0,0,1,0,len(body),0,0,0,0,len(name),0]
    b=b'070701'+''.join('%08x'%v for v in f).encode()+name
    b+=bytes((-len(b))%4);b+=body;b+=bytes((-len(b))%4)
    name=b'TRAILER!!!\0';f=[0]*13;f[11]=len(name)
    b+=b'070701'+''.join('%08x'%v for v in f).encode()+name
    return b+bytes((-len(b))%4)

class FullTrial(unittest.TestCase):
    def entry(self):
        spec=importlib.util.spec_from_file_location('jz08_trial_entry',ROOT/'tools/termux/__main__.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module
    def args(self,**overrides):
        values=dict.fromkeys(('selftest','flash','restore','report','postmortem','verify','prepare','ram_test','boot_only'),False)
        values.update(overrides);return SimpleNamespace(**values)
    def test_postmortem_cannot_reboot_restore_or_enter_a_write_chain(self):
        for available in (True,False):
            module=self.entry()
            with patch.object(module,'package_check'),patch.object(module,'root_check'),\
                 patch.object(module,'capture_android',return_value={'available':available}),\
                 patch.object(module,'backup_check') as backup,patch.object(module,'legacy') as legacy,\
                 patch.object(module,'restore') as restore,patch.object(module,'connected') as connected:
                module.main(self.args(postmortem=True))
                for call in (backup,legacy,restore,connected):call.assert_not_called()
                self.assertFalse(module.STATE['linux_init_verified'])
                self.assertEqual(module.STATE['status'],'STOCK_ANDROID_DIAGNOSTICS_CAPTURED' if available else 'STOCK_ANDROID_ADB_UNAVAILABLE')
    def test_ram_trial_with_failed_initial_adb_never_changes_recovery(self):
        module=self.entry()
        with patch.object(module,'package_check'),patch.object(module,'root_check'),\
             patch.object(module,'backup_check'),patch.object(module,'connected',return_value=False),\
             patch.object(module,'capture_android',return_value={'available':False}),\
             patch.object(module,'legacy') as legacy,patch.object(module,'restore') as restore:
            with self.assertRaisesRegex(RuntimeError,'ADB JZ08'):
                module.main(self.args(ram_test=True))
            legacy.assert_not_called();restore.assert_not_called()
            self.assertFalse(module.STATE.get('recovery_restore_required',False))
    def test_cpio_change_add_remove_and_runtime_password(self):
        b=rewrite(cpio_one(),{'init.openwrt':(0o100755,b'original'),'init':(0o100755,b'entry')})
        out={n:v for n,f,v in entries(b)}
        self.assertEqual(out['init.openwrt'],b'original');self.assertEqual(out['init'],b'entry')
        ram=credentials(gzip.compress(b),'a'*24)
        out={n:(f,v) for n,f,v in entries(gzip.decompress(ram))}
        self.assertEqual(out['etc/jz08-password'][0][1],0o100600)
        self.assertEqual(out['etc/jz08-password'][1],b'a'*24+b'\n')
        with self.assertRaises(ValueError):credentials(gzip.compress(b),'a'*23+';')
    def test_cpio_truncated_hidden_archive_and_duplicate_rejected(self):
        b=cpio_one()
        for damaged in (b[:-20],b+b'070701',b.replace(b'init\0',b'../x\0')):
            with self.assertRaises(ValueError):list(entries(damaged))
    def test_loader_destinations_and_previous_large_image_rejected(self):
        k=bytearray(8192);k[56:60]=b'ARMd';struct.pack_into('<QQ',k,8,0,16384)
        banks=[(0x80000000,256*1024**2)]
        b=boot_image(k,b'ram',b'dtb','a'*32,banks)
        self.assertEqual(struct.unpack_from('<I',b,12)[0],0x80000000)
        self.assertEqual(struct.unpack_from('<I',b,20)[0],0x82000000)
        self.assertEqual(struct.unpack_from('<I',b,32)[0],0x81e00000)
        struct.pack_into('<Q',k,16,38535168)
        with self.assertRaisesRegex(ValueError,'Перекрытие'):boot_image(k,b'ram',b'dtb','a'*32,banks)
    def test_initrd_must_fit_actual_confirmed_bank(self):
        k=bytearray(8192);k[56:60]=b'ARMd';struct.pack_into('<QQ',k,8,0,16384)
        with self.assertRaisesRegex(ValueError,'RAM'):
            boot_image(k,b'ram',b'dtb','a'*32,[(0x80000000,32*1024**2)])
    def test_luci_login_403_is_a_real_page_but_generic_403_is_not(self):
        class Opener:
            def __init__(self,headers,body):self.headers=headers;self.body=body
            def open(self,url,timeout):
                raise urllib.error.HTTPError(url,403,'Forbidden',self.headers,io.BytesIO(self.body))
        page=b'<html lang="ru"><title>INFEND - LuCI</title></html>'
        result=fetch_luci(Opener({'x-luci-login-required':'yes'},page),'http://example.invalid')
        self.assertTrue(result['luci_http_verified']);self.assertTrue(result['luci_russian_verified'])
        self.assertFalse(fetch_luci(Opener({},page),'http://example.invalid')['luci_http_verified'])

if __name__=='__main__':unittest.main()
