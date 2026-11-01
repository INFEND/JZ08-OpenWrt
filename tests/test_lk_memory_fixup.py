"""LK2ND's real legacy 32-bit RAM fixup must not corrupt an ARM64 DTB."""
import copy,struct,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools/termux'))
from bootlib import FDT
from lkprobe import memory_table_version,parse_read_word,GETTER_WORDS,VERSION_ADDRESS

def tree():
    d=FDT.__new__(FDT);c=lambda n:struct.pack('>I',n)
    d.cpu=0;d.reserved=[]
    d.nodes={
        '/':{'#address-cells':c(2),'#size-cells':c(2)},
        '/memory@80000000':{'device_type':b'memory\0','reg':struct.pack('>QQ',0x80000000,0x20000000)},
        '/reserved-memory':{'#address-cells':c(2),'#size-cells':c(2),'ranges':b''},
        '/reserved-memory/tz@86500000':{'reg':struct.pack('>QQ',0x86500000,0x180000)},
        '/reserved-memory/dynamic':{'size':struct.pack('>Q',0x600000),'alignment':struct.pack('>Q',0x100000),
                                    'alloc-ranges':struct.pack('>QQ',0x86800000,0x8000000)},
        '/soc@0':{'#address-cells':c(1),'#size-cells':c(1),'ranges':struct.pack('>4I',0,0,0,0xffffffff)},
        '/soc@0/usb@78d9000':{'reg':struct.pack('>4I',0x78d9000,0x200,0x78d9200,0x200)},
    };d.order=list(d.nodes);return d

class MemoryFixup(unittest.TestCase):
    def test_actual_legacy_getter_words_match_shipped_loader(self):
        b=(ROOT/'tools/recovery/bin/lk2nd.img').read_bytes()
        for address,word in GETTER_WORDS:self.assertEqual(struct.unpack_from('<I',b,2048+address-0x8f600000)[0],word)
    def test_legacy_v0_breaks_old_cells_and_works_after_complete_conversion(self):
        old=tree();old.nodes['/memory@80000000']['reg']=struct.pack('>II',0x80000000,0x20000000)
        with self.assertRaises(ValueError):old.memory()
        new=tree();usb=copy.deepcopy(new.nodes['/soc@0/usb@78d9000'])
        new.use_32bit_root()
        # Simulate the exact 32-bit v0 write, independent of host set_memory.
        new.nodes['/memory@80000000']['reg']=struct.pack('>II',0x80000000,0x20000000)
        self.assertEqual(FDT(new.encode()).memory(),[(0x80000000,0x20000000)])
        self.assertEqual(new.nodes['/reserved-memory']['#address-cells'],struct.pack('>I',1))
        self.assertEqual(new.nodes['/reserved-memory/tz@86500000']['reg'],struct.pack('>II',0x86500000,0x180000))
        self.assertEqual(new.nodes['/reserved-memory/dynamic']['size'],struct.pack('>I',0x600000))
        self.assertEqual(new.nodes['/reserved-memory/dynamic']['alloc-ranges'],struct.pack('>II',0x86800000,0x8000000))
        self.assertEqual(new.nodes['/soc@0']['ranges'],struct.pack('>3I',0,0,0xffffffff))
        self.assertEqual(new.nodes['/soc@0/usb@78d9000'],usb)
    def test_modern_fixup_and_host_memory_writer_accept_converted_cells(self):
        d=tree();d.use_32bit_root();d.set_memory([(0x80000000,0x20000000)])
        self.assertEqual(FDT(d.encode()).memory(),[(0x80000000,0x20000000)])
    def test_out_of_range_reserved_memory_fails_without_partial_conversion(self):
        d=tree();d.nodes['/reserved-memory/tz@86500000']['reg']=struct.pack('>QQ',0x100000000,0x180000)
        before=copy.deepcopy(d.nodes)
        with self.assertRaises(ValueError):d.use_32bit_root()
        self.assertEqual(d.nodes,before)
    def test_probe_verifies_code_before_reading_global(self):
        reads=[]
        def read(a):reads.append(a);return 0
        with self.assertRaises(ValueError):memory_table_version(read)
        self.assertNotIn(VERSION_ADDRESS,reads)
        data=dict(GETTER_WORDS);data[VERSION_ADDRESS]=0
        self.assertEqual(memory_table_version(data.__getitem__),0)
        data[VERSION_ADDRESS]=1;self.assertEqual(memory_table_version(data.__getitem__),1)
    def test_fastboot_read_zero_padding_and_ambiguous_reply(self):
        self.assertEqual(parse_read_word('(bootloader) 00000000\nOKAY [0.001s]\n'),0)
        self.assertEqual(parse_read_word('(bootloader) 0xe303347c\n'),0xe303347c)
        with self.assertRaises(ValueError):parse_read_word('(bootloader) 0x1\n(bootloader) 0x2\n')

if __name__=='__main__':unittest.main()
