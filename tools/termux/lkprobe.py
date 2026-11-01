"""Read only the exact supplied LK2ND's memory-table version, never MMIO/NV."""
import re

# Image SHA256 e0f260e31c6a681a1fa6e27d2e2e02418c17f726a46225b2348618659345dbae.
# Actual disassembly: getter at +0x2714 loads struct base 0x8f65347c,
# then reads version at +8. First verify the three instruction words live.
GETTER_WORDS=((0x8f602714,0xe303347c),(0x8f602718,0xe3483f65),(0x8f602728,0xe5930008))
VERSION_ADDRESS=0x8f653484

def parse_read_word(output):
    values=re.findall(r'^\s*(?:\(bootloader\)\s*)?(0x[0-9a-fA-F]{1,8}|0{1,8})\s*$',output,re.M)
    if len(values)!=1:raise ValueError('LK2ND: неоднозначный readl response')
    return int(values[0],0)

def memory_table_version(read_word):
    for address,expected in GETTER_WORDS:
        if read_word(address)!=expected:raise ValueError('LK2ND: код memory getter не совпал; чтение globals запрещено')
    version=read_word(VERSION_ADDRESS)
    if version>4:raise ValueError('LK2ND: неизвестная версия SMEM RAM table')
    return version
