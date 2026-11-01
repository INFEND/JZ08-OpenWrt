"""Validate a factory backup, both GPT copies, exact partition locations."""
import hashlib, re, struct, zlib
from pathlib import Path

BACKUP_SHA='2271764802356a14b8d51ba0950abc9e1af3634e260d488cdd9128c3e4fb34bc'
RECOVERY_SHA='8f2e9de8b8e3d26f76784f647655aa70b85ae2de86c5777da2974c2a1ea6a462'

def filehash(path,progress=None):
    h=hashlib.sha256();total=Path(path).stat().st_size;done=0
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(4*1024*1024),b''):
            h.update(b);done+=len(b)
            if progress:progress(done,total)
    return h.hexdigest()

def validate_gpt(path,layout):
    size=layout['disk_bytes'];sector=512;last=size//sector-1
    if Path(path).stat().st_size!=size:raise ValueError('Неверный размер полного дампа')
    with open(path,'rb') as f:
        mbr=f.read(512)
        if mbr[510:]!=b'\x55\xaa' or mbr[450]!=0xee:raise ValueError('Protective MBR повреждён')
        def header(lba,other):
            f.seek(lba*512);h=f.read(512)
            if h[:8]!=b'EFI PART':raise ValueError('Нет заголовка GPT')
            revision,hs,crc,res=struct.unpack_from('<4I',h,8)
            if revision!=0x10000 or not 92<=hs<=512 or res!=0:raise ValueError('GPT header fields')
            hh=bytearray(h[:hs]);hh[16:20]=bytes(4)
            if zlib.crc32(hh)!=crc:raise ValueError('GPT header CRC')
            here,there,first,end=struct.unpack_from('<4Q',h,24)
            if (here,there)!=(lba,other) or not 34<=first<=end<last:raise ValueError('GPT LBAs')
            tab,n,es,ec=struct.unpack_from('<QIII',h,72)
            if not 1<=n<=4096 or es<128 or es%8 or n*es>1024*1024:raise ValueError('GPT table dimensions')
            if tab*512+n*es>size or tab<2:raise ValueError('GPT table bounds')
            if lba==1 and tab*512+n*es>first*512:raise ValueError('GPT table overlaps partitions')
            if lba==last and not end<tab<last:raise ValueError('Secondary GPT position')
            f.seek(tab*512);entries=f.read(n*es)
            if len(entries)!=n*es or zlib.crc32(entries)!=ec:raise ValueError('GPT entries CRC')
            parts=[]
            for i in range(n):
                e=entries[i*es:(i+1)*es]
                if e[:16]==bytes(16):continue
                lo,hi=struct.unpack_from('<QQ',e,32)
                name=e[56:128].decode('utf-16le').split('\0',1)[0]
                if not name or not first<=lo<=hi<=end:raise ValueError('GPT partition bounds')
                parts.append({'index':i+1,'name':name,'start':lo,'sectors':hi-lo+1})
            sorted_parts=sorted(parts,key=lambda x:x['start'])
            for a,b in zip(sorted_parts,sorted_parts[1:]):
                if a['start']+a['sectors']>b['start']:raise ValueError('GPT partitions overlap')
            if parts!=layout['partitions']:raise ValueError('GPT не соответствует JZ08: смещения/размеры/имена')
            return h[56:72],entries
        a=header(1,last);b=header(last,1)
        if a!=b:raise ValueError('Основная и резервная GPT расходятся')
    return {'primary_crc':True,'secondary_crc':True,'partition_count':len(layout['partitions'])}

def validate_live_log(text,layout):
    text=re.sub(r'\x1b\[[0-9;]*m','',text)
    rows=[]
    for name,start,size in re.findall(r'^([A-Za-z0-9_]+):\s+Offset (0x[0-9A-Fa-f]+), Length (0x[0-9A-Fa-f]+)',text,re.M):
        a,n=int(start,16),int(size,16)
        if a%512 or n%512:raise ValueError('GPT: размер не кратен сектору')
        rows.append({'index':len(rows)+1,'name':name,'start':a//512,'sectors':n//512})
    sizes=re.findall(r'Total disk size:\s*(0x[0-9a-fA-F]+)',text)
    if len(sizes)!=1 or int(sizes[0],16)!=layout['disk_bytes'] or rows!=layout['partitions']:
        raise ValueError('Живая GPT не совпадает с точными 27 диапазонами JZ08')
    return True

def backup_candidates(root):
    root=Path(root)
    return [root/'XARKON_MIFI_SAFE_COPY/flash_emmc_20261028_082457_verified.bin',
            root/'XARKON_MIFI_BACKUPS/20261028_082457/flash_emmc.bin']
