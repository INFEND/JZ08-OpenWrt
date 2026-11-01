"""Bounded newc editor shared by the builder and the offline phone packer."""
import gzip
from pathlib import PurePosixPath

def entries(data):
    pos=0;seen=set()
    while pos+110<=len(data):
        h=data[pos:pos+110]
        if h[:6]!=b'070701':raise ValueError('CPIO: expected newc')
        f=[int(h[6+i*8:14+i*8],16) for i in range(13)]
        size,n=f[6],f[11]
        if not 1<=n<=4096 or size>128*1024**2:raise ValueError('CPIO: bounds')
        raw=data[pos+110:pos+110+n]
        if len(raw)!=n or raw[-1:]!=b'\0' or b'\0' in raw[:-1]:raise ValueError('CPIO: name')
        name=raw[:-1].decode();start=(pos+110+n+3)&~3;end=start+size
        if end>len(data):raise ValueError('CPIO: truncated')
        pos=(end+3)&~3
        if name=='TRAILER!!!':
            if size or data[pos:].strip(b'\0'):raise ValueError('CPIO: trailing data')
            return
        name=name.removeprefix('./')
        if (name.startswith('/') or '..' in PurePosixPath(name).parts or
                PurePosixPath(name).as_posix()!=name or name in seen):raise ValueError('CPIO: unsafe path')
        seen.add(name)
        yield name,f,data[start:end]
    raise ValueError('CPIO: missing trailer')

def rewrite(data,changes):
    """changes maps regular-file paths to (mode,bytes), or None for removal."""
    items={n:(f,b) for n,f,b in entries(data)}
    for n,change in changes.items():
        if change is None:items.pop(n,None);continue
        mode,body=change
        f=items[n][0][:] if n in items else [0,mode,0,0,1,0,0,0,0,0,0,0,0]
        f[1]=mode;f[4]=1;items[n]=(f,body)
    out=bytearray()
    for ino,(n,(f,body)) in enumerate([*items.items(),('TRAILER!!!',([0]*13,b''))],1):
        f=f[:];f[0]=ino;f[2]=f[3]=f[5]=f[12]=0;f[6]=len(body);nb=n.encode()+b'\0';f[11]=len(nb)
        out+=b'070701'+''.join('%08x'%x for x in f).encode()+nb
        out+=bytes((-len(out))%4);out+=body;out+=bytes((-len(out))%4)
    return bytes(out)

def credentials(ramdisk,password):
    if len(password)!=24 or any(c not in '0123456789abcdef' for c in password):raise ValueError('password format')
    return gzip.compress(rewrite(gzip.decompress(ramdisk),{
        'etc/jz08-password':(0o100600,password.encode()+b'\n'),
    }),9,mtime=0)
