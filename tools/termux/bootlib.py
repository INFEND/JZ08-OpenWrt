"""Strict DTB / Android boot v0 packer. No USB or device writes."""
import gzip, hashlib, struct

def align(n, page=2048):
    return (n+page-1)//page*page

class FDT:
    def __init__(self, data):
        if len(data)<40: raise ValueError('DTB: короткий заголовок')
        h=struct.unpack_from('>10I',data)
        magic,total,off,so,ro,ver,last,cpu,ss,sz=h
        if magic!=0xd00dfeed or not 40<=total<=len(data) or ver<17 or last>17:
            raise ValueError('DTB: недопустимый заголовок')
        if max(so+ss,off+sz)>total or min(so,off,ro)<40:raise ValueError('DTB: границы')
        self.cpu=cpu;self.nodes={};self.order=[];self.reserved=[]
        p=ro
        while p+16<=min(off,so):
            a,n=struct.unpack_from('>QQ',data,p);p+=16
            if (a,n)==(0,0):break
            self.reserved.append((a,n))
        else:raise ValueError('DTB: reservation terminator')
        strings=data[so:so+ss];p=off;end=off+sz;stack=[];done=False
        while p+4<=end:
            tag=struct.unpack_from('>I',data,p)[0];p+=4
            if tag==1:
                e=data.index(0,p,end);name=data[p:e].decode('ascii');p=align(e+1,4)
                if '/' in name:raise ValueError('DTB: имя узла')
                stack.append(name);path='/'+ '/'.join(stack[1:])
                if path in self.nodes:raise ValueError('DTB: повторный узел')
                self.nodes[path]={};self.order.append(path)
            elif tag==2:
                if not stack:raise ValueError('DTB: лишний END_NODE')
                stack.pop()
            elif tag==3:
                if p+8>end or not stack:raise ValueError('DTB: property header')
                n,o=struct.unpack_from('>II',data,p);p+=8
                if p+n>end or o>=len(strings):raise ValueError('DTB: property bounds')
                key=strings[o:strings.index(0,o)].decode('ascii')
                props=self.nodes['/'+'/'.join(stack[1:])]
                if key in props:raise ValueError('DTB: duplicate property')
                props[key]=data[p:p+n];p=align(p+n,4)
            elif tag==4:pass
            elif tag==9:
                if stack:raise ValueError('DTB: незавершённое дерево')
                done=True;break
            else:raise ValueError('DTB: неизвестный токен')
        if not done or '/' not in self.nodes:raise ValueError('DTB: отсутствует END')

    def encode(self):
        names={};strings=bytearray();blob=bytearray()
        for props in self.nodes.values():
            for name in props:
                if name not in names:names[name]=len(strings);strings+=name.encode()+b'\0'
        def pad():blob.extend(bytes((-len(blob))%4))
        def emit(path):
            blob.extend(struct.pack('>I',1));blob.extend((path.rsplit('/',1)[-1] if path!='/' else '').encode()+b'\0');pad()
            for key,v in self.nodes[path].items():
                blob.extend(struct.pack('>III',3,len(v),names[key]));blob.extend(v);pad()
            for ch in self.order:
                if ch!='/' and (ch.rsplit('/',1)[0] or '/')==path:emit(ch)
            blob.extend(struct.pack('>I',2))
        emit('/');blob.extend(struct.pack('>I',9))
        reserve=b''.join(struct.pack('>QQ',a,n) for a,n in self.reserved)+bytes(16)
        off=40+len(reserve);so=off+len(blob);total=so+len(strings)
        return struct.pack('>10I',0xd00dfeed,total,off,so,40,17,16,self.cpu,len(strings),len(blob))+reserve+blob+strings

    def memory(self):
        root=self.nodes['/'];ac=struct.unpack('>I',root.get('#address-cells',struct.pack('>I',2)))[0]
        sc=struct.unpack('>I',root.get('#size-cells',struct.pack('>I',1)))[0]
        if ac not in (1,2) or sc not in (1,2):raise ValueError('DTB: memory cells')
        banks=[]
        for path,props in self.nodes.items():
            if path.count('/')==1 and props.get('device_type')==b'memory\0':
                reg=props.get('reg',b'');stride=4*(ac+sc)
                if not reg or len(reg)%stride:raise ValueError('DTB: memory reg')
                for i in range(0,len(reg),stride):
                    a=int.from_bytes(reg[i:i+4*ac],'big');n=int.from_bytes(reg[i+4*ac:i+stride],'big')
                    if n:banks.append((a,n))
        banks.sort()
        if not banks or banks[0][0]!=0x80000000 or sum(n for a,n in banks)>2*1024**3:
            raise ValueError('OEM DTB: фактическая память не подтверждена')
        last=0
        for a,n in banks:
            if a%4096 or n%4096 or a<last or a+n>0x100000000:raise ValueError('OEM DTB: диапазоны RAM')
            last=a+n
        return banks

    def set_memory(self,banks):
        paths=[p for p,v in self.nodes.items() if p.count('/')==1 and v.get('device_type')==b'memory\0']
        if len(paths)!=1:raise ValueError('JZ08 DTB: ожидается один memory node')
        if self.nodes['/']['#address-cells']!=struct.pack('>I',2) or self.nodes['/']['#size-cells']!=struct.pack('>I',2):
            raise ValueError('JZ08 DTB: ожидаются 64-bit cells')
        self.nodes[paths[0]]['reg']=b''.join(struct.pack('>QQ',a,n) for a,n in banks)

def initramfs(init):
    if init[:4]!=b'\x7fELF' or init[4]!=2 or struct.unpack_from('<H',init,18)[0]!=183:
        raise ValueError('init: требуется ELF64 AArch64')
    phoff=struct.unpack_from('<Q',init,32)[0];psz,pnum=struct.unpack_from('<HH',init,54)
    if phoff+psz*pnum>len(init):raise ValueError('init: program headers')
    if any(struct.unpack_from('<I',init,phoff+i*psz)[0]==3 for i in range(pnum)):
        raise ValueError('init: динамический загрузчик не допускается')
    files=[(d,0o40755,b'',0,0) for d in ('dev','proc','sys','run')]
    files += [('dev/console',0o20600,b'',5,1),('init',0o100755,init,0,0),('TRAILER!!!',0,b'',0,0)]
    b=bytearray()
    for i,(name,mode,body,maj,minor) in enumerate(files,1):
        nb=name.encode()+b'\0'
        b+=('070701'+''.join('%08x'%v for v in [i,mode,0,0,1,0,len(body),0,0,maj,minor,len(nb),0])).encode()+nb
        b+=bytes((-len(b))%4);b+=body;b+=bytes((-len(b))%4)
    return gzip.compress(b,9,mtime=0)

def boot_image(kernel,ramdisk,dtb,nonce,banks):
    if len(kernel)<64:raise ValueError('kernel: короткий ARM64 header')
    if kernel[56:60]!=b'ARMd':raise ValueError('kernel: ARM64 magic')
    offset,size=struct.unpack_from('<QQ',kernel,8)
    # The supplied, hardware-proven LK2ND ignores Android header addresses.
    # Its ARM64 path uses (DDR_START & ~0x1fffff) + Image.text_offset,
    # tags=DDR_START+30 MiB, ramdisk=DDR_START+32 MiB. Verified by disassembly.
    # v34's 36.75 MiB image_size overlapped BOTH tags and initramfs here.
    ka=0x80000000+offset;ta=0x81e00000;ra=0x82000000
    if offset>2*1024**2 or not len(kernel)<=size or ka+max(size,align(len(kernel)))>ta:
        raise ValueError('Перекрытие ядра и DTB по фактическим адресам LK2ND')
    if len(nonce)!=32 or any(c not in '0123456789abcdef' for c in nonce):raise ValueError('nonce')
    q=bytearray(2048);struct.pack_into('<4sII',q,0,b'QCDT',2,8)
    for i,(soc,sub) in enumerate((s,b) for s in (206,248,249,250) for b in (0,256)):
        struct.pack_into('<6I',q,12+i*24,soc,8,sub,0,2048,align(len(dtb)))
    q+=dtb;q+=bytes((-len(q))%2048)
    if ta+len(q)+8192>ra:
        raise ValueError('Перекрытие DTB и initramfs по фактическим адресам LK2ND')
    for start,end in [(ka,ka+size),(ra,ra+len(ramdisk)),(ta,ta+len(q)+8192)]:
        if end>0x83200000 or not any(a<=start and end<=a+n for a,n in banks):
            raise ValueError('Образ не помещается в подтверждённую RAM')
    cmd=('console=ttyMSM0,115200 earlycon=msm_serial_dm,0x78b0000 loglevel=8 '
         'rdinit=/init panic=15 clk_ignore_unused regulator_ignore_unused '
         'lk2nd.pass-ramoops=zap xarkon.nonce='+nonce).encode()
    if len(cmd)>=512:raise ValueError('cmdline слишком длинная')
    h=bytearray(2048);h[:8]=b'ANDROID!'
    struct.pack_into('<10I',h,8,len(kernel),ka,len(ramdisk),ra,0,0,ta,2048,len(q),0)
    h[48:64]=b'JZ08-OPENWRT-V1'.ljust(16,b'\0');h[64:64+len(cmd)]=cmd
    digest=hashlib.sha1()
    for data in (kernel,ramdisk,b'',q):digest.update(data);digest.update(struct.pack('<I',len(data)))
    h[576:596]=digest.digest()
    return bytes(h)+kernel+bytes((-len(kernel))%2048)+ramdisk+bytes((-len(ramdisk))%2048)+q
