# -*- coding: utf-8 -*-
"""XARKON JZ08 v24: Original ARM32 kernel + OEM QCDT + experimental small userspace.
This is a hardware boot probe, NOT OpenWrt. Direct ZIP execution in Termux.
"""
import os,sys,struct,hashlib,zipfile,gzip,datetime,json,time,subprocess,shutil,traceback,re,zlib,html,argparse
from pathlib import Path
from types import ModuleType

A=argparse.ArgumentParser(description='XARKON JZ08 · Первая экспериментальная прошивка Recovery: ARM32, НЕ OpenWrt')
A.add_argument('--build',action='store_true',help='подготовить образ, никаких операций с роутером')
A.add_argument('--flash-probe',action='store_true',help='ОПАСНО: записать только экспериментальный recovery p26 и сверить чтением')
A.add_argument('--restore-factory',action='store_true',help='восстановить строго заводской recovery p26, сверить чтением')
A.add_argument('--self-test',action='store_true',help='проверка сборщика с синтетическим OEM-заголовком')
A.add_argument('--test-recovery',action='store_true',help='после записи перейти в тестовый Recovery через проверенный Native ADB')
A.add_argument('--check-marker',action='store_true',help='после возврата Android проверить маркер загрузки в /cache')
A.add_argument('--single-pass',action='store_true',help='ОДИН ПРОХОД: прошивка p26, пробный Recovery, проверка метки, возврат factory при доступном Android')
A.add_argument('--no-open',action='store_true',help='не пытаться открыть отчёт')
args=A.parse_args()
ROOT=Path('/sdcard/Download') if Path('/sdcard/Download').is_dir() else Path('/mnt/data') if Path('/mnt/data').is_dir() else Path.cwd()
REPORTS=ROOT/'XARKON_JZ08_REPORTS'
STAGE=ROOT/'XARKON_JZ08_ARM32_PROBE_V26'
FACT=ROOT/'XARKON_JZ08_RECOVERY_FIRST_V22'/'OEM_JZ08_RECOVERY_P26_FACTORY_ONLY.img'
BKP=ROOT/'XARKON_MIFI_SAFE_COPY'/'flash_emmc_20261028_082457_verified.bin'
BKP2=ROOT/'XARKON_MIFI_BACKUPS'/'20261028_082457'/'flash_emmc.bin'
CAND=STAGE/'EXPERIMENTAL_JZ08_OEM_LAYOUT_ARM32_RECOVERY_V26_NOT_OPENWRT.img'
STAMP=datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
STOCK_HASH='8f2e9de8b8e3d26f76784f647655aa70b85ae2de86c5777da2974c2a1ea6a462'
BOOT_HASH='1342def7e0f0c245385d4bac2852d361537a520abd8a45708618983cdab43c0a'
ABOOT_HASH='3012d51967524e4192ed0d65d9a4cefaebc5ffdedadcb2afdf27855b0127c177'
DISK=3909091328;PART_START=2395232;PART_SIZE=16777216
BOOT_START=396384; ABOOT_START=264192
PREF=Path(sys.argv[0]); LOG=[]
R={'marker_uses_cache':True,'project':'XARKON JZ08 OEM layout ARM32 recovery v26','time':STAMP,'mode':'BUILD','flash':False,'emmc_write':False,
   'boot_proven_on_hw':False,'openwrt':False,'events':LOG,'status':'START','candidate':str(CAND)}
COL={'ok':'\x1b[38;5;48m','warn':'\x1b[38;5;214m','fail':'\x1b[38;5;203m','step':'\x1b[38;5;141m','info':'\x1b[38;5;45m'}
COLOR=sys.stdout.isatty() and 'NO_COLOR' not in os.environ

def echo(s,k='info'):
    LOG.append({'status':k,'text':s,'time':datetime.datetime.now().isoformat(timespec='seconds')})
    title={'ok':'ГОТОВО','warn':'ВНИМАНИЕ','fail':'ОШИБКА','step':'ЭТАП','info':'ИНФО'}[k]
    t=f'[{title}] {s}';print((COL[k]+t+'\x1b[0m') if COLOR else t,flush=True)

def guard(test,msg):
    if not test:raise RuntimeError(msg)
    echo(msg,'ok')

def h256(data):return hashlib.sha256(data).hexdigest()

def hdisk(p,progress=False):
    h=hashlib.sha256();count=0;size=p.stat().st_size
    with p.open('rb') as f:
        while True:
            b=f.read(1024*1024)
            if not b:break
            h.update(b);count+=len(b)
            if progress and sys.stdout.isatty():
                pct=int(count*100/size);n=pct//5
                print('\r  ПРОВЕРКА ['+'█'*n+'░'*(20-n)+f'] {pct:3d}% ({count//1024//1024} / {size//1024//1024} МиБ)',end='',flush=True)
    if progress and sys.stdout.isatty():print()
    return h.hexdigest()

def gpt_check(path):
    guard(path.is_file() and path.stat().st_size==DISK,'Полный проверенный дамп eMMC найден')
    with path.open('rb') as f:
        f.seek(512);hdr=f.read(512)
        guard(hdr[:8]==b'EFI PART','Заводская GPT обнаружена')
        hs=struct.unpack_from('<I',hdr,12)[0];crc=struct.unpack_from('<I',hdr,16)[0]
        t=bytearray(hdr[:hs]);t[16:20]=b'\0'*4
        guard(92<=hs<=512 and zlib.crc32(t)==crc,'CRC заводской GPT совпадает')
        table,nent,es,ecrc=struct.unpack_from('<QIII',hdr,72)
        guard(nent*es<1024*1024,'Размер таблицы GPT разумен')
        f.seek(table*512);entries=f.read(nent*es)
        guard(zlib.crc32(entries)==ecrc,'CRC таблицы разделов совпадает')
        parts=[]
        for idx in range(nent):
            e=entries[idx*es:(idx+1)*es]
            if e[:16]!=b'\0'*16:
                n=e[56:128].decode('utf-16le','ignore').split('\0')[0]
                lo,hi=struct.unpack_from('<QQ',e,32)
                parts.append((idx+1,n,lo,hi))
        guard(len(parts)==27,'27 заводских разделов подтверждены')
        for name,item in [('recovery',(26,'recovery',2395232,2427999)),('boot',(22,'boot',396384,429151)),('system',(23,'system',429152,2067551)),('aboot',(4,'aboot',264192,266239)),('modemst2',(14,'modemst2',279552,282623))]:
            guard(item in parts,f'Разметка {name} подтверждена')

def stock_recovery():
    STAGE.mkdir(parents=True,exist_ok=True)
    if FACT.exists() and FACT.stat().st_size==PART_SIZE and hdisk(FACT)==STOCK_HASH:
        echo('Заводской recovery из v22 повторно используется','ok');return FACT
    src=BKP if BKP.is_file() else BKP2
    gpt_check(src)
    FACT.parent.mkdir(parents=True,exist_ok=True)
    tmp=FACT.with_suffix('.partial')
    with src.open('rb') as fi,tmp.open('wb') as fo:
        fi.seek(PART_START*512);left=PART_SIZE
        while left:
            b=fi.read(min(left,1024*1024))
            if not b:raise RuntimeError('Исходный дамп оборвался при извлечении recovery')
            fo.write(b);left-=len(b)
    guard(tmp.stat().st_size==PART_SIZE and hdisk(tmp,True)==STOCK_HASH,'SHA-256 заводского recovery совпадает')
    tmp.replace(FACT);return FACT

def align(n,p):return (n+p-1)//p*p

def extract_android(oem):
    guard(len(oem)==PART_SIZE,'Размер заводского p26 16 МиБ')
    guard(oem[:8]==b'ANDROID!','Оригинальный Android boot-заголовок')
    ks,ka,rs,ra,ss,sa,ta,page,dt_size=struct.unpack_from('<9I',oem,8)
    guard((ks,rs,dt_size,page,ka,ss)==(6442128,1070918,288768,2048,0x80008000,0),'Параметры заводского ядра и QCDT совпадают с v22')
    ko=page;ro=ko+align(ks,page);so=ro+align(rs,page);do=so+align(ss,page)
    guard(do+dt_size<=len(oem),'Исходный QCDT целиком в разделе')
    kernel=oem[ko:ko+ks];ramdisk=oem[ro:ro+rs];dt=oem[do:do+dt_size]
    guard(len(kernel)==ks and kernel[36:40]==bytes.fromhex('18286f01'),'Оригинальное ARM32 zImage с корректной сигнатурой')
    guard(dt[:4]==b'QCDT','Заводской QCDT распознан')
    guard(ramdisk[:2]==b'\x1f\x8b','Заводской ramdisk использует gzip')
    guard(gzip.decompress(ramdisk)[:6] in (b'070701',b'070702'),'Заводской ramdisk содержит initramfs cpio')
    tail_start=align(do+dt_size,page)
    tail=oem[tail_start:]
    # The factory partition is 16MiB, but Android boot payload ends earlier.
    # Any meaningful trailing bytes are potentially Qualcomm image metadata/signatures.
    # Record aggregate location/hashes, preserve original bytes at their original offsets.
    # Never allow write of an experimental image until their purpose is established.
    detailed=[];meaningful_count=0;meaningful_sectors=0;first=None;last=None
    for off in range(0,len(tail),512):
        block=tail[off:off+512]
        hits=[i for i,v in enumerate(block) if v not in (0,255)]
        if not hits:continue
        meaningful_count+=len(hits);meaningful_sectors+=1
        a=tail_start+off+hits[0];b=tail_start+off+hits[-1]
        first=a if first is None else min(first,a)
        last=b if last is None else max(last,b)
        if len(detailed)<36:
            preview=block[:32]
            detailed.append({'offset_hex':hex(tail_start+off),'meaningful_bytes':len(hits),
                             'sha256':h256(block),'first_32_hex':preview.hex(),
                             'first_32_ascii':''.join(chr(v) if 32<=v<=126 else '.' for v in preview)})
    R['oem_tail']={'start_hex':hex(tail_start),'length_bytes':len(tail),
                    'meaningful_bytes':meaningful_count,'meaningful_sectors':meaningful_sectors,
                    'first_meaningful_hex':hex(first) if first is not None else None,
                    'last_meaningful_hex':hex(last) if last is not None else None,
                    'sha256':h256(tail),'sector_samples':detailed,
                    'samples_truncated':meaningful_sectors>len(detailed)}
    if meaningful_count:
        echo(f'В заводском p26 есть дополнительные данные: {meaningful_count} байт, от {hex(first)} до {hex(last)}', 'warn')
        echo('Данные сохраняются в исходных адресах. Запись опытного образа ЗАПРЕЩЕНА до проверки их назначения.', 'warn')
    else:
        echo('Дополнительных значимых данных в хвостовой области не обнаружено','ok')
    original_id=oem[576:596]
    sha_base=hashlib.sha1();sha_base.update(kernel);sha_base.update(struct.pack('<I',ks))
    sha_base.update(ramdisk);sha_base.update(struct.pack('<I',rs));sha_base.update(struct.pack('<I',ss))
    sha_dt=sha_base.copy();sha_dt.update(dt);sha_dt.update(struct.pack('<I',dt_size))
    mode='qualcomm-dt' if original_id==sha_dt.digest() else 'android-legacy' if original_id==sha_base.digest() else 'unknown'
    R['original_boot_id_format']=mode
    if mode=='unknown': echo('Заводской SHA-1 ID не соответствует известным форматам. Сборка возможна, запись будет заблокирована.', 'warn')
    else: echo('Заводской алгоритм SHA-1 ID: '+mode,'ok')
    R['factory']={'sha256':h256(oem),'kernel_sha256':h256(kernel),'qcdt_sha256':h256(dt),'ramdisk_sha256':h256(ramdisk)}
    return (oem[:page],kernel,dt,ka,page)

def entry(name,mode,body=b'',rmaj=0,rmin=0,idx=1):
    name=name.encode('ascii')+b'\0'
    vals=[idx,mode,0,0,1,0,len(body),0,0,0,0,rmaj,rmin,len(name),0]
    # cpio newc: 13 numbers, not 15.
    vals=[idx,mode,0,0,1,0,len(body),0,0,rmaj,rmin,len(name),0]
    header=b'070701'+b''.join(f'{v:08X}'.encode('ascii') for v in vals)
    assert len(header)==110
    t=header+name;t+=b'\0'*(-len(t)%4);t+=body;t+=b'\0'*(-len(t)%4)
    return t

def exact_size_gzip(cpio, target):
    """GZIP/DEFLATE stored blocks, valid gzip EXACTLY OEM ramdisk_size bytes.
    Padding is inside the gzip stream rather than ambiguous trailing gzip bytes.
    The kernel unpacks the CPIO then ignores NUL padding after TRAILER!!!.
    """
    blocks=next((k for k in range(1,1000) if (target-21-5*k+65534)//65535==k),None)
    guard(blocks is not None,'Размер заводского ramdisk допускает точную gzip упаковку')
    raw_len=target-21-5*blocks
    guard(raw_len>=len(cpio) and raw_len<10*1024*1024,'Тестовая CPIO помещается в заводской ramdisk')
    raw=cpio
    guard(len(raw)==raw_len,'GZIP CPIO совпадает с точным заводским размером')
    packed=bytearray(b'\x1f\x8b\x08\x08\0\0\0\0\0\x03ab\0')
    for pos in range(0,len(raw),65535):
        block=raw[pos:pos+65535]
        last=pos+len(block)==len(raw)
        packed.append(1 if last else 0) # BFINAL; BTYPE=00 (stored)
        packed.extend(struct.pack('<HH',len(block),(~len(block))&0xFFFF))
        packed.extend(block)
    packed.extend(struct.pack('<II',zlib.crc32(raw)&0xFFFFFFFF,len(raw)&0xFFFFFFFF))
    guard(len(packed)==target,'Новый ramdisk имеет ТОЧНО заводской размер')
    guard(gzip.decompress(packed)==raw,'GZIP проходит полную проверку распаковки и CRC32')
    guard(raw.startswith(b'070701') and b'TRAILER!!!' in cpio,'Initramfs содержит корректные записи CPIO')
    return bytes(packed)

def ramdisk_bytes(program, target):
    guard(program[:4]==b'\x7fELF' and program[4]==1 and program[5]==1,'Тестовая программа ELF32 LE')
    guard(struct.unpack_from('<H',program,18)[0]==40,'Программа исполняется на ARM32')
    guard(b'/lib/ld-' not in program,'Программа статическая, без загрузчика библиотек')
    c=entry('.',0o40755)+entry('dev',0o40755)+entry('dev/console',0o20666,rmaj=5,rmin=1)+entry('dev/null',0o20666,rmaj=1,rmin=3)
    c+=entry('dev/kmsg',0o20666,rmaj=1,rmin=11)+entry('dev/fb0',0o20666,rmaj=29,rmin=0)
    c+=entry('dev/graphics',0o40755)+entry('dev/graphics/fb0',0o20666,rmaj=29,rmin=0)
    c+=entry('init',0o100755,body=program)
    trailer=entry('TRAILER!!!',0)
    blocks=next((k for k in range(1,1000) if (target-21-5*k+65534)//65535==k),None)
    guard(blocks is not None,'Размер gzip совместим с заводским')
    raw_len=target-21-5*blocks
    pad_bytes=raw_len-len(c)-len(entry('pad',0o100600))-len(trailer)
    guard(pad_bytes>=0 and pad_bytes%4==0,'Размер CPIO заполняется корректным файлом')
    c+=entry('pad',0o100600,body=b'\0'*pad_bytes)+trailer
    guard(len(c)==raw_len,'CPIO точно заполнил исходный размер')
    return exact_size_gzip(c,target)

def build(oem,program):
    original_header,kernel,dt,ka,page=extract_android(oem)
    old_rs=struct.unpack_from('<I',oem,16)[0]
    ks=len(kernel);dt_size=len(dt)
    ro=page+align(ks,page)
    dt_off=ro+align(old_rs,page)
    old_tail_start=align(dt_off+dt_size,page)
    ram=ramdisk_bytes(program,old_rs)
    guard(old_rs==len(ram) and len(oem)==PART_SIZE,'Сохранена оригинальная геометрия boot image')
    hdr=bytearray(original_header)
    sha=hashlib.sha1()
    sha.update(kernel);sha.update(struct.pack('<I',len(kernel)))
    sha.update(ram);sha.update(struct.pack('<I',len(ram)))
    sha.update(struct.pack('<I',0))
    if R.get('original_boot_id_format')=='qualcomm-dt':
        sha.update(dt);sha.update(struct.pack('<I',dt_size))
    guard(R.get('original_boot_id_format') in ('qualcomm-dt','android-legacy'),'Заводской алгоритм boot ID распознан')
    hdr[576:608]=sha.digest()+b'\0'*12
    new=bytearray(oem)
    new[:page]=hdr
    new[ro:ro+old_rs]=ram
    guard(new[page:ro]==oem[page:ro],'Ядро и его заводское выравнивание нетронуты')
    guard(new[dt_off:old_tail_start]==oem[dt_off:old_tail_start],'QCDT и адреса DTB нетронуты')
    guard(new[old_tail_start:]==oem[old_tail_start:],'Дополнительная OEM-область сохранена целиком')
    guard(new[ro+old_rs:]==oem[ro+old_rs:],'Все байты после ramdisk исходные')
    guard(new[:576]==oem[:576] and new[608:page]==oem[608:page], 'В OEM-заголовке изменён только идентификатор образа')
    guard(new[ro:ro+old_rs]!=oem[ro:ro+old_rs],'Изменён только ramdisk')
    guard(gzip.decompress(new[ro:ro+old_rs])[:6]==b'070701','Тестовый initramfs читается после повторной упаковки')
    R['candidate_meta']={
      'kernel_same_as_oem':True,'qcdt_same_as_oem':True,
      'extra_oem_bytes_same_as_oem':True,'android_header_geometry_same_as_oem':True,
      'ramdisk_bytes':len(ram),'ramdisk_offset':hex(ro),'qcdt_offset':hex(dt_off),
      'tail_offset':hex(old_tail_start),'sha256':h256(new),'full_bytes':len(new),
      'kernel_addr':hex(ka),'arm32_init_sha256':h256(program),
      'modified_ranges':['0x240..0x25f: boot id','%s..%s: ramdisk'%(hex(ro),hex(ro+old_rs))],
      'verified_boot_not_proven':True}
    echo('Порядок и смещения заводских секций НЕ изменены; OEM-хвост побайтово сохранён','ok')
    echo('Подпись OEM может отклонить экспериментальный ramdisk: это будет установлено только аппаратным испытанием','warn')
    return bytes(new)

def read_pkg(path):
    with zipfile.ZipFile(PREF) as z:return z.read(path)

def load_legacy():
    m=ModuleType('edl_legacy');m.__dict__['__name__']='edl_legacy'
    exec(compile(read_pkg('legacy/edl_v21_5_main.py'),'legacy/edl_v21_5_main.py','exec'),m.__dict__)
    return m

def native_recover():
    from adbtransport import recovery_connect
    notes=[];session=recovery_connect(notes)
    R['adb_servers']=notes[-15:]
    guard(session is not None,'Подтверждён живой ADB MIFI, MSM8916 и JZ_MIFI_LCD')
    R['adb_server_port']=session.server.port

def enter_edl(leg):
    guard(shutil.which('su') is not None,'Magisk su доступен')
    mode,dev=leg.usb()
    guard(len(dev)==1 and mode in ('9024','9091','9008'),'Ровно один Qualcomm USB JZ08')
    e=leg.find_edl();guard(e is not None,'Рабочий Firehose и USB-модули совместимости доступны')
    if mode=='9024':
        native_recover()
        guard(leg.auto_transition_from_9024(),'Переход Native ADB → EDL 9008')
    elif mode=='9091':guard(leg.auto_transition_from_9091(*e),'Переход Qualcomm DIAG → EDL 9008')
    mode,dev=leg.usb();guard(mode=='9008' and len(dev)==1,'EDL 9008 доступен')
    guard(leg.preflight_libusb(*e),'EDL доступен через USB')
    return e

def command(leg,ep,py,words,expected_size=None):
    REPORTS.mkdir(parents=True,exist_ok=True)
    log=REPORTS/('V26_EDL_'+words[0]+'_'+(words[1] if len(words)>1 else '')+'_'+STAMP+'.log')
    # Never call subprocess with shell=True. Only legacy EDL client, fixed partition names.
    rc=leg.run_root_log(ep,py,words,log,timeout=330 if words[0]=='w' else 220,watch=Path(words[2]) if words[0]=='r' else None,expected_size=expected_size)
    R.setdefault('edl',[]).append({'cmd':' '.join([words[0], words[1] if len(words)>1 else '']),'rc':rc,'log_name':log.name})
    guard(rc==0,'Firehose команда '+words[0]+' '+(words[1] if len(words)>1 else '')+' успешно завершена')
    return log

def readpart(leg,ep,py,part,expected):
    path=REPORTS/('V26_'+part+'_read_'+STAMP+'.bin')
    command(leg,ep,py,['r',part,str(path),'--memory=emmc'],expected_size=expected)
    guard(path.exists() and path.stat().st_size==expected,'Размер прочитанного '+part+' совпадает')
    return path

def device_flash(candidate,restore=False):
    R['mode']='RESTORE_STOCK' if restore else 'FLASH_ARM32_PROBE'
    echo('Физическая запись только p26 recovery; остальные разделы не затрагиваются.','warn')
    legacy=load_legacy()
    ep,py=enter_edl(legacy)
    may_reset=True
    was_write=False
    try:
        echo('Заводские ABOOT, BOOT и GPT: сверка прямо с устройства','step')
        ab=readpart(legacy,ep,py,'aboot',1048576)
        guard(hdisk(ab)==ABOOT_HASH,'Живой ABOOT совпадает с заводским')
        boot=readpart(legacy,ep,py,'boot',PART_SIZE)
        guard(hdisk(boot)==BOOT_HASH,'Живой Android BOOT совпадает с заводским')
        gp=REPORTS/('V26_GPT_'+STAMP+'.log')
        rc=legacy.run_root_log(ep,py,['printgpt','--memory=emmc'],gp,timeout=90)
        guard(rc==0, 'Firehose printgpt успешно завершён')
        from gptlib import validate_live_log
        validate_live_log(gp.read_text('utf-8','replace'),json.loads(read_pkg('factory_layout.json')))
        guard(True, 'Живая GPT: совпали геометрия и все 27 диапазонов')
        # Read only GPT edges; compare to the already verified local factory dump.
        source=Path(os.environ.get('XARKON_V37_BACKUP',str(BKP if BKP.is_file() else BKP2)))
        if not restore or source.is_file():
            guard(source.is_file() and source.stat().st_size==DISK, 'Исходный дамп доступен для сверки живой GPT')
            for first,count,label in [(0,34,'primary'),(DISK//512-33,33,'secondary')]:
                edge=REPORTS/('V37_GPT_'+label+'.bin')
                edge.unlink(missing_ok=True)
                command(legacy,ep,py,['rs',str(first),str(count),str(edge),'--memory=emmc'],expected_size=count*512)
                guard(edge.is_file() and edge.stat().st_size==count*512, 'GPT '+label+': прочитано нужное число секторов')
                with source.open('rb') as factory:
                    factory.seek(first*512);expected=factory.read(count*512)
                guard(edge.read_bytes()==expected, 'GPT '+label+': побайтовое совпадение с factory backup')
                R.setdefault('live_gpt_edges',{})[label]=h256(expected)
                edge.unlink()

        old=readpart(legacy,ep,py,'recovery',PART_SIZE)
        h=hdisk(old)
        R['recovery_live_before_sha256']=h
        if not restore:
            guard(h==STOCK_HASH,'До испытания p26 обязан полностью совпадать с заводским')
            guard(hdisk(candidate)==R['candidate_meta']['sha256'],'Экспериментальный образ не изменился на диске')
        elif h==STOCK_HASH:
            echo('p26 уже заводской, перезаписывать не нужно','ok')
            R['status']='STOCK_ALREADY_PRESENT_NO_WRITE'
            return
        else:
            guard(hdisk(candidate)==STOCK_HASH,'Исходный factory recovery идентичен проверенному дампу')
        # DO NOT reboot after interrupted write until factory image restored.
        may_reset=False
        was_write=True
        R['write_attempted']=True
        command(legacy,ep,py,['w','recovery',str(candidate),'--memory=emmc'])
        after=readpart(legacy,ep,py,'recovery',PART_SIZE)
        target=hdisk(candidate)
        guard(hdisk(after)==target,'Физическая запись p26 сверена SHA-256')
        R['emmc_write']=True
        R['recovery_live_after_sha256']=target
        R['status']='STOCK_RECOVERY_RESTORED' if restore else 'ARM32_PROBE_WRITTEN_NOT_BOOTED'
        may_reset=True
    except BaseException as ex:
        if was_write and not restore:
            echo('После начала записи возник сбой. Пробую автоматически вернуть заводской p26.','warn')
            R['rollback_attempted']=True
            try:
                stock=stock_recovery()
                command(legacy,ep,py,['w','recovery',str(stock),'--memory=emmc'])
                restored=readpart(legacy,ep,py,'recovery',PART_SIZE)
                guard(hdisk(restored)==STOCK_HASH,'ROLLBACK: заводской p26 снова совпадает SHA-256')
                R['rollback_verified']=True
                R['status']='EXPERIMENT_FAILED_FACTORY_RECOVERY_RESTORED'
                may_reset=True
            except BaseException as rb:
                R['rollback_verified']=False
                R['rollback_error']=repr(rb)
                echo('ОТКАТ НЕ ПОДТВЕРЖДЁН. Роутер оставлен в EDL для ручного восстановления.','fail')
        elif was_write and restore:
            echo('Восстановление заводского p26 НЕ подтверждено. Не отключай питание EDL.','fail')
        raise
    finally:
        if may_reset:
            try:command(legacy,ep,py,['reset'])
            except BaseException as ex:echo('Команда выхода из EDL не подтверждена: '+str(ex),'warn')
        else:
            echo('Роутер сохранён в EDL: требуется проверенное восстановление.','fail')

def test_recovery():
    # From OEM Android ONLY. Does not write eMMC.
    import shlex
    R['mode']='TEST_RECOVERY_BOOT'
    echo('ВНИМАНИЕ: следующий шаг перезагрузит JZ08 в экспериментальный Recovery.','warn')
    echo('Если экран зависнет, отключить USB, снять/установить АКБ, загрузить Android, затем --restore-factory.','warn')
    if not CAND.is_file() or CAND.stat().st_size!=PART_SIZE:
        raise RuntimeError('Сначала собрать и записать образ v26')
    expected=R.get('candidate_meta',{}).get('sha256')
    if expected:guard(hdisk(CAND)==expected,'Образ на телефоне готов к проверке')
    native_recover()
    def call(*params):
        return adb_command(*params,timeout=28)
    cp=call('devices','-l')
    lines=[x for x in cp.stdout.splitlines() if re.match(r'^\S+\s+device\b',x)]
    guard(len(lines)==1 and 'model:MIFI' in lines[0] and 'product:MIFI' in lines[0], 'Единственный Native ADB MIFI подтверждён')
    serial=lines[0].split()[0]
    cp=call('-s',serial,'shell','getprop','ro.board.platform')
    guard(cp.returncode==0 and 'msm8916' in cp.stdout.lower(),'Плата MSM8916 подтверждена')
    cp=call('-s',serial,'reboot','recovery')
    R['recovery_reboot_result']={'rc':cp.returncode,'out':cp.stdout[-300:],'err':cp.stderr[-300:]}
    guard(cp.returncode==0,'Команда входа в Recovery отправлена через Native ADB')
    R['status']='RECOVERY_TEST_COMMAND_SENT_NOT_BOOT_VERIFIED'
    echo('Роутер перезагружается. Сам запуск тестового /init не доказан: проверь LCD.','warn')


MARKER='/cache/XARKON_JZ08_V26_INIT_OK.txt'
def adb_command(*args,timeout=32):
    from adbtransport import recovery_command
    return recovery_command(args,timeout)
def marker_check(fresh=False):
    R['mode']='CHECK_BOOT_MARKER'
    native_recover()
    cp=adb_command('devices','-l')
    lines=[line for line in cp.stdout.splitlines() if re.match(r'^\S+\s+device\b',line)]
    guard(len(lines)==1 and 'model:MIFI' in lines[0] and 'product:MIFI' in lines[0], 'Единственный MIFI снова доступен по Native ADB')
    serial=lines[0].split()[0]
    cp=adb_command('-s',serial,'shell','cat',MARKER)
    R['marker_check']={'returncode':cp.returncode,'stdout':cp.stdout[-1500:],'stderr':cp.stderr[-1500:],'marker':MARKER}
    success=(cp.returncode==0 and 'XARKON JZ08 v26: ARM32 /init executed' in cp.stdout)
    R['boot_proven_on_hw']=bool(success)
    if success:
        R['status']='V26_INIT_EXECUTED_CACHE_MARKER_CONFIRMED'
        echo('ВЫПОЛНЕНИЕ ARM32 /init ДОКАЗАНО: прочитан маркер из /cache','ok')
        if not fresh:echo('Маркер подтверждает хотя бы один запуск v26; для повторных тестов нужно учитывать его сохранение','warn')
    else:
        R['status']='V26_NO_MARKER_BOOT_NOT_PROVEN'
        echo('Маркер не найден или недоступен. Отсутствие маркера НЕ доказывает, что загрузчик отверг образ.','warn')
    return success

def wait_for_native(tag,attempts=5,delay=20):
    for k in range(1,attempts+1):
        echo(f'{tag}: проверка Native ADB {k}/{attempts}', 'step')
        try:
            native_recover()
            return True
        except Exception as ex:
            echo('ADB ещё не восстановлен: '+str(ex),'warn')
        if k!=attempts:time.sleep(delay)
    return False

def report():
    REPORTS.mkdir(parents=True,exist_ok=True)
    p=REPORTS/('XARKON_JZ08_BOOT_EVIDENCE_V26_'+STAMP+'.zip')
    R['finished_at']=datetime.datetime.now().isoformat()
    summary='XARKON // JZ08 · BOOT EVIDENCE v26\n\n'
    summary+='Статус: '+R['status']+'\n'
    summary+='ОБРАЗ НЕ ЯВЛЯЕТСЯ OPENWRT. Используется заводское ARM32 zImage и заводской QCDT.\n'
    summary+='Запись eMMC: '+('ДА, ТОЛЬКО recovery p26' if R['emmc_write'] else 'НЕТ')+'\n'
    summary+='Проверка загрузки ядра на устройстве: '+('ДА' if R['boot_proven_on_hw'] else 'НЕТ')+'\n'
    summary+='\nСОБЫТИЯ:\n'+'\n'.join('['+it['status']+'] '+it['text'] for it in LOG)
    with zipfile.ZipFile(p,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=7) as z:
        z.writestr('ОТЧЁТ.txt',summary)
        z.writestr('РЕЗУЛЬТАТ.json',json.dumps(R,ensure_ascii=False,indent=2))
        z.writestr('ОТЧЁТ.html','<meta charset="utf-8"><style>body{background:#080e1b;color:#dce8ff;font:16px monospace;padding:24px;white-space:pre-wrap}h2{color:#c39bff}</style><h2>XARKON // JZ08 · BOOT EVIDENCE v26</h2>'+html.escape(summary))
    echo('ZIP-отчёт сохранён: '+str(p),'ok')
    if not args.no_open and shutil.which('termux-open'):
        try:subprocess.Popen(['termux-open',str(p)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        except OSError:pass
    return p

def selftest():
    # Synthetic image validates repacker without pretending a hardware boot was tested.
    kernel=bytearray(b'\0'*6442128);kernel[36:40]=bytes.fromhex('18286f01')
    dt=b'QCDT'+b'\0'*(288768-4)
    rr=gzip.compress(entry('.',0o40755)+entry('init',0o100755,b'hello')+entry('TRAILER!!!',0),mtime=0)
    # synthetic original has same fixed OEM RAMDISK length, padded only for mock
    rr+=b'\0'*(1070918-len(rr))
    h=bytearray(2048);h[:8]=b'ANDROID!';struct.pack_into('<9I',h,8,6442128,0x80008000,1070918,0x81000000,0,0,0,2048,288768)
    sha=hashlib.sha1()
    sha.update(bytes(kernel));sha.update(struct.pack('<I',6442128))
    sha.update(rr);sha.update(struct.pack('<I',1070918));sha.update(struct.pack('<I',0))
    sha.update(dt);sha.update(struct.pack('<I',len(dt)))
    h[576:596]=sha.digest()
    # Synthetic original image has valid Qualcomm DT-based boot ID.
    o=bytes(h)+bytes(kernel)+b'\0'*(-len(kernel)%2048)+rr+b'\0'*(-len(rr)%2048)+dt+b'\0'*(-len(dt)%2048)
    o+=b'\0'*(PART_SIZE-len(o))
    # No factory hash check for synthetic mock, only format / OEM preservation.
    test=build(o,read_pkg('bin/probe_init.arm32'))
    guard(len(test)==PART_SIZE,'Самопроверка: 16 МиБ')
    guard(h256(test)!=h256(o),'Самопроверка: изменён только ramdisk и идентификатор')
    k=6442128;rs=1070918;ro=2048+align(k,2048);do=ro+align(rs,2048)
    guard(test[do:]==o[do:],'Самопроверка: QCDT, OEM tail и все адреса исходные')
    guard(test[ro:ro+rs]!=o[ro:ro+rs],'Самопроверка: ramdisk заменён')
    guard(test[:576]==o[:576] and test[608:ro]==o[608:ro],'Самопроверка: структура заголовка исходная')
    guard(len(gzip.decompress(test[ro:ro+rs]))>len(read_pkg('bin/probe_init.arm32')),'Самопроверка: целый GZIP без хвостового мусора')
    echo('Самопроверка синтетической упаковки успешно пройдена. Это НЕ тест на JZ08.','ok')

def main():
    print('\n\033[38;5;141m══════════════ XARKON // JZ08 // BOOT EVIDENCE v26 ══════════════\033[0m\n')
    try:
        if args.self_test:selftest();R['status']='LOCAL_SELFTEST_ONLY';return
        if args.test_recovery:test_recovery();return
        if args.check_marker:marker_check();return
        echo('01 / ЗАВОДСКОЙ RECOVERY И ВЕРИФИКАЦИЯ','step')
        source=stock_recovery();oem=source.read_bytes()
        if args.restore_factory:
            R['candidate_sha256']=h256(oem)
            device_flash(source,restore=True);return
        echo('02 / СОХРАНЕНИЕ OEM-КОМПОНОВКИ И СБОРКА ARM32 RAMDISK','step')
        program=read_pkg('bin/probe_init.arm32')
        output=build(oem,program)
        tmp=CAND.with_suffix('.partial');tmp.write_bytes(output);tmp.replace(CAND)
        guard(CAND.stat().st_size==PART_SIZE and hdisk(CAND,True)==h256(output),'Тестовый recovery.img собран и SHA-256 совпадает')
        R['status']='BUILT_NOT_FLASHED'
        echo('Только локальный образ: OEM-ядро+экспериментальный ramdisk, НЕ OpenWrt.','warn')
        if args.flash_probe or args.single_pass:
            guard(R['candidate_meta']['qcdt_offset']==hex(0x72B000),
                  'QCDT остаётся на исходном смещении 0x72B000')
            guard(R['candidate_meta']['tail_offset']==hex(0x771800),
                  'OEM хвост остаётся на исходном смещении 0x771800')
            guard(R.get('original_boot_id_format') in ('qualcomm-dt','android-legacy'),
                  'Алгоритм заводского Android boot ID известен; запись допустима')
            echo('03 / ПЕРВАЯ ЭКСПЕРИМЕНТАЛЬНАЯ ПРОШИВКА p26 RECOVERY','step')
            device_flash(CAND)
            echo('Запись проверена, раздел p26 изменён.','warn')
            if args.single_pass:
                R['mode']='SINGLE_PASS_FLASH_BOOT_CHECK_RESTORE'
                if not wait_for_native('Возврат Android после EDL',attempts=5,delay=15):
                    R['status']='V26_FLASHED_ANDROID_NOT_DETECTED'
                    echo('Android не обнаружен. Не запускаю Recovery и не предпринимаю новую запись. При необходимости выключи роутер снятием АКБ.','fail')
                    return
                test_recovery()
                echo('Ожидаю возвращения заводского Android после испытания Recovery. На самом LCD может не быть индикации.', 'warn')
                if not wait_for_native('Ожидание после тестового Recovery',attempts=7,delay=20):
                    R['status']='V26_TEST_REBOOT_NO_ADB_RECOVERY_LEFT_MODIFIED'
                    echo('Автозапуск Android после Recovery не подтверждён. НУЖНО вручную обесточить роутер и запустить --restore-factory после возврата Android.','fail')
                    return
                marker_check(fresh=True)
                result=R['boot_proven_on_hw']
                R['single_pass_marker_success']=result
                factory=stock_recovery()
                echo('Восстанавливаю заводской p26 после теста, независимо от результата маркера','warn')
                device_flash(factory,restore=True)
                R['status']='V26_PROBE_CONFIRMED_AND_FACTORY_RESTORED' if result else 'V26_PROBE_UNPROVEN_FACTORY_RESTORED'
                R['boot_proven_on_hw']=result
                echo('Цикл завершён: заводской recovery возвращён. Полная OpenWrt НЕ установлена.', 'ok')
            else:
                echo('Запись проверена. Автоматически в Recovery НЕ перезагружаю.','warn')
                echo('После возврата Android запусти --test-recovery; после возврата ещё раз --check-marker, затем --restore-factory.', 'warn')
    except Exception as e:
        R['status']='FAILED';R['error']=repr(e);R['traceback']=traceback.format_exc()
        echo(str(e),'fail')
    finally:
        report()

if __name__=='__main__':main()
