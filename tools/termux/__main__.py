#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""INFEND JZ08 full OpenWrt trial v3, exact preflight and recovery restoration."""
import argparse, datetime, hashlib, json, os, re, secrets, shlex, shutil, struct, subprocess, sys, time, zipfile
from pathlib import Path
from bootlib import FDT, boot_image
from gptlib import BACKUP_SHA, RECOVERY_SHA, backup_candidates, filehash, validate_gpt

ROOT=Path('/storage/emulated/0/Download')
PREFIX=Path(os.environ.get('PREFIX','/data/data/com.termux/files/usr'))
STAMP=datetime.datetime.now().astimezone(datetime.timezone(datetime.timedelta(hours=3))).strftime('%Y%m%d_%H%M%S')
STAGE=ROOT/'INFEND_JZ08_OPENWRT'
REPORTS=ROOT/'XARKON_JZ08_REPORTS'
PACKAGE=Path(sys.argv[0]).resolve()
EXPECTED_SERIAL=None
EVENTS=[];FILES={};STATE={'version':3,'runtime_kind':'full-openwrt','status':'START','linux_init_verified':False,'emmc_read_verified':False,
                         'openwrt_installed':False,'full_system_flash_allowed':False,'hardware_test_in_this_environment':False,'openwrt_runtime_verified':False,'luci_http_verified':False}
def say(message,kind='INFO'):
    EVENTS.append({'time':datetime.datetime.now().isoformat(timespec='seconds'),'kind':kind,'text':message})
    names={'INFO':'ИНФО','OK':'ГОТОВО','WARN':'ВНИМАНИЕ','ERROR':'ОШИБКА'}
    color={'INFO':'\033[36m','OK':'\033[92m','WARN':'\033[93m','ERROR':'\033[91m'}
    line='['+names[kind]+'] '+message
    print(color[kind]+line+'\033[0m' if sys.stdout.isatty() else line,flush=True)
def require(ok,message):
    if not ok:raise RuntimeError(message)
def read(name):
    with zipfile.ZipFile(PACKAGE) as z:return z.read(name)
def redact(text):
    text=text.replace(EXPECTED_SERIAL,'[SERIAL]') if EXPECTED_SERIAL else text
    text=re.sub(r'(?i)(imei|iccid|imsi|password|psk|serialno|serialnumber)([\"\s:=]+)[^\s,\"<>]+',r'\1\2[REDACTED]',text)
    text=re.sub(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b','[MAC]',text)
    return text
def package_check():
    manifest=json.loads(read('MANIFEST_SHA256.json'))
    with zipfile.ZipFile(PACKAGE) as z:
        require(len(z.namelist())==len(set(z.namelist())),'В ZIP есть повторяющиеся имена')
        require(set(z.namelist())==set(manifest['files'])|{'MANIFEST_SHA256.json'},'Состав ZIP не соответствует manifest')
        for name,h in manifest['files'].items():
            require(hashlib.sha256(z.read(name)).hexdigest()==h,'Повреждён файл '+name)
    STATE['package_integrity']=True
    say('Целостность ядра, initramfs, DTB и исходников подтверждена','OK')
def runroot(argv,timeout=30):
    env=['env','HOME=/data/data/com.termux/files/home','PATH='+str(PREFIX/'bin')+':/system/bin:/system/xbin','LD_LIBRARY_PATH='+str(PREFIX/'lib'),
         'TMPDIR='+str(PREFIX/'tmp'),'ADB_LIBUSB=0','ADB_SERVER_PORT=5063']
    cmd=' '.join(shlex.quote(str(x)) for x in env+list(argv))
    return subprocess.run(['su','-c',cmd],capture_output=True,text=True,errors='replace',timeout=timeout)
def root_check():
    require(ROOT.is_dir(),'Нужен Termux на S24; разреши доступ к Download через termux-setup-storage')
    require(shutil.which('su'),'Не найден Magisk su')
    r=runroot(['id','-u']);require(r.returncode==0 and r.stdout.strip()=='0','Magisk не предоставил root')
    require((PREFIX/'bin/fastboot').is_file(),'Нет fastboot в Termux (пакет android-tools)')
    require(shutil.disk_usage(ROOT).free>250*1024**2,'Нужно хотя бы 250 МиБ свободно в Download')
    STAGE.mkdir(parents=True,exist_ok=True)
def backup_check():
    layout=json.loads(read('factory_layout.json'))
    candidates=backup_candidates(ROOT)
    path=next((p for p in candidates if p.is_file() and p.stat().st_size==layout['disk_bytes']),None)
    require(path is not None,'Не найден уже сохранённый полный дамп в XARKON_MIFI_SAFE_COPY или XARKON_MIFI_BACKUPS/20261028_082457')
    say('Проверяю существующий дамп; повторного чтения всей eMMC не будет')
    previous=[-1]
    def progress(done,total):
        pct=done*100//total
        if pct//5>previous[0]:
            previous[0]=pct//5
            print(f'  SHA-256 [{"█"*(pct//5)}{"░"*(20-pct//5)}] {pct:3d}%  {done//1024**2}/{total//1024**2} МиБ',flush=True)
    require(filehash(path,progress)==BACKUP_SHA,'SHA-256 полного дампа не совпал')
    STATE['backup']=validate_gpt(path,layout);STATE['backup']['sha256_verified']=True
    os.environ['XARKON_V37_BACKUP']=str(path)
    say('Дамп, обе GPT и все 27 диапазонов разделов проверены','OK')
    collect_factory_dtb(path,layout)
    return path
def collect_factory_dtb(path,layout):
    # Static board metadata only. No partition payload, NV or calibration data.
    part=next(p for p in layout['partitions'] if p['name']=='boot')
    with path.open('rb') as f:
        f.seek(part['start']*512);b=f.read(part['sectors']*512)
    require(b[:8]==b'ANDROID!','Factory boot: нет Android header')
    ks,ka,rs,ra,ss,sa,ta,page,ds=struct.unpack_from('<9I',b,8)
    require(page in (2048,4096) and ss==0,'Factory boot: неизвестная компоновка')
    align=lambda n:(n+page-1)//page*page
    off=page+align(ks)+align(rs)
    require(off+ds<=len(b) and b[off:off+4]==b'QCDT','Factory boot: QCDT вне границ')
    ver,num=struct.unpack_from('<II',b,off+4)
    require(ver==2 and num==8 and 12+24*num<=ds,'Factory boot: ожидаются 8 QCDT v2 entries')
    output=[]
    for i in range(num):
        soc,board,sub,rev,start,length=struct.unpack_from('<6I',b,off+12+24*i)
        require(0<length and start+length<=ds,'Factory boot: DTB вне секции')
        dt=FDT(b[off+start:off+start+length]);nodes={}
        for name,props in dt.nodes.items():
            if not any(k in name.lower() for k in ('memory','reserve','usb','sdhc','mmc','spi','panel','wcnss','pronto','regulator','rpm','pin','pmic','battery','charger')):continue
            node={}
            for key,value in props.items():
                if any(k in key.lower() for k in ('serial','mac-address','imei','iccid','imsi','secret','calibr','nvbin')):continue
                node[key]={'hex':value.hex()}
                if value and all(c==0 or 32<=c<127 for c in value):node[key]['text']=value.rstrip(b'\0').decode('ascii').replace('\0',' | ')
            nodes[name]=node
        output.append({'entry':i,'soc':soc,'board':board,'subtype':sub,'revision':rev,'nodes':nodes})
    FILES['factory-dtb-board-metadata.json']=json.dumps(output,ensure_ascii=False,indent=2)
    STATE['factory_dtb_entries']=len(output)
    say('Из существующего backup извлечены настройки платы из 8 заводских DTB','OK')
def fb(args,timeout=20,target=True):
    argv=[str(PREFIX/'bin/fastboot')]
    if target and EXPECTED_SERIAL:argv+=['-s',EXPECTED_SERIAL]
    return runroot(argv+list(args),timeout)
def connected():
    global EXPECTED_SERIAL
    r=fb(['devices'],target=False)
    names=[line.split()[0] for line in r.stdout.splitlines() if re.match(r'^\S+\s+fastboot(?:\s|$)',line)]
    if not names:return False
    require(len(names)==1 and (EXPECTED_SERIAL is None or names==[EXPECTED_SERIAL]),'Подключён другой Fastboot или несколько устройств; остановка')
    EXPECTED_SERIAL=names[0]
    r=fb(['getvar','all']);s=r.stdout+r.stderr
    require(r.returncode==0 and 'product:lk2nd-msm8916' in s.replace(' ','') and
            'lk2nd:compatible:xarkon,jz08-3000-nkv' in s.replace(' ',''),'Не подтверждён LK2ND JZ08')
    return True
def save_asset(name,dest):
    data=read(name);tmp=dest.with_suffix(dest.suffix+'.tmp');tmp.write_bytes(data);tmp.replace(dest);return dest
def legacy(action):
    child=save_asset('legacy/v32-guarded.zip',STAGE/'v32-guarded.zip')
    folder=STAGE/'legacy_reports';folder.mkdir(exist_ok=True)
    env=os.environ.copy();env['XARKON_V37_REPORT_DIR']=str(folder)
    log=STAGE/('legacy-'+action.lstrip('-')+'.log');start=time.time()
    say('Проверенная цепочка recovery: '+action)
    with log.open('w') as f:
        p=subprocess.Popen([sys.executable,str(child),action],stdout=f,stderr=subprocess.STDOUT,env=env,start_new_session=True)
        STATE['legacy_process_active']=True
        until=time.monotonic()+1200;offset=0
        try:
            while p.poll() is None:
                if time.monotonic()>until:
                    # Let the child perform its rollback; never kill it during a write.
                    p.send_signal(__import__('signal').SIGINT)
                    try:p.wait(timeout=400)
                    except subprocess.TimeoutExpired:raise RuntimeError('Цепочка recovery ещё работает; не запускай второй процесс')
                    break
                time.sleep(1)
                with log.open(errors='replace') as src:src.seek(offset);s=src.read();offset=src.tell()
                if s:print(redact(s),end='',flush=True)
        except KeyboardInterrupt:
            p.send_signal(__import__('signal').SIGINT)
            try:p.wait(timeout=400)
            except subprocess.TimeoutExpired:pass
            raise
        finally:STATE['legacy_process_active']=p.poll() is None
    FILES[log.name]=redact(log.read_text(errors='replace'))
    reports=sorted(folder.glob('XARKON_JZ08_LK2ND_PROOF_V32_*.zip'),key=lambda p:p.stat().st_mtime,reverse=True)
    current=next((p for p in reports if p.stat().st_mtime>=start-1),None)
    require(current is not None,'Цепочка recovery не создала свежий результат')
    with zipfile.ZipFile(current) as z:d=json.loads(z.read('РЕЗУЛЬТАТ.json'))
    STATE['legacy_'+action.lstrip('-')]=json.loads(redact(json.dumps(d,ensure_ascii=False)))
    if action=='--cycle':
        require(d.get('status')=='CYCLE_LK2ND_VERIFIED_RESTORE_REQUIRED' and d.get('fastboot_proof',{}).get('lk2nd_verified') is True,
                'Временная загрузка LK2ND не подтверждена; нужен --restore')
    else:
        require(d.get('status')=='FACTORY_RECOVERY_RESTORED_READBACK' and
                (d.get('recovery_live_after_sha256')==RECOVERY_SHA or d.get('recovery_live_before_sha256')==RECOVERY_SHA),
                'Возврат factory recovery не подтверждён; сохраняй питание и выполни --restore')
        STATE['recovery_restored']=True
    return d
def get_staged(command,name):
    path=STAGE/name
    if path.exists():path.unlink()
    r=fb(command);require(r.returncode==0,'LK2ND не выполнил '+' '.join(command))
    r=fb(['get_staged',str(path)],30)
    require(r.returncode==0 and path.is_file() and path.stat().st_size<2*1024**2,'Не получен '+name)
    return path.read_bytes()
def restore():
    if connected():
        r=fb(['oem','reboot-edl']);require(r.returncode==0,'LK2ND не подтвердил переход в EDL')
        time.sleep(3)
    legacy('--restore-factory')
    say('Заводской recovery восстановлен и перечитан с проверкой SHA-256','OK')
def usb_descriptor(nonce):
    # sysfs works without requiring an Android CDC ACM kernel driver.
    code='from pathlib import Path\nfor p in Path("/sys/bus/usb/devices").glob("*"):\n try:\n  if (p/"idVendor").read_text().strip()=="1d6b" and (p/"idProduct").read_text().strip()=="0104" and (p/"serial").read_text().strip()=="JZ08-INIT-'+nonce+'":print("MATCH")\n except OSError:pass\n'
    r=runroot([sys.executable,'-c',code],10)
    return r.returncode==0 and r.stdout.splitlines().count('MATCH')==1
def capture_usb(nonce):
    r=runroot([sys.executable,str(PACKAGE),'--usb-read',nonce],25)
    if r.returncode==0:
        try:return json.loads(r.stdout)
        except ValueError:pass
    # The existing EDL venv may contain PyUSB when Termux Python does not.
    base=Path.home()/'.local/share/xarkon_mifi_edl'
    for py in sorted(base.glob('venv*/bin/python'))[:6]:
        r=runroot([str(py),str(PACKAGE),'--usb-read',nonce],25)
        if r.returncode==0:
            try:return json.loads(r.stdout)
            except ValueError:pass
    return {'descriptor_verified':True,'report_complete':False,'error':'PyUSB capture unavailable; descriptor proof retained'}
def capture_http(nonce):
    code=('import sys,json;sys.path.insert(0,'+repr(str(PACKAGE))+');'
          'from httpcheck import inspect;print(json.dumps(inspect('+repr(nonce)+')))')
    r=runroot([sys.executable,'-c',code],65)
    if r.returncode==0:
        try:return json.loads(r.stdout)
        except ValueError:pass
    return {'descriptor_verified':True,'report_complete':False,'error':'USB HTTP read unavailable'}
def capture_android(label,start=False):
    r=runroot([sys.executable,str(PACKAGE),'--android-read','start' if start else 'existing'],85)
    try:result=json.loads(r.stdout) if r.returncode==0 else {'available':False,'error':'Android reader failed'}
    except ValueError:result={'available':False,'error':'Invalid Android reader response'}
    post=result.pop('postmortem',None)
    if post:
        FILES['android-'+label+'.txt']=redact(post.pop('log'))
        result['postmortem']=post
    # Keep failed probes visible without growing an unbounded report.
    STATE.setdefault('android_probes',{})[label]=result
    return result
def observe(nonce,seconds=720):
    from postmortem import USB_CODE
    end=time.monotonic()+seconds;last=-1;captured=False;previous_usb=None;last_android=-30
    while time.monotonic()<end:
        elapsed=int(seconds-(end-time.monotonic()))
        if elapsed//10>last:last=elapsed//10;say(f'Ожидание Linux / USB: {elapsed} с')
        r=runroot([sys.executable,'-c',USB_CODE],10)
        try:usb=json.loads(r.stdout) if r.returncode==0 else []
        except ValueError:usb=[]
        if usb!=previous_usb:
            previous_usb=usb
            STATE.setdefault('usb_transitions',[]).append({'elapsed_seconds':elapsed,'devices':usb})
            say('USB: '+(', '.join(d['vid']+':'+d['pid'] for d in usb) or 'цель не видна'))
        if elapsed>5 and elapsed-last_android>=20 and any(d['vid']=='05c6' and d['pid'] in ('9024','9091') for d in usb):
            last_android=elapsed
            try:post=capture_android('after')
            except Exception as ex:
                STATE['android_probe_error']=str(ex);post=None
            if post and post.get('available'):
                STATE['returned_to_stock_android']=post
                if 'INFEND_JZ08_INIT_REACHED '+nonce in FILES.get('android-after.txt',''):
                    STATE['linux_init_verified']=True;STATE['proof_channel']='Android retained log + fresh init nonce'
                say('Подтверждён возврат штатного Android. Сохраняю журналы и завершаю ожидание.','WARN')
                return
        if not captured and usb_descriptor(nonce):
            STATE['linux_init_verified']=True;STATE['proof_channel']='USB serial descriptor + fresh nonce'
            say('Подтверждено: новый Linux выполнил /init и сформировал USB-ответ','OK')
            proof=capture_http(nonce);STATE['usb_proof']=proof;captured=proof.get('report_complete',False)
            STATE['luci_http_verified']=proof.get('luci_http_verified',False)
            if STATE['luci_http_verified']:
                say('Подтверждён HTTP LuCI: http://192.168.73.1/ — пароль в INFEND_JZ08_ACCESS.txt','OK')
            if proof.get('report_complete'):
                text=proof.get('text','');FILES['linux-usb-proof.txt']=redact(text)
                STATE['openwrt_runtime_verified']='"rootfs_type": "initramfs"' in text and 'OPENWRT_RELEASE=' in text
                STATE['emmc_read_verified']=bool(re.search(r'\[/sys/block/mmcblk0/size\]\s+7634944\s',text))
                STATE['emmc_readonly']=('BLOCK mmcblk0 force_readonly=1' in text)
                if STATE['emmc_read_verified']:say('Linux прочитал геометрию eMMC: 7 634 944 сектора','OK')
        if elapsed>5 and connected():
            STATE['returned_to_lk2nd']=True
            try:
                log=get_staged(['oem','ramoops','console'],'ramoops-console.txt').decode('utf8','replace')
                FILES['ramoops-console.txt']=redact(log)
                if 'INFEND_JZ08_INIT_REACHED '+nonce in log:
                    STATE['linux_init_verified']=True;STATE['proof_channel']='ramoops current nonce'
            except Exception as ex:STATE['ramoops_error']=str(ex)
            return
        time.sleep(2)
def main(args):
    global ROOT,STAGE,REPORTS
    if args.selftest:
        package_check();STATE['status']='OFFLINE_INTEGRITY_PASS';say('Офлайн-проверка пакета пройдена. Железо не тестировалось','OK');return
    package_check()
    if args.flash:
        raise RuntimeError('Полная запись заблокирована: готового и аппаратно проверенного OpenWrt/JZ08 в этом пакете нет. Доступен --ram-test с новым ядром.')
    root_check()
    if args.restore:
        restore();STATE['status']='FACTORY_RECOVERY_RESTORED';return
    if args.report:
        STATE['status']='REPORT_ONLY';return
    if args.postmortem:
        say('Читаю доступные журналы штатного JZ08 через уже работающий ADB; без перезагрузки')
        post=capture_android('current',start=True)
        STATE['status']='STOCK_ANDROID_DIAGNOSTICS_CAPTURED' if post.get('available') else 'STOCK_ANDROID_ADB_UNAVAILABLE'
        say('Чтение JZ08 завершено; доступность каждого журнала указана в отчёте' if post.get('available') else 'Живой ADB JZ08 не подтверждён; сведения о серверах сохранены',
            'OK' if post.get('available') else 'WARN')
        return
    if args.verify:
        last=STAGE/'last-run.json';require(last.is_file(),'Нет nonce предыдущего запуска OpenWrt')
        nonce=json.loads(last.read_text())['nonce'];observe(nonce,25)
        STATE['status']='LINUX_INIT_VERIFIED' if STATE['linux_init_verified'] else 'LINUX_NOT_VERIFIED';return
    backup_check()
    if args.prepare or not (args.ram_test or args.boot_only):
        STATE['status']='PREFLIGHT_PASS_NO_DEVICE_WRITE'
        say('Подготовка пройдена. Для полного RAM-сеанса требуется явный --ram-test','OK');return
    changed=False
    try:
        if not connected():
            require(args.ram_test,'Для --boot-only нужен уже работающий LK2ND')
            say('Проверяю живой ADB до изменения recovery и сохраняю исходные журналы')
            baseline=capture_android('before',start=True)
            require(baseline.get('available'),'ADB JZ08 не подтверждён до испытания; recovery не изменён. Сведения сохранены в отчёт.')
            say('Временная запись только recovery p26 (16 МиБ), затем RAM-загрузка и возврат заводского recovery. При потере USB автоматический возврат может потребовать ручного перезапуска.','WARN')
            changed=True;STATE['recovery_restore_required']=True
            legacy('--cycle')
        require(connected(),'LK2ND не найден после recovery-цепочки')
        oem=get_staged(['oem','dtb'],'oem-dtb.bin');banks=FDT(oem).memory()
        STATE['oem_ram_banks']=[{'address':hex(a),'bytes':n} for a,n in banks]
        from lkprobe import memory_table_version,parse_read_word
        def read_word(address):
            require(any(a<=address and address+4<=a+n for a,n in banks),'Адрес LK2ND contract вне подтверждённой RAM; STOP')
            r=fb(['oem','debug','readl',hex(address)])
            FILES['lk2nd-ram-contract.txt']=FILES.get('lk2nd-ram-contract.txt','')+hex(address)+'\n'+redact(r.stdout+r.stderr)+'\n'
            require(r.returncode==0,'Не прочитан LK2ND RAM fixup contract; RAM-запуск остановлен')
            value=parse_read_word(r.stdout+r.stderr)
            STATE.setdefault('lk2nd_contract_reads',[]).append({'address':hex(address),'value':hex(value)})
            return value
        version=memory_table_version(read_word)
        dt=FDT(read('bin/jz08.dtb'))
        if version==0:dt.use_32bit_root()
        dt.set_memory(banks)
        STATE['memory_fixup']={'smem_version':version,'root_address_cells':int.from_bytes(dt.nodes['/']['#address-cells'],'big'),
                               'live_loader_getter_verified':True}
        say('SMEM RAM table: версия '+str(version)+'; DTB cells: '+str(STATE['memory_fixup']['root_address_cells']),'OK')
        nonce=secrets.token_hex(16);STATE['nonce']=nonce
        (STAGE/'last-run.json').write_text(json.dumps({'nonce':nonce,'time':STAMP}))
        from cpio import credentials
        password=secrets.token_hex(12)
        access=ROOT/'INFEND_JZ08_ACCESS.txt'
        access.write_text('USB LuCI: http://192.168.73.1/\nЛогин: root\nПароль: '+password+'\nСеанс RAM: 10 минут; настройки временные.\n')
        say('Адрес и временный пароль: '+str(access))
        ramdisk=credentials(read('bin/initramfs.cpio.gz'),password)
        image=boot_image(read('bin/linux_Image'),ramdisk,dt.encode(),nonce,banks)
        img=STAGE/'INFEND_JZ08_FULL_RAM.img';img.write_bytes(image)
        STATE['ram_image']={'bytes':len(image),'sha256':hashlib.sha256(image).hexdigest()}
        say('OEM RAM подтверждена; передаю новое ядро в память')
        r=fb(['boot',str(img)],180);FILES['fastboot-boot.txt']=redact(r.stdout+r.stderr)
        require(r.returncode==0,'Fastboot boot не принят; Linux не подтверждён')
        say('Fastboot принял '+str(len(image))+' байт RAM-образа; теперь проверяется выполнение /init')
        STATE['fastboot_accepted']=True
        observe(nonce)
        STATE['status']='LINUX_INIT_VERIFIED' if STATE['linux_init_verified'] else 'LINUX_NOT_VERIFIED'
        if not STATE['linux_init_verified']:say('Linux не подтверждён. Журнал и стадия сбоя записаны в отчёт.','WARN')
    finally:
        if changed and not STATE.get('legacy_process_active'):
            say('Возвращаю заводской recovery после RAM-теста')
            try:restore();STATE['recovery_restore_required']=False
            except Exception as ex:
                STATE['restore_error']=str(ex);STATE['recovery_restore_required']=True
                say('Автовосстановление не подтверждено. Верни USB в штатный режим и запусти этот ZIP с --restore.','ERROR')
def report():
    try:
        if not ROOT.is_dir():return
        REPORTS.mkdir(parents=True,exist_ok=True)
        STATE['events']=EVENTS;out=REPORTS/('INFEND_JZ08_OPENWRT_REPORT_'+STAMP+'.zip')
        with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
            z.writestr('RESULT.json',redact(json.dumps(STATE,ensure_ascii=False,indent=2)))
            z.writestr('ОТЧЁТ.txt','INFEND JZ08 / OpenWrt v3\nСТАТУС: '+STATE['status']+'\n\n'+'\n'.join(e['text'] for e in EVENTS))
            for name,body in FILES.items():z.writestr(name,redact(body))
        say('Один итоговый ZIP-отчёт: '+str(out),'OK')
    except Exception as ex:print('Не удалось сохранить отчёт:',ex,flush=True)

if __name__=='__main__':
    ap=argparse.ArgumentParser(description='INFEND JZ08 / полный OpenWrt RAM-комплект / аппаратная проверка не выполнена')
    mode=ap.add_mutually_exclusive_group()
    for flag in ('prepare','ram-test','boot-only','verify','restore','report','postmortem','flash','selftest'):mode.add_argument('--'+flag,action='store_true')
    mode.add_argument('--usb-read',metavar='NONCE',help=argparse.SUPPRESS)
    mode.add_argument('--android-read',choices=('existing','start'),help=argparse.SUPPRESS)
    args=ap.parse_args()
    if args.android_read:
        try:
            from postmortem import capture_existing
            print(json.dumps(capture_existing(start=args.android_read=='start')));sys.exit(0)
        except Exception:
            print(json.dumps({'available':False,'error':'Android transport probe failed'}));sys.exit(2)
    if args.usb_read:
        try:
            from usbproof import capture
            print(json.dumps(capture(args.usb_read)));sys.exit(0)
        except Exception as ex:print(json.dumps({'error':str(ex)}));sys.exit(2)
    rc=0
    try:main(args)
    except KeyboardInterrupt:
        STATE['status']='INTERRUPTED';say('Остановлено. Если recovery изменён, используй --restore.','ERROR');rc=130
    except Exception as ex:
        STATE['status']='FAILED';STATE['error']=str(ex);say(str(ex),'ERROR');rc=2
    finally:report()
    if STATE.get('recovery_restore_required') or STATE['status'] in ('LINUX_NOT_VERIFIED','STOCK_ANDROID_ADB_UNAVAILABLE'):rc=3
    sys.exit(rc)
