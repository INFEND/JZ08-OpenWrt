#!/usr/bin/env python3
"""XARKON MiFi Backup-First Cyber v21.5

Termux/S24 root. Uses upstream bkerler/edl already installed by earlier XARKON
kits. Never writes eMMC and never guesses a device-specific Firehose.

--backup expressly permits EDL transition via the upstream DIAG implementation,
then GPT and whole eMMC READ ONLY, with verification. There are no prompts.
"""
from __future__ import annotations
import argparse, datetime, hashlib, json, os, re, shlex, shutil, signal, subprocess, sys, time, zipfile, zlib
from pathlib import Path

VERSION = '21.5'
DOWNLOAD = Path('/storage/emulated/0/Download')
if not DOWNLOAD.is_dir():
    DOWNLOAD = Path.home()/'storage'/'downloads'
VAULT = DOWNLOAD/'XARKON_MIFI_BACKUPS'
REPORTS = DOWNLOAD/'XARKON_MIFI_REPORTS'
TOOLS = Path.home()/'.local/share/xarkon_mifi_edl'
EDL_CACHE = None
PREFIX = os.environ.get('PREFIX','/data/data/com.termux/files/usr')
ZIP_SELF = str(Path(sys.argv[0]).expanduser().resolve())
COLORS = sys.stdout.isatty() and 'NO_COLOR' not in os.environ and '--no-color' not in sys.argv
PALETTE={'reset':'\033[0m','cyan':'\033[38;5;45m','green':'\033[38;5;48m','purple':'\033[38;5;141m','yellow':'\033[38;5;214m','red':'\033[38;5;203m','dim':'\033[38;5;245m'}
EVENTS=[]
STATE={'version':VERSION,'started':datetime.datetime.now().isoformat(timespec='seconds'),'events':EVENTS,
       'writes_emmc':False,'uses_user_supplied_loader':False}


def paint(t,c='cyan'):
    return PALETTE[c]+str(t)+PALETTE['reset'] if COLORS else str(t)

def line(label, message):
    col={'PASS':'green','WARN':'yellow','BLOCK':'red','INFO':'cyan','STEP':'purple'}.get(label,'dim')
    print(paint('['+label+']',col),message,flush=True)
    EVENTS.append({'time':datetime.datetime.now().isoformat(timespec='seconds'),
                   'level':label,'message':str(message)[:550]})

def heading(title):
    print('\n'+paint('╔'+'═'*62+'╗','cyan'))
    print(paint('║','cyan')+'  '+paint('XARKON // '+title,'green'))
    print(paint('╚'+'═'*62+'╝','cyan'),flush=True)

def shellrun(argv,timeout=20,cwd=None):
    try:
        p=subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True,errors='replace',timeout=timeout,cwd=cwd)
        return p.returncode,p.stdout
    except subprocess.TimeoutExpired as exc:
        data=exc.stdout or b''
        if isinstance(data,bytes):data=data.decode('utf8','replace')
        return 124,data+'\nTIMEOUT'
    except Exception as exc:
        return 127,type(exc).__name__+': '+str(exc)

# Offline inspection of EDL logs on Samsung. No device I/O occurs here.
# HWID and PK_HASH are retained as hashes/identifiers needed to locate a suitable loader;
# the device's unique chip serial and subscriber credentials are redacted.
def sanitize_log(raw):
    value=raw.replace('\x00','')
    patterns = [
      (r'(?i)(\b(?:IMEI|IMSI|ICCID|MEID|password|passwd|token|api[_ -]?key|wifi[_ -]?key|ssid)[\s:=\"\']+)\S+',r'\1[REDACTED]'),
      (r'(?im)(^\s*(?:chip serial number|device serial|serial number|serials|serial)\s*[:=]\s*)\S+',r'\1[REDACTED]'),
      (r'(?i)\b[0-9]{14,16}\b','[REDACTED_15_DIGITS]')]
    for pattern,replacement in patterns:
      value=re.sub(pattern,replacement,value)
    return value

def classify_failure(data):
    s=data.lower()
    if 'GPT Table:' in data and 'Total disk size:' in data and 'Loader successfully uploaded.' in data:
        return 'SUCCESS_GPT_READ'
    if 'Loader successfully uploaded.' in data and 'TargetName=MSM8916' in data:
        return 'SUCCESS_FIREHOSE_SESSION'
    variants=[
     ('LOADER_MISSING', ['couldn\'t find a loader','couldn\'t find a suitable loader','no loader found','no suitable loader','loader is missing','could not find a loader']),
     ('USB_PERMISSIONS', ['permission denied','access denied','libusb_error_access']),
     ('USB_TIMEOUT', ['libusb_error_timeout','usb timeout','read timed out','timeouterror']),
     ('SAHARA_HANDSHAKE', ['sahara protocol error','sahara error','invalid sahara','sahara connect failed','mode detected: error']),
     ('FIREHOSE_NAK', ['firehose error','firehose configuration failed','nak','could not connect to firehose']),
     ('PYTHON_DEPENDENCY', ['modulenotfounderror','importerror','no module named','syntaxerror']),
     ('ANDROID_USB_BACKEND', ["object has no attribute 'backend'",'no backend available','libusb_backend_missing']),
     ('LIBUSB_ENUMERATION', ['libusb_error_not_supported','libusb_error_no_device','libusb_error_io']),
     ('CLI_ARGUMENT', ['unrecognized arguments','invalid choice','usage: edl.py']),
     ('NO_USB_DEVICE', ['no device found','waiting for the device','device not found'])]
    for kind,needles in variants:
      if any(token in s for token in needles):return kind
    if 'detected loader' in s or 'trying loader' in s:return 'LOADER_SELECTED_BUT_UNCONFIRMED'
    if 'traceback' in s:return 'PYTHON_RUNTIME_ERROR'
    return 'UNCLASSIFIED_REVIEW_LOG'

def analyze_gpt_log(path, rc):
    """Analyze the complete log, not just its tail (v21.4 false negative).

    Firehose must have genuinely printed a GPT table, sizes, and all critical
    partitions. No log success alone authorizes writing or flashing.
    """
    raw = path.read_text(encoding='utf8',errors='replace') if path.is_file() else ''
    clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    hit = re.search(r'Total disk size\s*:\s*0x([0-9a-f]+)\s*,\s*sectors\s*:\s*0x([0-9a-f]+)',clean,re.I)
    partitions={}
    for name, start, size in re.findall(
        r'^\s*([a-zA-Z_][\w-]*):\s+Offset\s+0x([0-9a-fA-F]+),\s+Length\s+0x([0-9a-fA-F]+)',
        clean, re.M):
        partitions[name.lower()]=(int(start,16),int(size,16))
    byte_count=int(hit.group(1),16) if hit else 0
    sector_count=int(hit.group(2),16) if hit else 0
    critical=('modem','boot','system','recovery','persist','modemst1','modemst2','fsg','userdata')
    failures=[]
    if rc!=0:failures.append('nonzero_edl_exit')
    if 'GPT Table:' not in clean:failures.append('no_gpt_table')
    if not hit:failures.append('no_total_disk_size')
    if len(partitions)<20:failures.append('too_few_partitions')
    if not all(k in partitions for k in critical):failures.append('critical_partitions_missing')
    if not 2*1024**3 < byte_count < 16*1024**3:failures.append('implausible_disk_size')
    if sector_count*512!=byte_count:failures.append('sector_count_mismatch')
    if byte_count and any(start+length>byte_count or length==0 for start,length in partitions.values()):
        failures.append('partition_outside_disk')
    if re.search(r'Traceback \(most recent call last\)|\b(?:Fatal error|Exception in thread)\b',clean,re.I):
        failures.append('python_exception')
    return {
        'valid': not failures, 'failures':failures, 'disk_size_bytes':byte_count,
        'sectors':sector_count, 'sector_size':512, 'partition_count':len(partitions),
        'critical_present':{k:k in partitions for k in critical},
        'loader_success': 'Loader successfully uploaded.' in clean,
        'target_name':'MSM8916' if re.search(r'TargetName\s*=\s*MSM8916',clean,re.I) else 'unconfirmed',
        'reader':'complete_log',
    }

def recent_edl_logs():
    paths=[]
    if VAULT.is_dir():
      for x in VAULT.glob('*/gpt_probe.log'):
        if x.is_file():paths.append(x)
      for x in VAULT.glob('*/full_read.log'):
        if x.is_file():paths.append(x)
    if REPORTS.is_dir():
      for x in REPORTS.glob('diag_*.log'):
        if x.is_file():paths.append(x)
    return sorted(paths,key=lambda x:x.stat().st_mtime,reverse=True)[:4]

def add_edl_log_to_state():
    snapshots=[]
    for log in recent_edl_logs():
      try:
        size=log.stat().st_size
        with log.open('rb') as f:
          if size>32000:f.seek(size-32000)
          content=f.read().decode('utf8','replace')
        safe=sanitize_log(content)
        kind=classify_failure(safe)
        snapshots.append({'path':str(log),'size_bytes':size,'failure_type':kind,
                          'tail_redacted':safe[-18000:]})
      except Exception as exc:
        snapshots.append({'path':str(log),'read_error':type(exc).__name__})
    STATE['edl_logs']=snapshots
    return snapshots

def diagnose_existing():
    heading('EDL / EXISTING GPT LOG ANALYSIS')
    # Only local files and sysfs; no ADB, DIAG or EDL commands here.
    mode,devices=usb()
    line('INFO',f'Текущий USB-режим: {mode} (без переключения)')
    logs=add_edl_log_to_state()
    if not logs:
      line('BLOCK','GPT-журналы не найдены. Для анализа нужен gpt_probe.log из папки XARKON_MIFI_BACKUPS.')
      STATE['backup_status']='BLOCK_NO_EDL_LOG'
      return 2
    for i,entry in enumerate(logs[:3],1):
      line('INFO',f'Журнал #{i}: {entry.get("failure_type","READ_ERROR")} / {entry.get("size_bytes",0)} байт')
    STATE['backup_status']='DIAGNOSTICS_COLLECTED_NO_FLASH'
    return 0

def root(script,timeout=20):
    return shellrun(['su','-c',script],timeout)

def write_report(label):
    REPORTS.mkdir(parents=True,exist_ok=True)
    dest=DOWNLOAD/('XARKON_MIFI_BACKUP_FIRST_'+label+'_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S')+'.zip')
    STATE['completed_at']=datetime.datetime.now().isoformat(timespec='seconds')
    # Always attach sanitized existing EDL error logs for analysis.
    if 'edl_logs' not in STATE:
        add_edl_log_to_state()
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('report.json',json.dumps(STATE,ensure_ascii=False,indent=2))
        z.writestr('SUMMARY.txt',f'XARKON v{VERSION} / {label}\nUSB: {STATE.get("usb_mode")}\nBackup: {STATE.get("backup_status","NONE")}\n'
                   'Отчёт не содержит дамп eMMC. Индивидуальные данные модема не присылать.\n')
    line('PASS',f'ZIP-отчёт: {dest}')
    return dest

def usb():
    # A shell's exit status can be the result of its last test in a loop.
    # Older v21 returned rc=1 even after it had printed 05c6:9024/9091.
    cmd = r'''
for d in /sys/bus/usb/devices/*; do
    [ -r "$d/idVendor" ] || continue
    v=$(cat "$d/idVendor" 2>/dev/null) || continue
    p=$(cat "$d/idProduct" 2>/dev/null) || continue
    case "$v" in
        05c6|05C6) printf 'QUALCOMM %s %s:%s\n' "${d##*/}" "$v" "$p" ;;
    esac
done
exit 0
'''
    rc, out = root(cmd, 15)
    # Parse a positive match regardless of a shell exit code. A verified
    # sysfs device is not made invisible by a stray exit=1.
    items = re.findall(r'qualcomm\s+(\S+)\s+05c6:([0-9a-f]{4})', out.lower())
    pids = [pid for _, pid in items]
    mode = ('9008' if '9008' in pids else
            '9091' if '9091' in pids else
            '9024' if '9024' in pids else
            'OTHER' if pids else
            'ERROR' if rc != 0 else 'NOT_FOUND')
    STATE['usb_mode'] = mode
    STATE['usb_devices'] = [{'bus':bus,'pid':pid} for bus,pid in items]
    STATE['usb_scan'] = {'exit_code':rc,'raw':out[-1600:]}
    if mode == 'ERROR':
        STATE['usb_error'] = 'root_usb_query_failed'
    else:
        STATE.pop('usb_error', None)
    return mode, items

# Native ADB is the confirmed USB path for this MiFi. Never target the Samsung.
ADB_PORT = 5063
ADB_BIN = Path(PREFIX) / 'bin' / 'adb'
XARKON_PORTS = (5046, 5061, 5062, 5063)


def adb_run(arguments, timeout=18, port=ADB_PORT):
    if not ADB_BIN.is_file():
        return 127, 'Termux adb binary not found'
    cmd = ('export HOME=' + shlex.quote(str(Path.home())) +
           ' TMPDIR=' + shlex.quote(PREFIX+'/tmp') +
           ' ADB_LIBUSB=0 ADB_SERVER_PORT=' + str(port) + '; ' +
           shlex.quote(str(ADB_BIN)) + ' -P ' + str(port) + ' ' +
           ' '.join(shlex.quote(str(a)) for a in arguments))
    return root(cmd, timeout)


def list_native_mifi():
    rc, result = adb_run(['devices','-l'], 15)
    STATE.setdefault('adb', {})['last_list_rc'] = rc
    # Never select emulator-5554 or Samsung; require an explicit MIFI model.
    targets = []
    for entry in result.splitlines():
        if not re.search(r'\bdevice\b', entry) or not re.search(r'\bmodel:MIFI\b', entry, re.I):
            continue
        match = re.match(r'^([^\s]+)\s+device\b', entry)
        if match:
            targets.append(match.group(1))
    return targets


def obtain_native_mifi():
    line('STEP', 'Native ADB / восстановление сеанса для USB 9024')
    adb_run(['start-server'], 18)
    for attempt in range(3):
        targets = list_native_mifi()
        if len(targets) == 1:
            return validate_mifi(targets[0])
        if len(targets) > 1:
            line('BLOCK','Несколько MIFI в ADB. Автовыбор запрещён.')
            return None
        time.sleep(1.5)
    # Proven user-specific recovery: shut down only prior XARKON servers.
    # Never touch Android debugging default 5037.
    line('WARN', 'MiFi не появился. Перезапускаю только сеансы XARKON')
    for port in XARKON_PORTS:
        adb_run(['kill-server'], 7, port)
    adb_run(['start-server'], 18)
    for attempt in range(12):
        targets = list_native_mifi()
        if len(targets) == 1:
            return validate_mifi(targets[0])
        if len(targets) > 1:
            line('BLOCK','Несколько MIFI в ADB. Автовыбор запрещён.')
            return None
        time.sleep(1.5)
    line('BLOCK', 'USB 9024 виден, но Native ADB MiFi не обнаружен')
    return None


def validate_mifi(serial):
    if serial == 'emulator-5554':
        line('BLOCK','Обнаружен ADB телефона, а не MiFi.')
        return None
    rc, platform = adb_run(['-s',serial,'shell','getprop','ro.board.platform'], 18)
    actual = platform.strip().lower()
    STATE.setdefault('adb', {}).update({'target':'MIFI','platform':actual[:80], 'validation_rc':rc})
    if rc != 0 or 'msm8916' not in actual:
        line('BLOCK', 'Платформа MiFi не подтверждена MSM8916: '+repr(actual[:80]))
        return None
    line('PASS', 'MiFi подтверждён: MSM8916 / Native ADB')
    return serial


def wait_for_edl(seconds=40):
    until = time.monotonic()+seconds
    while time.monotonic() < until:
        mode, items = usb()
        if len(items)==1 and mode=='9008':
            return True
        if len(items)>1:
            line('BLOCK', 'Обнаружено несколько устройств Qualcomm, остановка')
            return False
        time.sleep(1.5)
    return False


def auto_transition_from_9024():
    # ADB reboot edl is intentionally done only in --backup/--transition-only.
    serial = obtain_native_mifi()
    if serial is None:
        STATE['transition'] = {'from':'9024', 'result':'BLOCK_ADB_TARGET'}
        return False
    line('WARN','Запрашиваю переход MiFi 9024 -> EDL 9008 через ADB')
    rc, msg = adb_run(['-s',serial,'reboot','edl'], 20)
    STATE['transition'] = {'from':'9024','method':'Native ADB reboot edl','adb_rc':rc}
    # Some devices disconnect before ADB sends a clean response.
    if rc != 0:
        line('WARN', f'ADB transition rc={rc}, проверяю фактический USB режим')
    good = wait_for_edl()
    STATE['transition']['result'] = 'EDL_9008' if good else 'BLOCK_NOT_9008'
    line('PASS' if good else 'BLOCK', 'Qualcomm 9008 обнаружен' if good else 'Переход в EDL не подтверждён')
    return good


def auto_transition_from_9091(entry, py):
    line('WARN','Переключение 9091 -> 9008 через официальный qc_diag Sahara')
    if not (entry.parent/'edlclient/Tools/qc_diag.py').is_file():
        STATE['transition']={'from':'9091','result':'BLOCK_NO_DIAG_TOOL'}
        return False
    log=REPORTS/('diag_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S')+'.log')
    # Confirmed upstream argparse: sahara -vid ... -pid ... -interface ...
    rc=run_root_log(entry,py,['sahara','-vid','0x05c6','-pid','0x9091','-interface','0'],log,timeout=35,diag=True)
    STATE['transition']={'from':'9091','method':'upstream qc_diag sahara','diag_rc':rc,
                         'diag_log_local':str(log)}
    good=wait_for_edl(28)
    STATE['transition']['result']='EDL_9008' if good else 'BLOCK_NOT_9008'
    line('PASS' if good else 'BLOCK', 'Qualcomm 9008 обнаружен' if good else 'EDL 9008 не обнаружен после DIAG')
    return good

# Temporary Python shim for Android pySerial; exactly the approach that
# previously passed the user's v14.8 host-side EDL tests.
BOOTSTRAP=(
    "import sys,runpy;"
    "sys.path.insert(0,sys.argv[1]);"
    "sys.path.insert(0,sys.argv[2]);"
    "from android_serial_compat import enable;enable();"
    "from usb_backend_compat import patch_usb_class;patch_usb_class();"
    "sys.argv=[sys.argv[3]]+sys.argv[4:];"
    "runpy.run_path(sys.argv[0],run_name='__main__')"
)

def find_edl():
    global EDL_CACHE
    if EDL_CACHE is not None: return EDL_CACHE
    repos=sorted(TOOLS.glob('edl_verified_*/edl.py'),key=lambda p:p.stat().st_mtime,reverse=True)
    if not repos:repos=sorted(TOOLS.glob('**/edl.py'),key=lambda p:p.stat().st_mtime,reverse=True)
    pys=list(TOOLS.glob('venv_v144_system*/bin/python'))+list(TOOLS.glob('venv_v146_system*/bin/python'))+list(TOOLS.glob('venv*/bin/python'))+[Path(sys.executable)]
    unique=[]; seen=set()
    for py in pys:
        if str(py) not in seen and py.is_file():unique.append(py);seen.add(str(py))
    for entry in repos[:2]:
        for py in unique[:6]:
            argv=[str(py),'-c',BOOTSTRAP,ZIP_SELF,str(entry.parent),str(entry),'-h']
            rc,out=shellrun(argv,timeout=18,cwd=entry.parent)
            if rc==0 and 'edl.py' in out.lower() and ('sahara' in out.lower() or 'firehose' in out.lower()):
                STATE['edl']={'repo':str(entry.parent),'python':str(py),'client_help':'PASS'}
                EDL_CACHE=(entry,py)
                return EDL_CACHE
    STATE['edl']={'client_help':'BLOCK','repositories':len(repos),'python_candidates':len(unique)}
    return None

def edl_argv(entry,py,args,diag=False):
    path=entry.parent/'edlclient/Tools/qc_diag.py' if diag else entry
    return [str(py),'-c',BOOTSTRAP,ZIP_SELF,str(entry.parent),str(path),*args]

def root_command(entry,py,args,diag=False):
    argv=edl_argv(entry,py,args,diag)
    env={
        'HOME':str(Path.home()),'TMPDIR':PREFIX+'/tmp',
        'PATH':PREFIX+'/bin:/system/bin:/system/xbin',
        'LD_LIBRARY_PATH':PREFIX+'/lib','PYTHONPATH':str(entry.parent)
    }
    parts=['env']+[k+'='+shlex.quote(v) for k,v in env.items()]+[shlex.quote(x) for x in argv]
    return 'cd '+shlex.quote(str(entry.parent))+' && '+' '.join(parts)

def run_root_log(entry,py,args,path,timeout=90,diag=False,watch=None,expected_size=None):
    path.parent.mkdir(parents=True,exist_ok=True)
    cmd=root_command(entry,py,args,diag)
    started=time.monotonic()
    last_growth=started
    last_bytes=-1
    with path.open('w',encoding='utf8') as log:
        p=subprocess.Popen(['su','-c',cmd],stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                           start_new_session=True)
        try:
            while p.poll() is None:
                elapsed=int(time.monotonic()-started)
                size=watch.stat().st_size if watch and watch.exists() else 0
                if watch and size != last_bytes:
                    last_bytes=size
                    last_growth=time.monotonic()
                counter=(f'  {size/1024**3:.2f}/{expected_size/1024**3:.2f} GiB'
                         if watch and expected_size else f'  {size/1024**3:.2f} GiB' if watch else '')
                if watch and expected_size and size>expected_size:
                    os.killpg(p.pid,signal.SIGTERM)
                    p.wait(timeout=8)
                    print();return 125
                if watch and time.monotonic()-last_growth>300:
                    os.killpg(p.pid,signal.SIGTERM)
                    try:p.wait(8)
                    except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL)
                    print();return 124
                print('\r'+paint('◈','purple')+f' {"DIAG" if diag else "EDL"} / {elapsed}s{counter}  ',end='',flush=True)
                if timeout is not None and elapsed>timeout:
                    os.killpg(p.pid,signal.SIGTERM)
                    try:p.wait(8)
                    except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL)
                    print();return 124
                time.sleep(.5)
        except KeyboardInterrupt:
            os.killpg(p.pid,signal.SIGTERM)
            try:p.wait(8)
            except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL)
            print();return 130
    print()
    return p.returncode

def tail(path,limit=1000):
    if not path.exists():return ''
    with path.open('rb') as f:
        f.seek(max(0,path.stat().st_size-12000))
        s=f.read().decode('utf8','replace')
    return s[-limit:]

def gpt_checks(path):
    if not path.is_file() or path.stat().st_size<1024:return {'valid':False,'why':'small or missing'}
    with path.open('rb') as f: block=f.read(1024)
    header=block[512:1024]
    if header[:8]!=b'EFI PART':return {'valid':False,'why':'no GPT at LBA1'}
    sz=int.from_bytes(header[12:16],'little')
    if sz<92 or sz>512:return {'valid':False,'why':'invalid GPT header size'}
    check=bytearray(header[:sz]);stored=int.from_bytes(check[16:20],'little');check[16:20]=b'\0\0\0\0'
    crc=zlib.crc32(check)&0xffffffff
    return {'valid':crc==stored and block[510:512]==b'\x55\xaa','protective_mbr':block[510:512]==b'\x55\xaa',
            'gpt_header_crc_ok':crc==stored,'backup_gpt_lba':int.from_bytes(header[32:40],'little')}

def check():
    heading('BACKUP FIRST / SYSTEM CHECK')
    if not DOWNLOAD.is_dir():
        line('BLOCK','Download недоступен. Разреши доступ к памяти Termux.');STATE['backup_status']='BLOCK_NO_DOWNLOAD';return 2
    rc,out=root('id',12)
    if rc or 'uid=0' not in out:
        line('BLOCK','Нет root через Magisk на Samsung.');STATE['backup_status']='BLOCK_NO_ROOT';return 2
    line('PASS','Magisk root работает')
    mode,items=usb()
    line('PASS' if mode in ('9024','9091','9008') else 'WARN',f'USB Qualcomm: {mode}')
    if len(items)!=1:line('WARN','Требуется ровно одно устройство Qualcomm, иначе backup заблокирован.')
    edl=find_edl()
    line('PASS' if edl else 'BLOCK','EDL-клиент: найден' if edl else 'EDL-клиент не прошёл проверку запуска')
    if edl:
        entry,py=edl
        rc,out=root(root_command(entry,py,['-h']),timeout=22)
        STATE['edl']['root_help_rc']=rc
        if rc!=0:line('BLOCK','EDL через root не прошёл проверку.');edl=None
        else:line('PASS','EDL доступен под root Samsung')
    free=shutil.disk_usage(DOWNLOAD).free
    STATE['free_gib']=round(free/1024**3,2)
    line('INFO',f'Свободное место: {free/1024**3:.1f} GiB')
    if mode=='9091':line('INFO','DIAG 9091: для дампа нужен переход в EDL 9008; доступен режим --backup.')
    if mode=='9024':line('INFO','ADB 9024: режим --backup автоматически переключит MiFi через Native ADB')
    if mode=='9008':line('INFO','EDL 9008: --backup пропустит переход и проверит GPT.')
    STATE['backup_status']='NOT_STARTED'
    return 0 if edl else 2

def preflight_libusb(entry, py):
    # Read-only libusb enumeration before the upstream EDL client can send Sahara
    # or load a programmer. Avoid confusing Android Python bugs with Firehose errors.
    snippet = (
      'import sys,json;'
      'sys.path.insert(0,sys.argv[1]);'
      'sys.path.insert(0,sys.argv[2]);'
      'from android_serial_compat import enable;enable();'
      'from usb_backend_compat import preflight;'
      'res=preflight();'
      'print("XARKON_LIBUSB_PREFLIGHT="+json.dumps(res));'
      'sys.exit(0 if res.get("target_found") else 2)'
    )
    args=[str(py),'-c',snippet,ZIP_SELF,str(entry.parent)]
    env={'HOME':str(Path.home()),'TMPDIR':PREFIX+'/tmp',
         'PATH':PREFIX+'/bin:/system/bin:/system/xbin',
         'LD_LIBRARY_PATH':PREFIX+'/lib','PYTHONPATH':str(entry.parent)}
    cmd='cd '+shlex.quote(str(entry.parent))+' && '+' '.join(['env']+[k+'='+shlex.quote(v) for k,v in env.items()]+[shlex.quote(x) for x in args])
    rc,raw=root(cmd,25)
    matches=re.findall(r'XARKON_LIBUSB_PREFLIGHT=(\{[^\r\n]*\})',raw)
    try:
      record=json.loads(matches[-1]) if matches else {'error':'preflight_no_json'}
    except Exception as exc:
      record={'error':type(exc).__name__+': '+str(exc)}
    STATE['libusb_preflight']={'exit_code':rc,'details':record,'output_tail':sanitize_log(raw)[-1500:]}
    if rc==0 and record.get('target_found'):
      line('PASS',f'Android PyUSB видит Qualcomm 9008 через {record.get("library","libusb")}')
      return True
    line('BLOCK','PyUSB не видит EDL 9008. Не запускаю Sahara/Firehose; смотри ZIP-отчёт.')
    STATE['backup_status']='BLOCK_LIBUSB_PREFLIGHT'
    return False


def run_backup():
    check_rc=check()
    mode,items=usb()
    if check_rc!=0 or len(items)!=1:
        STATE['backup_status']='BLOCK_PREFLIGHT';return 2
    edl=find_edl()
    if not edl:
        STATE['backup_status']='BLOCK_NO_EDL_CLIENT';return 2
    entry,py=edl
    # Automatic but one-shot route. Never enter EDL during a status-only run.
    if mode=='9024':
        heading('AUTO-ROUTE / 9024 TO 9008')
        if not auto_transition_from_9024():
            STATE['backup_status']='BLOCK_EDL_TRANSITION';return 2
    elif mode=='9091':
        heading('AUTO-ROUTE / 9091 TO 9008')
        if not auto_transition_from_9091(entry,py):
            STATE['backup_status']='BLOCK_EDL_TRANSITION';return 2
    elif mode=='9008':
        line('PASS','Уже в режиме EDL 9008, повторный переход пропущен')
    else:
        STATE['backup_status']='BLOCK_UNSUPPORTED_USB_MODE'
        line('BLOCK','Неизвестный USB-режим. Переход отключён.')
        return 2
    mode, items = usb()
    if mode!='9008' or len(items)!=1:
        STATE['backup_status']='BLOCK_NOT_EDL_9008'
        line('BLOCK','Нужен ровно один Qualcomm 9008. Чтение не начато.')
        return 2
    if shutil.disk_usage(DOWNLOAD).free<8*1024**3:
        STATE['backup_status']='BLOCK_LOW_STORAGE';line('BLOCK','Нужно не менее 8 GiB свободного места.');return 2
    heading('ANDROID / LIBUSB PRE-FLIGHT')
    if not preflight_libusb(entry,py):
        return 2
    heading('EDL / VERIFY FIREHOSE VIA GPT')
    line('WARN','EDL автоматически подбирает Firehose по HWID/PK_HASH. Совместимость с этой платой пока не гарантирована.')
    # EDL printgpt automatically picks programmer using HWID/PKHash when possible.
    # No forced loader. This uploads firmware only into device RAM; no eMMC write.
    run=VAULT/datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    run.mkdir(parents=True,exist_ok=False)
    gpt_log=run/'gpt_probe.log'
    rc=run_root_log(entry,py,['printgpt','--memory=emmc'],gpt_log,timeout=150)
    parsed=analyze_gpt_log(gpt_log,rc)
    STATE['gpt']={'command':'printgpt --memory=emmc','rc':rc,'plausible_gpt':parsed['valid'],
                  'analysis':parsed,'log':str(gpt_log),
                  'log_tail':'(подробности включены в ZIP в обезличенном виде)'}
    if not parsed['valid']:
        line('BLOCK','GPT не прошла проверку: '+', '.join(parsed['failures']))
        STATE['backup_status']='BLOCK_NO_VALIDATED_GPT';return 2
    line('PASS',f'Firehose / GPT: {parsed["partition_count"]} разделов; {parsed["disk_size_bytes"]/1024**3:.2f} GiB')
    heading('EDL / FULL eMMC READ')
    file=run/'flash_emmc.partial'
    readlog=run/'full_read.log'
    STATE['backup_status']='READING'
    line('WARN','Не отключай кабель. Дамп может содержать IMEI и калибровки, не отправляй его.')
    rc=run_root_log(entry,py,['rf',str(file),'--memory=emmc'],readlog,timeout=None,watch=file,expected_size=parsed['disk_size_bytes'])
    STATE['read']={'rc':rc,'log':str(readlog),'size':file.stat().st_size if file.exists() else 0}
    if rc!=0 or not file.exists():
        STATE['backup_status']='FAILED_INCOMPLETE';line('BLOCK',f'Чтение не завершилось (код {rc}). Файл .partial нельзя использовать для восстановления.');return 2
    size=file.stat().st_size
    checkgpt=gpt_checks(file)
    STATE['gpt_validation']=checkgpt
    size_ok=(size==parsed['disk_size_bytes'])
    STATE['size_matches_gpt']=size_ok
    if not(size_ok and checkgpt['valid']):
        STATE['backup_status']='FAILED_VALIDATION'
        line('BLOCK',f'Дамп не прошёл проверку: {size:,} / ожидается {parsed["disk_size_bytes"]:,} байт; GPT CRC: {checkgpt.get("gpt_header_crc_ok",False)}. Сохранён .partial.')
        return 2
    sha=hashlib.sha256()
    with file.open('rb') as f:
        while True:
            data=f.read(4*1024*1024)
            if not data:break
            sha.update(data)
    final=file.with_name('flash_emmc.bin')
    file.rename(final)
    manifest={'status':'LOCAL_VERIFIED_NOT_INDEPENDENT_REREAD','size_bytes':size,'sha256':sha.hexdigest(),
              'gpt':checkgpt,'source':'Qualcomm EDL rf','output':final.name,
              'created_at':datetime.datetime.now().isoformat(timespec='seconds')}
    (run/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf8')
    STATE['backup_status']='LOCAL_VERIFIED'
    STATE['backup']={'bytes':size,'sha256':sha.hexdigest(),'folder':str(run),'local_validation':True}
    line('PASS',f'Дамп сохранён: {size/1024**3:.2f} GiB / SHA-256 {sha.hexdigest()}')
    line('WARN','Сделай независимую вторую копию перед прошивкой.')
    return 0

def transition_only():
    check_rc=check()
    mode,items=usb()
    if check_rc or len(items)!=1:
        STATE['backup_status']='BLOCK_PREFLIGHT';return 2
    if mode=='9008':
        line('PASS','Уже EDL 9008, переход пропущен')
        STATE['backup_status']='EDL_READY_NO_BACKUP';return 0
    if mode=='9024':
        success=auto_transition_from_9024()
    elif mode=='9091':
        entry,py=find_edl()
        success=auto_transition_from_9091(entry,py)
    else:
        success=False
    STATE['backup_status']='EDL_READY_NO_BACKUP' if success else 'BLOCK_EDL_TRANSITION'
    line('PASS' if success else 'BLOCK','EDL готов: копирование не запущено' if success else 'EDL не подтверждён')
    return 0 if success else 2

def verify_existing():
    heading('VAULT / VERIFY EXISTING IMAGE')
    files=sorted(VAULT.glob('*/flash_emmc.bin'),key=lambda x:x.stat().st_mtime,reverse=True)
    if not files:STATE['backup_status']='NO_IMAGE';line('BLOCK','Полного дампа нет.');return 2
    file=files[0]; manifest=file.parent/'manifest.json'
    if not manifest.exists():line('BLOCK','Нет манифеста.');return 2
    meta=json.loads(manifest.read_text(encoding='utf8'))
    sha=hashlib.sha256()
    with file.open('rb') as f:
        while True:
            data=f.read(4*1024*1024)
            if not data:break
            sha.update(data)
    good=(file.stat().st_size==meta.get('size_bytes') and sha.hexdigest()==meta.get('sha256') and gpt_checks(file)['valid'])
    STATE['backup_status']='VERIFY_PASS' if good else 'VERIFY_FAIL'
    line('PASS' if good else 'BLOCK',f'Повторная проверка: {"OK" if good else "ERROR"} / {file}')
    return 0 if good else 2

def inspect_firmware(path):
    heading('OFFLINE / FIRMWARE IMAGE AUDIT')
    target=Path(path).expanduser().resolve()
    if not target.is_file() or target.stat().st_size>16*1024**3:
        line('BLOCK','Файл не найден или больше 16 GiB.');return 2
    sha=hashlib.sha256()
    with target.open('rb') as f:
        while True:
            data=f.read(4*1024*1024)
            if not data:break
            sha.update(data)
    data={'name':target.name,'bytes':target.stat().st_size,'sha256':sha.hexdigest(),'board_verified':False,
          'image_status':'UNVERIFIED_DO_NOT_FLASH'}
    if zipfile.is_zipfile(target):
        with zipfile.ZipFile(target) as z:
            data['members']=[{'name':x.filename,'bytes':x.file_size} for x in z.infolist()[:100]]
    STATE['firmware_candidate']=data
    line('PASS',f'Файл прочитан, SHA-256 {sha.hexdigest()}')
    line('BLOCK','Нет подтверждения совместимости с LCD-платой, запись не предусмотрена.')
    return 0

def main():
    parser=argparse.ArgumentParser(description='XARKON MiFi Backup First v21.5: S24 + Termux (no interactive prompts)')
    g=parser.add_mutually_exclusive_group()
    g.add_argument('--diagnose',action='store_true',help='inspect prior GPT failure logs, NO EDL commands, no transition')
    g.add_argument('--backup',action='store_true',help='AUTO 9024/9091 -> EDL 9008, GPT and full EMMC read (risk)')
    g.add_argument('--transition-only',action='store_true',help='auto EDL switch, do not use Firehose or read eMMC')
    g.add_argument('--verify',action='store_true',help='verify existing backup')
    g.add_argument('--inspect-firmware',metavar='PATH',help='offline checksum and contents, NO flash')
    g.add_argument('--demo',action='store_true',help='UI demo, no hardware access')
    parser.add_argument('--no-color',action='store_true')
    args=parser.parse_args()
    if args.demo:
        heading('CYBER / DEMO')
        line('PASS','Цвета и терминал готовы');line('WARN','Никакой записи в роутер');return 0
    code=2
    try:
        if args.diagnose:code=diagnose_existing()
        elif args.backup:code=run_backup()
        elif args.transition_only:code=transition_only()
        elif args.verify:code=verify_existing()
        elif args.inspect_firmware:code=inspect_firmware(args.inspect_firmware)
        else:code=check()
    except KeyboardInterrupt:
        line('WARN','Остановлено. Проверь неполные файлы перед дальнейшими действиями.')
        STATE['backup_status']='INTERRUPTED';code=130
    except Exception as exc:
        line('BLOCK','Ошибка инструмента: '+type(exc).__name__+': '+str(exc))
        STATE['backup_status']='TOOL_ERROR';code=3
    try:write_report('RESULT')
    except Exception as exc:print('Report failure:',repr(exc))
    return code

if __name__=='__main__':raise SystemExit(main())
