# -*- coding: utf-8 -*-
"""XARKON JZ08 v32: secondary lk2nd loader recovery-only proof of boot, not OpenWrt.

Run without extraction: python /sdcard/Download/XARKON_JZ08_LK2ND_OEM_LAYOUT_v31_1.zip --prepare
"""
import argparse,datetime,hashlib,json,os,struct,sys,zipfile,traceback
from pathlib import Path
from types import ModuleType

ap=argparse.ArgumentParser(description='JZ08 LK2ND v31 OEM layout: только recovery p26')
mode=ap.add_mutually_exclusive_group()
mode.add_argument('--cycle',action='store_true',help='один проход: подготовка, запись p26, reboot recovery, USB-монитор (риск)')
mode.add_argument('--prepare',action='store_true',help='проверить сборку и подготовить образ, БЕЗ ЗАПИСИ')
mode.add_argument('--flash',action='store_true',help='РИСК: записать экспериментальный lk2nd ТОЛЬКО в p26 recovery')
mode.add_argument('--boot-test',action='store_true',help='РИСК: перезагрузить в ранее записанный recovery; наблюдать USB/экран')
mode.add_argument('--restore-factory',action='store_true',help='восстановить заводской p26 через проверенный Firehose')
mode.add_argument('--probe-fastboot',action='store_true',help='ТОЛЬКО ЧТЕНИЕ: опрос текущего USB Fastboot без записи eMMC')
mode.add_argument('--self-test',action='store_true',help='тест логики без USB/EDL и без файлов роутера')
arg=ap.parse_args()
ROOT=Path('/sdcard/Download') if Path('/sdcard/Download').is_dir() else (Path('/mnt/data') if Path('/mnt/data').is_dir() else Path.cwd())
STAGE=ROOT/'XARKON_JZ08_LK2ND_FASTBOOT_PROOF_V32'
REPORT=Path(os.environ.get('XARKON_V37_REPORT_DIR',str(ROOT/'XARKON_JZ08_REPORTS')))
STAMP=datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
STOCK_SHA='8f2e9de8b8e3d26f76784f647655aa70b85ae2de86c5777da2974c2a1ea6a462'
LK_SHA='e0f260e31c6a681a1fa6e27d2e2e02418c17f726a46225b2348618659345dbae'
PART_SIZE=16*1024*1024
OEM_DECLARED_END=0x771800
QCDT_SOC={206,248,249,250}
QCDT_BOARDS={(8,0),(8,256)}
CAN=STAGE/'EXPERIMENTAL_LK2ND_JZ08_OEM_LAYOUT_P26_V31_NOT_OPENWRT.img'
STATE=STAGE/'last_verified_flash.json'
R={'project':'XARKON JZ08 lk2nd v32: factory-layout recovery-only test','time':STAMP,
   'mode':'FASTBOOT_PROBE_ONLY' if arg.probe_fastboot else 'CYCLE' if arg.cycle else 'SELFTEST' if arg.self_test else 'RESTORE' if arg.restore_factory else 'BOOT_TEST' if arg.boot_test else 'FLASH' if arg.flash else 'PREPARE',
   'emmc_write_attempted':False,'status':'STARTED','bootloader_booted':False,
   'warning':'Compiling LK2ND is NOT OEM ABOOT boot validation. Never write boot/aboot/GPT/modem.'}
LOG=[]
def say(t,kind='INFO'):
 labels={'OK':'ГОТОВО','WARN':'ВНИМАНИЕ','INFO':'ИНФО','FAIL':'ОШИБКА','WAIT':'ОЖИДАНИЕ'}
 LOG.append({'kind':kind,'text':str(t)})
 colors={'OK':'\x1b[38;5;48m','WARN':'\x1b[38;5;214m','INFO':'\x1b[38;5;45m','FAIL':'\x1b[38;5;196m','WAIT':'\x1b[38;5;141m'}
 line=f'[{labels.get(kind,"ИНФО")}] {t}'
 print(colors.get(kind,'')+line+'\x1b[0m' if sys.stdout.isatty() else line,flush=True)

def check(v,s):
 if not v:raise RuntimeError(s)
 say(s,'OK')
def sha(b):return hashlib.sha256(b).hexdigest()
def shafile(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  while True:
   c=f.read(1024*1024)
   if not c:break
   h.update(c)
 return h.hexdigest()
def readz(path):
 with zipfile.ZipFile(sys.argv[0]) as z:return z.read(path)

def parse_lk(b):
 check(sha(b)==LK_SHA,'LK2ND: совпадает SHA-256 сборки v29')
 check(len(b)==290832 and b[:8]==b'ANDROID!','LK2ND: Android boot v0, известный размер')
 (klen,kaddr,rdlen,rdaddr,secondlen,secondaddr,tagsaddr,pagesize,dtsz,unused)=struct.unpack_from('<10I',b,8)
 check(kaddr==0x80008000 and pagesize==2048 and rdlen in (0,1) and secondlen==0,'LK2ND: OEM kernel address, page size, no ramdisk payload')
 qcdt_off=pagesize+((klen+pagesize-1)//pagesize)*pagesize+((rdlen+pagesize-1)//pagesize)*pagesize
 check(qcdt_off==0x46000 and b[qcdt_off:qcdt_off+4]==b'QCDT','LK2ND: QCDT table aligned and present')
 magic,ver,n=struct.unpack_from('<4sII',b,qcdt_off)
 check(ver==2 and n==8 and dtsz==4096,'LK2ND: QCDT v2, 8 records, table size 4096')
 actual=set()
 for i in range(n):
  soc,plat,subtype,rev,dt_off,dt_len=struct.unpack_from('<6I',b,qcdt_off+12+i*24)
  actual.add((soc,plat,subtype));
  check(dt_off==2048 and dt_len==2048,'QCDT record %s points to included FDT'%i)
 check(actual=={(s,bo,bi) for s in QCDT_SOC for bo,bi in QCDT_BOARDS},'Все OEM SoC/Board ID совпали: 206/248/249/250 × 8/0,8/256')
 fdt=qcdt_off+2048
 check(b[fdt:fdt+4]==b'\xd0\x0d\xfe\xed','FDT magic для LK2ND найден')
 fdt_size=struct.unpack_from('>I',b,fdt+4)[0]
 check(0<fdt_size<=2048,'Размер FDT корректен')
 R['lk2nd_meta']={'bytes':len(b),'sha256':sha(b),'kernel_size':klen,'kernel_address':hex(kaddr),'page':pagesize,'qcdt_offset':hex(qcdt_off),'qcdt_count':n,'fdt_size':fdt_size,'android_ramdisk_size':rdlen,'dt_size':dtsz}
 return b

def coremod():
 # Reuse *already hardware-tested* v26 Firehose readback+rollback logic.
 # Do not execute the core's main(). It is loaded with a safe known argparse switch.
 module=ModuleType('jz08_v26_core')
 original=sys.argv[:]
 try:
  sys.argv=[original[0],'--build']
  exec(compile(readz('core/v26_core.py'),'core/v26_core.py','exec'),module.__dict__)
 finally:sys.argv=original
 module.STAGE=STAGE;module.CAND=CAN;module.REPORTS=REPORT;module.STAMP=STAMP
 module.R=R;module.LOG=LOG
 return module

def align(n, page=2048):
 return (n+page-1)//page*page

def boot_sha1(kernel, ramdisk, dt, mode='qualcomm-dt'):
 h=hashlib.sha1()
 h.update(kernel);h.update(struct.pack('<I',len(kernel)))
 h.update(ramdisk);h.update(struct.pack('<I',len(ramdisk)))
 h.update(struct.pack('<I',0)) # no second-stage image
 if mode=='qualcomm-dt':
  h.update(dt);h.update(struct.pack('<I',len(dt)))
 return h.digest()

def build(core,lk):
 factory=core.stock_recovery()
 check(factory.stat().st_size==PART_SIZE and shafile(factory)==STOCK_SHA,'Заводской recovery: SHA-256 и размер подтверждены')
 old=factory.read_bytes()
 check(old[:8]==b'ANDROID!','OEM Android boot header')
 ks,ka,rs,ra,ss,sa,ta,page,dtsz=struct.unpack_from('<9I',old,8)
 check((ks,ka,rs,ss,page,dtsz)==(6442128,0x80008000,1070918,0,2048,288768),'Точная OEM компоновка установлена')
 off_kernel=page
 off_ramdisk=off_kernel+align(ks,page)
 off_dt=off_ramdisk+align(rs,page)
 off_tail=align(off_dt+dtsz,page)
 check((off_dt,off_tail)==(0x72B000,OEM_DECLARED_END),'Оригинальное физическое смещение QCDT и OEM tail')
 check(old[off_dt:off_dt+4]==b'QCDT','Заводская QCDT найдена')
 original_ks=old[off_kernel:off_kernel+ks]
 original_rs=old[off_ramdisk:off_ramdisk+rs]
 original_dt=old[off_dt:off_dt+dtsz]
 original_id=old[576:596]
 check(original_id==boot_sha1(original_ks,original_rs,original_dt),'Оригинальный Qualcomm SHA1 ID известен и проверен')
 lksize=struct.unpack_from('<I',lk,8)[0]
 check(lksize>0 and lksize<ks and lk[:8]==b'ANDROID!','Размер LK2ND kernel соответствует слоту OEM')
 lk_kernel=lk[2048:2048+lksize]
 check(len(lk_kernel)==lksize,'LK2ND kernel извлечён без изменения')
 lk_qoff=0x46000
 check(lk[lk_qoff:lk_qoff+4]==b'QCDT','LK2ND QCDT существует')
 check(struct.unpack_from('<II',lk,lk_qoff+4)==(2,8),'LK2ND QCDT содержит 8 OEM вариантов')
 new_dt=bytearray(dtsz)
 new_dt[:4096]=lk[lk_qoff:lk_qoff+4096]
 check(new_dt[:4]==b'QCDT' and new_dt[2048:2052]==b'\xd0\x0d\xfe\xed','OEM QCDT заменена на LK2ND-QCDT в исходном адресе')
 out=bytearray(old)
 out[off_kernel:off_kernel+ks]=lk_kernel+b'\0'*(ks-lksize)
 out[off_dt:off_dt+dtsz]=new_dt
 # OEM ramdisk remains unchanged, though lk2nd ignores it.
 check(out[off_ramdisk:off_ramdisk+rs]==original_rs,'Заводской ramdisk оставлен на прежнем месте')
 out[576:596]=boot_sha1(out[off_kernel:off_kernel+ks],original_rs,new_dt)
 check(out[off_tail:]==old[off_tail:],'OEM tail побайтово не изменён')
 check(out[:8]==b'ANDROID!' and struct.unpack_from('<9I',out,8)==(ks,ka,rs,ra,ss,sa,ta,page,dtsz),'Штатные параметры Android header сохранены')
 check(out[off_dt:off_dt+4]==b'QCDT' and out[off_dt+2048:off_dt+2052]==b'\xd0\x0d\xfe\xed','QCDT осталась на OEM позиции')
 check(out[576:596]==boot_sha1(out[off_kernel:off_kernel+ks],original_rs,out[off_dt:off_dt+dtsz]),'Qualcomm SHA1 ID пересчитан')
 check(len(out)==PART_SIZE,'Образ равен 16 МиБ')
 STAGE.mkdir(parents=True,exist_ok=True)
 tmp=CAN.with_suffix('.partial');tmp.write_bytes(out);tmp.replace(CAN)
 digest=shafile(CAN)
 check(digest==sha(out),'Проверка SHA-256 образа после записи на телефон')
 R['candidate_meta']={'sha256':digest,'bytes':len(out),'contains_lk2nd_sha256':LK_SHA,'oem_tail_preserved':True,
   'factory_android_header_parameters_retained':True,'qcdt_physical_offset':hex(off_dt),
   'ramdisk_physical_offset':hex(off_ramdisk),'kernel_padded_to_stock_size':True,'real_openwrt':False,
   'security_warning':'OEM signature authentication remains unknown; may fail to boot'}
 say('КАНДИДАТ v32: заводская физическая компоновка и QCDT сохранены; запуск не подтверждён.','WARN')
 return CAN

def usb_snapshot():
 import subprocess
 cmd='for d in /sys/bus/usb/devices/*; do if [ -f "$d/idVendor" ] && [ -f "$d/idProduct" ]; then v=$(cat "$d/idVendor" 2>/dev/null); p=$(cat "$d/idProduct" 2>/dev/null); [ "$v" = "1d6b" ] && continue; printf "%s:%s" "$v" "$p"; for i in "$d":*; do if [ -f "$i/bInterfaceClass" ]; then a=$(cat "$i/bInterfaceClass"); b=$(cat "$i/bInterfaceSubClass"); c=$(cat "$i/bInterfaceProtocol"); printf " [%s:%s:%s]" "$a" "$b" "$c"; fi; done; echo; fi; done'
 try:
  r=subprocess.run(['su','-c',cmd],capture_output=True,text=True,timeout=12)
  return (r.stdout or '').strip()[:1800] or '[none]'
 except Exception as e: return 'USB_READ_ERROR:'+repr(e)

def adb_call(*params, timeout=22):
 import shlex,subprocess
 pref=os.environ.get('PREFIX','/data/data/com.termux/files/usr')
 adb=pref+'/bin/adb'
 home='/data/data/com.termux/files/home'
 env='env HOME='+shlex.quote(home)+' TMPDIR='+shlex.quote(pref+'/tmp')+' ADB_LIBUSB=0 ADB_SERVER_PORT=5063 '
 cmd=env+' '.join(shlex.quote(str(x)) for x in (adb,'-P','5063',*params))
 return subprocess.run(['su','-c',cmd],capture_output=True,text=True,timeout=timeout)

def verified_mifi():
 """Check LIVE adb transport; checking that adb process exists is not enough."""
 import re
 cp=adb_call('devices','-l')
 found=[line for line in cp.stdout.splitlines() if re.match(r'^\S+\s+device\b',line)]
 if cp.returncode!=0 or len(found)!=1 or 'model:MIFI' not in found[0] or 'product:MIFI' not in found[0]:
  return None,'ADB не видит ровно один MIFI (USB ещё переключается)'
 serial=found[0].split()[0]
 info=adb_call('-s',serial,'shell','getprop','ro.board.platform')
 if info.returncode!=0 or 'msm8916' not in info.stdout.lower():
  return None,'Обнаружен USB ADB, но плата MSM8916 не подтверждена'
 return serial,'Подтверждено устройство MIFI, MSM8916 и рабочий ADB'

def await_verified_android(c,seconds=145):
 import time
 started=time.monotonic();tries=0;last_recover=-999
 while time.monotonic()-started<seconds:
  tries+=1
  elapsed=int(time.monotonic()-started)
  if elapsed-last_recover>=22:
   last_recover=elapsed
   try:c.native_recover()
   except Exception as ex:say('Восстановление ADB: '+str(ex)[:145],'WAIT')
  try:
   serial,reason=verified_mifi()
   if serial:
    R['adb_verified']={'serial':serial,'board':'msm8916','time_sec':elapsed,'attempts':tries}
    say('ADB ПРОВЕРЕН: '+reason,'OK')
    return serial
  except Exception as ex:
   reason='USB-подключение ещё не готово: '+str(ex)[:130]
  say(f'Ожидание Android/ADB: {elapsed}/{seconds} сек. {reason}','WAIT')
  time.sleep(6)
 R['adb_verified']=False
 say('ADB не подтверждён. Команду reboot recovery НЕ отправляю.','FAIL')
 return None

def send_reboot_recovery(serial):
 R['mode']='RECOVERY_BOOT_TEST'
 try:
  cp=adb_call('-s',serial,'reboot','recovery',timeout=28)
 except Exception as ex:
  R['recovery_reboot_result']={'error':str(ex)}
  say('Команда reboot recovery не подтверждена: '+str(ex),'WARN')
  return False
 R['recovery_reboot_result']={'returncode':cp.returncode,'stdout':cp.stdout[-350:],'stderr':cp.stderr[-350:]}
 if cp.returncode!=0:
  say('Команда перезагрузки не подтверждена (код '+str(cp.returncode)+')','FAIL')
  return False
 say('Команда reboot recovery успешно отправлена. Это НЕ доказательство запуска LK2ND.','OK')
 return True

def fb_run(cmd_name, args, serial=None, timeout=12):
  """Read-only USB fastboot operations as root, no FLASH/ERASE/BOOT/REBOOT."""
  import subprocess,shlex
  allowed={('devices','-l'),('getvar','version'),('getvar','product'),('getvar','version-bootloader'),
           ('getvar','all'),('getvar','lk2nd'),('oem','log')}
  is_staged=(len(args)==2 and args[0]=='get_staged' and str(args[1]).startswith(str(STAGE)+os.sep))
  if tuple(args) not in allowed and not is_staged:
   raise RuntimeError('Команда не входит в безопасный список Fastboot: '+repr(args))
  prefix=os.environ.get('PREFIX','/data/data/com.termux/files/usr')
  exe=prefix+'/bin/'+cmd_name
  if not Path(exe).is_file():return {'exit':127,'stdout':'','stderr':'Команда '+cmd_name+' не установлена'}
  cmd=['env','HOME=/data/data/com.termux/files/home','TMPDIR='+prefix+'/tmp',exe]
  if serial:cmd.extend(['-s',serial])
  cmd.extend(args)
  try:
   cp=subprocess.run(['su','-c',' '.join(shlex.quote(str(a)) for a in cmd)],capture_output=True,text=True,timeout=timeout)
   return {'exit':cp.returncode,'stdout':cp.stdout[-4500:],'stderr':cp.stderr[-4500:]}
  except subprocess.TimeoutExpired:
   return {'exit':124,'stdout':'','stderr':'Время ожидания Fastboot истекло'}
  except Exception as e:
   return {'exit':126,'stdout':'','stderr':'Ошибка запуска: '+str(e)[:250]}

def parse_fastboot_devices(txt):
  """Accept only a single connected Fastboot serial; avoid probing another device."""
  import re
  out=[]
  for line in txt.splitlines():
   m=re.match(r'^([^\s]+)\s+fastboot(?:\s|$)',line.strip(),re.IGNORECASE)
   if m:out.append(m.group(1))
  return out

def probe_fastboot():
  import time
  say('Проверяю Fastboot: только чтение, БЕЗ flash / erase / reboot.','INFO')
  details={'usb':usb_snapshot(),'commands':[],'lk2nd_verified':False}
  R['fastboot_proof']=details
  if '[ff:42:03]' not in details['usb'].lower():
   say('Fastboot сейчас не обнаружен по USB.','WARN');details['status']='USB_FASTBOOT_ABSENT';return False
  names=['fastboot','termux-fastboot']
  driver=None; serial=None
  for n in names:
   res=fb_run(n,['devices','-l'],timeout=12)
   details['commands'].append({'tool':n,'args':['devices','-l'],'result':res})
   devices=parse_fastboot_devices(res['stdout'])
   if len(devices)==1 and res['exit']==0:
    driver=n;serial=devices[0];break
  if not serial:
   say('USB Fastboot есть, но утилита не получила серийный номер.','WARN')
   details['status']='USB_FASTBOOT_NO_CLI_TARGET';return False
  say('Fastboot-подключение активно: '+serial,'OK')
  details['tool']=driver;details['serial']=serial
  for args in [('getvar','version'),('getvar','product'),('getvar','version-bootloader'),('getvar','lk2nd'),('getvar','all'),('oem','log')]:
   out=fb_run(driver,list(args),serial,timeout=12)
   details['commands'].append({'tool':driver,'args':list(args),'result':out})
   body=(out['stdout']+' '+out['stderr']).strip()
   say(('Fastboot '+ ' '.join(args)+': '+ ('успешно' if out['exit']==0 else 'код '+str(out['exit'])) + '; '+body[:170]).replace('\n',' '),'INFO' if out['exit']==0 else 'WARN')
  # Official lk2nd supports `fastboot oem log` and `get_staged`, stock ABOOT commonly does not.
  STAGE.mkdir(parents=True,exist_ok=True)
  stagefile=STAGE/'lk2nd_boot_log_v32.txt'
  if stagefile.exists():stagefile.unlink()
  out=fb_run(driver,['get_staged',str(stagefile)],serial,timeout=20)
  details['commands'].append({'tool':driver,'args':['get_staged','<report-file>'],'result':out})
  if out['exit']==0 and stagefile.is_file():
   size=stagefile.stat().st_size
   raw=stagefile.read_bytes()[:1024*1024]
   details['staged_bytes']=size
   details['staged_log_preview']=raw.decode('utf8','replace')[:2000]
   if b'lk2nd' in raw.lower():
    details['lk2nd_verified']=True;details['status']='LK2ND_IDENTIFIED_BY_BOOT_LOG'
    say('LK2ND ПОДТВЕРЖДЁН: получен журнал загрузчика с идентификатором lk2nd.','OK')
   else:
    details['status']='STAGED_LOG_WITHOUT_LK2ND_MARKER'
    say('Журнал получен, но надписи lk2nd нет. Идентификация не подтверждена.','WARN')
  else:
   combined=' '.join((a['result']['stdout']+' '+a['result']['stderr']) for a in details['commands'] if a['args']!=['devices','-l']).lower()
   if 'lk2nd' in combined and not ('unknown variable: lk2nd' in combined or 'unknown command: lk2nd' in combined):
    details['status']='LK2ND_MARKER_IN_GETVAR_NEEDS_CONFIRMATION'
    say('Обнаружено упоминание lk2nd в ответах. Требуется подтверждение журналом.','WARN')
   else:
    details['status']='FASTBOOT_RESPONDS_LK2ND_NOT_PROVEN'
    say('Fastboot отвечает, но подтвердить LK2ND не удалось. Возможен заводской ABOOT.','WARN')
  return bool(details['lk2nd_verified'])

def usb_watch(duration=75):
  import time
  R['usb_samples']=[]
  say('Наблюдаю USB и автоматически опрашиваю Fastboot.','INFO')
  start=time.monotonic();last=None;seen_fastboot=False;attempts=0;lastprobe=-999
  while time.monotonic()-start<duration:
   observed=usb_snapshot();elapsed=int(time.monotonic()-start)
   R['usb_samples'].append({'elapsed_sec':elapsed,'usb':observed})
   if observed!=last:
    say('USB ('+str(elapsed)+' сек): '+observed,'INFO');last=observed
   else:say('Наблюдение USB: '+str(elapsed)+'/'+str(duration)+' сек.','WAIT')
   if '[ff:42:03]' in observed.lower():
    seen_fastboot=True
    if attempts<2 and elapsed-lastprobe>=15:
     attempts+=1;lastprobe=elapsed
     if probe_fastboot():
      R['bootloader_booted']=True
      break
   time.sleep(5)
  R['fastboot_usb_interface_seen']=seen_fastboot
  if not R.get('bootloader_booted'):
   say('ИТОГ: lk2nd не подтверждён. Один USB Fastboot недостаточен для вывода.','WARN')
  else:
   say('ИТОГ: lk2nd подтверждён по содержимому его журнала.','OK')
  say('После ручного возврата Android восстанови заводской p26: --restore-factory.','WARN')

def report():
 """Never throw another exception while reporting an earlier failure."""
 try:
  REPORT.mkdir(parents=True,exist_ok=True)
  R['event_log']=LOG
  dest=REPORT/('XARKON_JZ08_LK2ND_PROOF_V32_'+STAMP+'.zip')
  status_map={'ok':'ГОТОВО','warn':'ВНИМАНИЕ','step':'ЭТАП','fail':'ОШИБКА','info':'ИНФО',
              'OK':'ГОТОВО','WARN':'ВНИМАНИЕ','FAIL':'ОШИБКА','INFO':'ИНФО','WAIT':'ОЖИДАНИЕ'}
  lines=['XARKON JZ08 LK2ND v32','', 'СТАТУС: '+str(R.get('status','НЕИЗВЕСТНО')), '']
  for e in LOG:
   if not isinstance(e,dict):lines.append(str(e));continue
   kind=e.get('kind',e.get('status','INFO'))
   lines.append('['+status_map.get(str(kind),str(kind))+'] '+str(e.get('text','')))
  if R.get('error'):lines.extend(['','ОШИБКА: '+str(R['error'])])
  lines.extend(['','ВНИМАНИЕ: автоматический выход из EDL не доказывает запуск LK2ND.'])
  with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED) as f:
   f.writestr('РЕЗУЛЬТАТ.json',json.dumps(R,ensure_ascii=False,indent=2))
   f.writestr('ОТЧЁТ.txt','\n'.join(lines)+'\n')
  say('ZIP-отчёт сохранён: '+str(dest),'OK')
 except Exception as err:
  print('[ОШИБКА] Не удалось сохранить ZIP-отчёт: '+str(err),flush=True)

def main():
 say('JZ08 // LK2ND V32 // OEM-FIXED LAYOUT / RECOVERY p26')
 if arg.self_test:
  check(parse_fastboot_devices('TEST_JZ08\tfastboot usb:1-1\n')==['TEST_JZ08'],'Разбор серийного номера Fastboot')
  check(parse_fastboot_devices('нет устройств\n')==[],'Отсутствующий Fastboot корректно обработан')
  lk=parse_lk(readz('bin/lk2nd.img'))
  check(sha(readz('bin/lk2nd.img'))==LK_SHA,'Аудит готового LK2ND завершён без доступа к устройству')
  LOG.append({'status':'ok','text':'Тест совместимости со старым форматом журнала'});R['status']='OFFLINE_SELFTEST_PASS';return
 if arg.probe_fastboot:
  R['status']='READ_ONLY_LK2ND_PROBE' if probe_fastboot() else 'READ_ONLY_FASTBOOT_UNCONFIRMED'
  return
 c=coremod()
 if arg.restore_factory:
  say('Возврат заводского Recovery через EDL; Android и USB должны быть доступны','WARN')
  factory=c.stock_recovery()
  R['emmc_write_attempted']=True
  c.device_flash(factory,restore=True)
  STATE.unlink(missing_ok=True)
  R['status']='FACTORY_RECOVERY_RESTORED_READBACK';return
 if arg.boot_test:
  check(STATE.exists(),'Нет подтверждения записи LK2ND. Запуск Recovery отменён')
  state=json.loads(STATE.read_text())
  check(CAN.exists() and shafile(CAN)==state['candidate_sha256'],'Образ изменился, операция отменена')
  check(state.get('flash_verified') is True,'Нет контрольного чтения после записи')
  serial=await_verified_android(c)
  check(serial is not None,'Android MIFI не обнаружен. Ничего не перезагружено')
  if send_reboot_recovery(serial):
   R['status']='REBOOT_RECOVERY_SENT_BOOT_NOT_PROVEN'
   usb_watch(65)
  else:R['status']='REBOOT_RECOVERY_NOT_SENT'
  say('После теста восстанови заводской Recovery командой --restore-factory','WARN')
  return
 lk=parse_lk(readz('bin/lk2nd.img'))
 img=build(c,lk)
 if arg.flash or arg.cycle:
  say('ОПАСНО: реальная запись lk2nd в p26. В случае несовместимости OEM boot может отвергнуть образ.','WARN')
  # The inherited function checks LIVE ABOOT and BOOT hashes, GPT and stock recovery SHA,
  # reads back exactly 16 MiB and attempts rollback in the same EDL session on failure.
  STATE.unlink(missing_ok=True)  # Never reuse an older successful flash marker.
  R['emmc_write_attempted']=True
  c.device_flash(img,restore=False)
  check(R.get('recovery_live_after_sha256')==R['candidate_meta']['sha256'],'SHA-256 живого p26 равен собранному LK2ND образу')
  STATE.write_text(json.dumps({'flash_verified':True,'candidate_sha256':R['candidate_meta']['sha256'],'time':STAMP},indent=2))
  R['status']='LK2ND_IN_RECOVERY_VERIFIED_NOT_BOOTED'
  say('p26 записан и проверен.','WARN')
  if arg.cycle:
    R['cycle_flash_sha256']=R['recovery_live_after_sha256']
    serial=await_verified_android(c)
    if not serial:
     R['status']='LK2ND_WRITTEN_ADB_NOT_READY_RESTORE_REQUIRED'
     say('LK2ND записан в p26, но Android не подтверждён. Тест НЕ запускался.','FAIL')
     say('Верни штатный режим, затем --restore-factory. Не считай EDL RESET запуском LK2ND.','WARN')
     return
    if not send_reboot_recovery(serial):
     R['status']='LK2ND_WRITTEN_REBOOT_COMMAND_FAILED_RESTORE_REQUIRED'
     say('Тест не отправлен. После восстановления Android выполни --restore-factory.','FAIL')
     return
    R['status']='RECOVERY_REBOOT_SENT_USB_MONITORING'
    usb_watch(65)
    R['status']='CYCLE_LK2ND_VERIFIED_RESTORE_REQUIRED' if R.get('bootloader_booted') else 'CYCLE_COMPLETE_LK2ND_BOOT_UNPROVEN_RESTORE_REQUIRED'
    say('USB-монитор закончен. Верни штатный Android и восстанови p26 через --restore-factory.','WARN')
  else:
   say('После возврата Android запускай --boot-test, затем --restore-factory.','WARN')
 else:R['status']='CANDIDATE_READY_NOT_FLASHED'

if __name__=='__main__':
 try: main()
 except BaseException as e:
  R['status']='INTERRUPTED' if isinstance(e,KeyboardInterrupt) else 'FAILED'
  R['error']=str(e) if str(e) else e.__class__.__name__
  R['traceback']=traceback.format_exc()[-4000:]
  reason=str(e)
  if reason=='Полный проверенный дамп eMMC найден':reason='Не найден полный проверенный дамп eMMC или его расположение изменилось'
  if reason=='Единственный Native ADB MIFI подтверждён':reason='MIFI не доступен по Native ADB; проверь USB и штатный Android'
  say('Операция прервана пользователем' if isinstance(e,KeyboardInterrupt) else 'Операция не завершена: '+reason,'FAIL')
 finally:report()
