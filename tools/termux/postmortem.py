"""Read-only USB/stock-Android observations; never change a USB mode."""
import json,re

USB_CODE='''import json
from pathlib import Path
out=[]
for p in Path('/sys/bus/usb/devices').glob('*'):
 try:
  vid=(p/'idVendor').read_text().strip();pid=(p/'idProduct').read_text().strip()
  if vid=='05c6' or (vid,pid) in [('18d1','d00d'),('1d6b','0104')]:
   out.append({'vid':vid,'pid':pid})
 except OSError:pass
print(json.dumps(out))
'''

def stock_android(adb):
    """adb(list[str],timeout)->CompletedProcess. Require exactly one MIFI."""
    r=adb(['devices'],5)
    devices=[m for m in re.findall(r'^(\S+)\s+(device|offline|unauthorized)\b[^\n]*$',r.stdout,re.M)
             if not m[0].startswith('emulator-')]
    if r.returncode or len(devices)!=1 or devices[0][1]!='device':return None
    target=['-s',devices[0][0]]
    r=adb(target+['shell','getprop ro.board.platform; getprop ro.product.model; getprop ro.build.display.id'],8)
    lines=r.stdout.replace('\r','').strip().splitlines()
    if r.returncode or len(lines)!=3:return None
    platform,model,build=lines
    if platform!='msm8916' or 'MIFI' not in model.upper() or not build.startswith('JZ_MIFI_LCD_'):return None
    # Separate bounded requests keep a large old last_kmsg from hiding dmesg.
    commands=[('boot','getprop ro.boot.bootreason; getprop sys.boot.reason; cat /proc/uptime'),
              ('last_kmsg','cat /proc/last_kmsg'),
              ('pstore_console','cat /sys/fs/pstore/console-ramoops'),
              ('pstore_panic','cat /sys/fs/pstore/dmesg-ramoops-0'),
              ('dmesg','dmesg')]
    logs=[];sources=[]
    for name,command in commands:
        script=command+' 2>&1; r=$?; printf "\\nINFEND_REMOTE_EXIT=%s\\n" "$r"'
        try:
            r=adb(target+['shell',script],10)
            body=r.stdout[:256*1024]
            match=re.search(r'\nINFEND_REMOTE_EXIT=(\d+)\s*$',body)
            sources.append({'source':name,'transport_exit':r.returncode,
                            'remote_exit':int(match[1]) if match else None,
                            'truncated':len(r.stdout)>256*1024 or 'OUTPUT_TRUNCATED' in getattr(r,'stderr','')})
            logs.append('SOURCE:'+name+'\n'+body)
        except (OSError,TimeoutError):
            sources.append({'source':name,'transport_exit':1,'remote_exit':None,'error':'read timeout/unavailable'})
    text='\n'.join(logs)
    # Extra numeric-ID filter before normal report redaction on the phone.
    text=re.sub(r'(?<!\d)\d{14,22}(?!\d)','[ID]',text)
    return {'identity':{'platform':platform,'model':model,'build':build},'log':text,
            'sources':sources}


def capture_existing(start=False):
    from adbtransport import discover,ensure_mifi,AmbiguousDevice
    notes=[]
    try:
        session=ensure_mifi(notes) if start else discover(notes)
        if session is None:return {'available':False,'servers':notes[-15:]}
        post=stock_android(session)
        if post is None:return {'available':False,'servers':notes[-15:],'error':'live identity not verified'}
        return {'available':True,'server_port':session.server.port,'servers':notes[-15:],'postmortem':post}
    except AmbiguousDevice:
        return {'available':False,'servers':notes[-15:],'error':'multiple physical ADB devices; selection blocked'}
