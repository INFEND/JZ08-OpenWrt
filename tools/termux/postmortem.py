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
    serials=[m[0] for m in re.findall(r'^(\S+)\s+(device)\s*$',r.stdout,re.M)
             if not m[0].startswith('emulator-')]
    if len(serials)!=1:return None
    target=['-s',serials[0]]
    r=adb(target+['shell','getprop ro.board.platform; getprop ro.product.model; getprop ro.build.display.id'],8)
    lines=r.stdout.replace('\r','').strip().splitlines()
    if r.returncode or len(lines)!=3:return None
    platform,model,build=lines
    if platform!='msm8916' or 'MIFI' not in model.upper() or not build.startswith('JZ_MIFI_LCD_'):return None
    # These are kernel/boot diagnostics only. No modem/NV/firmware payload.
    script=('getprop ro.boot.bootreason; getprop sys.boot.reason; '
            'for p in /proc/last_kmsg /sys/fs/pstore/console-ramoops /sys/fs/pstore/dmesg-ramoops-0; '
            'do echo SOURCE:$p; cat "$p" 2>/dev/null; done; dmesg 2>/dev/null')
    r=adb(target+['shell',script],15)
    text=r.stdout[:256*1024]
    # Extra numeric-ID filter before normal report redaction on the phone.
    text=re.sub(r'(?<!\d)\d{14,22}(?!\d)','[ID]',text)
    return {'identity':{'platform':platform,'model':model,'build':build},'log':text,
            'command_exit':r.returncode}
