"""Inspect only the per-run USB LAN; LuCI uses 403 for its login page."""
import subprocess,time,urllib.request,urllib.error
from pathlib import Path

def fetch_luci(opener,url):
    try:response=opener.open(url,timeout=3)
    except urllib.error.HTTPError as ex:
        if ex.code!=403:raise
        response=ex
    status=response.code
    html=response.read(131072).decode(errors='replace').lower()
    verified=('<html' in html and 'luci' in html and status in (200,403) and
              (status==200 or response.headers.get('x-luci-login-required')=='yes'))
    return {'luci_http_verified':verified,'luci_http_status':status,
            'luci_russian_verified':verified and 'lang="ru"' in html}

def inspect(nonce):
    if len(nonce)!=32 or any(c not in '0123456789abcdef' for c in nonce):raise ValueError('nonce')
    interfaces=[]
    for p in Path('/sys/bus/usb/devices').glob('*'):
        try:
            if (p/'serial').read_text().strip()=='JZ08-OW1-'+nonce:
                interfaces.extend(n.name for n in p.glob('*/net/*'))
        except OSError:pass
    interfaces=sorted(set(interfaces))
    result={'descriptor_verified':True,'report_complete':False,'luci_http_verified':False}
    if len(interfaces)!=1:
        result['error']='Android USB network interface unavailable; nonce proof retained'
        return result
    iface=interfaces[0]
    subprocess.run(['ip','link','set',iface,'up'],check=True,capture_output=True)
    subprocess.run(['ip','addr','replace','192.168.73.2/24','dev',iface],check=True,capture_output=True)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for attempt in range(10):
        try:
            text=opener.open('http://192.168.73.1/jz08/proof.txt',timeout=3).read(131072).decode()
            if 'BEGIN '+nonce in text and 'END '+nonce in text and 'OPENWRT_RELEASE=' in text:
                result.update(text=text,report_complete=True)
                result.update(fetch_luci(opener,'http://192.168.73.1/cgi-bin/luci/'))
                break
        except Exception as ex:result['error']=str(ex)
        time.sleep(2)
    return result
