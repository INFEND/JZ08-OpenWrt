"""Read only the RAM proof gadget carrying the expected per-run nonce."""
import json, struct, time

def complete_report(data,nonce):
    # ttyGS0 may retain OPOST/ONLCR; accept both raw LF and terminal CRLF.
    data=bytes(data).replace(b'\r\n',b'\n')
    begin=('BEGIN '+nonce+'\n').encode();finish=('END '+nonce+'\n').encode()
    start=data.find(begin)
    if start<0:return None
    stop=data.find(finish,start)
    return data[start:stop+len(finish)] if stop>=0 else None

def capture(nonce,seconds=18):
    import usb.core, usb.util
    if len(nonce)!=32 or any(c not in '0123456789abcdef' for c in nonce):raise ValueError('nonce')
    matches=[]
    for d in usb.core.find(find_all=True,idVendor=0x1d6b,idProduct=0x0104):
        try:
            if usb.util.get_string(d,d.iSerialNumber)=='JZ08-OW1-'+nonce:matches.append(d)
        except usb.core.USBError:continue
    if len(matches)!=1:return {'descriptor_verified':False,'reason':'no unique matching gadget'}
    d=matches[0];result={'descriptor_verified':True,'nonce':nonce,'report_complete':False}
    detached=[];claimed=[];data=bytearray()
    try:
        cfg=d.get_active_configuration()
        comm=next(i for i in cfg if i.bInterfaceClass==2)
        itf=next(i for i in cfg if i.bInterfaceClass==10)
        for i in (comm.bInterfaceNumber,itf.bInterfaceNumber):
            try:
                if d.is_kernel_driver_active(i):d.detach_kernel_driver(i);detached.append(i)
            except NotImplementedError:pass
            usb.util.claim_interface(d,i);claimed.append(i)
        ep=next(e for e in itf if usb.util.endpoint_direction(e.bEndpointAddress)==usb.util.ENDPOINT_IN)
        d.ctrl_transfer(0x21,0x20,0,comm.bInterfaceNumber,struct.pack('<IBBB',115200,0,0,8),timeout=2000)
        d.ctrl_transfer(0x21,0x22,3,comm.bInterfaceNumber,b'',timeout=2000)
        end=time.monotonic()+seconds
        while time.monotonic()<end and len(data)<256*1024:
            try:data.extend(ep.read(16384,timeout=1000))
            except usb.core.USBTimeoutError:continue
            framed=complete_report(data,nonce)
            if framed is not None:
                data=framed;result['report_complete']=True;break
        result['text']=bytes(data).decode('utf8','replace')
    except Exception as ex:result['error']=str(ex)
    finally:
        for i in reversed(claimed):
            try:usb.util.release_interface(d,i)
            except Exception:pass
        for i in detached:
            try:d.attach_kernel_driver(i)
            except Exception:pass
        usb.util.dispose_resources(d)
    return result
