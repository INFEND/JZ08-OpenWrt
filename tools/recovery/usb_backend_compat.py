"""Termux Android compatibility shim for bkerler/edl PyUSB.

Upstream usb_class.__init__ sets self.backend on sys.platform linux/darwin/freebsd,
or Windows, but not Android. This module injects only the missing attribute
into newly created usb_class instances. Does not touch installed site-packages
or send any USB command."""
from __future__ import annotations
import os
import sys


def _libusb_candidates():
    prefix=os.environ.get('PREFIX','/data/data/com.termux/files/usr')
    return [os.path.join(prefix,'lib','libusb-1.0.so'),
            os.path.join(prefix,'lib','libusb-1.0.so.0'),
            'libusb-1.0.so','libusb-1.0.so.0']


def get_backend():
    import usb.backend.libusb1
    errors=[]
    for cand in _libusb_candidates():
        try:
            b=usb.backend.libusb1.get_backend(find_library=lambda _lib, p=cand: p)
            if b is not None:
                return b,cand,errors
            errors.append(cand+': backend None')
        except Exception as exc:
            errors.append(cand+': '+type(exc).__name__+': '+str(exc)[:160])
    return None,'',errors


def patch_usb_class():
    if sys.platform.lower() != 'android':
        return False
    from edlclient.Library.Connection import usblib
    cls=usblib.usb_class
    if getattr(cls,'_xarkon_android_backend_patched',False):
        return True
    original=cls.__init__
    def initializer(self,*args,**kwargs):
        backend,_name,_errors=get_backend()
        self.backend=backend
        original(self,*args,**kwargs)
        # Upstream unsets backend if libusb_set_option is not supported.
        # It is not a reason to discard a successfully initialized backend.
        if self.backend is None and backend is not None:
            self.backend=backend
    cls.__init__=initializer
    cls._xarkon_android_backend_patched=True
    return True


def preflight():
    import usb.core
    b,name,errors=get_backend()
    result={'platform':sys.platform,'library':name,'backend_available':b is not None,
            'target_found':False,'errors':errors[-4:]}
    if b is None:
        result['error']='LIBUSB_BACKEND_MISSING'
        return result
    try:
        devices=list(usb.core.find(find_all=True,backend=b) or [])
        # Do not report unrelated USB devices or any serial numbers.
        result['qualcomm_devices']=['%04x:%04x'%(d.idVendor,d.idProduct)
                                    for d in devices if d.idVendor==0x05c6]
        result['target_found']=sum(d.idVendor==0x05c6 and d.idProduct==0x9008 for d in devices)==1
        result['target_count']=sum(d.idVendor==0x05c6 and d.idProduct==0x9008 for d in devices)
        if not result['target_found']:
            result['error']='EDL_9008_NOT_ENUMERATED_BY_PYUSB'
    except Exception as exc:
        result['error']=type(exc).__name__+': '+str(exc)[:300]
    return result
