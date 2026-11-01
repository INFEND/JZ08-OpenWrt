"""Termux-only, in-memory workaround for pySerial serial port enumeration.

The Python interpreter used by Termux reports sys.platform == 'android'.
pySerial 3.5 does not recognize this name in list_ports_posix and raises an
ImportError when the module is imported, even when a program only uses libusb.
This adds a minimal Android implementation without modifying packages on disk.
An empty list is a normal result: USB EDL devices are not /dev/tty*.
"""
from __future__ import annotations

import glob
import os
import sys
import types


def enable():
    if sys.platform.lower() != 'android':
        return False
    import serial.tools.list_ports_common as common
    module_name='serial.tools.list_ports_posix'
    if module_name in sys.modules:
        return True
    shim=types.ModuleType(module_name)
    shim.__doc__='XARKON Android safe enumerator for pySerial: read-only tty paths.'

    def comports(include_links=False):
        patterns=('/dev/ttyUSB[0-9]*','/dev/ttyACM[0-9]*',
                  '/dev/ttyHS[0-9]*')
        names=set()
        for pattern in patterns:
            for path in glob.glob(pattern):
                if os.path.exists(path) and (include_links or not os.path.islink(path)):
                    names.add(path)
        return [common.ListPortInfo(path) for path in sorted(names)]

    shim.comports=comports
    sys.modules[module_name]=shim
    return True
