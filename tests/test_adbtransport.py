"""Real smart-socket framing and selection across competing local ADB servers."""
import socket
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/termux'))
import adbtransport as adb

SERIAL='TEST_JZ08'
INFO=['product:MIFI','model:MIFI','device:MIFI']
IDENTITY={'platform':'msm8916','model':'MIFI','build':'JZ_MIFI_LCD_TEST'}


class FakeServer:
    def __init__(self,port,devices,identity=IDENTITY):
        self.port=port;self.listing=devices;self.identity=identity;self.services=[]
    def devices(self):
        return ''.join(s+'\t'+state+' '+' '.join(info)+'\n' for s,state,info in self.listing),self.listing
    def service(self,serial,service,timeout=8,limit=262144):
        self.services.append(service)
        return '\n'.join(self.identity.values())+'\n',False


class Transport(unittest.TestCase):
    def test_reuses_other_server_instead_of_starting_another_usb_owner(self):
        servers={5063:FakeServer(5063,[]),5037:FakeServer(5037,[(SERIAL,'device',INFO)])}
        def create(port,timeout):
            if port not in servers:raise ConnectionRefusedError()
            return servers[port]
        notes=[];starts=[]
        with patch.object(adb,'Server',side_effect=create):
            session=adb.ensure_mifi(notes,start=lambda:starts.append(True),attempts=0)
        self.assertEqual(session.server.port,5037);self.assertEqual(starts,[])
        self.assertNotIn(SERIAL,str(notes));self.assertNotIn('host:kill',str(servers[5037].services))

    def test_two_physical_devices_on_different_servers_block_before_shell(self):
        servers={1:FakeServer(1,[(SERIAL,'device',INFO)]),2:FakeServer(2,[('PHONE','device',['model:Samsung'])])}
        with patch.object(adb,'Server',side_effect=lambda port,timeout:servers[port]):
            with self.assertRaises(adb.AmbiguousDevice):adb.discover(ports=(1,2))
        self.assertTrue(all(not s.services for s in servers.values()))

    def test_same_device_on_two_servers_is_not_counted_twice(self):
        with patch.object(adb,'Server',side_effect=lambda port,timeout:FakeServer(port,[(SERIAL,'device',INFO)])):
            self.assertIsNotNone(adb.discover(ports=(1,2)))

    def test_other_phone_is_never_sent_identity_or_kernel_commands(self):
        server=FakeServer(1,[('PHONE','device',['model:Samsung','product:phone'])])
        with patch.object(adb,'Server',return_value=server):self.assertIsNone(adb.discover(ports=(1,)))
        self.assertEqual(server.services,[])

    def test_reboot_rechecks_identity_and_rejects_swapped_device(self):
        server=FakeServer(1,[(SERIAL,'device',INFO)],{'platform':'other','model':'MIFI','build':'JZ_MIFI_LCD_TEST'})
        session=adb.Session(server,SERIAL,IDENTITY)
        result=session(['-s',SERIAL,'reboot','edl'])
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('reboot:edl',server.services)

    def test_no_server_starts_once_then_waits_for_live_identity(self):
        found=object();starts=[]
        with patch.object(adb,'discover',side_effect=[None,found]),patch.object(adb.time,'sleep'):
            self.assertIs(adb.ensure_mifi(start=lambda:starts.append(1) or True,attempts=1),found)
        self.assertEqual(starts,[1])

    def test_existing_empty_server_does_not_cause_a_competing_start(self):
        def empty(notes):notes.append({'port':5037,'server':'reachable'});return None
        starts=[]
        with patch.object(adb,'discover',side_effect=empty):
            self.assertIsNone(adb.ensure_mifi(start=lambda:starts.append(1),attempts=0))
        self.assertEqual(starts,[])

    def test_request_rejects_corrupt_or_truncated_length(self):
        class Sock:
            def __init__(self,parts):self.parts=iter(parts)
            def recv(self,n):return next(self.parts,b'')
        for chunks in ([b'xyzz'],[b'00',b'']):
            with self.assertRaises(adb.ProtocolError):adb.Server.length(Sock(chunks))

    def test_protocol_error_never_exposes_server_serial(self):
        class Sock:
            def __init__(self):self.parts=iter([b'FAIL',b'0009',b'SECRET_ID'])
            def recv(self,n):return next(self.parts)
            def sendall(self,data):pass
        with self.assertRaises(adb.ProtocolError) as result:adb.Server.request(Sock(),'host:devices-l')
        self.assertNotIn('SECRET_ID',str(result.exception))

    def test_actual_loopback_server_fragmented_frames_and_legacy_shell(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        listener.settimeout(3);port=listener.getsockname()[1];requests=[];errors=[]
        def read_request(conn):
            size=int(adb.Server.exact(conn,4),16)
            service=adb.Server.exact(conn,size).decode();requests.append(service);return service
        def serve():
            try:
                with listener:
                    with listener.accept()[0] as conn:
                        self.assertEqual(read_request(conn),'host:devices-l')
                        data=(SERIAL+'\tdevice product:MIFI model:MIFI\n').encode()
                        for byte in b'OKAY'+f'{len(data):04x}'.encode()+data:conn.sendall(bytes([byte]))
                    with listener.accept()[0] as conn:
                        self.assertEqual(read_request(conn),'host:transport:'+SERIAL);conn.sendall(b'OKAY')
                        self.assertEqual(read_request(conn),'shell:'+adb.IDENTITY);conn.sendall(b'OKAY')
                        conn.sendall(b'msm8916\r\nMIFI\r\nJZ_MIFI_LCD_TEST\r\n')
            except Exception as ex:errors.append(ex)
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        server=adb.Server(port)
        text,devices=server.devices();self.assertEqual(devices[0][0],SERIAL)
        output,truncated=server.service(SERIAL,'shell:'+adb.IDENTITY)
        thread.join(4)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,[]);self.assertFalse(truncated)
        self.assertIn('JZ_MIFI_LCD_TEST',output);self.assertEqual(len(requests),3)


if __name__=='__main__':unittest.main()
