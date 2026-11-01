"""Reuse an existing local ADB server without spawning competing USB owners.

AOSP smart-socket protocol, including the legacy shell service for Android 4.4.
Only loopback and the already used ADB ports are contacted. No host:kill,
detach, USB reset, adbd restart, or device writes are used for discovery.
"""
import os
import re
import shlex
import socket
import subprocess
import time
from pathlib import Path

PORTS = (5063, 5037, 5046, 5061, 5062)
IDENTITY = 'getprop ro.board.platform; getprop ro.product.model; getprop ro.build.display.id'


class ProtocolError(RuntimeError):
    pass


class AmbiguousDevice(ProtocolError):
    pass


class Server:
    def __init__(self, port, timeout=3):
        self.port = int(port)
        self.timeout = timeout

    def connect(self):
        return socket.create_connection(('127.0.0.1', self.port), self.timeout)

    @staticmethod
    def exact(sock, size):
        out = bytearray()
        while len(out) < size:
            part = sock.recv(size - len(out))
            if not part:
                raise ProtocolError('truncated ADB response')
            out.extend(part)
        return bytes(out)

    @classmethod
    def length(cls, sock):
        raw = cls.exact(sock, 4)
        if not re.fullmatch(b'[0-9a-fA-F]{4}', raw):
            raise ProtocolError('invalid ADB response length')
        return int(raw, 16)

    @classmethod
    def request(cls, sock, service):
        raw = service.encode('utf-8')
        if not 0 < len(raw) <= 65535 or b'\0' in raw:
            raise ProtocolError('invalid ADB request')
        sock.sendall(f'{len(raw):04x}'.encode('ascii') + raw)
        status = cls.exact(sock, 4)
        if status == b'FAIL':
            # A server error can contain a private serial; never propagate it.
            cls.exact(sock, cls.length(sock))
            raise ProtocolError('ADB service refused the request')
        if status != b'OKAY':
            raise ProtocolError('invalid ADB response status')

    def devices(self):
        with self.connect() as sock:
            self.request(sock, 'host:devices-l')
            size = self.length(sock)
            if size > 16384:
                raise ProtocolError('oversized ADB device list')
            text = self.exact(sock, size).decode('utf-8', 'replace')
        devices = []
        for line in text.splitlines():
            fields = line.split()
            if len(fields) < 2:
                if fields:
                    raise ProtocolError('malformed ADB device list')
                continue
            serial, state = fields[:2]
            if serial.startswith('emulator-'):
                continue
            if not re.fullmatch(r'[A-Za-z0-9_.:@+-]{1,200}', serial):
                raise ProtocolError('invalid ADB device identifier')
            devices.append((serial, state, fields[2:]))
        return text, devices

    def service(self, serial, service, timeout=8, limit=262144):
        end = time.monotonic() + timeout
        with self.connect() as sock:
            sock.settimeout(max(0.01, end - time.monotonic()))
            self.request(sock, 'host:transport:' + serial)
            self.request(sock, service)
            out = bytearray()
            while len(out) <= limit:
                sock.settimeout(max(0.01, end - time.monotonic()))
                chunk = sock.recv(min(16384, limit + 1 - len(out)))
                if not chunk:
                    return out.decode('utf-8', 'replace'), False
                out.extend(chunk)
            return out[:limit].decode('utf-8', 'replace'), True


class Session:
    def __init__(self, server, serial, identity):
        self.server = server
        self.serial = serial
        self.identity = identity

    def __call__(self, args, timeout=10):
        """Small, explicit adapter for the audited recovery transport callers."""
        argv = list(args)
        try:
            if argv in (['devices'], ['devices', '-l']):
                text, _ = self.server.devices()
                return subprocess.CompletedProcess(argv, 0, 'List of devices attached\n' + text, '')
            if argv[:2] != ['-s', self.serial]:
                raise ProtocolError('explicit verified MIFI target required')
            command = argv[2:]
            if command and command[0] == 'shell':
                script = command[1] if len(command) == 2 else ' '.join(shlex.quote(a) for a in command[1:])
                out, truncated = self.server.service(self.serial, 'shell:' + script, timeout)
                return subprocess.CompletedProcess(argv, 0, out, 'OUTPUT_TRUNCATED' if truncated else '')
            if len(command) == 2 and command[0] == 'reboot' and command[1] in ('recovery', 'edl'):
                # Recheck the live listing and fingerprint before changing boot mode.
                live = identify(self.server, self.serial)
                if live != self.identity:
                    raise ProtocolError('MIFI identity changed before reboot')
                self.server.service(self.serial, 'reboot:' + command[1], timeout, limit=4096)
                return subprocess.CompletedProcess(argv, 0, '', '')
            raise ProtocolError('unsupported ADB operation')
        except (OSError, ProtocolError):
            return subprocess.CompletedProcess(argv, 1, '', 'Verified MIFI ADB request failed')


def identify(server, serial):
    _, devices = server.devices()
    if len(devices) != 1 or devices[0][:2] != (serial, 'device'):
        return None
    # Do not send any shell command to a listed Samsung or another model.
    info = devices[0][2]
    if 'model:MIFI' not in info or 'product:MIFI' not in info:
        return None
    text, truncated = server.service(serial, 'shell:' + IDENTITY, timeout=6, limit=4096)
    lines = text.replace('\r', '').strip().splitlines()
    if truncated or len(lines) != 3:
        return None
    platform, model, build = lines
    if platform != 'msm8916' or model.upper() != 'MIFI' or not build.startswith('JZ_MIFI_LCD_'):
        return None
    return {'platform': platform, 'model': model, 'build': build}


def discover(notes=None, ports=PORTS):
    """List every known server first; never silently select among two devices."""
    notes = notes if notes is not None else []
    listings = []
    identifiers = set()
    for port in ports:
        try:
            server = Server(port, timeout=0.6)
            _, devices = server.devices()
            notes.append({'port': port, 'server': 'reachable', 'device_states': [d[1] for d in devices]})
            listings.append((server, devices))
            identifiers.update(d[0] for d in devices)
        except (OSError, ProtocolError):
            notes.append({'port': port, 'server': 'unavailable'})
    if len(identifiers) > 1:
        raise AmbiguousDevice('Several physical ADB devices; automatic selection blocked')
    for server, devices in listings:
        if len(devices) != 1 or devices[0][1] != 'device':
            continue
        try:
            identity = identify(server, devices[0][0])
        except (OSError, ProtocolError):
            continue
        if identity:
            return Session(server, devices[0][0], identity)
    return None


def start_single_server():
    """Start port 5063 only when no existing server was reachable."""
    prefix = Path(os.environ.get('PREFIX', '/data/data/com.termux/files/usr'))
    args = ['env', 'HOME=/data/data/com.termux/files/home', 'TMPDIR=' + str(prefix / 'tmp'),
            'LD_LIBRARY_PATH=' + str(prefix / 'lib'), 'ADB_LIBUSB=0', 'ADB_SERVER_PORT=5063',
            str(prefix / 'bin/adb'), '-P', '5063', 'start-server']
    return subprocess.run(['su', '-c', ' '.join(shlex.quote(a) for a in args)],
                          capture_output=True, text=True, timeout=20).returncode == 0


def ensure_mifi(notes=None, start=start_single_server, attempts=5, pause=1):
    notes = notes if notes is not None else []
    fresh = []
    found = discover(fresh)
    notes.extend(fresh)
    if found:
        return found
    if not any(n['server'] == 'reachable' for n in fresh):
        notes.append({'start_port': 5063, 'start_succeeded': bool(start())})
    for _ in range(attempts):
        time.sleep(pause)
        found = discover(notes)
        if found:
            return found
    return None


_session = None


def recovery_connect(notes=None):
    global _session
    _session = ensure_mifi(notes)
    return _session


def recovery_command(args, timeout=22):
    global _session
    if _session is None:
        _session = ensure_mifi()
    if _session is None:
        return subprocess.CompletedProcess(args, 1, '', 'No live verified MIFI ADB transport')
    if list(args) == ['start-server']:
        return subprocess.CompletedProcess(args, 0, '', '')
    return _session(args, timeout)
