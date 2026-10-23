"""Subprocess-only synthetic boundary fixture; never connects to a phone or runs age/ADB."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import socket
import struct
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

scenario = sys.argv[1]
driver = Path(__file__).with_name('replay-probe.py')
real_hash = hashlib.sha256


def cbor(value):
    if isinstance(value, int):
        return b'\x1b' + value.to_bytes(8, 'big')
    if isinstance(value, bytes):
        return b'\x59' + len(value).to_bytes(2, 'big') + value
    return bytes([0x80 + len(value)]) + b''.join(cbor(v) for v in value)


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary) / 'phone-beta2-p1-20261023'
    (root / 'package').mkdir(parents=True)
    (root / 'synthetic').mkdir()
    (root / 'package' / 'age-plugin-phone.exe').write_bytes(b'fixture product')
    (root / 'local-inputs.json').write_text(json.dumps(dict(matching='synthetic', digest=real_hash(b'synthetic').hexdigest())))
    expiry = int(time.time()) + (-1 if scenario == 'expired' else 300)
    payload = cbor([2, 3, 1, 0, 0, 0, 0, 0, 0, expiry, 0])
    body = cbor([payload, b'synthetic signature'])
    session = bytes(16)
    request = b'APTS\x00\x01\x02\x01' + session + struct.pack('>I', len(body)) + body
    if scenario == 'malformed-frame':
        request = b'BAD!' + request[4:]
    response = b'APTS\x00\x01\x02\x02' + (bytes([1])*16 if scenario == 'wrong-session' else session) + struct.pack('>I', 1) + b'R'

    class Stream:
        def __init__(self, data=b''): self.data = data
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def recv(self, size):
            data, self.data = self.data[:size], self.data[size:]
            return data
        def sendall(self, data): pass
        def settimeout(self, value): pass
        def setsockopt(self, *args): pass
        def bind(self, *args): pass
        def listen(self, *args): pass
        def connect(self, *args): pass
        def getsockname(self): return ('192.168.1.3', 47140)
        def accept(self): return Stream(request), None

    connections = 0
    def connect(*args, **kwargs):
        global connections
        connections += 1
        if connections == 1: return Stream(response)
        return Stream(b'X' if scenario == 'replay-response' else b'')

    class Process:
        returncode = 0
        def __init__(self, args, **kwargs):
            Path(args[args.index('-o')+1]).write_bytes(b'synthetic')
        def communicate(self, **kwargs): return b'', b''
        def poll(self): return 0

    def run(args, **kwargs):
        if list(args[1:]) == ['devices']: output = b'fixture-device\tdevice\n'
        elif list(args[1:]) == ['reverse', '--list']: output = b'residue' if scenario == 'reverse-residue' else b''
        else: output = b'192.168.1.0/24 src 192.168.1.2'
        return subprocess.CompletedProcess(args, 0, output, b'')

    def digest(data=b''):
        if data == b'fixture product' and scenario != 'wrong-product':
            class Expected:
                def hexdigest(self): return '62d8f3836598dd1ab287c3b2ac432539870bfb0cbe7bdfd547d08cf3be373e2b'
            return Expected()
        return real_hash(data)

    with patch.dict(os.environ, TEMP=temporary, LOCALAPPDATA=temporary), \
         patch.object(sys, 'argv', [str(driver)]), \
         patch('hashlib.sha256', digest), patch('socket.socket', lambda *a, **k: Stream()), \
         patch('socket.create_connection', connect), patch('socket.SO_EXCLUSIVEADDRUSE', 4, create=True), \
         patch('subprocess.Popen', Process), patch('subprocess.run', run), patch('time.sleep', lambda _: None):
        try:
            runpy.run_path(str(driver), run_name='__main__')
        except SystemExit as error:
            code = error.code
    reports = list(root.glob('wifi-exact-request-replay-*.json'))
    if len(reports) != 1:
        raise RuntimeError('driver did not write exactly one report')
    report = json.loads(reports[0].read_text())
    print('FIXTURE_RESULT=' + json.dumps(dict(exit_code=code, result=report['result'])))
