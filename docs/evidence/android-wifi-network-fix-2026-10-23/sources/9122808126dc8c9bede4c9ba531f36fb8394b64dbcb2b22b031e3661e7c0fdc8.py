import datetime, hashlib, ipaddress, json, os, pathlib, re, socket, struct, subprocess, time, uuid

D = pathlib.Path(os.environ['TEMP']) / 'phone-beta2-p1-20261023'
R = {'case': 'wifi-exact-request-replay', 'result': 'incomplete', 'phone_observation': 'pending'}
P = None

def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def run(*args):
    p = subprocess.run(args, capture_output=True, timeout=15)
    if p.returncode: raise RuntimeError('precondition')
    return p.stdout.decode('utf-8', errors='replace')

def read_exact(s, n):
    b = bytearray()
    while len(b) < n:
        part = s.recv(n-len(b))
        if not part: raise RuntimeError('short frame')
        b.extend(part)
    return b

def frame(s, direction, session=None):
    h = read_exact(s, 28)
    assert h[:8] == b'APTS\x00\x01\x02' + bytes([direction])
    if session is not None: assert h[8:24] == session
    n = struct.unpack('>I', h[24:28])[0]
    assert 0 < n <= 65536
    return h + read_exact(s, n)

def cbor(data):
    # Bounded test-only decoder. Values never leave process memory.
    def item(pos, depth=0):
        assert depth < 12 and pos < len(data)
        tag=data[pos]; pos+=1; major=tag>>5; ai=tag&31
        if tag == 246: return None,pos
        if ai < 24: n=ai
        else:
            size={24:1,25:2,26:4,27:8}[ai]
            assert pos+size <= len(data)
            n=int.from_bytes(data[pos:pos+size],'big');pos+=size
        if major == 0: return n,pos
        if major in (2,3):
            assert n <= 65536 and pos+n <= len(data)
            return data[pos:pos+n],pos+n
        assert major == 4 and n <= 64
        values=[]
        for _ in range(n):
            v,pos=item(pos,depth+1);values.append(v)
        return values,pos
    v,end=item(0);assert end==len(data);return v

def connect_phone(ip):
    # Refused connections may occur during rearm; never retry after sending bytes.
    deadline=time.monotonic()+8
    while True:
        try: return socket.create_connection((ip,47140),timeout=3)
        except ConnectionRefusedError:
            if time.monotonic()>=deadline: raise
            time.sleep(.2)

request = response = None
try:
    R['started_utc']=now()
    R['driver_sha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    product=D/'package'/'age-plugin-phone.exe'
    assert hashlib.sha256(product.read_bytes()).hexdigest()=='62d8f3836598dd1ab287c3b2ac432539870bfb0cbe7bdfd547d08cf3be373e2b'
    devices=re.findall(r'^\S+\s+device\s*$',run('adb','devices'),re.M)
    assert len(devices)==1
    assert not run('adb','reverse','--list').strip()
    route=run('adb','shell','ip','-4','route','show','dev','wlan0')
    phone=re.search(r'\bsrc\s+(\d+\.\d+\.\d+\.\d+)',route).group(1)
    assert ipaddress.ip_address(phone).is_private
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
        probe.connect((phone,47140)); local=probe.getsockname()[0]
    assert ipaddress.ip_address(local).is_private and not ipaddress.ip_address(local).is_loopback
    inputs=json.loads((D/'local-inputs.json').read_text(encoding='utf-8-sig'))
    output=D/'synthetic'/('replay-approved-'+uuid.uuid4().hex+'.bin')
    env=os.environ.copy()
    for k in ('AGE_PLUGIN_PHONE_ADB_SERIAL','AGE_PLUGIN_PHONE_MESSAGES'):
        env.pop(k,None)
    env.update(AGE_PLUGIN_PHONE_TRANSPORT='wifi',AGE_PLUGIN_PHONE_WIFI_ADDRESS=f'{local}:47140',AGE_PLUGIN_PHONE_CONFIG_DIR=str(pathlib.Path(os.environ['LOCALAPPDATA'])/'age-plugin-phone'))
    env['PATH']=str(product.parent)+os.pathsep+env['PATH']
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
        listener.bind((local,47140));listener.listen(1);listener.settimeout(15)
        P=subprocess.Popen(['age','-d','-i',inputs['matching'],'-o',str(output),str(D/'synthetic'/'synthetic.age')],cwd=product.parent,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        client,_=listener.accept()
        with client,connect_phone(phone) as upstream:
            client.settimeout(95);upstream.settimeout(95)
            request=frame(client,1)
            envelope=cbor(request[28:]);assert len(envelope)==2
            payload=cbor(envelope[0]);assert len(payload)==11 and payload[:3]==[2,3,1]
            expiry=payload[9];assert isinstance(expiry,int) and time.time()<expiry
            upstream.sendall(request)
            print('Original request forwarded; awaiting fresh phone verification.',flush=True)
            response=frame(upstream,2,request[8:24]);client.sendall(response)
    stdout,stderr=P.communicate(timeout=15)
    assert P.returncode==0 and stdout==b''
    assert hashlib.sha256(output.read_bytes()).hexdigest().lower()==inputs['digest'].lower()
    R['original_exit_code']=0;R['original_output_check']='byte-identical'
    R['replays']=[]
    for mode in ('identical-frame','fresh-outer-session-same-signed-request'):
        time.sleep(1)
        replay=bytearray(request)
        if mode != 'identical-frame': replay[8:24]=os.urandom(16)
        assert replay[28:]==request[28:]
        if mode=='identical-frame': assert replay==request
        remaining=expiry-int(time.time());assert remaining>30
        with connect_phone(phone) as peer:
            peer.settimeout(10)
            start=time.monotonic();peer.sendall(replay)
            try:
                received=peer.recv(1)
                assert received==b''
                outcome='closed-without-response'
            except ConnectionResetError: outcome='reset-without-response'
            assert time.time()<expiry
        replay[:]=b'\x00'*len(replay)
        R['replays'].append({'mode':mode,'signed_request_byte_identical':True,'expiry_remaining_seconds_at_send':remaining,'peer_result':outcome,'elapsed_seconds':round(time.monotonic()-start,3)})
        print('Replay rejected without response: '+mode,flush=True)
    assert not run('adb','reverse','--list').strip()
    R['adb_reverse_count']=0
    R['result']='automated-checks-passed-awaiting-observation'
except Exception:
    R['result']='failed';R['failure_category']='proxy-or-replay-assertion-failed'
finally:
    if P is not None and P.poll() is None:
        P.kill();P.communicate(timeout=15)
    for value in (request,response):
        if value is not None: value[:]=b'\x00'*len(value)
    R['finished_utc']=now()
    (D/('wifi-exact-request-replay-'+uuid.uuid4().hex+'.json')).write_text(json.dumps(R,indent=2))
    print(json.dumps(R,indent=2),flush=True)
raise SystemExit(0 if R['result'].startswith('automated-checks') else 1)
