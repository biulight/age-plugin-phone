import argparse, datetime, hashlib, ipaddress, json, os, pathlib, re, select, socket, struct, subprocess, time, uuid

from replay_checks import check_original, check_network_cycle, require

parser = argparse.ArgumentParser()
parser.add_argument('--network-cancel', action='store_true')
parser.add_argument('--auto-cycle', action='store_true', help='cycle Wi-Fi after 10 seconds with the request still pending')
args = parser.parse_args()
if args.auto_cycle and not args.network_cancel:
    parser.error('--auto-cycle requires --network-cancel')
D = pathlib.Path(os.environ['TEMP']) / 'phone-beta2-p1-20261023'
R = {'case': 'wifi-exact-request-replay', 'result': 'incomplete', 'phone_observation': 'pending'}
if args.network_cancel:
    R['case'] = 'wifi-network-cancel-exact-replay'
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
    require(h[:8] == b'APTS\x00\x01\x02' + bytes([direction]))
    if session is not None: require(h[8:24] == session)
    n = struct.unpack('>I', h[24:28])[0]
    require(0 < n <= 65536)
    return h + read_exact(s, n)

def cbor(data):
    # Bounded test-only decoder. Values never leave process memory.
    def item(pos, depth=0):
        require(depth < 12 and pos < len(data))
        tag=data[pos]; pos+=1; major=tag>>5; ai=tag&31
        if tag == 246: return None,pos
        if ai < 24: n=ai
        else:
            size={24:1,25:2,26:4,27:8}[ai]
            require(pos+size <= len(data))
            n=int.from_bytes(data[pos:pos+size],'big');pos+=size
        if major == 0: return n,pos
        if major in (2,3):
            require(n <= 65536 and pos+n <= len(data))
            return data[pos:pos+n],pos+n
        require(major == 4 and n <= 64)
        values=[]
        for _ in range(n):
            v,pos=item(pos,depth+1);values.append(v)
        return values,pos
    v,end=item(0);require(end==len(data));return v

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
    R['replay_checks_sha256']=hashlib.sha256(pathlib.Path(__file__).with_name('replay_checks.py').read_bytes()).hexdigest()
    product=D/'package'/'age-plugin-phone.exe'
    require(hashlib.sha256(product.read_bytes()).hexdigest()=='62d8f3836598dd1ab287c3b2ac432539870bfb0cbe7bdfd547d08cf3be373e2b')
    devices=re.findall(r'^\S+\s+device\s*$',run('adb','devices'),re.M)
    require(len(devices)==1)
    require(not run('adb','reverse','--list').strip())
    route=run('adb','shell','ip','-4','route','show','dev','wlan0')
    phone=re.search(r'\bsrc\s+(\d+\.\d+\.\d+\.\d+)',route).group(1)
    require(ipaddress.ip_address(phone).is_private)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
        probe.connect((phone,47140)); local=probe.getsockname()[0]
    require(ipaddress.ip_address(local).is_private and not ipaddress.ip_address(local).is_loopback)
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
            envelope=cbor(request[28:]);require(len(envelope)==2)
            payload=cbor(envelope[0]);require(len(payload)==11 and payload[:3]==[2,3,1])
            expiry=payload[9];require(isinstance(expiry,int) and time.time()<expiry)
            upstream.sendall(request)
            print('Original request forwarded; '+('leave the native prompt pending for the network cycle.' if args.network_cancel else 'awaiting fresh phone verification.'),flush=True)
            if args.network_cancel:
                if args.auto_cycle:
                    # Do not cycle an already closed or unexpectedly answered request.
                    readable, _, _ = select.select([upstream], [], [], 10)
                    require(not readable)
                    switch = pathlib.Path(__file__).with_name('switch-wifi.ps1')
                    base = pathlib.Path(__file__).resolve().parent.parent / 'windows-minimal-acceptance.ps1'
                    R['provenance'] = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in (
                        ('switch_sha256', switch),
                        ('common_sha256', switch.with_name('common.ps1')),
                        ('base_helper_sha256', base))}
                    R['automatic_cycle_delay_seconds'] = 10
                    cycle_process = subprocess.run(['pwsh', '-NoProfile', '-File', str(switch)],
                                                   capture_output=True, timeout=60)
                    require(cycle_process.returncode == 0)
                    print('Checked Wi-Fi cycle completed; waiting for original failure, then replaying.', flush=True)
                try:
                    received = upstream.recv(1)
                    require(received == b'')
                    R['original_peer_result'] = 'closed-without-response'
                except ConnectionResetError:
                    R['original_peer_result'] = 'reset-without-response'
                except socket.timeout:
                    R['original_peer_result'] = 'bounded-read-timeout-without-response'
                client.shutdown(socket.SHUT_RDWR)
            else:
                response=frame(upstream,2,request[8:24]);client.sendall(response)
    stdout,stderr=P.communicate(timeout=15)
    check_original(P.returncode, stdout, output.read_bytes() if output.exists() else b'', inputs['digest'], args.network_cancel)
    R['original_exit_code']=P.returncode
    R['original_output_check']='no-output' if args.network_cancel else 'byte-identical'
    if args.network_cancel:
        cycles = []
        for path in D.glob('wifi-interface-cycle-*.json'):
            cycle = json.loads(path.read_text(encoding='utf-8-sig'))
            if cycle['started_utc'] >= R['started_utc']:
                cycles.append((path, cycle))
        require(len(cycles) == 1)
        path, cycle = cycles[0]
        check_network_cycle(cycle, R['started_utc'])
        R['network_cycle_file'] = path.name
        R['network_cycle_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        route=run('adb','shell','ip','-4','route','show','dev','wlan0')
        phone=re.search(r'\bsrc\s+(\d+\.\d+\.\d+\.\d+)',route).group(1)
        require(ipaddress.ip_address(phone).is_private)
    R['replays']=[]
    for mode in ('identical-frame','fresh-outer-session-same-signed-request'):
        time.sleep(1)
        replay=bytearray(request)
        if mode != 'identical-frame': replay[8:24]=os.urandom(16)
        require(replay[28:]==request[28:])
        if mode=='identical-frame': require(replay==request)
        remaining=expiry-int(time.time());require(remaining>30)
        with connect_phone(phone) as peer:
            peer.settimeout(10)
            start=time.monotonic();peer.sendall(replay)
            try:
                received=peer.recv(1)
                require(received==b'')
                outcome='closed-without-response'
            except ConnectionResetError: outcome='reset-without-response'
            require(time.time()<expiry)
        replay[:]=b'\x00'*len(replay)
        R['replays'].append({'mode':mode,'signed_request_byte_identical':True,'expiry_remaining_seconds_at_send':remaining,'peer_result':outcome,'elapsed_seconds':round(time.monotonic()-start,3)})
        print('Replay rejected without response: '+mode,flush=True)
    require(not run('adb','reverse','--list').strip())
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
    (D/(R['case']+'-'+uuid.uuid4().hex+'.json')).write_text(json.dumps(R,indent=2))
    print(json.dumps(R,indent=2),flush=True)
raise SystemExit(0 if R['result'].startswith('automated-checks') else 1)
