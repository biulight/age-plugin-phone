"""Bounded pending-request diagnostic; only coarse public states are retained."""
import datetime,hashlib,json,os,pathlib,re,subprocess,sys,tempfile,time
root=pathlib.Path(os.environ['TEMP'])/'phone-beta2-p1-20261023'
script=pathlib.Path(sys.argv[1])
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
def query(*args):
 try:
  p=subprocess.run(['adb',*args],capture_output=True,text=True,timeout=10)
  return p.stdout if p.returncode==0 else None
 except subprocess.TimeoutExpired:return None
def snapshot():
 power=query('shell','dumpsys','power'); activity=query('shell','dumpsys','activity','activities'); wifi=query('shell','settings','get','global','wifi_on'); route=query('shell','ip','-4','addr','show','dev','wlan0')
 resumed=[x for x in (activity or '').splitlines() if 'topResumedActivity=' in x or 'mResumedActivity:' in x]
 return dict(utc=now(),awake=None if power is None else bool(re.search(r'mWakefulness=Awake',power)),app_resumed=None if activity is None else any('io.github.biulight.age_plugin_phone/' in x for x in resumed),wifi_enabled=None if wifi is None else wifi.strip()=='1',wifi_ipv4_present=None if route is None else bool(re.search(r'\binet \d+\.',route)))
r=dict(case='early-peer-diagnostic',started_utc=now(),python_version=sys.version.split()[0],command=['python','p1/replay-probe.py','--network-cancel','--auto-cycle','--restart-after-cancel'],driver_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),wrapper_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),before=snapshot())
with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
 p=subprocess.Popen([sys.executable,str(script),'--network-cancel','--auto-cycle','--restart-after-cancel'],stdout=out,stderr=err)
 try:r['exit_code']=p.wait(timeout=180)
 except subprocess.TimeoutExpired:
  p.kill();p.wait();r['exit_code']=None;r['bounded_wait_expired']=True
r['after']=snapshot();r['finished_utc']=now()
(root/'early-peer-diagnostic.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r,indent=2),flush=True)
raise SystemExit(0 if r['exit_code']==0 else 1)
