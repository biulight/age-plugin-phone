"""Run one pending Wi-Fi request and a checked interface cycle; no direct connection or replay."""
import datetime,hashlib,json,os,pathlib,subprocess,time,uuid,tempfile
D=pathlib.Path(os.environ['TEMP'])/'phone-beta2-p1-20261023'
S=pathlib.Path(__file__).parent
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
r={'case':'pending-network-cycle-orchestration','started_utc':now(),'result':'failed','driver_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()}
p=None
stdout_file=tempfile.TemporaryFile()
stderr_file=tempfile.TemporaryFile()
try:
 p=subprocess.Popen(['pwsh','-NoProfile','-File',str(S/'step-regression.ps1'),'-Case','wifi-network'],stdout=stdout_file,stderr=stderr_file)
 time.sleep(12)
 if p.poll() is not None:raise RuntimeError('request-ended-before-cycle')
 r['pending_process_before_cycle']=True
 c=subprocess.run(['pwsh','-NoProfile','-File',str(S/'switch-wifi.ps1')],capture_output=True,timeout=60)
 if c.returncode:raise RuntimeError('checked-cycle-failed')
 print('Checked network cycle completed. Waiting for original request to terminate.',flush=True)
 p.wait(timeout=130)
 stdout_file.seek(0);out=stdout_file.read(98304)
 r['original_driver_exit_code']=p.returncode
 if p.returncode:raise RuntimeError('original-negative-check-failed')
 report=json.loads(out.decode('utf-8-sig'))
 if report.get('result')!='automated-checks-passed-awaiting-observation' or report.get('output_check')!='no-output' or report.get('exit_code') in (None,0):raise RuntimeError('invalid-negative-report')
 r['request_started_utc']=report['started_utc'];r['request_finished_utc']=report['finished_utc']
 r['result']='automated-checks-passed-awaiting-observation'
except Exception as e:
 r['failure_category']=type(e).__name__
finally:
 if p is not None and p.poll() is None:
  p.kill();p.wait(timeout=15);r['harness_terminated_driver']=True
 stdout_file.close();stderr_file.close()
 r['finished_utc']=now()
 (D/('pending-cycle-'+uuid.uuid4().hex+'.json')).write_text(json.dumps(r,indent=2)+'\n')
 print(json.dumps(r),flush=True)
raise SystemExit(0 if r['result']=='automated-checks-passed-awaiting-observation' else 1)
