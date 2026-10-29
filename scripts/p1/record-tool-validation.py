"""Run isolated acceptance-tool regressions and retain public, source-bound run records."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import uuid

SCRIPTS = Path(__file__).resolve().parent.parent
SOURCES = ['p1/record-tool-validation.py', 'p1/replay-probe.py', 'p1/replay_checks.py', 'p1/phone_restart.py',
           'p1/replay_driver_fixture.py', 'p1/evidence_fixture.py', 'test-p1-replay.py', 'check-p1-evidence.py',
           'test-p1-evidence.py', 'p1/switch-wifi.ps1', 'p1/common.ps1', 'windows-minimal-acceptance.ps1']


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def hashes():
    return {name: hashlib.sha256((SCRIPTS / name).read_bytes()).hexdigest() for name in SOURCES}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    args.destination.mkdir(parents=True, exist_ok=True)
    all_passed = True
    for script, flags in [('test-p1-replay.py', []), ('test-p1-evidence.py', []), ('test-p1-evidence.py', ['-O'])]:
        before = hashes()
        command = [sys.executable, *flags, '-B', script, '-v']
        env = os.environ.copy()
        env.pop('PYTHONOPTIMIZE', None)
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        record = dict(schema_version=1, platform=platform.system(), python_version=platform.python_version(),
                      python_implementation=platform.python_implementation(), executable_name=Path(sys.executable).name,
                      command=['python', *flags, '-B', script, '-v'], working_directory='scripts',
                      environment={'PYTHONOPTIMIZE':'unset for parent; replay suite sets child modes explicitly',
                                   'PYTHONDONTWRITEBYTECODE':'1'},
                      source_sha256=before, started_utc=now())
        try:
            result = subprocess.run(command, cwd=SCRIPTS, env=env, capture_output=True, text=True, timeout=180)
            record['exit_code'] = result.returncode
            # Keep diagnostic output, but remove machine-specific checkout/interpreter locations.
            output = result.stdout + result.stderr
            output = output.replace(str(SCRIPTS.parent), '<workspace>').replace(str(Path(sys.executable).parent), '<python>')
            if '/Users/' in output or re.search(r'[A-Za-z]:\\Users\\', output):
                raise ValueError('unredacted private path in test output')
            record['output'] = output
            record['source_unchanged'] = before == hashes()
            count = re.search(r'Ran (\d+) tests? in ', output)
            record['test_methods'] = int(count.group(1)) if count else None
            expected = 4 if script == 'test-p1-replay.py' else 10
            passed = result.returncode == 0 and record['source_unchanged'] and record['test_methods'] == expected and output.rstrip().endswith('OK')
            record['result'] = 'passed' if passed else 'failed'
        except Exception as error:
            record['result'] = 'failed'
            record.setdefault('exit_code', None)
            record['failure_category'] = type(error).__name__
        record['finished_utc'] = now()
        path = args.destination / (platform.system().lower() + '-' + uuid.uuid4().hex + '.json')
        path.write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps({k:record.get(k) for k in ('platform','command','python_version','exit_code','test_methods','result')}, ensure_ascii=False), flush=True)
        all_passed = all_passed and record['result'] == 'passed'
    return 0 if all_passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
