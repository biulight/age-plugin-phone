"""Bounded restart of the test application only; never clears data or replay state."""
import datetime
import re
import subprocess
import time

PACKAGE = 'io.github.biulight.age_plugin_phone'


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def command(*arguments):
    return subprocess.run(['adb', 'shell', *arguments], capture_output=True, timeout=15)


def pid():
    result = command('pidof', PACKAGE)
    if result.returncode == 1 and not result.stdout.strip() and not result.stderr.strip():
        return None
    if result.returncode != 0 or not re.fullmatch(rb'[0-9]+', result.stdout.strip()):
        raise ValueError('application process query failed')
    return result.stdout.strip()


def restart():
    record = {'started_utc': now(), 'package': PACKAGE}
    previous = pid()
    if previous is None:
        raise ValueError('application was not running before restart')
    if command('am', 'force-stop', PACKAGE).returncode != 0:
        raise ValueError('application stop failed')
    if pid() is not None:
        raise ValueError('application did not stop')
    record['old_process_stopped'] = True
    result = command('am', 'start', '-W', '-n', PACKAGE + '/.MainActivity')
    if result.returncode != 0 or not re.search(rb'(?m)^Status: ok\r?$', result.stdout):
        raise ValueError('application launch failed')
    for _ in range(10):
        current = pid()
        if current is not None:
            if current == previous:
                raise ValueError('application process did not change')
            record.update(fresh_process_started=True, finished_utc=now(), result='passed')
            return record
        time.sleep(.5)
    raise ValueError('application did not return')
