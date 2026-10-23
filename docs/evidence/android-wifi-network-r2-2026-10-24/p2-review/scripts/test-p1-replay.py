import hashlib
import json
import os
import subprocess
import pathlib
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).parent / "p1"))
from replay_checks import check_original, check_network_cycle


class ReplayChecksTest(unittest.TestCase):
    def test_actual_driver_in_normal_flag_and_environment_optimization_modes(self):
        fixture = pathlib.Path(__file__).parent / 'p1' / 'replay_driver_fixture.py'
        for mode in ('normal', 'flag', 'environment'):
            for scenario in ('valid', 'replay-response', 'expired', 'malformed-frame', 'wrong-session', 'wrong-product', 'reverse-residue'):
                with self.subTest(mode=mode, scenario=scenario):
                    env = os.environ.copy()
                    env.pop('PYTHONOPTIMIZE', None)
                    if mode == 'environment': env['PYTHONOPTIMIZE'] = '1'
                    command = [sys.executable] + (['-O'] if mode == 'flag' else []) + [str(fixture), scenario]
                    process = subprocess.run(command, env=env, capture_output=True, text=True, timeout=20)
                    self.assertEqual(process.returncode, 0, process.stderr)
                    line = next(x for x in process.stdout.splitlines() if x.startswith('FIXTURE_RESULT='))
                    report = json.loads(line.split('=', 1)[1])
                    self.assertEqual(report['exit_code'], 0 if scenario == 'valid' else 1)
                    self.assertEqual(report['result'], 'automated-checks-passed-awaiting-observation' if scenario == 'valid' else 'failed')

    def test_cancel_requires_failure_and_no_output(self):
        check_original(1, b"", b"", "unused", True)
        for code, stdout, output in [(0, b"", b""), (1, b"leak", b""), (1, b"", b"leak")]:
            with self.assertRaises(AssertionError):
                check_original(code, stdout, output, "unused", True)

    def test_original_approval_requires_exact_output(self):
        digest = hashlib.sha256(b"synthetic").hexdigest()
        check_original(0, b"", b"synthetic", digest, False)
        for code, output in [(1, b"synthetic"), (0, b""), (0, b"different")]:
            with self.assertRaises(AssertionError):
                check_original(code, b"", output, digest, False)

    def test_cycle_requires_removal_restore_and_current_attempt(self):
        cycle = dict(result="passed", disabled_and_ipv4_removed=True, wifi_ipv4_restored=True,
                     started_utc="2026-10-24T01:00:01Z", disabled_utc="2026-10-24T01:00:02Z",
                     finished_utc="2026-10-24T01:00:10Z")
        start = "2026-10-24T01:00:00Z"
        check_network_cycle(cycle, start)
        for key, value in [("result", "failed"), ("disabled_and_ipv4_removed", False),
                           ("wifi_ipv4_restored", False), ("started_utc", "2026-10-23T01:00:00Z"),
                           ("finished_utc", "2026-10-24T01:00:00Z")]:
            with self.assertRaises(AssertionError):
                check_network_cycle(dict(cycle, **{key: value}), start)


if __name__ == "__main__":
    unittest.main()
