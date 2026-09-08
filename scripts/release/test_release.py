"""No live network: exercise the real state machine with injectable I/O."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import crates_release as release
import gates

SHA = 'a' * 40
VERSION = '0.1.0-alpha.4'
SECRET = 'fixture-sensitive-token-never-persist'


def setUpModule():
    # A missed mock must fail, never fall through to a real network or Cargo upload.
    global NETWORK, PROCESS
    NETWORK = patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('network forbidden in fixtures'))
    PROCESS = patch('subprocess.run', side_effect=AssertionError('subprocess forbidden in fixtures'))
    NETWORK.start()
    PROCESS.start()


def tearDownModule():
    NETWORK.stop()
    PROCESS.stop()


class Fake:
    def __init__(self):
        self.calls = []
        self.versions = {}
        self.fail = None
        self.delays = 0

    def lookup(self, name):
        self.calls.append(('lookup', name))
        if self.fail == 'auth-lookup':
            raise gates.Stop('http-status-403')
        return self.versions.get(name)

    def dry_run(self, name):
        self.calls.append(('dry-run', name))
        if self.fail == 'dry-run':
            raise gates.Stop('command-failed')
        return {'sha256': hashlib.sha256(name.encode()).hexdigest(), 'files': {'src/lib.rs': SHA}}

    def verify(self, name, version, expected):
        gates.require(version == expected['sha256'], 'registry-checksum-mismatch')

    def check_archive(self, name, expected):
        self.calls.append(('check-archive', name))

    def publish(self, name):
        self.calls.append(('publish', name))
        if self.fail == 'denied':
            raise gates.Stop('http-status-403')
        self.versions[name] = self.dry_run(name)['sha256']
        if self.fail == 'timeout':
            raise gates.Stop('command-timeout')

    def wait(self, name, expected):
        self.calls.append(('wait', name))
        gates.require(name in self.versions, 'registry-visibility-timeout')
        self.verify(name, self.versions[name], expected)


class ControlFlow(unittest.TestCase):
    def setUp(self):
        self.state = release.initial(SHA, VERSION, 'publish', {'run_id': 1}, [])
        self.fake = Fake()
        self.saved = []
        self.flow = release.Release(self.state, self.fake, lambda: self.saved.append(copy.deepcopy(self.state)))

    def chain(self):
        for name in release.ORDER:
            if self.flow.prepare(name):
                self.flow.upload(name)

    def test_success_serial_order_and_intent_before_upload(self):
        self.chain()
        self.assertEqual([n for call, n in self.fake.calls if call == 'publish'], release.ORDER)
        for name in release.ORDER:
            self.assertEqual(self.state['packages'][name]['visible'], 'verified')
            self.assertTrue(any(s['packages'][name]['upload'] == 'armed' for s in self.saved))
            self.assertTrue(any(s['packages'][name]['upload'] == 'attempted' for s in self.saved))

    def test_wrong_order_and_private_packages(self):
        for name in [release.ORDER[1], 'age-plugin-phone-mobile', 'tauri-plugin-phone-identity']:
            with self.assertRaises(gates.Stop):
                self.flow.prepare(name)
        self.assertEqual(self.fake.calls, [])

    def test_dry_run_failure_stops_all_uploads(self):
        self.fake.fail = 'dry-run'
        with self.assertRaises(gates.Stop):
            self.chain()
        self.assertFalse(any(c == 'publish' for c, _ in self.fake.calls))

    def test_authentication_failure_stops_later_packages(self):
        self.fake.fail = 'denied'
        with self.assertRaises(gates.Stop):
            self.chain()
        self.assertEqual([n for c, n in self.fake.calls if c == 'publish'], release.ORDER[:1])

    def test_timeout_after_success_reconciles_but_stops(self):
        self.fake.fail = 'timeout'
        with self.assertRaisesRegex(gates.Stop, 'upload-error-reconciled-stop'):
            self.chain()
        self.assertEqual(self.state['packages'][release.ORDER[0]]['visible'], 'verified')
        self.assertEqual([n for c, n in self.fake.calls if c == 'publish'], release.ORDER[:1])

    def test_no_duplicate_upload_in_same_run(self):
        name = release.ORDER[0]
        self.flow.prepare(name)
        self.flow.upload(name)
        with self.assertRaisesRegex(gates.Stop, 'duplicate-or-unprepared'):
            self.flow.upload(name)
        self.assertEqual(sum(c == 'publish' for c, _ in self.fake.calls), 1)

    def test_version_appears_between_prepare_and_upload(self):
        name = release.ORDER[0]
        self.flow.prepare(name)
        self.fake.versions[name] = self.fake.dry_run(name)['sha256']
        with self.assertRaisesRegex(gates.Stop, 'version-appeared'):
            self.flow.upload(name)
        self.assertFalse(any(c == 'publish' for c, _ in self.fake.calls))

    def test_existing_matching_without_evidence_is_not_candidate_proof(self):
        name = release.ORDER[0]
        self.fake.versions[name] = self.fake.dry_run(name)['sha256']
        with self.assertRaisesRegex(gates.Stop, 'without-evidence'):
            self.chain()

    def test_partial_release_resume_skips_verified_existing(self):
        name = release.ORDER[0]
        self.flow.prepare(name)
        self.flow.upload(name)
        previous = copy.deepcopy(self.state)
        self.state = release.initial(SHA, VERSION, 'publish', {'run_id': 1}, [previous])
        self.flow = release.Release(self.state, self.fake, lambda: None)
        self.chain()
        self.assertEqual([n for c, n in self.fake.calls if c == 'publish'], release.ORDER)
        self.assertEqual(self.state['packages'][name]['upload'], 'reused-verified')

    def test_missing_after_prior_intent_requires_manual_review(self):
        self.flow.prepare(release.ORDER[0])
        state = release.initial(SHA, VERSION, 'publish', {}, [copy.deepcopy(self.state)])
        with self.assertRaisesRegex(gates.Stop, 'uncertain-prior'):
            release.Release(state, self.fake, lambda: None).prepare(release.ORDER[0])

    def test_existing_inconsistent_registry_or_evidence(self):
        name = release.ORDER[0]
        self.flow.prepare(name)
        self.flow.upload(name)
        previous = copy.deepcopy(self.state)
        for mismatch in ['registry', 'evidence']:
            with self.subTest(mismatch=mismatch):
                prior = copy.deepcopy(previous)
                self.fake.versions[name] = prior['packages'][name]['sha256']
                if mismatch == 'registry':
                    self.fake.versions[name] = 'b' * 64
                else:
                    prior['packages'][name]['files'] = {}
                state = release.initial(SHA, VERSION, 'publish', {}, [prior])
                with self.assertRaises(gates.Stop):
                    release.Release(state, self.fake, lambda: None).prepare(name)

    def test_bad_recovery_candidate_or_order(self):
        for field, value in [('sha', 'b' * 40), ('version', '1.0.0'), ('order', list(reversed(release.ORDER)))]:
            prior = copy.deepcopy(self.state)
            prior[field] = value
            prior['packages'][release.ORDER[0]]['upload'] = 'armed'
            with self.assertRaisesRegex(gates.Stop, 'recovery-candidate'):
                release.initial(SHA, VERSION, 'publish', {}, [prior])


class Gates(unittest.TestCase):
    def setUp(self):
        self.context = dict(sha=SHA, repository=gates.REPOSITORY, event='workflow_dispatch', ref='refs/heads/main')
        self.workflow = dict(id=42, path=gates.CI_PATH, state='active')
        self.run = dict(id=1, workflow_id=42, path=gates.CI_PATH, repository={'full_name': gates.REPOSITORY},
                        head_repository={'full_name': gates.REPOSITORY}, head_sha=SHA, event='push',
                        head_branch='main', status='completed', conclusion='success', run_attempt=1)

    def test_sha_version_and_branch_mismatch(self):
        gates.candidate_gate(SHA, SHA, VERSION, VERSION, self.context, True)
        for sha, actual, version, expected, protected in [
                (SHA[:7], SHA, VERSION, VERSION, True), ('B' * 40, SHA, VERSION, VERSION, True),
                (SHA, 'b' * 40, VERSION, VERSION, True), (SHA, SHA, VERSION, '1.0.0', True),
                (SHA, SHA, VERSION, VERSION, False)]:
            with self.assertRaises(gates.Stop):
                gates.candidate_gate(sha, actual, version, expected, self.context, protected)
        for key, value in [('event', 'pull_request_target'), ('ref', 'refs/heads/codex/alpha.4'),
                           ('repository', 'attacker/fork')]:
            with self.assertRaises(gates.Stop):
                gates.candidate_gate(SHA, SHA, VERSION, VERSION, dict(self.context, **{key: value}), True)

    def api(self, run):
        class API:
            def get(_, path):
                return self.workflow if path.endswith('ci.yml') else run

            def pages(_, path, key):
                return [self.run, run]
        return API()

    def test_entire_ci_success_and_wrong_sources(self):
        self.assertEqual(gates.ci_gate(self.api(self.run), SHA)['run_id'], 1)
        for key, value in [('status', 'in_progress'), ('conclusion', 'failure'), ('conclusion', 'cancelled'),
                           ('event', 'pull_request'), ('head_branch', 'topic'), ('head_sha', 'b' * 40),
                           ('workflow_id', 99), ('path', '.github/workflows/other.yml'),
                           ('repository', {'full_name': 'evil/fork'}), ('head_repository', {'full_name': 'evil/fork'})]:
            with self.subTest(key=key, value=value), self.assertRaises(gates.Stop):
                gates.ci_gate(self.api(dict(self.run, id=2, **{key: value})), SHA)

    def test_workflow_identity(self):
        self.workflow['path'] = gates.RELEASE_PATH
        with self.assertRaisesRegex(gates.Stop, 'workflow-identity'):
            gates.ci_gate(self.api(self.run), SHA)

    def test_ci_absent(self):
        api = self.api(self.run)
        with patch.object(api, 'pages', return_value=[]), self.assertRaisesRegex(gates.Stop, 'ci-missing'):
            gates.ci_gate(api, SHA)

    def test_omitting_recovery_still_collects_all_same_version_runs(self):
        api = self.api(self.run)
        runs = [dict(self.run, id=i, display_title=f'crates.io {VERSION} (publish)') for i in [1, 2]]
        runs.append(dict(self.run, id=3, display_title='crates.io 9.0.0 (publish)'))
        with patch.object(api, 'pages', return_value=runs), patch('gates.recovery', return_value=[{}]) as recover:
            self.assertEqual(len(gates.prior_publications(api, VERSION)), 2)
            self.assertEqual(recover.call_count, 2)

    def test_recovery_artifact_digest_and_run_binding(self):
        import zipfile
        state = release.initial(SHA, VERSION, 'publish', {}, [])
        blob = io.BytesIO()
        with zipfile.ZipFile(blob, 'w') as archive:
            archive.writestr('result.json', json.dumps(state))
        artifact = dict(id=5, name='crates-evidence-intent-storage-1', expired=False,
                        digest='sha256:' + hashlib.sha256(blob.getvalue()).hexdigest())
        run = dict(self.run, path=gates.RELEASE_PATH, event='workflow_dispatch')
        class API:
            def get(_, path):
                return dict(self.workflow, path=gates.RELEASE_PATH) if path.endswith('.yml') else run

            def pages(_, path, key):
                return [artifact]
        with patch('gates.request', return_value=blob.getvalue()):
            self.assertEqual(gates.recovery(API(), '1', SHA), [state])
            artifact['digest'] = 'sha256:' + 'b' * 64
            with self.assertRaisesRegex(gates.Stop, 'artifact-digest'):
                gates.recovery(API(), '1', SHA)
            run['head_sha'] = 'b' * 40
            with self.assertRaisesRegex(gates.Stop, 'run-source'):
                gates.recovery(API(), '1', SHA)


class ProductionBoundaries(unittest.TestCase):
    def test_archive_source_sha_and_production_manifest(self):
        import tarfile
        name = release.ORDER[0]
        backend = object.__new__(release.Production)
        backend.s = {'sha': SHA, 'version': VERSION}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / 'crates/platform-storage'
            (package / 'src').mkdir(parents=True)
            (package / 'src/lib.rs').write_text('pub fn fixture() {}')
            (package / 'Cargo.toml').write_text('original fixture manifest')

            def archive(sha, registry):
                content = {
                    'src/lib.rs': (package / 'src/lib.rs').read_bytes(),
                    'Cargo.toml.orig': (package / 'Cargo.toml').read_bytes(),
                    '.cargo_vcs_info.json': json.dumps({'git': {'sha1': sha}}).encode(),
                    'Cargo.toml': (f'[package]\nname="{name}"\nversion="{VERSION}"\n'
                                   f'publish=["{registry}"]\n').encode(),
                }
                result = io.BytesIO()
                with tarfile.open(fileobj=result, mode='w:gz') as tar:
                    for path, blob in content.items():
                        entry = tarfile.TarInfo(f'{name}-{VERSION}/{path}')
                        entry.size = len(blob)
                        tar.addfile(entry, io.BytesIO(blob))
                return result.getvalue()

            with patch('crates_release.ROOT', root):
                self.assertIn('src/lib.rs', backend.inventory(archive(SHA, 'crates-io'), name))
                with self.assertRaisesRegex(gates.Stop, 'archive-source-sha'):
                    backend.inventory(archive('b' * 40, 'crates-io'), name)
                with self.assertRaisesRegex(gates.Stop, 'archive-production-manifest'):
                    backend.inventory(archive(SHA, 'preflight'), name)

    def test_preflight_unpublished_dependencies_are_blocked_not_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'evidence'
            release.save(release.initial(SHA, VERSION, 'preflight', {'run_id': 1}, []), out)
            fake = Fake()
            with patch('sys.argv', ['crates_release.py', 'preflight', '--output', str(out)]), \
                    patch('crates_release.command', side_effect=[SHA, '']), \
                    patch('crates_release.Production', return_value=fake):
                self.assertEqual(release.main(), 0)
            state = json.loads((out / 'result.json').read_text())
            self.assertEqual(state['packages'][release.ORDER[0]]['dry_run'], 'passed')
            for name in release.ORDER[1:]:
                self.assertEqual(state['packages'][name]['dry_run'], 'blocked-unpublished-dependency')
            self.assertFalse(any(c == 'publish' for c, _ in fake.calls))

    def test_workflow_preserves_permission_and_upload_order_contract(self):
        import re
        workflow = (release.ROOT / '.github/workflows/crates-release.yml').read_text()
        self.assertEqual(re.findall(r'crates_release.py upload --package (\S+)', workflow), release.ORDER)
        self.assertEqual(re.findall(r'crates_release.py prepare --package (\S+)', workflow), release.ORDER)
        self.assertEqual(workflow.count('id-token: write'), 1)
        preflight, publish = workflow.split('\n  publish:\n')
        self.assertNotIn('CARGO_REGISTRY_TOKEN', preflight)
        self.assertNotIn('id-token:', preflight)
        self.assertIn('environment: crates-io-publish', publish)
        self.assertIn('cancel-in-progress: false', workflow)
        self.assertNotIn('secrets.', workflow)
        for ref in re.findall(r'uses: [^@]+@(\S+)', workflow):
            self.assertRegex(ref, r'^[0-9a-f]{40}$')

    def test_cli_init_failure_keeps_safe_report_and_failure_position(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'evidence'
            argv = ['crates_release.py', 'init', '--output', str(out), '--expected-commit', 'bad',
                    '--expected-version', VERSION]
            with patch('sys.argv', argv), patch('crates_release.command', return_value=SHA), \
                    patch.object(gates.GitHub, 'get', return_value={'protected': True}), \
                    patch('sys.stderr', new_callable=io.StringIO) as stderr:
                self.assertEqual(release.main(), 1)
                state = json.loads((out / 'result.json').read_text())
                self.assertEqual(state['failure'], 'init:invalid-sha')
                self.assertNotIn(SECRET, stderr.getvalue())

    def test_cli_unexpected_external_error_never_echoes_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'evidence'
            with patch('sys.argv', ['crates_release.py', 'init', '--output', str(out)]), \
                    patch('crates_release.command', return_value=SHA), \
                    patch.object(gates.GitHub, 'get', side_effect=ValueError(SECRET)), \
                    patch('sys.stderr', new_callable=io.StringIO) as stderr:
                self.assertEqual(release.main(), 1)
                self.assertNotIn(SECRET, stderr.getvalue())
                for file in out.iterdir():
                    self.assertNotIn(SECRET, file.read_text())

    def test_http_errors_never_mean_missing_except_404(self):
        for code in [401, 403, 429, 500, 503, 404]:
            with patch('urllib.request.OpenerDirector.open', side_effect=urllib.error.HTTPError(
                    'https://crates.io', code, SECRET, {}, io.BytesIO(SECRET.encode()))):
                if code == 404:
                    self.assertIsNone(gates.request('https://crates.io', missing=True))
                else:
                    with self.assertRaises(gates.Stop) as raised:
                        gates.request('https://crates.io', missing=True)
                    self.assertNotIn(SECRET, str(raised.exception))
        with patch('urllib.request.OpenerDirector.open', side_effect=OSError(SECRET)):
            with self.assertRaisesRegex(gates.Stop, '^network-error$'):
                gates.request('https://crates.io', missing=True)

    def test_redirect_does_not_forward_github_token(self):
        req = gates.urllib.request.Request('https://api.github.com/a', headers={'Authorization': SECRET})
        redirected = gates.SafeRedirect().redirect_request(req, None, 302, '', {}, 'https://blob.example/a')
        self.assertFalse(redirected.has_header('Authorization'))

    def test_registry_backoff_and_timeout_actual_loop(self):
        backend = object.__new__(release.Production)
        now, sleeps = [0], []

        def sleep(seconds):
            sleeps.append(seconds)
            now[0] += seconds

        with patch.object(backend, 'lookup', side_effect=[None, None, {'checksum': 'x'}]), \
                patch.object(backend, 'verify'), patch.object(backend, 'resolve') as resolve:
            backend.wait(release.ORDER[0], {}, sleep=sleep, clock=lambda: now[0])
            self.assertEqual(sleeps, [5, 10])
            resolve.assert_called_once()
        now[0], sleeps[:] = 0, []
        with patch.object(backend, 'lookup', return_value=None):
            with self.assertRaisesRegex(gates.Stop, 'registry-visibility-timeout'):
                backend.wait(release.ORDER[0], {}, sleep=sleep, clock=lambda: now[0])
            self.assertLess(now[0], 600)
            self.assertLessEqual(max(sleeps), 60)

    def test_cargo_resolution_delay_does_not_skip_resolution(self):
        backend = object.__new__(release.Production)
        with patch.object(backend, 'lookup', return_value={}), patch.object(backend, 'verify'), \
                patch.object(backend, 'resolve', side_effect=[gates.Stop('command-failed'), None]) as resolve:
            backend.wait(release.ORDER[0], {}, sleep=lambda _: None)
            self.assertEqual(resolve.call_count, 2)

    def test_publish_exact_command_and_only_explicit_token(self):
        backend = object.__new__(release.Production)
        backend.env = {'PATH': '/bin'}
        with patch.dict(os.environ, {'CARGO_REGISTRY_TOKEN': SECRET}), patch('crates_release.command') as command:
            backend.publish(release.ORDER[0])
            argv = command.call_args.args[0]
            self.assertEqual(argv, ['cargo', '+1.88.0', 'publish', '--registry', 'crates-io', '--locked', '-p', release.ORDER[0]])
            self.assertNotIn(SECRET, ' '.join(argv))
            self.assertEqual(command.call_args.kwargs['env']['CARGO_REGISTRY_TOKEN'], SECRET)

    def test_command_and_artifact_never_log_output_token(self):
        result = subprocess.CompletedProcess(['cargo'], 1, SECRET.encode(), SECRET.encode())
        with patch('subprocess.run', return_value=result):
            with self.assertRaisesRegex(gates.Stop, '^command-failed$'):
                release.command(['cargo'])
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired(['cargo'], 1, output=SECRET)):
            with self.assertRaisesRegex(gates.Stop, '^command-timeout$'):
                release.command(['cargo'])
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'CARGO_REGISTRY_TOKEN': SECRET}):
            state = release.initial(SHA, VERSION, 'publish', {}, [])
            release.save(state, Path(tmp))
            for file in Path(tmp).iterdir():
                self.assertNotIn(SECRET, file.read_text())
            env = release.clean_env(Path(tmp), Path(tmp))
            self.assertNotIn('CARGO_REGISTRY_TOKEN', env)


if __name__ == '__main__':
    unittest.main()
