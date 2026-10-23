import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location('checker', Path(__file__).with_name('check-p1-evidence.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class EvidenceTests(unittest.TestCase):
    def test_missing_attempt_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'attempts').mkdir()
            report = root / 'attempts' / 'case.json'
            report.write_text(json.dumps({'case': 'synthetic', 'provenance': {'driver_sha256': '0'*64}}))
            (root / 'manifest.json').write_text(json.dumps({'files': [{'path': 'attempts/case.json', 'sha256': checker.digest(report)}]}))
            with self.assertRaises(ValueError): checker.check(root)

    def test_build_chain_rejects_rehashed_wrong_baseline_snapshot_and_apk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / 'build'
            (build / 'delta').mkdir(parents=True)
            snapshot = build / 'delta' / 'source.kt'
            snapshot.write_text('synthetic source')
            source = dict(base_commit='a'*40, base_tree='b'*40,
                          changed_source_snapshots=['source.kt'], source_sha256={'source.kt': checker.digest(snapshot)})
            source_path = build / 'build-source.json'
            result_path = build / 'build-result.json'
            signing = dict(result='passed', signature_verified=True, unsigned_sha256='c'*64, signed_sha256='d'*64)
            (root / 'signing.json').write_text(json.dumps(signing))
            (root / 'installation.json').write_text(json.dumps(dict(result='passed', installed_apk_sha256='d'*64)))
            def seal():
                source_path.write_text(json.dumps(source))
                result_path.write_text(json.dumps(dict(source_unchanged_during_build=True,
                    source_record_sha256=checker.digest(source_path), unsigned_apk_sha256='c'*64)))
                (root / 'manifest.json').write_text(json.dumps({'files': [
                    {'path': p.relative_to(root).as_posix(), 'sha256': checker.digest(p)}
                    for p in root.rglob('*') if p.is_file() and p.name != 'manifest.json']}))
            seal()
            checker.check(root)
            source['base_commit'] = ''
            seal()
            with self.assertRaises(ValueError): checker.check(root)
            source['base_commit'] = 'a'*40
            snapshot.write_text('changed source')
            seal()
            with self.assertRaises(ValueError): checker.check(root)
            snapshot.write_text('synthetic source')
            signing['signed_sha256'] = 'e'*64
            (root / 'signing.json').write_text(json.dumps(signing))
            seal()
            with self.assertRaises(ValueError): checker.check(root)

    def test_summary_cross_checks_even_after_manifest_is_resealed(self):
        import copy
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'attempts').mkdir()
            passed = dict(case='wifi-approve', started_utc='2026-10-24T00:00:00Z',
                          result='automated-checks-passed-awaiting-observation', phone_observation='pending',
                          exit_code=0, output_check='byte-identical', adb_reverse_count=0)
            failed = dict(case='wifi-background', started_utc='2026-10-24T00:01:00Z',
                          result='failed', phone_observation='pending', exit_code=1, output_check='no-output')
            obs = [dict(case=r['case'], started_utc=r['started_utc'], result=status, observation=status)
                   for r, status in [(passed, 'passed'), (failed, 'excluded')]]
            for name, r in [('pass.json', passed), ('fail.json', failed)]:
                (root / 'attempts' / name).write_text(json.dumps(r))
            def entry(name, r, status):
                return dict(case=r['case'], started_utc=r['started_utc'], attempt_file=name,
                            attempt_sha256=checker.digest(root / 'attempts' / name), owner_observation=status)
            base = dict(status='scoped-physical-regression-passed',
                        accepted=[entry('pass.json', passed, 'passed')],
                        excluded=[entry('fail.json', failed, 'excluded')])
            def validate(summary, observations, report=passed):
                (root / 'attempts' / 'pass.json').write_text(json.dumps(report))
                (root / 'accepted-summary.json').write_text(json.dumps(summary))
                (root / 'review-followup.json').write_text(json.dumps(dict(observations=observations)))
                (root / 'manifest.json').write_text(json.dumps({'files': [
                    {'path': p.relative_to(root).as_posix(), 'sha256': checker.digest(p)}
                    for p in root.rglob('*') if p.is_file() and p.name != 'manifest.json']}))
                return checker.check(root)
            validate(base, obs)
            mutations = []
            d = copy.deepcopy(base); d['accepted'][0]['attempt_sha256'] = '0'*64
            mutations.append(('wrong hash', d, obs, passed))
            d = copy.deepcopy(base); d['accepted'] += d['excluded']; d['excluded'] = []
            mutations.append(('promoted exclusion', d, obs, passed))
            mutations.append(('missing observations', base, [], passed))
            mutations.append(('duplicate observations', base, obs + [obs[0]], passed))
            d = copy.deepcopy(base); d['accepted'] *= 2
            mutations.append(('duplicate acceptance', d, obs, passed))
            d = copy.deepcopy(base); d['excluded'] = []
            mutations.append(('missing exclusion', d, obs[:1], passed))
            d = copy.deepcopy(base); d['accepted'][0]['owner_observation'] = 'invented'
            mutations.append(('mismatched observation', d, obs, passed))
            for key, value in [('result', 'failed'), ('exit_code', 1), ('output_check', 'no-output'), ('adb_reverse_count', 1)]:
                bad = dict(passed, **{key:value})
                (root / 'attempts' / 'pass.json').write_text(json.dumps(bad))
                d = copy.deepcopy(base); d['accepted'][0]['attempt_sha256'] = checker.digest(root / 'attempts' / 'pass.json')
                mutations.append(('invalid accepted '+key, d, obs, bad))
            for label, summary, observations, report in mutations:
                with self.subTest(label=label), self.assertRaises(ValueError):
                    validate(summary, observations, report)

    def test_valid_then_tampered_and_unlisted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / 'report.json'
            report.write_text('{"result":"passed"}')
            (root / 'manifest.json').write_text(json.dumps({'files': [{'path': 'report.json', 'sha256': checker.digest(report)}]}))
            self.assertEqual(checker.check(root), 1)
            extra = root / 'unlisted.json'
            extra.write_text('{}')
            with self.assertRaises(ValueError): checker.check(root)
            extra.unlink()
            report.write_text('{"result":"failed"}')
            with self.assertRaises(ValueError): checker.check(root)

    def test_traversal_and_private_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps({'files': [{'path': '../outside', 'sha256': '0'*64}]}))
            with self.assertRaises(ValueError): checker.check(root)
            report = root / 'report.json'
            report.write_text(json.dumps({'private': '/Users/synthetic/private-state'}))
            manifest.write_text(json.dumps({'files': [{'path': 'report.json', 'sha256': checker.digest(report)}]}))
            with self.assertRaises(ValueError): checker.check(root)


if __name__ == '__main__': unittest.main()
