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
