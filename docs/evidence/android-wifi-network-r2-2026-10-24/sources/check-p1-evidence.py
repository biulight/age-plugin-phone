"""Integrity checks for the deliberately public, sanitized P1 evidence archive."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(root):
    manifest = json.loads((root / 'manifest.json').read_text())
    listed = set()
    for entry in manifest['files']:
        name = entry['path']
        path = root / name
        if name in listed or Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('invalid archive path')
        if not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
            raise ValueError('archive path escapes root')
        listed.add(name)
        if digest(path) != entry['sha256']:
            raise ValueError('archive hash mismatch: ' + name)
        if path.suffix == '.json':
            value = json.loads(path.read_text(encoding='utf-8-sig'))
            serialized = json.dumps(value)
            for forbidden in ('/Users/', 'C:\\\\Users\\\\', 'AGE-SECRET-KEY-', '-----BEGIN PRIVATE KEY-----'):
                if forbidden in serialized:
                    raise ValueError('private content in JSON evidence')
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and p.name != 'manifest.json'}
    if actual != listed:
        raise ValueError('unlisted or missing archive files')
    coverage = root / 'source-coverage.json'
    available = {digest(p) for p in (root / 'sources').glob('*') if p.is_file()}
    if coverage.exists():
        data = json.loads(coverage.read_text())
        if not set(data['exact_sources_available']) <= available:
            raise ValueError('historical source hash missing')
    attempts = []
    for path in (root / 'attempts').glob('*.json'):
        report = json.loads(path.read_text(encoding='utf-8-sig'))
        attempts.append(report)
        required = set(report.get('provenance', {}).values())
        # New build-bound campaigns require all relay dependencies. Legacy archives
        # also retain excluded exploratory attempts without recoverable driver snapshots.
        if (root / 'build' / 'build-source.json').exists() or 'replay_checks_sha256' in report:
            required.update(report[key] for key in ('driver_sha256', 'replay_checks_sha256') if key in report)
        if not required <= available:
            raise ValueError('attempt source or dependency missing')
        if 'network_cycle_file' in report:
            name = report['network_cycle_file']
            if Path(name).name != name or digest(root / 'attempts' / name) != report['network_cycle_sha256']:
                raise ValueError('network replay cycle binding mismatch')
    followup = root / 'review-followup.json'
    if followup.exists():
        for observation in json.loads(followup.read_text())['observations']:
            matches = [r for r in attempts if (r['case'], r.get('started_utc')) ==
                       (observation['case'], observation['started_utc'])]
            if len(matches) != 1:
                raise ValueError('observation does not bind one exact attempt')
    build = root / 'build' / 'build-source.json'
    if build.exists():
        source = json.loads(build.read_text())
        result = json.loads((build.parent / 'build-result.json').read_text())
        if not all(re.fullmatch(r'[0-9a-f]{40}', source.get(key, '')) for key in ('base_commit', 'base_tree')):
            raise ValueError('missing build baseline')
        if result.get('source_unchanged_during_build') is not True or result['source_record_sha256'] != digest(build):
            raise ValueError('build source binding mismatch')
        for name in source['changed_source_snapshots']:
            if Path(name).is_absolute() or '..' in Path(name).parts:
                raise ValueError('invalid build source path')
            if digest(build.parent / 'delta' / name) != source['source_sha256'][name]:
                raise ValueError('build source snapshot mismatch')
        signing = json.loads((root / 'signing.json').read_text(encoding='utf-8-sig'))
        installation = json.loads((root / 'installation.json').read_text(encoding='utf-8-sig'))
        if (signing.get('result') != 'passed' or signing.get('signature_verified') is not True
                or installation.get('result') != 'passed'
                or result['unsigned_apk_sha256'] != signing['unsigned_sha256']
                or signing['signed_sha256'] != installation['installed_apk_sha256']):
            raise ValueError('build signing installation chain mismatch')
    return len(listed)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    print(f'P1 evidence integrity passed: {check(args.root)} files')
