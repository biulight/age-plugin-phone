"""Integrity checks for the deliberately public, sanitized P1 evidence archive."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_summary(root, attempts):
    summary_path = root / 'accepted-summary.json'
    # Legacy campaigns have no accepted-summary contract.
    if not summary_path.exists():
        if (root / 'build' / 'build-source.json').exists() and (root / 'review-followup.json').exists():
            raise ValueError('missing accepted summary')
        return
    summary = json.loads(summary_path.read_text())
    followup = json.loads((root / 'review-followup.json').read_text())
    observations = {}
    for observation in followup['observations']:
        key = (observation['case'], observation['started_utc'])
        if key in observations:
            raise ValueError('duplicate owner observation')
        observations[key] = observation
    seen = set()
    if summary.get('status') != 'scoped-physical-regression-passed' or not summary.get('accepted'):
        raise ValueError('invalid acceptance status')
    for category, expected in [('accepted', 'passed'), ('excluded', 'excluded')]:
        for entry in summary[category]:
            key = (entry['case'], entry['started_utc'])
            name = entry['attempt_file']
            if key in seen or Path(name).name != name:
                raise ValueError('duplicate or invalid summary attempt')
            seen.add(key)
            path = root / 'attempts' / name
            report = json.loads(path.read_text(encoding='utf-8-sig'))
            observation = observations.get(key)
            if (digest(path) != entry['attempt_sha256']
                    or (report['case'], report.get('started_utc')) != key
                    or observation is None or observation.get('result') != expected
                    or entry['owner_observation'] != observation.get('observation')):
                raise ValueError('summary report or observation mismatch')
            if category == 'accepted':
                if report.get('result') != 'automated-checks-passed-awaiting-observation':
                    raise ValueError('failed or incomplete attempt accepted')
                if report.get('adb_reverse_count') != 0:
                    raise ValueError('accepted attempt lacks reverse audit')
                if report['case'] == 'wifi-network-cancel-exact-replay':
                    replays = report.get('replays', [])
                    if (report.get('original_exit_code') in (None, 0)
                            or report.get('original_output_check') != 'no-output'
                            or not report.get('network_cycle_file')
                            or len(replays) != 2
                            or {x.get('mode') for x in replays} != {'identical-frame', 'fresh-outer-session-same-signed-request'}
                            or any(x.get('signed_request_byte_identical') is not True
                                   or x.get('expiry_remaining_seconds_at_send', 0) <= 30
                                   or x.get('peer_result') not in ('closed-without-response', 'reset-without-response')
                                   for x in replays)):
                        raise ValueError('accepted replay lacks rejection evidence')
                    cycle = json.loads((root / 'attempts' / report['network_cycle_file']).read_text(encoding='utf-8-sig'))
                    if (cycle.get('result') != 'passed' or cycle.get('disabled_and_ipv4_removed') is not True
                            or cycle.get('wifi_ipv4_restored') is not True):
                        raise ValueError('accepted replay lacks successful network cycle')
                elif report['case'] == 'wifi-background':
                    if report.get('exit_code') in (None, 0) or report.get('output_check') != 'no-output':
                        raise ValueError('background cancellation evidence mismatch')
                elif report.get('exit_code') != 0 or report.get('output_check') != 'byte-identical':
                    raise ValueError('successful unwrap evidence mismatch')
    expected_attempts = {(r['case'], r.get('started_utc')) for r in attempts if 'phone_observation' in r}
    if seen != set(observations) or seen != expected_attempts:
        raise ValueError('missing or extra acceptance/observation entries')


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
    check_summary(root, attempts)
    return len(listed)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    print(f'P1 evidence integrity passed: {check(args.root)} files')
