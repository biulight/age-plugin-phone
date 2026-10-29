"""Integrity checks for the deliberately public, sanitized P1 evidence archive."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent / "p1"))
from replay_checks import check_network_cycle, check_restart, timestamp


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
                mode = report.get('recipient_mode', 'phone')
                if mode not in ('phone', 'tag') or entry.get('recipient_mode', mode) != mode:
                    raise ValueError('recipient mode evidence mismatch')
                if report.get('result') != 'automated-checks-passed-awaiting-observation':
                    raise ValueError('failed or incomplete attempt accepted')
                if report['case'] == 'wifi-hostile-first':
                    if report.get('invalid_header_sent') is not True or report.get('peer_result') not in ('closed-without-response', 'reset-without-response'):
                        raise ValueError('invalid connection rejection evidence mismatch')
                    continue
                if report.get('adb_reverse_count') != 0:
                    raise ValueError('accepted attempt lacks reverse audit')
                if report['case'] in ('wifi-exact-request-replay', 'wifi-network-cancel-exact-replay', 'wifi-network-cancel-restart-exact-replay'):
                    replays = report.get('replays', [])
                    network = report['case'] != 'wifi-exact-request-replay'
                    original_valid = (report.get('original_exit_code') not in (None, 0) and report.get('original_output_check') == 'no-output') if network else (report.get('original_exit_code') == 0 and report.get('original_output_check') == 'byte-identical')
                    if (not original_valid
                            or (network and not report.get('network_cycle_file'))
                            or len(replays) != 2
                            or {x.get('mode') for x in replays} != {'identical-frame', 'fresh-outer-session-same-signed-request'}
                            or any(x.get('signed_request_byte_identical') is not True
                                   or x.get('expiry_remaining_seconds_at_send', 0) <= 30
                                   or x.get('peer_result') not in ('closed-without-response', 'reset-without-response')
                                   for x in replays)):
                        raise ValueError('accepted replay lacks rejection evidence')
                    if network:
                        cycle = json.loads((root / 'attempts' / report['network_cycle_file']).read_text(encoding='utf-8-sig'))
                        check_network_cycle(cycle, report['started_utc'], report.get('original_finished_utc', report['finished_utc']))
                    if report['case'] == 'wifi-network-cancel-restart-exact-replay':
                        check_restart(report['restart'], report['original_finished_utc'], report['finished_utc'])
                elif report['case'] in ('wifi-background', 'wifi-network', 'wifi-disconnect', 'wifi-cancel', 'wifi-timeout', 'wifi-paused', 'cancel', 'nonmatch-only'):
                    if report.get('exit_code') in (None, 0) or report.get('output_check') != 'no-output':
                        raise ValueError('negative request evidence mismatch')
                    if report['case'] == 'nonmatch-only' and report.get('diagnostic_category') != 'identity-miss':
                        raise ValueError('nonmatching identity evidence mismatch')
                elif report.get('exit_code') != 0 or report.get('output_check') != 'byte-identical':
                    raise ValueError('successful unwrap evidence mismatch')
    expected_attempts = {(r['case'], r.get('started_utc')) for r in attempts if 'phone_observation' in r}
    if seen != set(observations) or seen != expected_attempts:
        raise ValueError('missing or extra acceptance/observation entries')


def check_first_recovery(root, attempts):
    path = root / 'first-discovery-summary.json'
    if not path.exists():
        return
    entries = json.loads(path.read_text())['entries']
    accepted = {e['attempt_file'] for e in json.loads((root / 'accepted-summary.json').read_text())['accepted']}
    if len(entries) != 2 or {e['mode'] for e in entries} != {'idle', 'pending'}:
        raise ValueError('incomplete first discovery coverage')
    def bound(entry, key):
        name = entry[key + '_file']
        if Path(name).name != name or digest(root / 'attempts' / name) != entry[key + '_sha256']:
            raise ValueError('first discovery attempt binding mismatch')
        return json.loads((root / 'attempts' / name).read_text(encoding='utf-8-sig'))
    for entry in entries:
        cycle, recovery = bound(entry, 'cycle'), bound(entry, 'recovery')
        if (entry['recovery_file'] not in accepted or recovery.get('case') != 'wifi-after-network'
                or recovery.get('transport') != 'wifi' or recovery.get('route_mode') != 'authenticated-discovery'
                or recovery.get('exit_code') != 0 or recovery.get('output_check') != 'byte-identical'
                or timestamp(cycle['finished_utc']) > timestamp(recovery['started_utc'])):
            raise ValueError('invalid first discovery recovery')
        if entry['mode'] == 'pending':
            original = bound(entry, 'interrupted')
            if (entry['interrupted_file'] not in accepted or original.get('case') != 'wifi-network'
                    or original.get('exit_code') in (None, 0) or original.get('output_check') != 'no-output'
                    or timestamp(original['finished_utc']) > timestamp(recovery['started_utc'])):
                raise ValueError('invalid interrupted request')
            check_network_cycle(cycle, original['started_utc'], original['finished_utc'])
        else:
            check_network_cycle(cycle, cycle['started_utc'], cycle['finished_utc'])
            if any('phone_observation' in r and timestamp(r['started_utc']) <= timestamp(cycle['started_utc']) < timestamp(r['finished_utc']) for r in attempts):
                raise ValueError('idle cycle overlapped a request')
        # A request begun during the outage can complete after restoration and
        # rearm discovery. Exempt only the exact interrupted request in pending mode.
        exempt = (original['case'], original['started_utc']) if entry['mode'] == 'pending' else None
        if any('phone_observation' in r
               and (r['case'], r['started_utc']) != exempt
               and timestamp(r['started_utc']) < timestamp(recovery['started_utc'])
               and timestamp(r['finished_utc']) >= timestamp(cycle['started_utc'])
               for r in attempts):
            raise ValueError('recovery was not the first request after restoration')


def check_candidate(root):
    path = root / 'candidate-source-binding.json'
    if not path.exists():
        if (root / 'first-discovery-summary.json').exists():
            raise ValueError('missing candidate binding for first discovery campaign')
        return
    if not (root / 'first-discovery-summary.json').is_file():
        raise ValueError('candidate requires first discovery summary')
    binding = json.loads(path.read_text())
    reference = root.parent / 'android-wifi-network-r2-2026-10-24'
    published = root.parent / 'beta2-2026-10-23'
    if root.resolve() in (reference.resolve(), published.resolve()):
        raise ValueError('recursive candidate reference')
    expected_source = 'android-wifi-network-r2-2026-10-24/build/build-source.json'
    if binding.get('archived_build_source') != expected_source:
        raise ValueError('unexpected candidate source reference')
    # Referenced evidence must remain intact, not just agree with a new self-report.
    check(reference)
    check(published)
    source_path = reference / 'build/build-source.json'
    source = json.loads(source_path.read_text())
    if (binding.get('archived_build_source_sha256') != digest(source_path)
            or binding.get('source_inputs_checked') != len(source['source_sha256'])
            or binding.get('all_input_bytes_equal') is not True
            or any(binding.get(k) != [] for k in ('additional_inputs', 'missing_inputs', 'different_inputs'))
            or not re.fullmatch(r'[0-9a-f]{40}', binding.get('main_commit', ''))
            or binding.get('main_ci_result') != 'success'):
        raise ValueError('candidate source binding mismatch')
    signing = json.loads((reference / 'signing.json').read_text(encoding='utf-8-sig'))
    installed = json.loads((reference / 'installation.json').read_text(encoding='utf-8-sig'))
    android = json.loads((root / 'android-preflight.json').read_text(encoding='utf-8-sig'))
    windows = json.loads((root / 'windows-preflight.json').read_text(encoding='utf-8-sig'))
    previous_windows = json.loads((published / 'windows-preflight.json').read_text(encoding='utf-8-sig'))
    previous_android = next(r for r in json.loads((published / 'android-preflight.json').read_text(encoding='utf-8-sig')) if r['artifact'] == 'published')
    if (android.get('result') != 'passed' or android.get('signature_verified') is not True
            or android.get('installation_changed') is not False
            or not android.get('installed_apk_sha256') == binding.get('candidate_apk_sha256') == signing['signed_sha256'] == installed['installed_apk_sha256']
            or not android.get('signer_sha256') == signing['signer_sha256'] == previous_android['signer_sha256']
            or any(android.get(k) != previous_android[k] for k in ('package', 'version', 'version_code'))):
        raise ValueError('candidate Android preflight mismatch')
    if (windows.get('windows_supported') is not True or windows.get('custom_root_chain') != 'Valid'
            or windows.get('authenticode_status') not in ('UnknownError', 'NotTrusted')
            or windows.get('signtool_exit') != 1 or windows.get('trust_error') != 'untrusted-test-root'
            or windows.get('exe_sha256') != binding.get('windows_exe_sha256')
            or any(windows.get(k) != previous_windows[k] for k in ('version', 'commit', 'workflow_run', 'workflow_attempt', 'exe_sha256', 'signer_sha256', 'root_sha256'))):
        raise ValueError('candidate Windows preflight mismatch')
    check_device_followup(root, binding)


def check_device_followup(root, candidate):
    directory = root / 'p2-followup/device'
    links = json.loads((directory / 'request-binding.json').read_text())
    def bound(name):
        path = directory / (name + '.json')
        if digest(path) != links.get(name + '_sha256'):
            raise ValueError('device follow-up record hash mismatch')
        return json.loads(path.read_text(encoding='utf-8-sig'))
    preflight = bound('diagnostic-preflight')
    diagnostic = bound('early-peer-diagnostic')
    cleanup = bound('diagnostic-cleanup')
    if (preflight.get('case') != 'diagnostic-preflight' or preflight.get('result') != 'passed'
            or preflight.get('installation_changed') is not False or preflight.get('adb_reverse_count') != 0
            or preflight.get('installed_apk_sha256') != candidate['candidate_apk_sha256']
            or preflight.get('windows_exe_sha256') != candidate['windows_exe_sha256']):
        raise ValueError('device follow-up preflight mismatch')
    if (diagnostic.get('exit_code') != 0 or diagnostic.get('bounded_wait_expired', False) is not False
            or cleanup.get('result') != 'passed' or cleanup.get('adb_reverse_count') != 0
            or any(cleanup.get(k) is not True for k in ('synthetic_inputs_removed', 'owner_listening_paused', 'owner_controls_normal'))):
        raise ValueError('device follow-up did not finish successfully')
    sources = {digest(p) for p in (root / 'sources').iterdir() if p.is_file()}
    if any(diagnostic.get(k) not in sources for k in ('driver_sha256', 'wrapper_sha256')):
        raise ValueError('device diagnostic source missing')
    entries = links['requests']
    if len(entries) != 2 or len({e['attempt_file'] for e in entries}) != 2:
        raise ValueError('device follow-up requires two distinct requests')
    accepted = {e['attempt_file'] for e in json.loads((root / 'accepted-summary.json').read_text())['accepted']}
    reports = {}
    for entry in entries:
        name = entry['attempt_file']
        if Path(name).name != name or name not in accepted:
            raise ValueError('device follow-up request is not accepted')
        path = root / 'attempts' / name
        if digest(path) != entry['attempt_sha256']:
            raise ValueError('device follow-up request hash mismatch')
        report = json.loads(path.read_text(encoding='utf-8-sig'))
        reports[report['case']] = report
    if set(reports) != {'wifi-network-cancel-restart-exact-replay', 'wifi-after-replay'}:
        raise ValueError('device follow-up request cases mismatch')
    replay = reports['wifi-network-cancel-restart-exact-replay']
    recovery = reports['wifi-after-replay']
    if (replay['driver_sha256'] != diagnostic['driver_sha256']
            or recovery.get('transport') != 'wifi' or recovery.get('route_mode') != 'authenticated-discovery'):
        raise ValueError('device follow-up driver or recovery route mismatch')
    times = [timestamp(r[k]) for r, k in (
        (preflight, 'started_utc'), (preflight, 'finished_utc'), (diagnostic, 'started_utc'),
        (replay, 'started_utc'), (replay, 'finished_utc'), (diagnostic, 'finished_utc'),
        (recovery, 'started_utc'), (recovery, 'finished_utc'), (cleanup, 'started_utc'), (cleanup, 'finished_utc'))]
    if times != sorted(times):
        raise ValueError('device follow-up chronology mismatch')
    # Prevent a stale preflight being attached to an unrelated accepted pair while
    # omitting requests from this recorded preflight-to-cleanup interval.
    covered = set()
    for name in accepted:
        r = json.loads((root / 'attempts' / name).read_text(encoding='utf-8-sig'))
        if times[0] <= timestamp(r['started_utc']) <= times[-1]:
            covered.add(name)
    if covered != {e['attempt_file'] for e in entries}:
        raise ValueError('device follow-up request coverage mismatch')


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
            required.update(report[key] for key in ('driver_sha256', 'replay_checks_sha256', 'restart_helper_sha256') if key in report)
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
    check_first_recovery(root, attempts)
    check_candidate(root)
    return len(listed)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    print(f'P1 evidence integrity passed: {check(args.root)} files')
