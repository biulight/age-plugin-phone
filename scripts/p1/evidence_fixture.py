"""Small synthetic archives for checker regression tests; no physical evidence is read."""
import hashlib
import json


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    return path


def seal(root):
    write(root, 'manifest.json', {'files': [
        {'path': p.relative_to(root).as_posix(), 'sha256': digest(p)}
        for p in sorted(root.rglob('*')) if p.is_file() and p.name != 'manifest.json']})


def candidate(parent):
    root = parent / 'synthetic-candidate'
    reference = parent / 'android-wifi-network-r2-2026-10-24'
    published = parent / 'beta2-2026-10-23'
    unsigned, apk, exe, signer = ('c'*64, 'd'*64, 'e'*64, 'f'*64)
    android = dict(artifact='published', package='synthetic.app', version='0.1.0-beta.2',
                   version_code=1000, signer_sha256=signer)
    windows = dict(version='0.1.0-beta.2', commit='a'*40, workflow_run=123, workflow_attempt=1,
                   exe_sha256=exe, signer_sha256=signer, root_sha256='b'*64,
                   windows_supported=True, custom_root_chain='Valid', authenticode_status='UnknownError',
                   signtool_exit=1, trust_error='untrusted-test-root')
    write(published, 'android-preflight.json', [android])
    write(published, 'windows-preflight.json', windows)
    seal(published)
    source = write(reference, 'build/build-source.json', dict(base_commit='a'*40, base_tree='b'*40,
                   changed_source_snapshots=[], source_sha256={'synthetic.kt':'1'*64}))
    write(reference, 'build/build-result.json', dict(source_unchanged_during_build=True,
          source_record_sha256=digest(source), unsigned_apk_sha256=unsigned))
    write(reference, 'signing.json', dict(result='passed', signature_verified=True,
          unsigned_sha256=unsigned, signed_sha256=apk, signer_sha256=signer))
    write(reference, 'installation.json', dict(result='passed', installed_apk_sha256=apk))
    seal(reference)
    write(root, 'candidate-source-binding.json', dict(
        archived_build_source='android-wifi-network-r2-2026-10-24/build/build-source.json',
        archived_build_source_sha256=digest(source), source_inputs_checked=1, all_input_bytes_equal=True,
        additional_inputs=[], missing_inputs=[], different_inputs=[], main_commit='a'*40,
        main_ci_result='success', candidate_apk_sha256=apk, windows_exe_sha256=exe))
    write(root, 'android-preflight.json', dict(android, result='passed', signature_verified=True,
          installation_changed=False, installed_apk_sha256=apk))
    write(root, 'windows-preflight.json', windows)
    (root/'sources').mkdir()
    snapshot=root/'sources/synthetic.py';snapshot.write_text('# synthetic driver, never executed\n')
    sha=digest(snapshot)
    def time(clock): return '2026-10-29T'+clock+'Z'
    def request(case, start, end, success=True):
        return dict(case=case, started_utc=time(start), finished_utc=time(end), phone_observation='pending',
                    result='automated-checks-passed-awaiting-observation', recipient_mode='phone',
                    transport='wifi', route_mode='authenticated-discovery', exit_code=0 if success else 1,
                    output_check='byte-identical' if success else 'no-output', adb_reverse_count=0, driver_sha256=sha)
    def cycle(start, disabled, end):
        return dict(case='wifi-interface-cycle',result='passed', started_utc=time(start),
                    disabled_utc=time(disabled),finished_utc=time(end),disabled_and_ipv4_removed=True,wifi_ipv4_restored=True)
    reports = {
        'idle-cycle.json':cycle('10:01:00','10:01:01','10:01:02'),
        'idle-recovery.json':request('wifi-after-network','10:01:03','10:01:04'),
        'pending-cycle.json':cycle('10:03:01','10:03:02','10:03:03'),
        'interrupted.json':request('wifi-network','10:03:00','10:03:04',False),
        'pending-recovery.json':request('wifi-after-network','10:03:05','10:03:06'),
        'old-recovery.json':request('wifi-after-replay','10:05:00','10:05:01'),
        'replay-cycle.json':cycle('12:44:02','12:44:03','12:44:06'),
        'replay.json':request('wifi-network-cancel-restart-exact-replay','12:44:00','12:44:30',False),
        'wifi-after-replay-new.json':request('wifi-after-replay','12:46:00','12:46:02'),
    }
    for name, report in reports.items():write(root,'attempts/'+name,report)
    replay=reports['replay.json']
    replay.update(original_exit_code=1, original_output_check='no-output', original_finished_utc=time('12:44:20'),
                  network_cycle_file='replay-cycle.json', network_cycle_sha256=digest(root/'attempts/replay-cycle.json'),
                  replay_checks_sha256=sha, restart_helper_sha256=sha,
                  restart=dict(result='passed',package='io.github.biulight.age_plugin_phone',old_process_stopped=True,
                               fresh_process_started=True,started_utc=time('12:44:21'),finished_utc=time('12:44:22')),
                  replays=[dict(mode=m,signed_request_byte_identical=True,expiry_remaining_seconds_at_send=180,
                                peer_result='closed-without-response') for m in ('identical-frame','fresh-outer-session-same-signed-request')])
    write(root,'attempts/replay.json',replay)
    accepted=[];observations=[]
    for name,r in reports.items():
        if 'phone_observation' not in r:continue
        accepted.append(dict(case=r['case'],started_utc=r['started_utc'],attempt_file=name,
                        attempt_sha256=digest(root/'attempts'/name),owner_observation='synthetic observation'))
        observations.append(dict(case=r['case'],started_utc=r['started_utc'],result='passed',observation='synthetic observation'))
    write(root,'accepted-summary.json',dict(status='scoped-physical-regression-passed',accepted=accepted,excluded=[]))
    write(root,'review-followup.json',dict(observations=observations))
    entries=[]
    for mode, names in [('idle',dict(cycle='idle-cycle.json',recovery='idle-recovery.json')),
                        ('pending',dict(cycle='pending-cycle.json',recovery='pending-recovery.json',interrupted='interrupted.json'))]:
        e=dict(mode=mode)
        for key,name in names.items():e.update({key+'_file':name,key+'_sha256':digest(root/'attempts'/name)})
        entries.append(e)
    write(root,'first-discovery-summary.json',dict(entries=entries))
    directory='p2-followup/device/'
    write(root,directory+'diagnostic-preflight.json',dict(case='diagnostic-preflight',result='passed',installation_changed=False,
          adb_reverse_count=0,installed_apk_sha256=apk,windows_exe_sha256=exe,started_utc=time('12:40:00'),finished_utc=time('12:40:01')))
    write(root,directory+'early-peer-diagnostic.json',dict(exit_code=0,driver_sha256=sha,wrapper_sha256=sha,
          started_utc=time('12:43:00'),finished_utc=time('12:45:00')))
    write(root,directory+'diagnostic-cleanup.json',dict(result='passed',adb_reverse_count=0,synthetic_inputs_removed=True,
          owner_listening_paused=True,owner_controls_normal=True,started_utc=time('12:48:00'),finished_utc=time('12:48:01')))
    links={n+'_sha256':digest(root/directory/(n+'.json')) for n in ('diagnostic-preflight','early-peer-diagnostic','diagnostic-cleanup')}
    links['requests']=[dict(attempt_file=n,attempt_sha256=digest(root/'attempts'/n)) for n in ('replay.json','wifi-after-replay-new.json')]
    write(root,directory+'request-binding.json',links)
    seal(root)
    return root
