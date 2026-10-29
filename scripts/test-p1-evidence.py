import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent / "p1"))
from evidence_fixture import candidate as synthetic_candidate

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
            d = copy.deepcopy(base); d['accepted'][0]['recipient_mode'] = 'tag'
            mutations.append(('wrong recipient mode', d, obs, passed))
            for key, value in [('result', 'failed'), ('exit_code', 1), ('output_check', 'no-output'), ('adb_reverse_count', 1)]:
                bad = dict(passed, **{key:value})
                (root / 'attempts' / 'pass.json').write_text(json.dumps(bad))
                d = copy.deepcopy(base); d['accepted'][0]['attempt_sha256'] = checker.digest(root / 'attempts' / 'pass.json')
                mutations.append(('invalid accepted '+key, d, obs, bad))
            for label, summary, observations, report in mutations:
                with self.subTest(label=label), self.assertRaises(ValueError):
                    validate(summary, observations, report)

    def test_network_cycle_time_must_belong_to_accepted_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'attempts').mkdir()
            cycle = dict(case='wifi-interface-cycle', result='passed', disabled_and_ipv4_removed=True, wifi_ipv4_restored=True,
                         started_utc='2026-10-24T00:00:01Z', disabled_utc='2026-10-24T00:00:02Z',
                         finished_utc='2026-10-24T00:00:03Z')
            report = dict(case='wifi-network-cancel-exact-replay', started_utc='2026-10-24T00:00:00Z',
                          finished_utc='2026-10-24T00:00:10Z', phone_observation='pending',
                          result='automated-checks-passed-awaiting-observation', adb_reverse_count=0,
                          original_exit_code=1, original_output_check='no-output', network_cycle_file='cycle.json',
                          replays=[dict(mode=mode, signed_request_byte_identical=True,
                                        expiry_remaining_seconds_at_send=180, peer_result='closed-without-response')
                                   for mode in ['identical-frame', 'fresh-outer-session-same-signed-request']])
            def check(value):
                c = root / 'attempts' / 'cycle.json'; c.write_text(json.dumps(value))
                report['network_cycle_sha256'] = checker.digest(c)
                p = root / 'attempts' / 'replay.json'; p.write_text(json.dumps(report))
                obs = dict(case=report['case'], started_utc=report['started_utc'], result='passed', observation='confirmed')
                entry = dict(case=report['case'], started_utc=report['started_utc'], attempt_file='replay.json',
                             attempt_sha256=checker.digest(p), owner_observation='confirmed')
                (root / 'accepted-summary.json').write_text(json.dumps(dict(status='scoped-physical-regression-passed', accepted=[entry], excluded=[])))
                (root / 'review-followup.json').write_text(json.dumps(dict(observations=[obs])))
                (root / 'manifest.json').write_text(json.dumps({'files': [
                    {'path': p.relative_to(root).as_posix(), 'sha256': checker.digest(p)}
                    for p in root.rglob('*') if p.is_file() and p.name != 'manifest.json']}))
                return checker.check(root)
            check(cycle)
            check(dict(cycle, started_utc='2026-10-24T08:00:01+08:00'))
            for field, value in [('started_utc', '2026-10-23T00:00:01Z'),
                                 ('disabled_utc', '2026-10-24T00:00:00Z'),
                                 ('finished_utc', '2026-10-24T00:00:01Z'),
                                 ('finished_utc', '2026-10-24T00:00:11Z'),
                                 ('started_utc', '2026-10-24T00:00:01'),
                                 ('finished_utc', 'not-a-time')]:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    check(dict(cycle, **{field:value}))

            report['case'] = 'wifi-network-cancel-restart-exact-replay'
            report['original_finished_utc'] = '2026-10-24T00:00:04Z'
            restart = dict(result='passed', package='io.github.biulight.age_plugin_phone',
                           old_process_stopped=True, fresh_process_started=True,
                           started_utc='2026-10-24T00:00:05Z', finished_utc='2026-10-24T00:00:06Z')
            report['restart'] = restart
            check(cycle)
            report['original_finished_utc'] = '2026-10-24T00:00:02Z'
            with self.assertRaises(ValueError): check(cycle)
            report['original_finished_utc'] = '2026-10-24T00:00:04Z'
            for field, value in [('result', 'failed'), ('package', 'another.package'),
                                 ('old_process_stopped', False), ('fresh_process_started', False),
                                 ('started_utc', '2026-10-24T00:00:03Z'),
                                 ('finished_utc', '2026-10-24T00:00:11Z'),
                                 ('started_utc', '2026-10-24T00:00:05')]:
                report['restart'] = dict(restart, **{field:value})
                with self.subTest(restart_field=field, value=value), self.assertRaises(ValueError):
                    check(cycle)

    def test_first_discovery_rejects_intervening_or_direct_requests(self):
        import copy
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'attempts').mkdir()
            def time(second): return f'2026-10-29T00:00:{second:02d}Z'
            def cycle(a, b): return dict(case='wifi-interface-cycle', result='passed', disabled_and_ipv4_removed=True, wifi_ipv4_restored=True, started_utc=time(a), disabled_utc=time(a+1), finished_utc=time(b))
            def request(case, a, b, success=True): return dict(case=case, phone_observation='pending', started_utc=time(a), finished_utc=time(b), transport='wifi', route_mode='authenticated-discovery', exit_code=0 if success else 1, output_check='byte-identical' if success else 'no-output')
            reports = {'idle-cycle.json':cycle(1,3), 'idle-recovery.json':request('wifi-after-network',4,5),
                       'pending-cycle.json':cycle(12,14), 'interrupted.json':request('wifi-network',10,18,False),
                       'pending-recovery.json':request('wifi-after-network',20,22)}
            def check(values):
                for name, value in values.items(): (root/'attempts'/name).write_text(json.dumps(value))
                entries=[]
                for mode, pairs in [('idle', {'cycle':'idle-cycle.json','recovery':'idle-recovery.json'}),
                                    ('pending', {'cycle':'pending-cycle.json','interrupted':'interrupted.json','recovery':'pending-recovery.json'})]:
                    entry={'mode':mode}
                    for key, name in pairs.items(): entry.update({key+'_file':name,key+'_sha256':checker.digest(root/'attempts'/name)})
                    entries.append(entry)
                (root/'first-discovery-summary.json').write_text(json.dumps(dict(entries=entries)))
                (root/'accepted-summary.json').write_text(json.dumps(dict(accepted=[{'attempt_file':n} for n in ('idle-recovery.json','pending-recovery.json','interrupted.json')])))
                checker.check_first_recovery(root, list(values.values()))
            check(reports)
            mutations=[]
            for name, key, value in [('idle-recovery.json','route_mode','explicit-phone-address'), ('pending-recovery.json','exit_code',1),
                                     ('interrupted.json','output_check','byte-identical'), ('pending-cycle.json','started_utc',time(9))]:
                bad=copy.deepcopy(reports);bad[name][key]=value;mutations.append(bad)
            bad=copy.deepcopy(reports);bad['earlier.json']=request('wifi-approve',19,20);mutations.append(bad)
            bad=copy.deepcopy(reports);bad['active.json']=request('wifi-approve',0,2);mutations.append(bad)
            bad=copy.deepcopy(reports);bad['during-idle.json']=request('wifi-approve',2,4);mutations.append(bad)
            bad=copy.deepcopy(reports);bad['during-pending.json']=request('wifi-approve',13,16);mutations.append(bad)
            bad=copy.deepcopy(reports);bad['during-pending.json']=request('wifi-approve',13,19);bad['during-pending.json']['route_mode']='explicit-phone-address';mutations.append(bad)
            for bad in mutations:
                with self.assertRaises(ValueError):check(bad)

    def test_extended_case_semantics_reject_resealed_false_passes(self):
        import copy
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'attempts').mkdir()
            def check(report):
                path=root/'attempts/case.json';path.write_text(json.dumps(report))
                obs=dict(case=report['case'],started_utc=report['started_utc'],result='passed',observation='confirmed')
                entry=dict(case=report['case'],started_utc=report['started_utc'],attempt_file='case.json',attempt_sha256=checker.digest(path),owner_observation='confirmed')
                (root/'review-followup.json').write_text(json.dumps(dict(observations=[obs])))
                (root/'accepted-summary.json').write_text(json.dumps(dict(status='scoped-physical-regression-passed',accepted=[entry],excluded=[])))
                (root/'manifest.json').write_text(json.dumps(dict(files=[{'path':p.relative_to(root).as_posix(),'sha256':checker.digest(p)} for p in root.rglob('*') if p.is_file() and p.name!='manifest.json'])))
                checker.check(root)
            base=dict(started_utc='2026-10-29T00:00:00Z',phone_observation='pending',result='automated-checks-passed-awaiting-observation',adb_reverse_count=0)
            for case in ('wifi-network','wifi-disconnect','wifi-cancel','wifi-timeout','wifi-paused','cancel','nonmatch-only'):
                good=dict(base,case=case,exit_code=1,output_check='no-output',diagnostic_category='identity-miss')
                check(good)
                for key,value in [('exit_code',0),('output_check','byte-identical')]:
                    with self.subTest(case=case,key=key),self.assertRaises(ValueError):check(dict(good,**{key:value}))
            with self.assertRaises(ValueError):check(dict(good,diagnostic_category='other-error'))
            good=dict(base,case='wifi-hostile-first',invalid_header_sent=True,peer_result='closed-without-response')
            check(good)
            for key,value in [('invalid_header_sent',False),('peer_result','timeout')]:
                with self.assertRaises(ValueError):check(dict(good,**{key:value}))
            good=dict(base,case='wifi-exact-request-replay',original_exit_code=0,original_output_check='byte-identical',replays=[dict(mode=mode,signed_request_byte_identical=True,expiry_remaining_seconds_at_send=180,peer_result='closed-without-response') for mode in ('identical-frame','fresh-outer-session-same-signed-request')])
            check(good)
            for key,value in [('original_exit_code',1),('original_output_check','no-output')]:
                with self.assertRaises(ValueError):check(dict(good,**{key:value}))
            bad=copy.deepcopy(good);bad['replays'][0]['peer_result']='response'
            with self.assertRaises(ValueError):check(bad)

    def test_candidate_requires_first_discovery_and_bound_device_preflight(self):
        import copy
        with tempfile.TemporaryDirectory() as directory:
            root = synthetic_candidate(Path(directory))
            device = 'p2-followup/device/'
            originals = {p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob('*.json')}
            def seal():
                (root/'manifest.json').write_text(json.dumps(dict(files=[{'path':p.relative_to(root).as_posix(),'sha256':checker.digest(p)} for p in root.rglob('*') if p.is_file() and p.name!='manifest.json'])))
            def restore():
                for name, value in originals.items(): (root/name).write_bytes(value)
            def write(name, data): (root/name).write_text(json.dumps(data))
            checker.check(root)
            for name in ('first-discovery-summary.json', device+'request-binding.json', device+'diagnostic-preflight.json'):
                with self.subTest(missing=name):
                    (root/name).unlink();seal()
                    with self.assertRaises((ValueError, FileNotFoundError)):checker.check(root)
                    restore()
            cases = {
                'diagnostic-preflight': [('result','failed'),('installed_apk_sha256','0'*64),('windows_exe_sha256','0'*64),('installation_changed',True),('adb_reverse_count',1),('finished_utc','2026-10-29T13:00:00Z'),('started_utc','2026-10-29T00:00:00Z')],
                'early-peer-diagnostic': [('exit_code',1),('bounded_wait_expired',True),('driver_sha256','0'*64),('wrapper_sha256','0'*64),('finished_utc','2026-10-29T12:43:52Z')],
                'diagnostic-cleanup': [('result','failed'),('synthetic_inputs_removed',False),('started_utc','2026-10-29T12:44:00Z')],
            }
            for name, changes in cases.items():
                for key, value in changes:
                    with self.subTest(record=name,field=key):
                        path=device+name+'.json';data=json.loads(originals[path]);data[key]=value;write(path,data)
                        # Refresh both binding and manifest: semantic checks must still reject.
                        links=json.loads(originals[device+'request-binding.json'])
                        links[name+'_sha256']=checker.digest(root/path);write(device+'request-binding.json',links);seal()
                        with self.assertRaises(ValueError):checker.check(root)
                        restore()
            base=json.loads(originals[device+'request-binding.json'])
            variants=[]
            bad=copy.deepcopy(base);bad['requests']=bad['requests'][:1];variants.append(bad)
            bad=copy.deepcopy(base);bad['requests'][1]=bad['requests'][0];variants.append(bad)
            bad=copy.deepcopy(base);bad['requests'][0]['attempt_sha256']='0'*64;variants.append(bad)
            bad=copy.deepcopy(base);bad['diagnostic-preflight_sha256']='0'*64;variants.append(bad)
            # A real accepted request with a correct hash still cannot replace this run's recovery.
            summary=json.loads(originals['accepted-summary.json'])
            old=next(e for e in summary['accepted'] if e['case']=='wifi-after-replay' and e['started_utc']<'2026-10-29T12:00:00Z')
            bad=copy.deepcopy(base)
            recovery=next(i for i,e in enumerate(bad['requests']) if e['attempt_file'].startswith('wifi-after-replay-'))
            bad['requests'][recovery]={k:old[k] for k in ('attempt_file','attempt_sha256')};variants.append(bad)
            for index, bad in enumerate(variants):
                with self.subTest(binding=index):
                    write(device+'request-binding.json',bad);seal()
                    with self.assertRaises(ValueError):checker.check(root)
                    restore()

    def test_candidate_preflight_rejects_resealed_contradictions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = synthetic_candidate(Path(directory))
            originals={n:(root/n).read_bytes() for n in ('android-preflight.json','windows-preflight.json','candidate-source-binding.json')}
            def seal():
                (root/'manifest.json').write_text(json.dumps(dict(files=[{'path':p.relative_to(root).as_posix(),'sha256':checker.digest(p)} for p in sorted(root.rglob('*')) if p.is_file() and p.name!='manifest.json'])))
            checker.check(root)
            cases={
                'android-preflight.json':[('result','failed'),('signature_verified',False),('installed_apk_sha256','0'*64),('signer_sha256','0'*64),('version','0.1.0-beta.1'),('package','another.app')],
                'windows-preflight.json':[('exe_sha256','0'*64),('signer_sha256','0'*64),('root_sha256','0'*64),('custom_root_chain','Invalid'),('windows_supported',False),('signtool_exit',0)],
                'candidate-source-binding.json':[('candidate_apk_sha256','0'*64),('windows_exe_sha256','0'*64),('archived_build_source_sha256','0'*64),('all_input_bytes_equal',False),('different_inputs',['source.kt']),('source_inputs_checked',299),('archived_build_source','../outside')],
            }
            for name, mutations in cases.items():
                for key,value in mutations:
                    data=json.loads(originals[name].decode('utf-8-sig'));data[key]=value
                    (root/name).write_text(json.dumps(data));seal()
                    with self.subTest(file=name,key=key),self.assertRaises(ValueError):checker.check(root)
                    (root/name).write_bytes(originals[name])
            (root/'candidate-source-binding.json').unlink();seal()
            with self.assertRaises(ValueError):checker.check(root)

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
