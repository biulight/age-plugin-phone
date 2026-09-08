#!/usr/bin/env python3
"""Fail-closed, serial crates.io publication. No automatic upload retries.

The production adapter is deliberately separate from the fixture-driven state
machine. subprocess output and exception text are never persisted or printed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib

sys.dont_write_bytecode = True

from gates import GitHub, Stop, candidate_gate, ci_gate, prior_publications, request, require

ORDER = ['age-plugin-phone-platform-storage', 'age-plugin-phone-core',
         'age-plugin-phone-platform-keys', 'age-plugin-phone']
DIRECTORIES = ['platform-storage', 'core', 'platform-keys', 'desktop']
ROOT = Path(__file__).resolve().parents[2]
CARGO = ['cargo', '+1.88.0']


def digest(data):
    return hashlib.sha256(data).hexdigest()


def clean_env(home, target):
    # Keep toolchain/OS essentials, never arbitrary registry, wrapper or token variables.
    env = {key: os.environ[key] for key in ['PATH', 'HOME', 'RUSTUP_HOME', 'TMPDIR',
                                           'SystemRoot', 'USERPROFILE'] if key in os.environ}
    return dict(env, CARGO_HOME=str(home), CARGO_TARGET_DIR=str(target), RUSTC_WRAPPER='',
                CARGO_NET_RETRY='0', CARGO_HTTP_TIMEOUT='30', CARGO_TERM_COLOR='never')


def command(args, cwd=ROOT, env=None, timeout=1200):
    try:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise Stop('command-timeout') from None
    require(result.returncode == 0, 'command-failed')
    return result.stdout.decode()


def save(state, out):
    out.mkdir(parents=True, exist_ok=True)
    temporary = out / 'result.tmp'
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.replace(out / 'result.json')
    lines = [f"Candidate: `{state['sha']}` / `{state['version']}`", '',
             '| Package | Production SHA-256 | Dry-run | Upload | Registry visible |',
             '| --- | --- | --- | --- | --- |']
    for name in ORDER:
        p = state['packages'][name]
        lines.append(f"| {name} | {p.get('sha256', 'pending')} | {p['dry_run']} | {p['upload']} | {p['visible']} |")
    lines += ['', 'Failure: ' + str(state.get('failure')), 'Post-install checks: ' + state['smoke']]
    (out / 'summary.md').write_text('\n'.join(lines) + '\n')


def initial(sha, version, mode, ci, previous):
    previous = [{k: item[k] for k in ['sha', 'version', 'order', 'packages']}
                for item in previous if any(p['upload'] != 'not-attempted' for p in item['packages'].values())]
    for item in previous:
        require(item['sha'] == sha and item['version'] == version and item['order'] == ORDER,
                'recovery-candidate-mismatch')
    return dict(schema=1, sha=sha, version=version, mode=mode, ci=ci, order=ORDER,
                packages={n: dict(dry_run='pending', upload='not-attempted', visible='pending') for n in ORDER},
                previous=previous, failure=None, smoke='pending')


class Release:
    def __init__(self, state, backend, persist):
        self.s, self.b, self.persist = state, backend, persist

    def check_order(self, name):
        require(name in ORDER, 'non-publishable-package')
        require(all(self.s['packages'][n]['visible'] == 'verified' for n in ORDER[:ORDER.index(name)]),
                'wrong-publish-order')

    def prepare(self, name):
        self.check_order(name)
        p = self.s['packages'][name]
        require(p['upload'] == 'not-attempted', 'duplicate-prepare')
        existing = self.b.lookup(name)
        prior = [s['packages'][name] for s in self.s['previous']
                 if s['packages'][name]['upload'] != 'not-attempted']
        # Intent persisted before authentication/upload is deliberately uncertain
        # even if a runner dies before issuing the HTTP request.
        require(existing is not None or not prior, 'uncertain-prior-upload-manual-review')
        p['dry_run'] = 'running'
        self.persist()
        archive = self.b.dry_run(name)
        p.update(archive, dry_run='passed')
        if existing is not None:
            require(bool(prior), 'existing-version-without-evidence')
            require(all(x.get('sha256') == p['sha256'] and x.get('files') == p['files'] for x in prior),
                    'existing-version-evidence-mismatch')
            self.b.verify(name, existing, p)
            self.b.wait(name, p)
            p.update(upload='reused-verified', visible='verified')
        else:
            p['upload'] = 'armed'
        self.persist()
        return p['upload'] == 'armed'

    def upload(self, name):
        self.check_order(name)
        p = self.s['packages'][name]
        require(p['upload'] == 'armed' and p['dry_run'] == 'passed', 'duplicate-or-unprepared-upload')
        # Recheck the registry after authentication. No racing upload.
        require(self.b.lookup(name) is None, 'version-appeared-before-upload')
        self.b.check_archive(name, p)
        p['upload'] = 'attempted'
        self.persist()
        try:
            self.b.publish(name)
        except Stop as error:
            p['upload'] = 'uncertain'
            p['upload_error'] = str(error)
            self.persist()
            # A timeout/error may have accepted the upload. Inspect; never retry.
            self.b.wait(name, p)
            p.update(upload='verified-after-error', visible='verified')
            self.persist()
            # Stop the chain even when reconciled; a deliberate rerun can resume.
            raise Stop('upload-error-reconciled-stop') from error
        self.b.check_archive(name, p)
        p['upload'] = 'accepted'
        self.persist()
        self.b.wait(name, p)
        p['visible'] = 'verified'
        self.persist()


class Production:
    def __init__(self, state, work):
        self.s, self.work = state, work
        work.mkdir(parents=True, exist_ok=True)
        self.env = clean_env(work / 'cargo-home', work / 'target')
        # Cargo also walks ancestors of cwd for configuration; fail closed.
        for parent in [ROOT, *ROOT.parents, work, *work.parents]:
            require(not any((parent / '.cargo' / n).exists() for n in ['config', 'config.toml']),
                    'cargo-configuration-override')
        require(not any((work / 'cargo-home' / n).exists() for n in ['config', 'config.toml', 'credentials', 'credentials.toml']),
                'cargo-home-override')

    def archive(self, name):
        return self.work / 'target/package' / f"{name}-{self.s['version']}.crate"

    def lookup(self, name):
        data = request(f"https://crates.io/api/v1/crates/{name}/{self.s['version']}", missing=True)
        if data is None:
            return None
        version = json.loads(data)['version']
        require(version['crate'] == name and version['num'] == self.s['version'] and not version['yanked'],
                'registry-version-mismatch-or-yanked')
        return version

    def inventory(self, blob, name):
        import io
        files = {}
        prefix = f"{name}-{self.s['version']}/"
        with tarfile.open(fileobj=io.BytesIO(blob)) as archive:
            for member in archive.getmembers():
                require(member.name.startswith(prefix) and '..' not in Path(member.name).parts
                        and (member.isfile() or member.isdir()), 'invalid-archive')
                if member.isfile():
                    key = member.name[len(prefix):]
                    require(key not in files, 'duplicate-archive-file')
                    files[key] = digest(archive.extractfile(member).read())
            vcs = json.load(archive.extractfile(prefix + '.cargo_vcs_info.json'))
            require(vcs['git']['sha1'] == self.s['sha'] and not vcs['git'].get('dirty', False),
                    'archive-source-sha')
            manifest = tomllib.loads(archive.extractfile(prefix + 'Cargo.toml').read().decode())
            require(manifest['package']['name'] == name and manifest['package']['version'] == self.s['version']
                    and manifest['package']['publish'] == ['crates-io'], 'archive-production-manifest')
            for table in [manifest, *manifest.get('target', {}).values()]:
                for kind in ['dependencies', 'dev-dependencies', 'build-dependencies']:
                    for dep, spec in table.get(kind, {}).items():
                        require(not any(k in spec for k in ['path', 'git', 'registry', 'registry-index']),
                                'archive-nonproduction-dependency')
                        if dep in ORDER:
                            require(spec['version'] == '=' + self.s['version'], 'archive-internal-version')
            directory = ROOT / 'crates' / DIRECTORIES[ORDER.index(name)]
            require(files['Cargo.toml.orig'] == digest((directory / 'Cargo.toml').read_bytes()),
                    'archive-original-manifest')
            for path, checksum in files.items():
                if path not in {'Cargo.toml', 'Cargo.toml.orig', 'Cargo.lock', '.cargo_vcs_info.json'}:
                    require(checksum == digest((directory / path).read_bytes()), 'archive-source-content')
        return files

    def dry_run(self, name):
        command(CARGO + ['publish', '--registry', 'crates-io', '--locked', '-p', name, '--dry-run'], env=self.env)
        blob = self.archive(name).read_bytes()
        return dict(sha256=digest(blob), files=self.inventory(blob, name))

    def check_archive(self, name, expected):
        require(digest(self.archive(name).read_bytes()) == expected['sha256'], 'local-archive-changed')

    def verify(self, name, version, expected):
        require(version['checksum'] == expected['sha256'], 'registry-checksum-mismatch')
        blob = request(f"https://static.crates.io/crates/{name}/{name}-{self.s['version']}.crate")
        require(digest(blob) == expected['sha256'] and self.inventory(blob, name) == expected['files'],
                'registry-content-mismatch')

    def resolve(self, name):
        # Fresh cache each attempt ensures Cargo really resolves crates.io now.
        with tempfile.TemporaryDirectory(dir=self.work) as tmp:
            path = Path(tmp)
            (path / 'src').mkdir()
            (path / 'src/lib.rs').write_text('')
            (path / 'Cargo.toml').write_text('[package]\nname="release-resolution-probe"\nversion="0.0.0"\nedition="2024"\n'
                                           f'[dependencies]\n{name}={{version="={self.s["version"]}", registry="crates-io"}}\n')
            env = clean_env(path / 'home', path / 'target')
            # New consumer has no lock yet; generate once, then validate locked metadata.
            command(CARGO + ['generate-lockfile'], path, env, timeout=60)
            metadata = json.loads(command(CARGO + ['metadata', '--locked', '--format-version', '1'], path, env, timeout=60))
            require(any(p['name'] == name and p['version'] == self.s['version']
                        and p['source'] == 'registry+https://github.com/rust-lang/crates.io-index'
                        for p in metadata['packages']), 'cargo-registry-source')

    def wait(self, name, expected, sleep=time.sleep, clock=time.monotonic):
        deadline, delay = clock() + 600, 5
        while True:
            version = self.lookup(name)  # Non-404 errors stop, never imply absence.
            if version is not None:
                self.verify(name, version, expected)
                try:
                    self.resolve(name)
                    return
                except Stop as error:
                    if str(error) not in {'command-failed', 'command-timeout'}:
                        raise
            require(clock() + delay < deadline, 'registry-visibility-timeout')
            sleep(delay)
            delay = min(delay * 2, 60)

    def publish(self, name):
        token = os.environ.get('CARGO_REGISTRY_TOKEN')
        require(bool(token), 'publishing-token-missing')
        command(CARGO + ['publish', '--registry', 'crates-io', '--locked', '-p', name],
                env=dict(self.env, CARGO_REGISTRY_TOKEN=token))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['init', 'prepare', 'upload', 'preflight', 'smoke', 'summary'])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--package', choices=ORDER)
    parser.add_argument('--expected-commit')
    parser.add_argument('--expected-version')
    parser.add_argument('--mode', choices=['preflight', 'publish'], default='preflight')
    parser.add_argument('--recovery-run-id', default='')
    args = parser.parse_args()
    out = args.output.resolve()
    state = None
    stage = args.operation + (':' + args.package if args.package else '')
    try:
        if args.operation == 'init':
            require(not out.exists(), 'output-already-exists')
            version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
            # Initialize a safe report before gates, even if input is malicious.
            state = initial(command(['git', 'rev-parse', 'HEAD']).strip(), version, args.mode, None, [])
            save(state, out)
            api = GitHub()
            context = {k: os.environ.get(v, '') for k, v in dict(sha='GITHUB_SHA', repository='GITHUB_REPOSITORY',
                       event='GITHUB_EVENT_NAME', ref='GITHUB_REF').items()}
            candidate_gate(args.expected_commit or '', state['sha'], version, args.expected_version,
                           context, api.get('/branches/main')['protected'])
            require(os.environ.get('GITHUB_RUN_ATTEMPT', '1') == '1', 'use-new-dispatch-for-recovery')
            require(not command(['git', 'status', '--porcelain']).strip(), 'dirty-checkout')
            command(['bash', 'scripts/check-release-version.sh', version])
            command([sys.executable, 'scripts/check-package-layout.py'])
            state['ci'] = ci_gate(api, state['sha'])
            previous = prior_publications(api, version, args.recovery_run_id) if args.mode == 'publish' else []
            state = initial(state['sha'], version, args.mode, state['ci'], previous)
        else:
            state = json.loads((out / 'result.json').read_text())
            require(state['order'] == ORDER, 'state-order-mismatch')
            if args.operation == 'summary':
                if os.environ.get('RELEASE_JOB_STATUS', 'success') != 'success' and not state['failure']:
                    phase = os.environ.get('RELEASE_EXTERNAL_FAILURE') or 'external-workflow-step'
                    state['failure'] = phase
                save(state, out)
                summary = os.environ.get('GITHUB_STEP_SUMMARY')
                if summary:
                    with open(summary, 'a') as file:
                        file.write((out / 'summary.md').read_text())
                return
            require(command(['git', 'rev-parse', 'HEAD']).strip() == state['sha'], 'checkout-changed')
            require(not command(['git', 'status', '--porcelain']).strip(), 'dirty-checkout')
            require(state['ci'] is not None, 'missing-ci-gate')
            backend = Production(state, out.parent / (out.name + '-work'))
            release = Release(state, backend, lambda: save(state, out))
            if args.operation in ['prepare', 'upload']:
                require(state['mode'] == 'publish' and args.package is not None, 'publish-mode-required')
                if args.operation == 'prepare':
                    needed = release.prepare(args.package)
                    if os.environ.get('GITHUB_OUTPUT'):
                        with open(os.environ['GITHUB_OUTPUT'], 'a') as file:
                            file.write('upload=' + str(needed).lower() + '\n')
                else:
                    release.upload(args.package)
            elif args.operation == 'preflight':
                require(state['mode'] == 'preflight', 'preflight-mode-required')
                for name in ORDER:
                    p = state['packages'][name]
                    if any(backend.lookup(n) is None for n in ORDER[:ORDER.index(name)]):
                        p['dry_run'] = 'blocked-unpublished-dependency'
                    else:
                        for n in ORDER[:ORDER.index(name)]:
                            backend.resolve(n)
                        p['dry_run'] = 'running'
                        save(state, out)
                        p.update(backend.dry_run(name), dry_run='passed')
                    save(state, out)
            elif args.operation == 'smoke':
                require(all(p['visible'] == 'verified' for p in state['packages'].values()), 'incomplete-chain')
                from smoke import smoke
                state['smoke'] = 'running'
                save(state, out)
                smoke(state['version'], backend.work, command, clean_env)
                state['smoke'] = 'passed'
        state['failure'] = None
        save(state, out)
    except Exception as error:
        # Never log external error bodies, command output, env or tracebacks.
        code = str(error) if isinstance(error, Stop) else 'unexpected-' + type(error).__name__
        if state is not None:
            state['failure'] = stage + ':' + code
            save(state, out)
        print('Release stopped: ' + stage + ':' + code, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
