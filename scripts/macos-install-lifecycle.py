#!/usr/bin/env python3
"""Verify a completed local registry rehearsal's binary install lifecycle on synthetic Mac state.

Requires Python 3.11+, a completed registry-preflight.py output outside the repository,
and the explicitly built macos-install-acceptance example. Never installs globally,
publishes a crate, resets replay, or processes real phone pairing material.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tomllib


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root):
    result = {}
    for path in sorted(root.iterdir()):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('unexpected synthetic fixture entry')
        result[path.name] = {'sha256': sha(path), 'mode': path.stat().st_mode & 0o7777}
    return result


def run(args, env, cwd, log, expected=None):
    result = subprocess.run(list(map(str, args)), env=env, cwd=cwd, capture_output=True)
    log.write_bytes(result.stdout + result.stderr)
    if result.returncode != 0:
        raise RuntimeError(f'acceptance command failed; inspect {log}')
    if expected is not None and result.stdout.strip() != expected:
        raise RuntimeError('acceptance helper did not verify the fixture')
    return result


def verify_installed(binary, fixture, env):
    suffix = 'a5' * 16
    result = subprocess.run([
        str(binary), 'unwrap', '--identity-stub', str(fixture / f'identity-{suffix}.txt'),
        '--desktop-state', str(fixture / f'desktop-{suffix}.state'),
        '--replay-state', str(fixture / f'replay-{suffix}.state'),
        '--stanza-arg', 'synthetic-invalid', '--stanza-body', '!', '--transport', 'qr',
    ], env=dict(env, AGE_PLUGIN_PHONE_CONFIG_DIR=str(fixture)), capture_output=True)
    # This diagnostic is emitted only AFTER locator/both hardware roles open, and BEFORE
    # creating a signed request or opening a camera. No phone or approval is involved.
    if result.returncode == 0 or result.stdout or b'malformed stanza body' not in result.stderr:
        raise RuntimeError('installed binary did not reopen the synthetic hardware state')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registry-output', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != 'Darwin':
        raise RuntimeError('real macOS hardware is required; no skip is a pass')
    out = args.registry_output.resolve(strict=True)
    helper = args.helper.resolve(strict=True)
    fixture = args.fixture.absolute()
    if fixture.exists() or fixture.is_symlink():
        raise RuntimeError('fixture must be a new isolated path')
    evidence = json.loads((out / 'archive-evidence.json').read_text())
    if set(evidence) != {'age-plugin-phone', 'age-plugin-phone-core',
                         'age-plugin-phone-platform-keys', 'age-plugin-phone-platform-storage'}:
        raise RuntimeError('not a completed four-crate registry rehearsal')
    version = tomllib.loads((out / 'work/Cargo.toml').read_text())['workspace']['package']['version']
    install = out / 'install'
    binary = install / 'bin/age-plugin-phone'
    logs = out / 'install-lifecycle-logs'
    logs.mkdir(exist_ok=False)
    env = dict(os.environ, CARGO_HOME=str(out / 'cargo-home'), RUSTC_WRAPPER='',
               CARGO_TARGET_DIR=str(out / 'install-lifecycle-target'))
    for key in list(env):
        if key.startswith(('CARGO_REGISTRIES_', 'CARGO_SOURCE_')):
            del env[key]
    env.pop('CARGO_ENCODED_RUSTFLAGS', None)
    env.pop('RUSTFLAGS', None)
    run([helper, 'seed', fixture], env, out, logs / 'seed.log', b'synthetic_fixture_seeded')
    original_state = snapshot(fixture)
    original_binary = sha(binary)
    reports = []

    def verify(phase):
        verify_installed(binary, fixture, env)
        run([helper, 'verify', fixture], env, out, logs / f'{phase}.log', b'hardware_reopened_replay_rejected')
        if snapshot(fixture) != original_state:
            raise RuntimeError('installation or verification modified pairing/replay state')
        reports.append({'phase': phase, 'binary_sha256': sha(binary), 'state_unchanged': True,
                        'hardware_reopened': True, 'consumed_response_rejected': True})
        print(f'{phase}: passed', flush=True)

    verify('initial_install')
    cargo = ['cargo', '+1.88.0']
    install_args = cargo + ['install', '--registry', 'preflight', 'age-plugin-phone',
                            '--version', '=' + version, '--locked', '--offline', '--root', str(install)]
    # A different optimization setting produces an independent binary hash while retaining the
    # exact source version. This is rebuild/overwrite evidence, not a released-version upgrade.
    run(install_args + ['--force'], dict(env, RUSTFLAGS='-C opt-level=2'), out, logs / 'overwrite-build.log')
    if sha(binary) == original_binary:
        raise RuntimeError('independent build did not change the binary hash')
    verify('force_rebuild')
    run(cargo + ['uninstall', '--root', install, 'age-plugin-phone'], env, out, logs / 'uninstall.log')
    if binary.exists() or snapshot(fixture) != original_state:
        raise RuntimeError('uninstall failed to preserve exactly the synthetic state')
    reports.append({'phase': 'uninstall', 'binary_removed': True, 'state_unchanged': True})
    print('uninstall: passed', flush=True)
    run(install_args, env, out, logs / 'reinstall-build.log')
    verify('reinstall')
    report = {
        'schema_version': 1, 'source_version': version,
        'architecture': platform.machine(), 'macos': platform.mac_ver()[0],
        'fixture_kind': 'synthetic_only_no_phone', 'helper_sha256': sha(helper),
        'registry_evidence_sha256': sha(out / 'archive-evidence.json'),
        'state': original_state, 'phases': reports,
        'released_version_upgrade': 'not_tested', 'real_phone_and_caller_matrix': 'not_tested',
    }
    (out / 'macos-install-evidence.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
