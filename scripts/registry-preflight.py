#!/usr/bin/env python3
"""Cargo 1.88 alternate-registry rehearsal; never uploads to crates.io.

Requires Python 3.11+. All rewritten manifests, configuration and archives stay
under --output (which must not exist). Run --minimal before migrating packages.
"""
import argparse
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import threading
import tomllib


def run(args, cwd, env):
    print('+', ' '.join(map(str, args)), flush=True)
    subprocess.run(args, cwd=cwd, env=env, check=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--minimal', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    registry = out / 'registry'
    registry.mkdir()
    server = http.server.ThreadingHTTPServer(
        ('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(registry)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{server.server_port}'
    index = f'sparse+{url}/index/'
    (registry / 'index').mkdir()
    (registry / 'index/config.json').write_text(json.dumps({'dl': url + '/crates/{crate}/{version}/download'}))
    home = out / 'cargo-home'
    home.mkdir()
    (home / 'config.toml').write_text(f'[registries.preflight]\nindex = "{index}"\n')
    env = dict(os.environ, CARGO_HOME=str(home), RUSTC_WRAPPER='', CARGO_TARGET_DIR=str(out / 'target'))
    # Do not inherit caller registry/source overrides.
    for key in list(env):
        if key.startswith(('CARGO_REGISTRIES_', 'CARGO_SOURCE_')):
            del env[key]
    cargo = ['cargo', '+1.88.0']
    run(cargo + ['--version'], out, env)
    work = out / 'work'
    if args.minimal:
        work.mkdir()
        names = ['phone-preflight-storage', 'phone-preflight-core']
        (work / 'Cargo.toml').write_text('[workspace]\nmembers = ["storage", "core"]\nresolver = "2"\n')
        packages = []
        for i, directory in enumerate(['storage', 'core']):
            package = work / directory
            (package / 'src').mkdir(parents=True)
            dep = '' if i == 0 else f'\n[dependencies]\n{names[0]} = {{ path = "../storage", version = "=0.1.0-alpha.4", registry = "preflight" }}\n'
            (package / 'Cargo.toml').write_text(f'[package]\nname = "{names[i]}"\nversion = "0.1.0-alpha.4"\nedition = "2024"\npublish = ["preflight"]\n' + dep)
            (package / 'src/lib.rs').write_text('pub fn value() -> u8 { ' + ('7' if i == 0 else 'phone_preflight_storage::value()') + ' }\n#[test] fn check() { assert_eq!(value(), 7); }\n')
            packages.append(package)
    else:
        shutil.copytree(root, work, ignore=shutil.ignore_patterns('.git', 'target', 'node_modules', '.gradle', '.build', 'build', '.idea'))
        # Ignore rules affect generated mobile build directories only; verify every
        # publishable source below against the original before packaging.
        packages = [work / 'crates' / name for name in ['platform-storage', 'core', 'platform-keys', 'desktop']]
        names = [tomllib.loads((p / 'Cargo.toml').read_text())['package']['name'] for p in packages]
        original = tomllib.loads((work / 'Cargo.toml').read_text())
        manifest = (work / 'Cargo.toml').read_text()
        for name in names[:-1]:
            line = next(line for line in manifest.splitlines() if line.startswith(name + ' = '))
            manifest = manifest.replace(line, line.replace(' }', ', registry = "preflight" }'))
        (work / 'Cargo.toml').write_text(manifest)
        expected = tomllib.loads(manifest)
        for name in names[:-1]:
            assert expected['workspace']['dependencies'][name].pop('registry') == 'preflight'
        assert original == expected, 'workspace rewrite exceeded whitelist'
        changes = {}
        for p in packages:
            path = p / 'Cargo.toml'
            before = path.read_text()
            after = before.replace('publish = ["crates-io"]', 'publish = ["preflight"]')
            a, b = tomllib.loads(before), tomllib.loads(after)
            assert a['package'].pop('publish') == ['crates-io']
            assert b['package'].pop('publish') == ['preflight']
            assert a == b
            path.write_text(after)
            changes[str(path.relative_to(work))] = {'before': before, 'after': after}
        changes['Cargo.toml'] = {'before': (root / 'Cargo.toml').read_text(), 'after': manifest}
        (out / 'manifest-differences.json').write_text(json.dumps(changes, indent=2))
        for p in packages:
            for file in (root / p.relative_to(work)).rglob('*'):
                if file.is_file() and file.name != 'Cargo.toml':
                    assert file.read_bytes() == (work / file.relative_to(root)).read_bytes()
    evidence = {}
    try:
        for package in packages:
            info = tomllib.loads((package / 'Cargo.toml').read_text())['package']
            name = info['name']
            version = info['version']
            if isinstance(version, dict):
                version = tomllib.loads((work / 'Cargo.toml').read_text())['workspace']['package']['version']
            run(cargo + ['package', '--allow-dirty', '-p', name], work, env)
            archive = out / 'target/package' / f'{name}-{version}.crate'
            unpack = out / 'unpacked' / name
            unpack.mkdir(parents=True)
            with tarfile.open(archive) as tar:
                # Support early Python 3.11 too, without unsafe extractall fallback.
                for member in tar.getmembers():
                    destination = (unpack / member.name).resolve()
                    assert destination.is_relative_to(unpack.resolve()), 'archive path escapes root'
                    assert member.isdir() or member.isfile(), 'archive contains a link or special file'
                    if member.isdir():
                        destination.mkdir(parents=True, exist_ok=True)
                    else:
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(tar.extractfile(member).read())
            source = unpack / f'{name}-{version}'
            manifest = tomllib.loads((source / 'Cargo.toml').read_text())
            if not args.minimal:
                baseline_lock = tomllib.loads((root / 'Cargo.lock').read_text())['package']
                locked = {(p['name'], p['version']) for p in baseline_lock}
                archive_lock = tomllib.loads((source / 'Cargo.lock').read_text())['package']
                assert {(p['name'], p['version']) for p in archive_lock} <= locked, 'archive upgraded a dependency'
                for file in source.rglob('*'):
                    if file.is_file() and file.name not in {'Cargo.toml', 'Cargo.toml.orig', 'Cargo.lock', '.cargo_vcs_info.json'}:
                        assert file.read_bytes() == (root / package.relative_to(work) / file.relative_to(source)).read_bytes(), 'archive source differs'
                assert (source / 'Cargo.toml.orig').read_bytes() == (package / 'Cargo.toml').read_bytes()
            dependencies = []
            tables = [(None, manifest)] + list(manifest.get('target', {}).items())
            for target, table in tables:
                for kind, key in [('normal', 'dependencies'), ('build', 'build-dependencies'), ('dev', 'dev-dependencies')]:
                    for dep, spec in table.get(key, {}).items():
                        assert 'path' not in spec and 'git' not in spec
                        dependencies.append(dict(name=dep, req=spec['version'], features=spec.get('features', []), optional=spec.get('optional', False), default_features=spec.get('default-features', True), target=target, kind=kind, registry=index if dep in names else 'https://github.com/rust-lang/crates.io-index', package=spec.get('package')))
            download = registry / 'crates' / name / version / 'download'
            download.parent.mkdir(parents=True)
            shutil.copyfile(archive, download)
            entry = registry / 'index' / name[:2] / name[2:4] / name
            entry.parent.mkdir(parents=True, exist_ok=True)
            entry.write_text(json.dumps(dict(name=name, vers=version, deps=dependencies, cksum=digest(archive.read_bytes()), features=manifest.get('features', {}), yanked=False, links=manifest.get('package', {}).get('links'), rust_version='1.88')) + '\n')
            test_args = cargo + ['test', '--locked', '--manifest-path', str(source / 'Cargo.toml')]
            if os.name == 'nt' and not args.minimal:
                test_args += ['--']
                for test in (root / 'scripts/windows-portable-test-skips.txt').read_text().splitlines():
                    test_args += ['--skip', test]
            run(test_args, out, env)
            evidence[name] = {str(p.relative_to(source)): digest(p.read_bytes()) for p in sorted(source.rglob('*')) if p.is_file()}
        if not args.minimal:
            old = tomllib.loads((root / 'Cargo.lock').read_text())['package']
            new = tomllib.loads((work / 'Cargo.lock').read_text())['package']
            assert {(p['name'], p['version']) for p in old} == {(p['name'], p['version']) for p in new}, 'locked versions changed'
            # Only the four internal package sources/checksums may change.
            for a, b in zip(sorted(old, key=lambda p: (p['name'], p['version'])), sorted(new, key=lambda p: (p['name'], p['version']))):
                if a['name'] in names:
                    for key in ['source', 'checksum']:
                        a.pop(key, None)
                        b.pop(key, None)
                assert a == b, 'lockfile rewrite exceeded whitelist'
            run(cargo + ['install', '--registry', 'preflight', 'age-plugin-phone', '--version', '=' + version, '--locked', '--root', str(out / 'install')], out, env)
            binary = out / 'install/bin' / ('age-plugin-phone.exe' if os.name == 'nt' else 'age-plugin-phone')
            run([str(binary), '--help'], out, env)
            run([str(binary), 'setup', '--help'], out, env)
        (out / 'archive-evidence.json').write_text(json.dumps(evidence, indent=2))
        print('PASS: alternate registry and detached archive tests', flush=True)
    finally:
        server.shutdown()


if __name__ == '__main__':
    main()
