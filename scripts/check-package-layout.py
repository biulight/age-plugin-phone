#!/usr/bin/env python3
"""Check the four-package publication contract (Python 3.11+)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--archives', action='store_true', help='also validate cargo package --list')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
workspace = tomllib.loads((root / 'Cargo.toml').read_text())['workspace']
version = workspace['package']['version']
allowed = {
    'age-plugin-phone-platform-storage': set(),
    'age-plugin-phone-core': {'age-plugin-phone-platform-storage'},
    'age-plugin-phone-platform-keys': {'age-plugin-phone-core'},
    'age-plugin-phone': {'age-plugin-phone-core', 'age-plugin-phone-platform-keys', 'age-plugin-phone-platform-storage'},
}
private = {'age-plugin-phone-mobile', 'tauri-plugin-phone-identity'}
seen = set()
for member in workspace['members']:
    manifest = tomllib.loads((root / member / 'Cargo.toml').read_text())
    package = manifest['package']
    name = package['name']
    seen.add(name)
    assert package['version'] == {'workspace': True}, name
    assert package['publish'] == (['crates-io'] if name in allowed else False), name
    deps = set()
    for table in [manifest, *manifest.get('target', {}).values()]:
        for kind in ['dependencies', 'build-dependencies', 'dev-dependencies']:
            for dep, spec in table.get(kind, {}).items():
                if dep in allowed:
                    assert spec == {'workspace': True}, (name, dep)
                    shared = workspace['dependencies'][dep]
                    assert shared['version'] == '=' + version, dep
                    assert set(shared) == {'version', 'path'}, dep
                    assert (root / shared['path'] / 'Cargo.toml').is_file(), dep
                    deps.add(dep)
    if name in allowed:
        assert deps == allowed[name], (name, deps)
        for field in ['license', 'repository', 'rust-version', 'edition']:
            assert package[field] == {'workspace': True}, (name, field)
        assert (root / member / 'LICENSE').read_bytes() == (root / 'LICENSE').read_bytes()
        if args.archives:
            listing = subprocess.check_output(['cargo', '+1.88.0', 'package', '--allow-dirty', '--list', '-p', name], cwd=root, text=True)
            files = {line.replace('\\', '/') for line in listing.splitlines()}
            assert {'LICENSE', 'README.md', 'Cargo.toml', 'Cargo.toml.orig', 'Cargo.lock', 'src/lib.rs'} <= files, name
            assert all(f in {'LICENSE', 'README.md', 'Cargo.toml', 'Cargo.toml.orig', 'Cargo.lock', '.cargo_vcs_info.json'} or f.startswith(('src/', 'tests/', 'test-vectors/', 'examples/')) for f in files), name
            required = {p.relative_to(root / member).as_posix() for directory in ['src', 'tests', 'test-vectors', 'examples'] for p in (root / member / directory).rglob('*') if p.is_file()}
            assert required <= files, (name, required - files)
    else:
        assert name in private
        assert deps == ({'age-plugin-phone-core'} if name == 'age-plugin-phone-mobile' else set())
assert seen == set(allowed) | private
assert workspace['lints']['rust']['unsafe_code'] == 'forbid'
assert workspace['package']['rust-version'] == '1.88'
for directory in ['core', 'desktop']:
    assert tomllib.loads((root / 'crates' / directory / 'Cargo.toml').read_text())['lints'] == {'workspace': True}
for directory in ['platform-keys', 'platform-storage']:
    assert tomllib.loads((root / 'crates' / directory / 'Cargo.toml').read_text())['lints']['rust']['unsafe_op_in_unsafe_fn'] == 'deny'
for path in ['apps/mobile/package.json', 'apps/mobile/src-tauri/tauri.conf.json']:
    assert json.loads((root / path).read_text())['version'] == version
vectors = {
    'offline-envelope-v2.json': '5e1cca6da4f06ce1f1c0e3f19b42908871a3710e84fee6ff38af41e9da90699b',
    'p256-recipient-v1.json': '6028deb7ae9122407214d1e8d6c3bdeb8d53c33f85340c499568ac1ac969d1e6',
    'p256-recipient-v2.json': '3765db88b82b8f3ec9710a22090f09826502602d2be90611cbbadbc85ad3c48c',
    'pairing-transcript-v2.json': 'baaa4289a6ca0eb7f6c3876ff0a0eb1074cde98eb5b158b2ae870ca9a80e18bd',
}
for name, expected in vectors.items():
    assert hashlib.sha256((root / 'crates/core/test-vectors' / name).read_bytes()).hexdigest() == expected, name
assert not list((root / 'docs/test-vectors').glob('*.json'))
print('four-package graph, exact versions, boundaries, resources: PASS')
