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
            allowed_files = {'LICENSE', 'README.md', 'Cargo.toml', 'Cargo.toml.orig', 'Cargo.lock', '.cargo_vcs_info.json'}
            # The macOS Secure Enclave bridge is compiled from the published crate;
            # these two inputs must remain in the archive and are not generated files.
            if name == 'age-plugin-phone-platform-keys':
                allowed_files |= {'build.rs'}
                allowed_prefixes = ('src/', 'tests/', 'test-vectors/', 'examples/', 'native/')
            else:
                allowed_prefixes = ('src/', 'tests/', 'test-vectors/', 'examples/')
            assert all(f in allowed_files or f.startswith(allowed_prefixes) for f in files), name
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
# G5 binds the implementation and fixtures at 41dd48d and the final specification at 6206d79.
frozen_spec = '061e13025115bd22c1110fa37b445c88e5a360b79235b1f792893c3a9b75ee8d'
frozen_vectors = {
    'offline-envelope-v2.json': '5e1cca6da4f06ce1f1c0e3f19b42908871a3710e84fee6ff38af41e9da90699b',
    'p256-recipient-v1.json': '6028deb7ae9122407214d1e8d6c3bdeb8d53c33f85340c499568ac1ac969d1e6',
    'p256-recipient-v2.json': '3765db88b82b8f3ec9710a22090f09826502602d2be90611cbbadbc85ad3c48c',
    'p256tag-collision.json': '9dad2c42a5e26819a7ef8f7a935f95fd6a07f2b7d9b3099157bb9db34d2b3e62',
    'p256tag-envelope-v2.json': '832e81cece94cd848d4350ff2af8a95947a006ba235e6e9fec8d502e88432f04',
    'p256tag.json': 'd298ccda3620109a1f593af956910ef96bdbdbd848e014ce6694a09d25ea7b09',
    'pairing-transcript-v2.json': 'baaa4289a6ca0eb7f6c3876ff0a0eb1074cde98eb5b158b2ae870ca9a80e18bd',
    'phone-v2-envelope.json': 'adcc6d11df6dd0912a1e73718c6a9efe3b933ec82fa2b0c4a28700a8f203d343',
    'protocol-boundaries-v2.json': '09475ec03003ab22653596ad279027d458e2644a3d299f34541b079f2c1ad1aa',
    'protocol-rejections-v2.json': '61b352d605259bb9194e299348f0b26bd8c8fe275f76c40ad7dabfe1da3104a3',
    'public-identity-stub-v2.json': 'd98dd78d8fcf5c946f8c9f036a5f486ded5258844bfa14df05ef232de8171496',
}
frozen_files = {'docs/protocol-v2-spec.md': frozen_spec}
frozen_files.update({f'crates/core/test-vectors/{name}': digest for name, digest in frozen_vectors.items()})
for relative, expected in frozen_files.items():
    path = root / relative
    if not path.is_file():
        raise SystemExit(f'frozen v2 baseline: missing {relative}')
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f'frozen v2 baseline: {relative}: expected {expected}, got {actual}')
print('frozen v2 suite 1 specification and 11 public vectors: PASS')
assert not list((root / 'docs/test-vectors').glob('*.json'))
print('four-package graph, exact versions, boundaries, resources: PASS')
