"""Isolated production CLI install and existing released-client recovery checks."""
import hashlib
from pathlib import Path
import tarfile
import tempfile

from gates import request, require


def smoke(version, work, command, clean_env):
    root = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(dir=work) as tmp:
        path = Path(tmp)
        env = clean_env(path / 'cargo-home', path / 'target')
        command(['cargo', '+1.88.0', 'install', '--registry', 'crates-io', 'age-plugin-phone',
                 '--version', '=' + version, '--locked', '--root', str(path / 'install')], path, env)
        binary = path / 'install/bin/age-plugin-phone'
        command([str(binary), '--help'], path, env)
        command([str(binary), 'setup', '--help'], path, env)
        clients = [
            ('https://github.com/FiloSottile/age/releases/download/v1.3.1/age-v1.3.1-linux-amd64.tar.gz',
             'bdc69c09cbdd6cf8b1f333d372a1f58247b3a33146406333e30c0f26e8f51377'),
            ('https://github.com/str4d/rage/releases/download/v0.12.1/rage-v0.12.1-x86_64-linux.tar.gz',
             'c5d7ab41fbf1213590e89721fd2b8eb122e84518c155ce35866f1c5759a3a29f'),
        ]
        for index, (url, checksum) in enumerate(clients):
            blob = request(url)
            require(hashlib.sha256(blob).hexdigest() == checksum, 'released-client-checksum')
            archive = path / f'client-{index}.tar.gz'
            archive.write_bytes(blob)
            with tarfile.open(archive) as tar:
                tar.extractall(path=path, filter='data')
        command(['bash', str(root / 'scripts/interoperability-smoke.sh'),
                 str(path / 'age/age'), str(path / 'age/age-keygen'),
                 str(path / 'rage/rage'), str(path / 'rage/rage-keygen'), str(binary)], path, env)
