"""Guardrails for the explicit synthetic installation acceptance runner."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'lifecycle', Path(__file__).with_name('macos-install-lifecycle.py'))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class Guardrails(unittest.TestCase):
    def test_snapshot_detects_bytes_permissions_and_extra_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / 'replay'
            state.write_bytes(b'consumed synthetic digest')
            state.chmod(0o600)
            original = runner.snapshot(root)
            state.write_bytes(b'older synthetic state')
            self.assertNotEqual(original, runner.snapshot(root))
            state.write_bytes(b'consumed synthetic digest')
            state.chmod(0o644)
            self.assertNotEqual(original, runner.snapshot(root))
            state.chmod(0o600)
            (root / 'unexpected').touch()
            self.assertNotEqual(original, runner.snapshot(root))

    def test_snapshot_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'state').write_bytes(b'synthetic')
            (root / 'link').symlink_to(root / 'state')
            with self.assertRaises(RuntimeError):
                runner.snapshot(root)

    def test_installed_probe_requires_exact_failure_boundary_and_empty_stdout(self):
        cases = [
            (1, b'', b'malformed stanza body', True),
            (0, b'', b'malformed stanza body', False),
            (1, b'unexpected output', b'malformed stanza body', False),
            (1, b'', b'desktop authentication state is unavailable', False),
        ]
        for code, stdout, stderr, accepted in cases:
            with self.subTest(code=code, stdout=stdout, stderr=stderr):
                result = subprocess.CompletedProcess([], code, stdout, stderr)
                with patch.object(runner.subprocess, 'run', return_value=result) as invoked:
                    if accepted:
                        runner.verify_installed(Path('/binary'), Path('/synthetic'), {})
                    else:
                        with self.assertRaises(RuntimeError):
                            runner.verify_installed(Path('/binary'), Path('/synthetic'), {})
                    args = invoked.call_args.args[0]
                    self.assertEqual(args[-2:], ['--transport', 'qr'])
                    self.assertEqual(invoked.call_args.kwargs['env']['AGE_PLUGIN_PHONE_CONFIG_DIR'],
                                     '/synthetic')

    def test_helper_success_requires_attestation_and_zero_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for code, stdout in [(1, b'verified'), (0, b'wrong')]:
                result = subprocess.CompletedProcess([], code, stdout, b'')
                with patch.object(runner.subprocess, 'run', return_value=result):
                    with self.assertRaises(RuntimeError):
                        runner.run(['/helper'], {}, root, root / 'test.log', b'verified')


if __name__ == '__main__':
    unittest.main()
