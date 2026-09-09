#!/usr/bin/env python3
"""Runner guardrails, with no mounts, disk filling or host reboot."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("runner", Path(__file__).with_name("macos-m2-acceptance.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class Guardrails(unittest.TestCase):
    def test_refuses_large_volume_before_any_write(self):
        stat = types.SimpleNamespace(f_blocks=1024 * 1024, f_frsize=4096)
        with patch.object(runner.os, "statvfs", return_value=stat), patch.object(runner.os, "open") as opened:
            with self.assertRaisesRegex(RuntimeError, "volume_exceeds_safety_cap"):
                runner.fill_volume(Path("/never-write-here"))
            opened.assert_not_called()

    def fixture(self, root):
        (root / "probe").write_bytes(b"synthetic probe")
        (root / "reboot-state").write_bytes(b"synthetic state")
        (root / "reboot.json").write_text(json.dumps({"boot_id": "original",
            "binary_sha256": runner.digest(root / "probe"),
            "state_sha256": runner.digest(root / "reboot-state")}))

    def test_same_boot_is_not_reboot_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root)
            with patch.object(runner, "boot", return_value="original"), patch.object(runner, "invoke") as invoke:
                with self.assertRaisesRegex(RuntimeError, "actual_reboot_not_observed"):
                    runner.resume_reboot(root)
                invoke.assert_not_called()
            self.assertFalse((root / "reboot-result.json").exists())

    def test_changed_artifacts_block_resume(self):
        for name in ["probe", "reboot-state"]:
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                self.fixture(root)
                (root / name).write_bytes(b"changed")
                with patch.object(runner, "boot", return_value="new"), patch.object(runner, "invoke") as invoke:
                    with self.assertRaisesRegex(RuntimeError, "reboot_artifact_changed"):
                        runner.resume_reboot(root)
                    invoke.assert_not_called()

    def test_successful_resume_requires_original_state_rejecting_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root)
            with patch.object(runner, "boot", return_value="new"), patch.object(runner, "invoke", return_value="accepted"):
                with self.assertRaisesRegex(RuntimeError, "replay_not_rejected"):
                    runner.resume_reboot(root)
            self.assertFalse((root / "reboot-result.json").exists())

    def test_gate_stays_active_under_optimized_python(self):
        with self.assertRaisesRegex(RuntimeError, "failed_gate"):
            runner.require(False, "failed_gate")


if __name__ == "__main__":
    unittest.main()
