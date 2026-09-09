#!/usr/bin/env python3
"""Pure tests of session evidence guards; no native keys or screen transitions."""
import importlib.util
from pathlib import Path
import plistlib
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("session_probe", Path(__file__).with_name("macos-m0-session.py"))
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)


class SessionTests(unittest.TestCase):
    def test_lock_flag_requires_explicit_boolean(self):
        for value in [{}, {"IOConsoleLocked": 0}, {"IOConsoleLocked": "false"}]:
            with patch.object(session.subprocess, "run", return_value=subprocess.CompletedProcess(
                    [], 0, plistlib.dumps(value), b"")):
                with self.assertRaises(RuntimeError):
                    session.locked()
        for flag in [False, True]:
            for value in [{"IOConsoleLocked": flag}, [{"IOConsoleLocked": flag}]]:
                with patch.object(session.subprocess, "run", return_value=subprocess.CompletedProcess(
                        [], 0, plistlib.dumps(value), b"")):
                    self.assertIs(session.locked(), flag)

    def test_same_boot_cannot_be_reported_as_reboot(self):
        with patch.object(session, "load", return_value={"boot_id": "original"}), \
                patch.object(session, "boot", return_value="original"), \
                patch.object(session, "sample") as sample:
            with self.assertRaisesRegex(RuntimeError, "no_reboot_observed"):
                session.resume(Path("unused"))
            sample.assert_not_called()

    def test_changed_key_is_rejected(self):
        manifest = {"public": {"signing": "expected", "selection": "expected"}}
        with self.assertRaisesRegex(RuntimeError, "key_changed"):
            session.check_public({"signing": {"outcome": "success", "public_key_sha256": "wrong"}}, manifest)
        session.check_public({"signing": {"outcome": "error", "category": "native_code_-25308"}}, manifest)

    def test_mid_sample_unlock_is_not_stable_locked_evidence(self):
        with patch.object(session, "locked", side_effect=[True, False]), \
                patch.object(session, "observe", return_value={}), \
                patch.object(session, "boot", return_value="boot"), \
                patch.object(session, "save"):
            record = session.sample(Path("unused"), {"public": {}}, "test")
            self.assertFalse(record["stable_lock_observation"])


if __name__ == "__main__":
    unittest.main()
