#!/usr/bin/env python3
"""Deterministic runner tests: no native executable or Keychain access."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "probe_runner", Path(__file__).with_name("test-macos-key-probe.py")
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
BINDING = "PASS verify public_binding=" + "a" * 64


def result(ok, text):
    return subprocess.CompletedProcess([], 0 if ok else 1, text if ok else "", "" if ok else text)


class RunnerTests(unittest.TestCase):
    def execute(self, responses):
        calls = []

        def invoke(command, **_kwargs):
            calls.append(command[1])
            response = next(responses)
            if isinstance(response, Exception):
                raise response
            return response

        with patch("sys.argv", ["runner", "/unused/probe", "a" * 32]), \
                patch.object(runner.subprocess, "run", side_effect=invoke):
            try:
                runner.main()
            finally:
                self.calls = calls

    def test_lifecycle(self):
        self.execute(iter([
            result(False, "FAIL missing_signing"), result(True, BINDING),
            result(True, BINDING), result(False, "FAIL scope_already_exists"),
            result(True, "PASS delete"), result(False, "FAIL missing_selection"),
            result(False, "FAIL scope_already_exists"), result(True, "PASS delete"),
            result(False, "FAIL missing_signing"),
        ]))
        self.assertEqual(self.calls[-2:], ["delete", "verify"])

    def test_unavailable_keychain_never_creates_or_deletes(self):
        with self.assertRaises(RuntimeError):
            self.execute(iter([result(False, "FAIL lookup_signing:osstatus=-25291")]))
        self.assertEqual(self.calls, ["verify"])

    def test_existing_scope_never_deleted(self):
        with self.assertRaises(RuntimeError):
            self.execute(iter([result(False, "FAIL missing_signing"),
                               result(False, "FAIL scope_already_exists")]))
        self.assertEqual(self.calls, ["verify", "create"])

    def test_creation_timeout_cleans_partial_state(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.execute(iter([result(False, "FAIL missing_signing"),
                               subprocess.TimeoutExpired("probe", 30),
                               result(True, "PASS delete"), result(False, "FAIL missing_signing")]))
        self.assertEqual(self.calls[-2:], ["delete", "verify"])

    def test_wrong_binding_fails_and_cleans(self):
        with self.assertRaises(RuntimeError):
            self.execute(iter([result(False, "FAIL missing_signing"), result(True, BINDING),
                               result(True, BINDING.replace("a", "b")),
                               result(True, "PASS delete"), result(False, "FAIL missing_signing")]))
        self.assertEqual(self.calls[-2:], ["delete", "verify"])

    def test_cleanup_failure_is_not_success(self):
        with self.assertRaisesRegex(RuntimeError, "delete_signing"):
            self.execute(iter([result(False, "FAIL missing_signing"),
                               result(False, "FAIL create_selection:cfcode=-34018"),
                               result(False, "FAIL delete_signing:osstatus=-25291")]))


if __name__ == "__main__":
    unittest.main()
