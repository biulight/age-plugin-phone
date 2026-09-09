#!/usr/bin/env python3
"""No hardware: check cancellation/timeout process-tree cleanup in the M0 runner."""
import importlib.util
from pathlib import Path
import signal
import subprocess
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location(
    "cryptokit_runner", Path(__file__).with_name("test-macos-cryptokit-probe.py")
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CommandTests(unittest.TestCase):
    def test_normal_result(self):
        process = MagicMock(pid=1234, returncode=0)
        process.communicate.return_value = ("public report", "")
        with patch.object(runner.subprocess, "Popen") as popen, \
                patch.object(runner.os, "killpg") as kill:
            popen.return_value.__enter__.return_value = process
            result = runner.command(["unused"], data="public input")
            self.assertEqual(result.stdout, "public report")
            self.assertEqual(result.returncode, 0)
            kill.assert_not_called()
            self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_timeout_and_interrupt_stop_children(self):
        for error, expected in [(subprocess.TimeoutExpired("unused", 60), RuntimeError),
                                (KeyboardInterrupt(), KeyboardInterrupt)]:
            with self.subTest(error=type(error).__name__):
                process = MagicMock(pid=1234)
                process.communicate.side_effect = [error, ("", "")]
                with patch.object(runner.subprocess, "Popen") as popen, \
                        patch.object(runner.os, "killpg") as kill:
                    popen.return_value.__enter__.return_value = process
                    with self.assertRaises(expected):
                        runner.command(["unused"])
                    kill.assert_called_once_with(1234, signal.SIGKILL)
                    self.assertEqual(process.communicate.call_count, 2)


if __name__ == "__main__":
    unittest.main()
