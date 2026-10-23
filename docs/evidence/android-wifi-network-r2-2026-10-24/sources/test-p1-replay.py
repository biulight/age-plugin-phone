import hashlib
import pathlib
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).parent / "p1"))
from replay_checks import check_original, check_network_cycle


class ReplayChecksTest(unittest.TestCase):
    def test_cancel_requires_failure_and_no_output(self):
        check_original(1, b"", b"", "unused", True)
        for code, stdout, output in [(0, b"", b""), (1, b"leak", b""), (1, b"", b"leak")]:
            with self.assertRaises(AssertionError):
                check_original(code, stdout, output, "unused", True)

    def test_original_approval_requires_exact_output(self):
        digest = hashlib.sha256(b"synthetic").hexdigest()
        check_original(0, b"", b"synthetic", digest, False)
        for code, output in [(1, b"synthetic"), (0, b""), (0, b"different")]:
            with self.assertRaises(AssertionError):
                check_original(code, b"", output, digest, False)

    def test_cycle_requires_removal_restore_and_current_attempt(self):
        cycle = dict(result="passed", disabled_and_ipv4_removed=True, wifi_ipv4_restored=True,
                     started_utc="2026-10-24T01:00:01Z", disabled_utc="2026-10-24T01:00:02Z",
                     finished_utc="2026-10-24T01:00:10Z")
        start = "2026-10-24T01:00:00Z"
        check_network_cycle(cycle, start)
        for key, value in [("result", "failed"), ("disabled_and_ipv4_removed", False),
                           ("wifi_ipv4_restored", False), ("started_utc", "2026-10-23T01:00:00Z"),
                           ("finished_utc", "2026-10-24T01:00:00Z")]:
            with self.assertRaises(AssertionError):
                check_network_cycle(dict(cycle, **{key: value}), start)


if __name__ == "__main__":
    unittest.main()
