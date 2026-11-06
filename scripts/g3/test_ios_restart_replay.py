"""Synthetic host tests. No device, credentials or native authorization."""
import base64
from contextlib import contextmanager, ExitStack
import hashlib
import json
import subprocess
import sys
from pathlib import Path
import socket
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import ios_restart_replay as probe

VECTORS = Path(__file__).resolve().parents[2] / "crates/core/test-vectors"


def fixture(name="phone-v2-envelope"):
    doc = json.loads((VECTORS / (name + ".json")).read_text())
    body = base64.b64decode(doc["signed_request_base64"] + "==")
    header = b"APTS\x00\x01\x02\x01" + bytes(range(16)) + len(body).to_bytes(4, "big")
    return doc, bytearray(header + body)


class WireTests(unittest.TestCase):
    def test_metadata_matches_public_vectors(self):
        for name, mode in [("phone-v2-envelope", "phone"), ("p256tag-envelope-v2", "tag")]:
            doc, frame = fixture(name)
            expiry, digest = probe.request_info(frame, mode)
            self.assertEqual(expiry, doc["expires_at_unix"])
            self.assertEqual(bytes.fromhex(digest), base64.b64decode(doc["request_digest_base64"] + "=="))
            with self.assertRaises(probe.ProbeFailure):
                probe.request_info(frame, "phone" if mode == "tag" else "tag")

    def test_bounded_frame(self):
        _, frame = fixture()
        for data in [frame, frame[:-1], frame[:24] + (65537).to_bytes(4, "big"), b"x" * 28]:
            reader, writer = socket.socketpair()
            with reader, writer:
                writer.sendall(data)
                writer.shutdown(socket.SHUT_WR)
                if data == frame:
                    self.assertEqual(probe.capture(reader), frame)
                else:
                    with self.assertRaises(probe.ProbeFailure):
                        probe.capture(reader)

    def test_malformed_metadata(self):
        for data in (b"", b"\xff", b"\x9f", b"\x81" * 8, b"\x5a\xff\xff\xff\xff", b"\x00\x00"):
            with self.assertRaises(probe.ProbeFailure):
                probe.cbor(memoryview(data))

    def test_replay_preserves_body_and_rejects_timeout_or_response(self):
        _, frame = fixture()
        for fresh, outcome in [(False, b""), (True, b""), (False, b"x"), (True, socket.timeout())]:
            peer = MagicMock()
            peer.__enter__.return_value = peer
            peer.recv.side_effect = [outcome]
            with patch.object(socket, "create_connection", return_value=peer):
                if outcome != b"":
                    with self.assertRaises((probe.ProbeFailure, socket.timeout)):
                        probe.replay("unused", frame, fresh, time.time() + 10, time.monotonic() + 10)
                else:
                    result = probe.replay("unused", frame, fresh, time.time() + 10, time.monotonic() + 10)
                    self.assertEqual(result["peer_result"], "eof")
                outer, body = [call.args[0] for call in peer.sendall.call_args_list]
                self.assertEqual(body, frame[28:])
                self.assertEqual(outer[:8], frame[:8])
                self.assertEqual(outer[24:], frame[24:28])
                self.assertEqual(outer[8:24] == frame[8:24], not fresh)

    def test_expiry_after_send_disqualifies_eof(self):
        _, frame = fixture()
        peer = MagicMock()
        peer.__enter__.return_value = peer
        peer.recv.return_value = b""
        with patch.object(socket, "create_connection", return_value=peer), \
                patch.object(time, "time", side_effect=[100, 101, 111]), \
                patch.object(time, "monotonic", return_value=10):
            with self.assertRaisesRegex(probe.ProbeFailure, "expiry-or-clock"):
                probe.replay("unused", frame, False, 110, 20)

    def test_expiry_enforces_both_clocks(self):
        with patch.object(time, "time", return_value=100), patch.object(time, "monotonic", return_value=30):
            for expiry, deadline in [(100, 40), (120, 30), (500, 430)]:
                with self.assertRaises(probe.ProbeFailure):
                    probe.remaining(expiry, deadline)
            self.assertEqual(probe.remaining(120, 45), 15)

    def test_process_list_is_exact_and_fail_closed(self):
        exe = "/tmp/Phone.app/Phone"
        def parse(rows):
            return probe.process_ids({"info": {"outcome": "success"},
                                      "result": {"runningProcesses": rows}}, exe)
        app = {"executable": "file://" + exe, "processIdentifier": 90}
        self.assertEqual(parse([app, {"processIdentifier": 30}]), ({30, 90}, [90]))
        for rows in ([], [app, app], [app, dict(app, processIdentifier=91)], [{"processIdentifier": True}]):
            with self.assertRaises(probe.ProbeFailure):
                parse(rows)
        with self.assertRaises(probe.ProbeFailure):
            probe.process_ids({"info":{"outcome":"failed"}}, exe)


class CampaignTests(unittest.TestCase):
    def campaign(self, snapshots, cancel_output=b"", recovery_output=b"synthetic", missing_observation=None):
        # Use the real phase controller, digest/expiry checks and child outcome checks.
        _, frame = fixture()
        payload = b"synthetic"
        args = SimpleNamespace(phone="192.168.5.1", local="192.168.5.2", mode="phone",
                               executable="/example/Phone.app/Phone", digest=hashlib.sha256(payload).hexdigest())
        seen = []
        @contextmanager
        def decrypt(_args, route):
            child = MagicMock()
            outputs = [(0, payload), (1, cancel_output), (0, recovery_output)]
            child.returncode, output = outputs[len(seen)]
            child.poll.return_value = None
            child.communicate.return_value = (output, None)
            seen.append(route)
            yield child

        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            args.config_dir = Path(tmp)
            for key, name in [("age","age"), ("plugin","age-plugin-phone"), ("ipa","phone.ipa"), ("ciphertext","sample.age")]:
                path = Path(tmp) / name
                path.write_bytes(b"fixture")
                setattr(args, key, path)
            def mock(attr, **kwargs):
                return stack.enter_context(patch.object(probe, attr, **kwargs))
            stack.enter_context(patch.object(probe.sys.stdin, "isatty", return_value=True))
            stack.enter_context(patch.object(time, "time", return_value=1_000_000))
            listener = MagicMock()
            listener.accept.return_value = (MagicMock(), (args.local, 9999))
            stack.enter_context(patch.object(socket, "socket", return_value=listener))
            listener.__enter__.return_value = listener
            upstream = MagicMock()
            upstream.__enter__.return_value = upstream
            upstream.recv.return_value = b""
            stack.enter_context(patch.object(socket, "create_connection", return_value=upstream))
            mock("bind_inputs", return_value={"plugin": "fixture-hash"})
            mock("capture", return_value=frame)
            def observe(report, label, instruction):
                if label == missing_observation:
                    raise probe.ProbeFailure("observation-missing")
                report["observations"][label] = probe.utc()
            mock("observe", side_effect=observe)
            mock("decrypt", side_effect=decrypt)
            mock("query", side_effect=snapshots)
            report = {"observations": {}}
            probe.run(args, report)
            self.assertEqual(seen, [args.phone, args.local, args.phone])
            self.assertEqual([r["mode"] for r in report["replays"]], ["identical","fresh"])
            self.assertEqual(report["result"], "completed-awaiting-evidence-review")
            self.assertFalse(any(frame))

    def test_restart_and_fresh_recovery(self):
        old, stopped, new = ({8}, [8]), ({7}, []), ({9}, [9])
        self.campaign([old, old, stopped, new, new, new, new])

    def test_failed_or_ambiguous_restart(self):
        old, stopped, new = ({8}, [8]), ({7}, []), ({9}, [9])
        for snapshots in ([old, new], [old, old, old], [old, old, stopped, old],
                          [old, old, stopped, stopped], [old, old, stopped, new, old]):
            with self.assertRaises(probe.ProbeFailure):
                self.campaign(snapshots)

    def test_peer_eof_does_not_replace_operator_observations(self):
        old, stopped, new = ({8}, [8]), ({7}, []), ({9}, [9])
        for label in ("cancel", "replay_identical", "replay_fresh", "recovery"):
            with self.subTest(label=label), self.assertRaisesRegex(probe.ProbeFailure, "observation-missing"):
                self.campaign([old, old, stopped, new, new, new, new], missing_observation=label)

    def test_original_must_produce_no_output_and_recovery_must_match(self):
        old, stopped, new = ({8}, [8]), ({7}, []), ({9}, [9])
        for cancelled, recovered in [(b"unexpected", b"synthetic"), (b"", b"wrong")]:
            with self.assertRaises(probe.ProbeFailure):
                self.campaign([old, old, stopped, new, new, new, new], cancelled, recovered)


class CliTests(unittest.TestCase):
    def test_noninteractive_failure_record_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "result.json"
            command = [sys.executable, "-B", probe.__file__, "--report", str(path),
                       "--local", "192.168.1.2", "--phone", "192.168.1.3", "--mode", "phone"]
            for key in ("age", "plugin", "ipa", "ciphertext", "identity", "config-dir",
                        "device", "executable", "digest"):
                command.extend(["--" + key, "private-input-placeholder"])
            first = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True)
            self.assertEqual(first.returncode, 1)
            saved = path.read_bytes()
            self.assertEqual(json.loads(saved)["reason"], "interactive-terminal-required")
            self.assertNotIn(b"private-input-placeholder", saved + first.stderr + first.stdout)
            second = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True)
            self.assertEqual(second.returncode, 1)
            self.assertEqual(path.read_bytes(), saved)


if __name__ == "__main__":
    unittest.main()
