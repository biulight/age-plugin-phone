"""Fail-closed, payload-free assertions for physical replay evidence."""
import datetime
import hashlib


def check_original(exit_code, stdout, output, expected_digest, network_cancel):
    if stdout:
        raise AssertionError("unexpected stdout")
    if network_cancel:
        if exit_code == 0 or output:
            raise AssertionError("cancelled request produced success or output")
    elif exit_code != 0 or hashlib.sha256(output).hexdigest().lower() != expected_digest.lower():
        raise AssertionError("approved request did not produce the expected output")


def check_network_cycle(cycle, started):
    def timestamp(value):
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if (cycle.get("result") != "passed"
            or cycle.get("disabled_and_ipv4_removed") is not True
            or cycle.get("wifi_ipv4_restored") is not True
            or not timestamp(started) <= timestamp(cycle["started_utc"])
                <= timestamp(cycle["disabled_utc"]) <= timestamp(cycle["finished_utc"])):
        raise AssertionError("network cancellation was not established")
