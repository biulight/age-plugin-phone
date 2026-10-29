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


def timestamp(value):
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include timezone")
    return parsed


def check_network_cycle(cycle, started, finished):
    if (cycle.get("result") != "passed"
            or cycle.get("disabled_and_ipv4_removed") is not True
            or cycle.get("wifi_ipv4_restored") is not True
            or not timestamp(started) <= timestamp(cycle["started_utc"])
                <= timestamp(cycle["disabled_utc"]) <= timestamp(cycle["finished_utc"])
                <= timestamp(finished)):
        raise ValueError("network cancellation was not established within this attempt")


def require(condition):
    # Explicit validation survives both -O and PYTHONOPTIMIZE. No payload in errors.
    if not condition:
        raise AssertionError("replay acceptance condition failed")


def check_restart(record, original_finished, finished):
    if (record.get('result') != 'passed'
            or record.get('package') != 'io.github.biulight.age_plugin_phone'
            or record.get('old_process_stopped') is not True
            or record.get('fresh_process_started') is not True
            or not timestamp(original_finished) <= timestamp(record['started_utc'])
                <= timestamp(record['finished_utc']) <= timestamp(finished)):
        raise ValueError('cancelled request restart evidence mismatch')
