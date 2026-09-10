#!/usr/bin/env python3
"""Explicit M0 lock/reboot measurements. Never locks, unlocks or reboots the host.

The caller controls transitions. State is retained for post-reboot verification,
never re-created by watch/resume. Only synthetic references in an isolated root.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import select
import shutil
import signal
import subprocess
import time


def run(argv, data=None, timeout=10):
    return subprocess.run(argv, input=data, capture_output=True, text=True,
                          timeout=timeout, check=False)


def boot():
    result = run(["sysctl", "-n", "kern.bootsessionuuid"])
    if result.returncode or not result.stdout.strip():
        raise RuntimeError("boot_session_unavailable")
    return result.stdout.strip()


def locked():
    result = subprocess.run(["ioreg", "-n", "Root", "-d", "1", "-a"],
                            capture_output=True, timeout=10, check=False)
    if result.returncode:
        raise RuntimeError("lock_observation_unavailable")
    value = plistlib.loads(result.stdout)
    if isinstance(value, list):
        value = value[0]
    flag = value.get("IOConsoleLocked")
    if type(flag) is not bool:
        raise RuntimeError("lock_observation_unknown")
    return flag


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value, append=False):
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_APPEND if append else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(json.dumps(value, sort_keys=True) + "\n")
        output.flush()
        os.fsync(output.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare(args):
    if locked():
        raise RuntimeError("prepare_requires_unlocked_session")
    root = args.root
    root.mkdir(mode=0o700)
    (root / "state").mkdir(mode=0o700)
    for source, name in [(args.probe, "probe"), (args.verifier, "verifier")]:
        shutil.copyfile(source, root / name)
        (root / name).chmod(0o700)
    result = run([str(root / "probe"), "create", str(root / "state")])
    if result.returncode:
        raise RuntimeError("baseline_create_failed; retain isolated root")
    report = json.loads(result.stdout)
    if run([str(root / "verifier")], result.stdout).returncode:
        raise RuntimeError("baseline_crypto_failed")
    manifest = {"version": 1, "boot_id": boot(), "public_binding": report["public_binding"],
                "probe_sha256": digest(root / "probe"), "verifier_sha256": digest(root / "verifier"),
                "refs": {name: digest(root / "state" / name)
                         for name in ["signing.ref", "selection.ref", "binding"]},
                "public": {role: base64.b64encode(hashlib.sha256(base64.b64decode(
                    report[role + "_public"])).digest()).decode() for role in ["signing", "selection"]}}
    save(root / "manifest.json", manifest)
    baseline = sample(root, manifest, "baseline")
    if baseline["locked_before"] or baseline["locked_after"] or any(
            baseline["fresh"].get(role, {}).get("outcome") != "success"
            for role in ["signing", "selection"]):
        raise RuntimeError("baseline_operations_failed")
    print("PASS baseline_saved; original_keys_only_on_resume", flush=True)


def load(root):
    if root.is_symlink() or root.stat().st_mode & 0o077:
        raise RuntimeError("insecure_test_root")
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest["version"] != 1 or digest(root / "probe") != manifest["probe_sha256"] \
            or digest(root / "verifier") != manifest["verifier_sha256"]:
        raise RuntimeError("test_binary_changed")
    for name, expected in manifest["refs"].items():
        if digest(root / "state" / name) != expected:
            raise RuntimeError("test_reference_changed")
    return manifest


def observe(root):
    try:
        result = run([str(root / "probe"), "observe", str(root / "state")])
    except subprocess.TimeoutExpired:
        return {"process": "timeout"}
    if result.returncode:
        return {"process": "error"}
    return json.loads(result.stdout)


def check_public(report, manifest):
    for role in ["signing", "selection"]:
        value = report.get(role, {})
        if value.get("outcome") == "success" and value.get("public_key_sha256") != manifest["public"][role]:
            raise RuntimeError("key_changed")


def receive(process):
    if not select.select([process.stdout], [], [], 10)[0]:
        raise RuntimeError("held_process_timeout")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("held_process_ended")
    return json.loads(line)


def sample(root, manifest, phase, held=None):
    before = locked()
    fresh = observe(root)
    check_public(fresh, manifest)
    record = {"phase": phase, "time": time.time(), "boot_id": boot(),
              "locked_before": before, "fresh": fresh}
    if held:
        held.stdin.write("sample\n")
        held.stdin.flush()
        record["held"] = receive(held)
        check_public(record["held"], manifest)
    record["locked_after"] = locked()
    record["stable_lock_observation"] = before == record["locked_after"]
    save(root / "observations.jsonl", record, append=True)
    return record


def watch(root):
    manifest = load(root)
    if locked() or boot() != manifest["boot_id"]:
        raise RuntimeError("watch_requires_original_unlocked_boot")
    held = subprocess.Popen([str(root / "probe"), "hold", str(root / "state")],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, start_new_session=True)
    try:
        if receive(held) != {"ready": True}:
            raise RuntimeError("held_not_ready")
        sample(root, manifest, "before_lock", held)
        print("ARMED: held handles opened; waiting for user lock", flush=True)
        deadline = time.monotonic() + 240
        seen_locked = False
        count = 0
        while time.monotonic() < deadline:
            record = sample(root, manifest, "lock_watch", held)
            if record["stable_lock_observation"]:
                if record["locked_before"]:
                    seen_locked = True
                    count += 1
                    print("LOCKED sample=" + str(count) + " fresh=" +
                          json.dumps(record["fresh"], sort_keys=True) + " held=" +
                          json.dumps(record["held"], sort_keys=True), flush=True)
                elif seen_locked:
                    print("UNLOCKED: " + json.dumps(record["fresh"], sort_keys=True), flush=True)
                    print("DONE lock_observations_saved; inspect outcomes before acceptance", flush=True)
                    return
            time.sleep(5)
        raise RuntimeError("lock_cycle_timeout; observations_retained")
    finally:
        if held.poll() is None:
            os.killpg(held.pid, signal.SIGKILL)
        held.wait()


def resume(root):
    manifest = load(root)
    if boot() == manifest["boot_id"]:
        raise RuntimeError("no_reboot_observed")
    if locked():
        raise RuntimeError("post_reboot_user_login_required")
    record = sample(root, manifest, "after_reboot_login")
    if not record["stable_lock_observation"] or record["locked_after"]:
        raise RuntimeError("session_transition_during_post_reboot_probe")
    for role in ["signing", "selection"]:
        if record["fresh"].get(role, {}).get("outcome") != "success":
            raise RuntimeError("post_reboot_operation_failed")
    result = run([str(root / "probe"), "verify", str(root / "state")])
    if result.returncode or json.loads(result.stdout)["public_binding"] != manifest["public_binding"] \
            or run([str(root / "verifier")], result.stdout).returncode:
        raise RuntimeError("post_reboot_crypto_or_binding_failed")
    print("PASS boot_id_changed_original_keys_reopened_after_user_login", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "watch", "resume"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--verifier", type=Path)
    args = parser.parse_args()
    args.root = args.root.resolve()
    try:
        if args.action == "prepare":
            if not args.probe or not args.verifier:
                parser.error("prepare requires --probe and --verifier")
            prepare(args)
        elif args.action == "watch":
            watch(args.root)
        else:
            resume(args.root)
    except RuntimeError as error:
        raise SystemExit("FAIL " + str(error)) from None
    except (ValueError, OSError, subprocess.TimeoutExpired):
        raise SystemExit("FAIL session_test_unavailable; retain state") from None
