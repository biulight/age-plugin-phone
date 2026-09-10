#!/usr/bin/env python3
"""Synthetic M2 acceptance. Never reboots the host or accesses real pairing state.

Full-volume writes are restricted to a new <=256 MiB mounted APFS image, with an
independent write cap. Failed fixtures are retained for diagnosis; never reset replay.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import plistlib
import select
import shutil
import signal
import subprocess
import tempfile


def run(argv, timeout=30):
    result = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("command_failed:" + Path(argv[0]).name)
    return result.stdout.strip()


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def invoke(binary, command, state):
    return run([binary, command, state])


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w") as out:
        json.dump(value, out, sort_keys=True, indent=2)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def boot():
    return run(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"])


def seed(binary, root, name):
    state = root / name
    require(invoke(binary, "seed", state) == "seeded", "seed_failed")
    require(invoke(binary, "verify", state) == "replay_rejected", "replay_not_rejected")
    return state


def kill_holder(binary, command, state):
    process = subprocess.Popen([str(binary), command, str(state)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        if not select.select([process.stdout], [], [], 15)[0] or process.stdout.readline().strip() != "ready":
            raise RuntimeError("holder_not_ready")
        process.send_signal(signal.SIGKILL)
        if process.wait(timeout=10) != -signal.SIGKILL:
            raise RuntimeError("holder_not_killed")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        process.stdin.close()
        process.stdout.close()


def local(binary, root):
    committed = seed(binary, root, "committed")
    kill_holder(binary, "hold-committed", committed)
    require(invoke(binary, "verify-three", committed) == "replay_rejected", "crash_commit_not_preserved")
    pending = seed(binary, root, "uncertain")
    kill_holder(binary, "hold-pending", pending)
    marker = Path(str(pending) + ".pending")
    before = (digest(pending), digest(marker))
    require(invoke(binary, "verify-pending", pending) == "pending_rejected", "pending_not_rejected")
    require((digest(pending), digest(marker)) == before, "uncertain_state_changed")
    rollback = seed(binary, root, "rollback-demo")
    old = rollback.read_bytes()  # Synthetic canonical state only; not a real pairing.
    require(invoke(binary, "consume-two", rollback) == "consumed", "rollback_baseline_failed")
    with rollback.open("wb") as out:
        out.write(old)
        out.flush()
        os.fsync(out.fileno())
    accepted = invoke(binary, "consume-two", rollback) == "consumed"
    return {"sigkill_after_commit": "passed", "sigkill_with_pending": "passed",
            "snapshot_rollback_protection": "failed_observed" if accepted else "not_reproduced"}


def fill_volume(root):
    info = os.statvfs(root)
    if info.f_blocks * info.f_frsize > 256 * 1024 * 1024:
        raise RuntimeError("volume_exceeds_safety_cap")
    filler = root / "acceptance-filler"
    total = 0
    metadata_fill = root / "metadata-filler"
    metadata_fill.mkdir(mode=0o700)
    fd = os.open(filler, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    full = False
    try:
        for size in [1024 * 1024, 4096]:
            block = os.urandom(size)
            while total < 192 * 1024 * 1024:
                try:
                    count = os.write(fd, block)
                    if count <= 0:
                        raise RuntimeError("zero_write")
                    total += count
                except OSError as error:
                    if error.errno != errno.ENOSPC:
                        raise
                    full = True
                    break
            else:
                raise RuntimeError("filler_write_cap_reached")
        try:
            os.fsync(fd)
        except OSError as error:
            if error.errno != errno.ENOSPC:
                raise
            full = True
    finally:
        os.close(fd)
    if not full:
        raise RuntimeError("ENOSPC_not_observed")
    metadata_full = False
    for index in range(16384):
        try:
            item = os.open(metadata_fill / str(index), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(item)
        except OSError as error:
            if error.errno != errno.ENOSPC:
                raise
            metadata_full = True
            break
    if not metadata_full:
        raise RuntimeError("metadata_ENOSPC_not_observed_within_cap")
    return filler, total


def full_volume(binary, root):
    image = root / "bounded-apfs.dmg"
    mount = root / "mount"
    mount.mkdir(mode=0o700)
    run(["/usr/bin/hdiutil", "create", "-size", "128m", "-fs", "APFS", "-volname", "PhoneM2Acceptance",
         image], timeout=60)
    attached = False
    try:
        run(["/usr/bin/hdiutil", "attach", "-nobrowse", "-owners", "on", "-mountpoint", mount, image], timeout=60)
        attached = True
        if os.stat(mount).st_dev == os.stat(root).st_dev:
            raise RuntimeError("not_an_independent_volume")
        info = plistlib.loads(subprocess.check_output(["/usr/sbin/diskutil", "info", "-plist", str(mount)], timeout=15))
        if info.get("FilesystemType") != "apfs":
            raise RuntimeError("not_APFS")
        # New mount only. chmod never targets pre-existing user directories.
        mount.chmod(0o700)
        state_root = mount / "state"
        state_root.mkdir(mode=0o700)
        state = seed(binary, state_root, "responses")
        other = seed(binary, state_root, "other")
        filler, written = fill_volume(mount)
        result = invoke(binary, "consume-fails", state)
        if result != "commit_unavailable":
            raise RuntimeError("unexpected_full_volume_result")
        filler.unlink()  # Only the exact filler created above, on this bounded image.
        shutil.rmtree(mount / "metadata-filler")
        outcome = invoke(binary, "verify-closed", state)
        require(outcome in ["replay_rejected", "state_unavailable"], "unsafe_after_free_space")
        require(invoke(binary, "verify", other) == "replay_rejected", "other_pairing_changed")
        return {"filesystem": "apfs", "image_size_mib": 128, "filler_bytes": written,
                "ENOSPC_observed": True, "commit_at_full": result,
                "after_free_space": outcome, "other_pairing": "replay_rejected"}
    finally:
        if attached:
            run(["/usr/bin/hdiutil", "detach", mount], timeout=30)


def prepare_reboot(binary, root):
    state = seed(binary, root, "reboot-state")
    save(root / "reboot.json", {"boot_id": boot(), "binary_sha256": digest(binary),
                               "state_sha256": digest(state)})
    return {"reboot": "prepared_not_passed"}


def resume_reboot(root):
    manifest = json.loads((root / "reboot.json").read_text())
    binary = root / "probe"
    state = root / "reboot-state"
    if digest(binary) != manifest["binary_sha256"] or digest(state) != manifest["state_sha256"]:
        raise RuntimeError("reboot_artifact_changed")
    if boot() == manifest["boot_id"]:
        raise RuntimeError("actual_reboot_not_observed")
    require(invoke(binary, "verify", state) == "replay_rejected", "replay_not_rejected")
    report = {"reboot": "passed", "binary_unchanged": True, "state_unchanged": True,
              "consumed_response": "replay_rejected"}
    save(root / "reboot-result.json", report)
    print(json.dumps(report, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["local", "full-volume", "prepare-reboot", "resume-reboot"])
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    if args.mode == "resume-reboot":
        if args.root is None:
            parser.error("resume requires --root")
        resume_reboot(args.root.resolve(strict=True))
        return
    if args.binary is None:
        parser.error("--binary is required")
    if args.root:
        root = args.root.absolute()
        root.mkdir(mode=0o700)
    else:
        root = Path(tempfile.mkdtemp(prefix="phone-m2-acceptance-", dir="/private/tmp"))
    binary = root / "probe"
    shutil.copyfile(args.binary.resolve(strict=True), binary)
    binary.chmod(0o700)
    print("fixture=" + str(root), flush=True)
    mode = {"local": local, "full-volume": full_volume, "prepare-reboot": prepare_reboot}[args.mode]
    report = mode(binary, root)
    report["binary_sha256"] = digest(binary)
    save(root / "result.json", report)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
