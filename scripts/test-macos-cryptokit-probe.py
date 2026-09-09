#!/usr/bin/env python3
"""Explicit M0 hardware/source-install test. Never runs in ordinary CI.

All installs and opaque references live under a new private temporary directory.
Only synthetic public evidence is passed to the Rust verifier. No real pairing.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import select
import signal
import subprocess
import tempfile


def command(argv, *, data=None, env=None, timeout=60):
    with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, env=env,
                          start_new_session=True) as process:
        try:
            stdout, stderr = process.communicate(data, timeout=timeout)
        except BaseException as error:
            # Cargo may have a Swift compiler child. Stop the whole private process
            # group before temporary install/state directories are cleaned up.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            if isinstance(error, subprocess.TimeoutExpired):
                raise RuntimeError("native_or_build_timeout") from None
            raise
        return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--rust-verifier", type=Path, required=True)
    args = parser.parse_args()
    fixture = args.fixture.resolve()
    verifier = args.rust_verifier.resolve()

    with tempfile.TemporaryDirectory(prefix="age-phone-m0-cryptokit-") as temporary:
        root = Path(temporary)
        install = root / "install"
        binary = install / "bin" / "age-phone-m0-cryptokit-probe"
        first = root / "build-a"
        second = root / "build-b"
        state = root / "state"
        other = root / "other"
        state.mkdir(mode=0o700)
        other.mkdir(mode=0o700)

        def build(opt, target):
            env = dict(os.environ, RUSTC_WRAPPER="", M0_SWIFT_OPT=opt,
                       MACOSX_DEPLOYMENT_TARGET="14.0")
            result = command(["cargo", "install", "--locked", "--offline", "--force",
                              "--path", str(fixture), "--root", str(install),
                              "--target-dir", str(target)], env=env)
            if result.returncode:
                raise RuntimeError("cargo_install_failed (inspect fixture build separately)")
            signature = command(["codesign", "-dv", "--verbose=2", str(binary)])
            entitlements = command(["codesign", "-d", "--entitlements", ":-", str(binary)])
            if signature.returncode or "Signature=adhoc" not in signature.stderr \
                    or "TeamIdentifier=not set" not in signature.stderr \
                    or entitlements.returncode or entitlements.stdout.strip():
                raise RuntimeError("expected_adhoc_no_team_no_entitlements")
            return hashlib.sha256(binary.read_bytes()).hexdigest()

        def invoke(action, directory=state, executable=binary, expected=True):
            result = command([str(executable), action, str(directory)])
            if (result.returncode == 0) != expected:
                # Probe errors are coarse static categories, never native descriptions.
                raise RuntimeError("unexpected_" + action + ":" + result.stderr.strip())
            if not expected:
                if not result.stderr.startswith("FAIL "):
                    raise RuntimeError("unexpected_native_failure")
                return None
            report = json.loads(result.stdout)
            checked = command([str(verifier)], data=result.stdout)
            if checked.returncode:
                raise RuntimeError("rust_interoperability_failed")
            return report["public_binding"]

        def write(path, data):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(data)

        hash_a = build("-Onone", root / "target-a")
        shutil.copy2(binary, first)
        invoke("verify", expected=False)
        binding = invoke("create")
        if invoke("verify") != binding:
            raise RuntimeError("cross_process_binding_changed")
        invoke("create", expected=False)
        other_binding = invoke("create", other)
        if other_binding == binding:
            raise RuntimeError("scopes_not_independent")
        hash_b = build("-O", root / "target-b")
        if hash_a == hash_b:
            raise RuntimeError("build_hash_did_not_change")
        shutil.copy2(binary, second)
        if invoke("verify") != binding:
            raise RuntimeError("force_install_binding_changed")
        if invoke("verify", executable=first) != binding:
            raise RuntimeError("original_build_cannot_reopen")
        print("PASS cargo_install_force_and_independent_builds; adhoc_no_team_no_entitlements")
        print("build_a_sha256=" + hash_a)
        print("build_b_sha256=" + hash_b)

        # Same immutable references used by independent native processes. This
        # does not certify concurrent provisioning or product replay serialization.
        before = {name: hashlib.sha256((state / name).read_bytes()).hexdigest()
                  for name in ["signing.ref", "selection.ref", "binding"]}
        with ThreadPoolExecutor(max_workers=4) as pool:
            bindings = list(pool.map(lambda _: invoke("verify"), range(16)))
        if any(value != binding for value in bindings):
            raise RuntimeError("concurrent_binding_changed")
        minimal_env = {name: value for name, value in os.environ.items()
                       if name in {"HOME", "USER", "LOGNAME", "TMPDIR", "PATH"}}
        piped = command([str(binary), "verify", str(state)], env=minimal_env)
        if piped.returncode or json.loads(piped.stdout)["public_binding"] != binding \
                or command([str(verifier)], data=piped.stdout).returncode:
            raise RuntimeError("minimal_environment_noninteractive_failed")
        with subprocess.Popen([str(binary), "hold", str(state)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, start_new_session=True) as holder:
            try:
                if not select.select([holder.stdout], [], [], 10)[0] \
                        or json.loads(holder.stdout.readline()) != {"ready": True}:
                    raise RuntimeError("holder_not_ready")
                # Deliberate abnormal exit with already-open handles; not a claim
                # of interruption at a particular internal cryptographic instruction.
                os.killpg(holder.pid, signal.SIGKILL)
                holder.wait(timeout=10)
            finally:
                if holder.poll() is None:
                    os.killpg(holder.pid, signal.SIGKILL)
                holder.communicate()
        if invoke("verify") != binding or any(
                hashlib.sha256((state / name).read_bytes()).hexdigest() != value
                for name, value in before.items()):
            raise RuntimeError("process_termination_changed_state")
        print("PASS concurrent_16_operations_4_processes_minimal_env_and_killed_holder")

        names = ["signing.ref", "selection.ref", "binding"]
        original = {name: (state / name).read_bytes() for name in names}
        # These are deliberately retained opaque synthetic blobs, never logged.
        selection = state / "selection.ref"
        selection.unlink()
        invoke("verify", expected=False)
        invoke("create", expected=False)
        write(selection, original["selection.ref"])
        for replacement in [b"", b"\x07" * 32, b"x" * 8193,
                            original["selection.ref"][:-1],
                            bytes([original["selection.ref"][0] ^ 1]) + original["selection.ref"][1:],
                            (other / "selection.ref").read_bytes()]:
            write(selection, replacement)
            invoke("verify", expected=False)
        write(selection, original["selection.ref"])
        write(state / "signing.ref", original["selection.ref"])
        write(selection, original["signing.ref"])
        invoke("verify", expected=False)
        for name, data in original.items():
            write(state / name, data)
        write(state / "binding", bytes(32))
        invoke("verify", expected=False)
        write(state / "binding", original["binding"])
        selection.chmod(0o644)
        invoke("verify", expected=False)
        selection.chmod(0o600)
        selection.unlink()
        selection.symlink_to(other / "selection.ref")
        invoke("verify", expected=False)
        selection.unlink()
        os.link(other / "selection.ref", selection)
        invoke("verify", expected=False)
        selection.unlink()
        write(selection, original["selection.ref"])
        if invoke("verify") != binding:
            raise RuntimeError("restored_fixture_binding_changed")
        print("PASS missing_partial_malformed_swapped_wrong_binding_permissions_links")

        # Demonstrate the actual cleanup boundary, not a claim of hardware destruction.
        for name in names:
            (state / name).unlink()
        invoke("verify", expected=False)
        if invoke("verify", other) != other_binding:
            raise RuntimeError("other_scope_affected_by_cleanup")
        for name, data in original.items():
            write(state / name, data)
        if invoke("verify") != binding:
            raise RuntimeError("restore_observation_changed")
        print("OBSERVED copied_wrapped_references_survive_file_deletion_on_same_mac")
        uninstalled = command(["cargo", "uninstall", "--root", str(install),
                               "age-phone-m0-cryptokit-probe"])
        if uninstalled.returncode or binary.exists():
            raise RuntimeError("cargo_uninstall_failed")
        if invoke("verify", executable=second) != binding:
            raise RuntimeError("uninstall_changed_key_access")
        build("-O", root / "target-b")
        if invoke("verify") != binding:
            raise RuntimeError("reinstall_binding_changed")
        print("PASS uninstall_reinstall_and_second_scope_isolation")
        print("PASS native_and_rust_prehash_low_s_ecdh_interoperability")
    print("PASS isolated_test_files_removed; hardware_destruction_NOT_CLAIMED")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        raise SystemExit("FAIL " + str(error)) from None
    except ValueError:
        raise SystemExit("FAIL invalid_public_report") from None
