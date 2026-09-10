#!/usr/bin/env python3
"""Explicit hardware experiment; never part of ordinary CI/test runs.

The caller retains the random run ID for exact cleanup after forced termination.
No phone, protocol, production state, or real data is involved.
"""
import argparse
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("run_id")
    parser.add_argument("--upgrade-binary")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{32}", args.run_id):
        parser.error("run_id must be a freshly generated 128-bit lowercase hex value")

    def invoke(action, binary=None):
        return subprocess.run(
            [binary or args.binary, action, args.run_id],
            capture_output=True, text=True, timeout=30, check=False,
        )

    def require(result, expected):
        output = (result.stdout + result.stderr).strip()
        if (result.returncode == 0) != expected or not output:
            raise RuntimeError("unexpected probe outcome: " + output)
        return output

    # Never clean a scope we found already populated or could not inspect.
    missing = require(invoke("verify"), False)
    if missing != "FAIL missing_signing":
        raise RuntimeError("fresh namespace preflight failed: " + missing)
    # A selection-only orphan is rejected by create before creating any key.
    # The harness requires a fresh random scope; do not reuse runs concurrently.
    created = False
    try:
        created = True  # timeout may leave partial native state
        result = invoke("create")
        if result.returncode != 0 and result.stderr.strip() == "FAIL scope_already_exists":
            created = False
            raise RuntimeError("refusing existing scope")
        binding = require(result, True)
        if not re.fullmatch(r"PASS verify public_binding=[0-9a-f]{64}", binding):
            raise RuntimeError("invalid public binding output")
        if require(invoke("verify"), True) != binding:
            raise RuntimeError("cross-process key binding changed")
        if require(invoke("create"), False) != "FAIL scope_already_exists":
            raise RuntimeError("duplicate creation did not fail closed")
        if args.upgrade_binary:
            if require(invoke("verify", args.upgrade_binary), True) != binding:
                raise RuntimeError("upgrade key binding changed")
        require(invoke("delete-selection"), True)
        if require(invoke("verify"), False) != "FAIL missing_selection":
            raise RuntimeError("missing role was not rejected")
        if require(invoke("create"), False) != "FAIL scope_already_exists":
            raise RuntimeError("partial state was repaired")
    finally:
        if created:
            require(invoke("delete"), True)
            if require(invoke("verify"), False) != "FAIL missing_signing":
                raise RuntimeError("cleanup verification failed; retain run ID")

    print("PASS lifecycle; upgrade=" + ("tested" if args.upgrade_binary else "NOT_TESTED"))


if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired:
        raise SystemExit("FAIL native_timeout; retain run ID for exact cleanup") from None
    except RuntimeError as error:
        raise SystemExit("FAIL " + str(error)) from None
