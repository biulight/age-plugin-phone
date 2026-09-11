#!/usr/bin/env python3
"""Run synthetic review probes against the exact Beta source candidate, without hardware keys."""
from pathlib import Path
import subprocess
import tempfile

CANDIDATE = "a41ba2e5be59f76980bf7d1a42bce94aba0d3019"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
IOS = "plugins/tauri-plugin-phone-identity/ios/"


def source(path):
    return subprocess.check_output(
        ["rtk", "proxy", "git", "show", f"{CANDIDATE}:{path}"], cwd=ROOT, text=True
    )


with tempfile.TemporaryDirectory(prefix="phone-beta-review-") as temporary:
    work = Path(temporary)
    cbor = work / "StrictCBOR.swift"
    cbor.write_text(source(IOS + "Core/Sources/PhoneIdentityCore/StrictCBOR.swift"))
    stream = work / "StreamSession.swift"
    # Preserve the codec/session implementation. Substitute only the Network import
    # and omit unrelated listener/discovery types so callbacks can be fault-injected.
    stream.write_text(source(IOS + "Sources/StreamTransport.swift").split(
        "final class ForegroundStreamListener"
    )[0].replace("import Network\n", ""))
    for name, production, harness in [
        ("replay-array", cbor, "ReplayArrayBoundary.swift"),
        ("stream-disconnect", stream, "StreamDisconnectHarness.swift"),
    ]:
        executable = work / name
        subprocess.run([
            "rtk", "proxy", "swiftc", "-package-name", "review",
            "-module-cache-path", str(work / "module-cache"),
            str(production), str(HERE / harness), "-o", str(executable)
        ], check=True)
        subprocess.run(["rtk", "proxy", str(executable)], check=True)
