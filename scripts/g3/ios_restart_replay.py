"""Owner-operated iOS Wi-Fi restart/replay probe. See docs/protocol-v2-g3-acceptance-plan.md."""
import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import secrets
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import unquote, urlsplit

PORT = 47140
LIMIT = 65536
SOURCE = "41dd48d79bd7497f72ac1e7e3d63ffe97d4462d1"


class ProbeFailure(Exception):
    """Only fixed, payload-free diagnostic categories may be reported."""


def require(condition, category):
    if not condition:
        raise ProbeFailure(category)


def utc():
    return datetime.now(timezone.utc).isoformat()


def file_hash(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def ipv4(text):
    addr = ipaddress.IPv4Address(text)
    allowed = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
    if not any(addr in ipaddress.ip_network(net) for net in allowed):
        raise argparse.ArgumentTypeError("expected a private or link-local IPv4 address")
    return str(addr)


def observe(report, label, instruction):
    print(instruction + " Type YES only after observing it.", file=sys.stderr, flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], 90)
    require(ready and sys.stdin.readline().strip() == "YES", "observation-missing")
    report["observations"][label] = utc()


def process_ids(document, executable):
    # An incomplete listing cannot establish that the old process stopped.
    require(document.get("info", {}).get("outcome") == "success", "process-query-failed")
    rows = document.get("result", {}).get("runningProcesses")
    require(isinstance(rows, list) and rows, "process-list-unavailable")
    all_ids, app_ids = set(), []
    for row in rows:
        pid = row.get("processIdentifier")
        require(type(pid) is int and pid > 0 and pid not in all_ids, "invalid-process-id")
        all_ids.add(pid)
        path = row.get("executable")
        if isinstance(path, str) and path.startswith("file://"):
            path = unquote(urlsplit(path).path)
        if path == executable:
            app_ids.append(pid)
    require(len(app_ids) <= 1, "ambiguous-app-process")
    return all_ids, app_ids


def query(args):
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "processes.json"
        subprocess.run(["xcrun", "devicectl", "device", "info", "processes",
                        "--device", args.device, "--timeout", "10", "--quiet",
                        "--json-output", str(out)], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True, timeout=15)
        return process_ids(json.loads(out.read_bytes()), args.executable)


def read_exact(peer, size, deadline):
    buf = bytearray(size)
    pos = 0
    while pos < size:
        left = deadline - time.monotonic()
        require(left > 0, "frame-timeout")
        peer.settimeout(left)
        n = peer.recv_into(memoryview(buf)[pos:])
        require(n, "short-frame")
        pos += n
    return buf


def capture(peer):
    deadline = time.monotonic() + 8
    header = read_exact(peer, 28, deadline)
    require(header[:8] == b"APTS\x00\x01\x02\x01", "unexpected-frame")
    size = int.from_bytes(header[24:], "big")
    require(0 < size <= LIMIT, "invalid-frame-size")
    return header + read_exact(peer, size, deadline)


def cbor(data):
    # Bounded metadata reader only. The phone verifies the original signed bytes.
    def item(pos, depth):
        require(depth <= 4 and pos < len(data), "malformed-metadata")
        tag = data[pos]
        pos += 1
        if tag == 0xf6:
            return None, pos
        n = tag & 31
        if n >= 24:
            require(n <= 27, "indefinite-metadata")
            size = 1 << (n - 24)
            require(pos + size <= len(data), "short-metadata")
            n = int.from_bytes(data[pos:pos + size], "big")
            pos += size
        major = tag >> 5
        if major == 0:
            return n, pos
        if major in (2, 3):
            require(pos + n <= len(data), "short-metadata")
            value = data[pos:pos + n]
            return (value if major == 2 else value.tobytes().decode("utf-8")), pos + n
        require(major == 4 and n <= 11, "invalid-metadata-array")
        values = []
        for _ in range(n):
            value, pos = item(pos, depth + 1)
            values.append(value)
        return values, pos
    value, end = item(0, 0)
    require(end == len(data), "trailing-metadata")
    return value


def request_info(frame, mode):
    body = memoryview(frame)[28:]
    envelope = cbor(body)
    require(isinstance(envelope, list) and len(envelope) == 2
            and all(isinstance(v, memoryview) for v in envelope)
            and len(envelope[1]) == 64, "invalid-envelope")
    fields = cbor(envelope[0])
    require(isinstance(fields, list) and len(fields) == 11 and fields[:3] == [2, 3, 1]
            and isinstance(fields[7], list) and len(fields[7]) == 3
            and fields[7][0] == {"phone": "phone-p256-v2", "tag": "p256tag"}[mode]
            and type(fields[9]) is int, "unexpected-request")
    digest = hashlib.sha256(b"age-plugin-phone/request-digest/v2\0")
    digest.update(body)
    return fields[9], digest.hexdigest()


def remaining(expiry, deadline):
    left = min(expiry - time.time(), deadline - time.monotonic())
    require(0 < left <= 300, "expiry-or-clock")
    return left


def expect_close(peer, timeout):
    peer.settimeout(timeout)
    try:
        require(peer.recv(1) == b"", "unexpected-response")
        return "eof"
    except ConnectionResetError:
        return "reset"


def replay(phone, frame, fresh, expiry, deadline):
    outer = bytearray(frame[:28])
    if fresh:
        outer[8:24] = secrets.token_bytes(16)
        require(outer[8:24] != frame[8:24], "session-collision")
    # Each attempt sends exactly once, preserving the signed body even in the fresh frame.
    with socket.create_connection((phone, PORT), timeout=5) as peer:
        left = remaining(expiry, deadline)
        peer.settimeout(min(5, left))
        sent = utc()
        peer.sendall(outer)
        peer.sendall(memoryview(frame)[28:])
        outcome = expect_close(peer, min(10, remaining(expiry, deadline)))
        remaining(expiry, deadline)
    return {"mode": "fresh" if fresh else "identical", "sent_utc": sent,
            "seconds_remaining_at_send": left, "peer_result": outcome}


def age(args, route):
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGE_PLUGIN_PHONE_")}
    env.update(AGE_PLUGIN_PHONE_TRANSPORT="wifi", AGE_PLUGIN_PHONE_WIFI_ADDRESS=f"{route}:{PORT}",
               AGE_PLUGIN_PHONE_CONFIG_DIR=str(args.config_dir),
               PATH=str(args.plugin.parent) + os.pathsep + env.get("PATH", ""))
    return subprocess.Popen([args.age, "-d", "-i", args.identity, args.ciphertext],
                            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, start_new_session=True)


@contextlib.contextmanager
def decrypt(args, route):
    child = age(args, route)
    try:
        yield child
    finally:
        if child.poll() is None:
            # The age plugin may still be waiting for a phone when a probe aborts.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.communicate(timeout=10)


def fresh_decrypt(args, report, stage):
    with decrypt(args, args.phone) as child:
        data, _ = child.communicate(timeout=90)
        require(child.returncode == 0 and data and
                hashlib.sha256(data).hexdigest() == args.digest, "fresh-output-mismatch")
    observe(report, stage, f"Confirm fresh native approval for the {stage} decrypt.")


def bind_inputs(args):
    require(args.local != args.phone and args.config_dir.is_dir(), "invalid-route-or-state")
    require(args.plugin.name == "age-plugin-phone" and os.access(args.plugin, os.X_OK)
            and args.ciphertext.stat().st_size <= LIMIT, "invalid-test-input")
    require(re.fullmatch(r"[a-f0-9]{64}", args.digest), "invalid-output-digest")
    require(args.executable.startswith("/") and ".app/" in args.executable, "invalid-app-path")
    require(re.fullmatch(r"(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{16}|[0-9a-fA-F]{40}|"
                         r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})", args.device),
            "explicit-device-id-required")
    # Use the desktop's strict public stub reader: a recovery identity or multiple identities
    # could otherwise make baseline and recovery decryption succeed through another recipient.
    subprocess.run([args.plugin, "recipients", "--identity", args.identity,
                    "--recipient-type", args.mode], check=True, timeout=10,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {k: file_hash(getattr(args, k)) for k in ("plugin", "ipa", "age", "ciphertext", "identity")}


@contextlib.contextmanager
def cancelled_request(args, report):
    frame = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((args.local, PORT))
            listener.listen(1)
            listener.settimeout(20)
            with decrypt(args, args.local) as child:
                client, addr = listener.accept()
                with client:
                    listener.close()
                    require(addr[0] == args.local and child.poll() is None, "unexpected-client")
                    frame = capture(client)
                    expiry, digest = request_info(frame, args.mode)
                    deadline = time.monotonic() + (expiry - time.time())
                    remaining(expiry, deadline)
                    report.update(request_digest=digest, expires_unix=expiry)
                    with socket.create_connection((args.phone, PORT), timeout=5) as peer:
                        peer.sendall(frame)
                        observe(report, "cancel", f"Verify phone prompt {digest[:16]}, then cancel it.")
                        report["cancel_peer"] = expect_close(peer, min(10, remaining(expiry, deadline)))
                        remaining(expiry, deadline)
                    require(child.poll() is None, "desktop-ended-before-cancel-confirmation")
                data, _ = child.communicate(timeout=10)
                require(child.returncode != 0 and not data, "cancelled-decrypt-produced-output")
        yield frame, expiry, deadline
    finally:
        if frame is not None:
            frame[:] = bytes(len(frame))


def observe_restart(args, report, old_pid):
    _, current = query(args)
    require(current == [old_pid], "process-changed-before-stop")
    observe(report, "stopped", "Quit only the selected app without clearing data.")
    pids, current = query(args)
    require(old_pid not in pids and not current, "original-process-still-present")
    report["original_process_absent_utc"] = utc()
    observe(report, "relaunched", "Reopen the same app and restore its foreground Wi-Fi listener.")
    pids, current = query(args)
    require(old_pid not in pids and len(current) == 1, "restart-not-established")
    report.update(old_pid=old_pid, new_pid=current[0], relaunched_process_seen_utc=utc())
    return current[0]


def run(args, report):
    require(sys.stdin.isatty(), "interactive-terminal-required")
    report.update(target_candidate_source=SOURCE, mode=args.mode, transport="wifi",
                  hashes=bind_inputs(args), driver_sha256=file_hash(Path(__file__)))
    observe(report, "binding", "Confirm disposable candidate packages, pairing, synthetic input, and selected device/route.")
    _, old = query(args)
    require(len(old) == 1, "initial-process-missing")
    fresh_decrypt(args, report, "baseline")
    with cancelled_request(args, report) as (frame, expiry, deadline):
        new_pid = observe_restart(args, report, old[0])
        report["replays"] = []
        for fresh in (False, True):
            mode = "fresh" if fresh else "identical"
            observe(report, "watch_" + mode, "Confirm the listener is ready and watch for the next replay.")
            _, current = query(args)
            require(current == [new_pid], "restarted-process-changed")
            report["replays"].append(replay(args.phone, frame, fresh, expiry, deadline))
            observe(report, "replay_" + mode,
                    "Confirm this attempt reached the relaunched app, showed replay rejection and no new prompt.")
        _, current = query(args)
        require(current == [new_pid], "restarted-process-changed")
    fresh_decrypt(args, report, "recovery")
    require(bind_inputs(args) == report["hashes"], "campaign-inputs-changed")
    report["result"] = "completed-awaiting-evidence-review"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("age", "plugin", "ipa", "ciphertext", "identity", "config-dir", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("device", "executable", "digest"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--mode", choices=("phone", "tag"), required=True)
    for name in ("local", "phone"):
        parser.add_argument("--" + name, type=ipv4, required=True)
    args = parser.parse_args()
    for name in ("age", "plugin", "ipa", "ciphertext", "identity", "config_dir"):
        setattr(args, name, getattr(args, name).absolute())
    report = {"case": "ios-cancel-restart-replay", "result": "incomplete",
              "started_utc": utc(), "observations": {}}
    try:
        fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        print("Cannot create a new report file.", file=sys.stderr)
        return 1
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        try:
            run(args, report)
        except (Exception, KeyboardInterrupt) as exc:
            report["result"] = "failed"
            report["reason"] = str(exc) if isinstance(exc, ProbeFailure) else type(exc).__name__
        finally:
            report["finished_utc"] = utc()
            json.dump(report, output, indent=2)
            output.write("\n")
    return int(report["result"] != "completed-awaiting-evidence-review")


if __name__ == "__main__":
    raise SystemExit(main())
