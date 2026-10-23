"""Capture public source provenance; never reads signing configuration or environment secrets."""
import argparse
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCOPES = ["Cargo.toml", "Cargo.lock", "mise.toml", "crates", "plugins", "apps/mobile"]


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def included(name):
    return not (name.startswith("apps/mobile/src-tauri/gen/apple/")
                or name.startswith("apps/mobile/src-tauri/gen/schemas/")
                or "__pycache__" in name)


def inventory():
    names = git("ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", *SCOPES)
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in sorted(set(names.decode().split("\0")))
            if name and included(name) and (ROOT / name).is_file()}


def capture(destination):
    destination.mkdir(parents=True, exist_ok=False)
    files = inventory()
    baseline = git("rev-parse", "HEAD").decode().strip()
    changed = set(git("diff", "HEAD", "--name-only", "-z", "--", *SCOPES).decode().split("\0"))
    changed.update(git("ls-files", "--others", "--exclude-standard", "-z", "--", *SCOPES).decode().split("\0"))
    snapshots = []
    deleted = []
    for name in sorted(changed):
        if not name or not included(name):
            continue
        if name not in files:
            deleted.append(name)
            continue
        path = destination / "delta" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / name).read_bytes())
        snapshots.append(name)
    record = dict(base_commit=baseline, base_tree=git("rev-parse", "HEAD^{tree}").decode().strip(),
                  source_sha256=files, changed_source_snapshots=snapshots, deleted_sources=deleted,
                  excluded="Apple project and generated Tauri schemas; neither is Android source input",
                  build_command="bunx tauri android build --apk --target aarch64 --ci",
                  build_directory="apps/mobile", java_major=17, rustc_wrapper="disabled",
                  signing="separate Windows signing record; no credential material captured")
    (destination / "build-source.json").write_text(json.dumps(record, indent=2) + "\n")
    print("Captured source baseline and %d input hashes" % len(files))


def verify(destination, apk):
    record = json.loads((destination / "build-source.json").read_text())
    if inventory() != record["source_sha256"]:
        raise SystemExit("Source changed after capture; do not attribute this build to the snapshot")
    for name in record["changed_source_snapshots"]:
        if hashlib.sha256((destination / "delta" / name).read_bytes()).hexdigest() != record["source_sha256"][name]:
            raise SystemExit("Source snapshot mismatch")
    result = dict(source_unchanged_during_build=True,
                  source_record_sha256=hashlib.sha256((destination / "build-source.json").read_bytes()).hexdigest(),
                  unsigned_apk_sha256=hashlib.sha256(apk.read_bytes()).hexdigest())
    (destination / "build-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["capture", "verify"])
    parser.add_argument("destination", type=pathlib.Path)
    parser.add_argument("--apk", type=pathlib.Path)
    args = parser.parse_args()
    if args.mode == "capture":
        capture(args.destination)
    else:
        if not args.apk:
            parser.error("verify requires --apk")
        verify(args.destination, args.apk)
