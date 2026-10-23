# Network-cancellation acceptance-tool follow-up

This revision adds one shared timezone-aware constraint: request start ≤ cycle start
≤ disable time ≤ restored/finished time ≤ request finish. Both the live relay and the
archive cross-check use it. Rehashed archives with old, future, reversed, missing-zone
or malformed cycle timestamps are rejected. Equivalent timezone offsets are accepted.

The actual driver subprocess fixture now runs 22 scenarios in each of normal, `-O`
and `PYTHONOPTIMIZE=1` modes (66 combinations per host). These include manual and
automatic network cancellation, switch failure, early close/response, original response
or output, original success, absent/duplicate/old/future cycles, failed restoration and
unexpected replay response. All sockets, ADB, age and network switching are synthetic.
No new phone request, APK build, installation, commit or push is part of this revision.

`runs/` contains three recorded suite invocations per host: replay regressions,
evidence regressions, and evidence regressions under `-O`. Each record contains its
command relative to the scripts directory, interpreter version/implementation,
executable basename, UTC start/end, exit code, captured output and before/after source
hash agreement. Each `DRIVER_CASE` output line additionally records the child command,
environment mode, actual interpreter optimization level, timestamps, driver result and
exit codes. Machine-specific checkout paths are redacted from diagnostics.

`scripts/` contains the exact source snapshots for those runs, including the recorder
and all test dependencies. The outer archive manifest hashes each snapshot and run.
Older physical attempts and earlier P2 records remain historical and are not replaced
or relabeled as executions of this revision.
