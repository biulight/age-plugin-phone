# Same-signer network recovery candidate evidence

This is the local, uncommitted Android fix tested with the published Beta 2 Windows
EXE on the same Windows host and Android phone used for the failure reproduction.
It is not a new published release and does not overwrite the original Beta 2 failure.

`acceptance.json` binds ten owner-observed attempts and two checked network cycles
to the installed candidate APK and Windows executable. `review-followup.json` binds
each phone observation to a unique case/start timestamp. `attempts/` preserves machine
reports without retroactively changing their observation-pending status. Signature,
in-place installation, source/build hashes and final cleanup are separately recorded.
The initial unsigned-build metadata retains its original pending status as historical
build evidence; `acceptance.json` is the final scoped disposition.

Both the pending-authorization and idle network cycles passed on their first
automatic-discovery request after restoration, without explicit-address requests or
manual listener toggles. Cancellation/background failures produced no plaintext;
fresh recovery succeeded. Two exact signed-request replays within expiry produced
no response and no new prompt; a fresh request then succeeded.

`sources/` holds exact hash-matching test drivers, dependencies and changed Android
source. `manifest.json` detects accidental file edits or omissions, not malicious
rewriting of the manifest itself. There are no private paths, raw protocol captures,
recovery keys, signing credentials or synthetic plaintext in this archive.

```console
python scripts/check-p1-evidence.py docs/evidence/android-wifi-network-fix-2026-10-23
```

See [the implementation and validation record](../../android-wifi-network-recovery.md)
for remaining device, roaming and restart-persistence limits.
