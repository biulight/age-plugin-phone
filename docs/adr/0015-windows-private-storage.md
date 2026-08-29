# ADR 0015: Windows private locator and replay storage

- Status: implemented and native-validated on the designated Windows 11 host
- Date: 2026-08-25
- Scope: Windows desktop locator, TPM metadata, and response-replay files

## Context

The Unix backend relies on modes, advisory `flock`, same-directory rename, file `fsync`, and
directory `fsync`. Those operations do not establish the equivalent Windows security or crash
semantics. In particular, inherited `%LOCALAPPDATA%` permissions, reparse points, hard links, and
Windows sharing modes need an explicit fail-closed boundary.

## Decision

Windows private state lives directly under `%LOCALAPPDATA%\age-plugin-phone` unless the existing
absolute test override is explicitly used. The configuration directory and every private file are
created with a protected DACL containing one full-control ACE for the current user. Opens verify
the owner, protected DACL, exact ACE, regular file or directory type, absence of a reparse-point
attribute, and a link count of one.

The isolated `age-plugin-phone-windows-storage` crate owns the Win32 filesystem FFI. It provides:

- bounded reads through a handle opened with `FILE_FLAG_OPEN_REPARSE_POINT`;
- non-blocking lifetime locks on sibling `.lock` files by opening with a zero share mode;
- new-file creation through a same-directory private temporary and `MoveFileExW` write-through;
- replacement through a flushed same-directory private temporary and
  `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`; and
- post-operation validation so a widened ACL, reparse point, or hard link poisons the caller.

Replay state retains the version 2 canonical encoding, scope, clock high-water mark, capacity, and
copy-before-commit state transition specified by ADR 0003. A replacement failure poisons the guard
without updating its in-memory state. Missing state is never recreated by open.

The locator contains absolute paths only and remains bound to the desktop ID, identity ID, and full
pairing transcript fingerprint. On Windows the pairing command requires its TPM metadata and replay
paths to be direct children of the selected private configuration root. New locator filenames bind
both the phone identity ID and desktop ID so distinct pairings to one phone identity cannot collide.
Readers continue to accept the legacy identity-only filename after validating the complete encoded
binding; cleanup resolves and deletes whichever validated form exists.

## Consequences

- Windows file privacy does not depend on Unix mode emulation or inherited ACLs.
- Concurrent age/plugin processes fail closed before reading or modifying replay state.
- Copying locator, replay, TPM metadata, or the public identity stub to another machine does not
  copy the non-exportable TPM operations and therefore cannot create a signed request.
- Administrators and kernel-level attackers remain outside the desktop filesystem threat boundary.
- Windows does not use a directory-handle `fsync`; write-through move plus file flush is the
  platform durability boundary and must be validated on supported filesystems.

## Validation

Portable tests cover canonical replay behavior and the unchanged protocol bindings. Windows-only
tests cover private create/read/replace, bounded reads, lock exclusion and reopen, restart replay
rejection, wrong scope, corruption, missing state, and hard-link rejection. The storage, replay,
and CNG test targets cross-compile for `x86_64-pc-windows-msvc` with warnings denied.

Native Windows tests passed for exact private ACL enforcement, widened-ACL and hard-link rejection,
bounded reads, atomic create and replacement, lock exclusion and reopen, restart replay rejection,
wrong scope, corruption, missing state, and persistence-failure poisoning. The complete desktop
crate compiled and passed Clippy with warnings denied and passed its native test suite. The CNG
tests provisioned, exercised, reopened, and removed distinct TPM signing and selection keys; a
post-test Microsoft Platform Crypto Provider enumeration contained no `age-plugin-phone-` key.
