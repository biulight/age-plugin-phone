# Owner-assisted hardware replay probe

This separate, unpublished harness uses the candidate desktop/core/storage APIs.
It does not alter the four product packages or add a product retry policy. Use it
only with the explicitly created synthetic upgrade pairing, never ordinary user state.

Build on the validation Windows host with Cargo 1.88 and the included lock file.
Arguments are `ACTION CONFIG_ROOT IDENTITY_STUB`; paths must refer to the same
existing test pairing. No command creates a missing pairing, identity or replay store.

- `stored-response`: open existing TPM keys and verify both public-key bindings;
  read an already consumed response entry through the private storage boundary;
  require `Replay` at its recorded clock and `ClockRollback` one second earlier;
  require byte-for-byte unchanged persisted state after both rejected calls. This
  deliberately uses a test clock, not the current wall clock, and does not claim
  an expired response was rejected as a live network replay.
- `approve-replay`: require a fresh real phone approval, authenticate the encrypted
  response and compare the transient synthetic file key without displaying it;
  durably consume the response through the candidate guard.
- `cancel-replay`: the owner cancels the first native prompt. A missing response
  alone does not prove cancellation; the owner must confirm the observed action.

For the last two actions, wait until the phone has returned to its normal controls
and type `READY` on the desktop. The harness then opens a fresh transport and
re-sends the identical signed request still held only in zeroizing memory. It
requires a successful transport connection followed by rejection within ten
seconds, with at least 25 seconds of request validity remaining beforehand.
The owner must separately confirm no new native-authentication prompt appeared.
Connection failures, timeouts and unconfirmed phone observations are not passes.

Raw requests/responses, file keys and decrypted values are never printed or written
to disk. The only persisted response consumption is the ordinary authenticated
success path. The harness never restores replay bytes or caches authorization.
Its hidden ADB cleanup-guard entry point preserves the product's cleanup behavior.
