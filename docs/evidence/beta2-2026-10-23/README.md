# Beta 2 P1 evidence index

This archive contains sanitized machine results, explicit owner-observation summaries,
historical source snapshots, and the review follow-up. It contains no device serials,
private filesystem paths, raw protocol messages, synthetic plaintext or recovery keys.

- `core-acceptance.json` and `wifi-acceptance.json`: historical manually correlated
  results. These are preserved as recorded, **not the final disposition** after review.
- `attempts/`: individual reports, including failed and unobserved attempts. A machine
  result awaiting observation is not an accepted phone result.
- `review-followup.json`: final review disposition and exact attempt/observation mapping.
- `source-coverage.json`: historical driver coverage. All five hashes referenced by
  accepted Wi-Fi reports have exact matching sources. Earlier source versions were
  reconstructed by removing known later edits, and retained only on an exact SHA-256
  match. No approximate source is substituted. Core reports that predate hash capture
  and helper reports without hashes cannot acquire retrospective provenance.
- `sources/`: historical source, including known bugs; **do not run these snapshots**.
  Maintained probes are under `scripts/p1/`. Corrected run snapshots are named by hash.
- `manifest.json`: hashes for every archived file except the manifest itself. This
  detects accidental edits and missing files; it is not an external signature or an
  independently timestamped attestation.

The historical interface-cycle report used unchecked ADB output and is qualified by
that defect. The corrected repeat checked every command and observed the same interface
loss. Network automatic-discovery recovery remains an open Beta 2 availability issue:
the failure reproduced with `wifi-discovery-no-match`; explicit-address unwrap and a
later automatic-discovery unwrap succeeded, each with fresh native verification.
No authentication bypass or plaintext release was observed.

Check integrity from the repository root:

```console
python scripts/check-p1-evidence.py docs/evidence/beta2-2026-10-23
```

The archive is maintainer evidence, not an expansion of product support or public
publisher trust. See the [acceptance record](../../beta2-package-acceptance-2026-10-23.md).
