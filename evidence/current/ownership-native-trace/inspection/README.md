# Ownership native inspection and strengthened recheck

The retained positive, stale-read and repeated-release images pass the current
fixed-profile instruction checks. Their original observations are unchanged:
two acquisitions, two releases and final reference count one; each negative
has one explicit A release and one cleanup B release. No native guest was
rerun and no kernel, provider, verifier or native image was changed.

The [authored inspection](native-review.md) traces all three complete native
images and the linked failure/cleanup path. The [current receipt](results.json)
checks 479 native words against retained LLVM operands, all source/native map
intervals and branch targets, the complete gateway and selected compiled
gate/entry/cleanup sequences. Its input hashes bind the original log,
configuration, linked kernel identity, exact function bytes and full listings.

Three distinct assurances are retained:

| Assurance | What it establishes | Limit |
|---|---|---|
| Production encoder self-check | The emitter re-encodes and compares every word | Internal consistency using the same encoder, not independent decoding |
| External fixed-profile receipt checks | Logged bytes, LLVM operands, fixed instruction sequences and targets agree; ordered events and completion pass | Handwritten bounded checks, not a general validator or compiler proof |
| Authored source/native inspection | The listed instructions explain the selected failure return, skipped continuation and cleanup | AI-assisted internal inspection, not independent external review or reproduction |

The [provenance receipt](receipt.json) records this post-run work separately
from the original `run/` and earlier `derivation/` and `revalidation/` records.
An offline decoder replay reproduced all three native listings and the
complete linked listing byte-for-byte; its [extraction receipt](decoder-replay/extraction.json),
[commands](decoder-replay/commands.json) and [comparison](decoder-replay/comparison.json)
are retained. The listings themselves remain in `../derivation/`.

Current sources are snapshotted here: [checker](check_ownership_trace.py),
[fixed checks](ownership_native_checks.py), [shared completion checks](native_receipt_common.py),
[regressions](test_ownership_native.py), [decoder preparer](prepare_ownership_inspection.py)
and [runner recipe](run_ownership_trace.sh). The runner snapshot is a future
recipe, not a claim that a new guest used it.

## Recheck offline

From the repository root:

```sh
make checker-tests
make evidence-recheck
make evidence
```

All are included in `make check`. They need no Docker, QEMU or downloads.
The 11 new ownership tests include internally consistent forged listings,
the review's mostly-NOP image with preserved spill/reload/call markers, every
non-NOP native word replaced in turn, all 56 gateway words replaced in turn,
wrong branch targets, map/envelope errors and broken cleanup instructions.
These constructed host records are checker tests, not runtime bypass evidence.

The native check supports only the reviewed little-endian, non-BTI/non-PAC
fixture layout. Linked checks require recorded zero relocation and the exact
reviewed compiled terminal-sequence offsets. Changed layouts require inspection
and checker updates, not automatic acceptance. Full kernel and toolchain
distributions remain external; the [global manifest](../../../publication-manifest.json)
checks publication integrity, not authenticity or semantic correctness.

The result remains synthetic native containment through production mechanisms.
It does not establish admission of stale BPF, callback release eligibility,
callback-local leak prevention, complete mediation, a compiler correctness
proof, hardware attestation or complete CVE mitigation.
