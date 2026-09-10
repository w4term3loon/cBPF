# Ownership boundary controls

This is a [publication copy](../../README.md). Paths are redacted; original
execution/source hashes are distinct from publication integrity hashes.

This study adds the missing controls around the existing protected ownership
path. The production resolver, wrapper/transition assembly, native compiler,
platform patch, and integration patch retain the earlier enforcement. Three init-only
trusted resolver checks are added before kfunc registration; a failed check
refuses registration. No verifier or native instruction mutation is introduced.

The fresh kernel build and first offline guest passed on 6 September 2026 in
`build/ownership-m3-run.l2BxDW`: four verifier-accepted executions, three trusted
resolver checks, and three verifier-only rejections. The runner checked all
38 ordered gate events and clean QEMU exit zero. Final native review passed.
**The boundary controls are complete within the scope below.**

## Decisive controls

| Control | Observed result | Evidence boundary |
|---|---|---|
| `ab_spill` | A/B distinct cells, A consumed, B reads 42, two releases, refs=1. | Repeats the original 26-instruction valid program. |
| `ab_alternate` | Same A/B result with different registers and forward NULL branches. | A second 27-instruction structural arrangement; no general compiler proof. |
| `null_second` | A acquired; B returns NULL without acquisition; A explicitly released; return 7, refs=1. | Existing production NULL branch. |
| `fail_second` | Second acquire argument 2 is rejected before its effect; A is cleaned up; return 0, refs=1. | Normally verified BPF; fixed terminal epilogue must skip all continuation effects. |
| Trusted `stale_copy` / `stale_spill` | Public alias remains tagged and canonical after A's private authority is cleared; resolver rejects the read without a read effect. | Init-only kernel C, no native BPF execution; spill is reloaded after consumption. |
| Trusted `duplicate_release` | Resolver rejects consumed A without a second decrement; refs remain 1. | A separate terminal trusted control. |
| Invalid BPF `stale_copy` / `stale_spill` / `duplicate_release` | Normal verifier rejects at load; none reaches `TEST_RUN`. | Unexpected acceptance aborts without execution. |

The original A/B native image matches the earlier execution's 660 bytes; the
alternate is 664 bytes, and NULL/failure are each 660 bytes. The four program
executions acquire six references and release all six: five explicit releases
and one cleanup release, with two reads. Each invocation restores refs=1.
The three trusted controls separately acquire/release one reference each.

The [kernel/model mapping](../../../theory/kernel-ownership.md) defines
`E = released - cleanup`, `D = cleanup`, and the completed-operation accounting
invariant. A `clear` event precedes the provider effect, so that intermediate
record is not a completed abstract transition.

The trusted stale checks explicitly establish a synthetic private kernel
state. They exercise the production resolver, not invalid restricted BPF.
The protected positive cases separately establish full-capability transport;
the real failure case exercises terminal native cleanup. These are distinct
observations supporting a conditional mediation argument.

Scalar 2 exercises pre-provider argument rejection, not forced allocation or
exact-bounds failure. Capacity/construction failure ordering remains inspected.
Nonzero cleanup on ordinary BPF return is not exercised: the unchanged
verifier rejects leaked references. Normal valid returns, the shared cleanup
loop, the model, and actual terminal failure cover their stated boundaries.
No arbitrary verifier/JIT fault tolerance, whole-kernel isolation, spatial
composition, or new CVE result is claimed.

## Retained evidence

`boot.log` is the raw guest log; `summary.txt` and `results.json` retain the
runner's checked selection. The `native-*.bin` files are bytes returned for
the four executed programs, checked against the emitted kernel words.
`source/` preserves the executed mechanisms and recipes; `kernel/` records
source/configuration/compiler/output identities and the full build log.
Large pinned kernel and toolchain dependencies remain outside the selection.
Original checksum digests remain recorded; host paths are redacted.

`audit/native-review.json` binds the final linked production and init-control
disassembly to the observations. The AI-assisted inspection evaluated changes
by another contributor within the same research environment and used the
retained run; this is not
external human review or independent reproduction. For decoding only, each
native binary was wrapped in an ELF object whose extracted `.text` matched
the original bytes. No inspection wrapper was executed.

`manifest.json` records original sizes and SHA-256 identities. `make check`
verifies publication integrity and existing local model/host checks without
repeating kernel execution. The earlier execution remains separately identified.

## Reproduction and preservation

`make ownership-kernel` and `make ownership-run` now use the separate
`build/ownership-m3-*` locations. Earlier build/source/headers/receipts remain separate,
and its original source/execution identities are retained in
[the protected execution selection](../ownership/README.md). The runner uses one offline virtual
CPU and accepts only the matching built artifacts and current source snapshots.

One preflight build was deliberately stopped to correct the trusted spill
ordering before any guest ran. Its files remain under
`build/ownership-m3-*.attempt1`. The interrupted local-reproduction start is separately
[preserved and deferred](../local-reproduction/README.md).
