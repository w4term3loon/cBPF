# Trusted callback witness

This is a [publication copy](../../README.md). Source/recipe paths are redacted;
original build hashes remain historical identities.

**The two controls passed on 7 September 2026** in one fresh offline Morello
guest. Final linked inspection and retained identities accompany the result.
The callback witness adds 114 net runtime lines for init-only controls and their registration
guard. The production gate, wrapper/assembly, compiler, guest loader and
integration/platform patches are unchanged from the ownership boundary controls.

## Decisive observations

One invocation and one context retain full public acquisition capabilities
through actual C function-pointer callback calls. Both controls use the
production `cbpf_gate_impl` and the same permanently allocated provider object.

| Control | Observed outcome | Accounting |
|---|---|---|
| `retained_release` | First callback consumes A. Second reloads the same tagged canonical alias, sees private tag zero and rejects. Planned third callback never enters. | 2 entries, 1 completion, 1 acquisition, 1 release, 0 reads, 0 cleanup, refs=1. |
| `independent_b` | First callback consumes A; second reads B=42 and consumes B. Both acquisitions name the same object through distinct cells. | 2 entries/completions, 2 acquisitions/releases, 1 read, 0 cleanup, refs=1. |

The exact callback trace is at [boot.log](run/boot.log), lines 245–266. The
[results](run/results.json) also record the reused boundary controls: four accepted
native executions, three trusted resolver checks and three load-only verifier
rejections. No invalid BPF executes. The guest powers off cleanly with QEMU
exit zero. One virtual CPU, no network and no shared host filesystem are used.

## Source and effect correspondence

The [source delta](review/source-delta.json) checks the unchanged production
components against retained boundary-control sources. The
[linked review](review/linked-review.json) identifies real indirect dispatch,
full-capability context loads and preservation across calls, persistent
invocation state, and termination before another callback on rejection. It
also checks the production resolver's membership/liveness decisions and
private-tag invalidation before provider decrement. The accompanying
[disassembly](review/runtime-linked-disassembly.txt) permits direct inspection.
This is internal source/linked-code review, not an independent compiler proof.

`source/` retains publication snapshots of the runtime, compiler, patches,
header, guest, BTF IDs and recipes. `build/` retains the configuration, pinned source
commit/tree, compiler/image identity, verified inputs/sources and kernel output
hashes. `run/` retains the console, parsed outcomes, four native BPF images,
BTF selection and launch-input identities. Full kernel/build artifacts and
cached toolchain remain external under `build/ownership-c1-*`; hashes do not
establish portable reproduction or authenticate every external dependency.

The base is official Morello Linux commit
`b96da308ef1a054c3c04c9445e5ed70259b7c397`. The verifier remains byte-identical
to that base (SHA-256
`48268a29931754296882a9ff6847eb556ba8e8564959be1c62754afdb2fb4851`).
The configuration retains the existing protections; no historical verifier
weakening or vulnerable-program execution is imported.

## Interpretation and reproduction

The witness demonstrates trusted C callback transport (`native_bpf=0`). These
callbacks run in executive kernel mode; they are not isolated from private
state. The result does not establish protection against a malicious callback,
protected BPF callback support, original CVE/helper execution, Linux's
callback-frame ownership policy, concurrent or cross-invocation validity,
reference-leak prevention, or heap reclamation. Public aliases remain tagged;
the gate rejects their consumed private acquisition state.

The [CVE argument](../../../docs/ownership-cve-case.md) explains relevance to
CVE-2022-50650 and the difference from its upstream repair. The
[trust taxonomy](../../../docs/trust-taxonomy.md) separates architectural
checks from construction, mediation and lifetime premises.

From the repository root, `make ownership-kernel` followed by
`make ownership-run` reproduces the bounded experiment using cached
dependencies; preserve existing generated directories first.
`python3 tools/verify_evidence.py` checks publication identities. `make check`
performs portable checks and publication integrity only. The earlier boundary
controls and ownership case retain separate original identities and scope.
