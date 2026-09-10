# Historical array-map store comparison

Publication copy of the historical store study (V5); see [redaction and identity scope](../../../README.md).

Recorded result: 2026-09-02  
Canonical result: `experiment-result-v2.json`  
Canonical result SHA-256: `791ca42072c7b22616fdb20c28222dc4e5e0b43835e5cc81add2e100e9ce6ff8`

## Result

The preregistered V5 classification is
`bounded_fault_class_differentiation_supported`. Ten fresh boots ran once in
the frozen two-block order. The attempt terminal records exit status 0 and no
exception; every retained row is complete and claim-eligible.

| Mode | Block 1 | Block 2 |
| --- | --- | --- |
| Fixed calibration | verifier rejection; monitored bytes unchanged | verifier rejection; monitored bytes unchanged |
| Faulty baseline | adjacent key-1 effect completed | adjacent key-1 effect completed |
| Selected source-mapped AEE offset mechanism | branchless sanitizer executed `8 -> 8`; adjacent key-1 effect completed | branchless sanitizer executed `8 -> 8`; adjacent key-1 effect completed |
| cBPF exact | FSC `0x2a` at the mapped store before the effect | FSC `0x2a` at the mapped store before the effect |
| cBPF broad | adjacent key-1 effect completed | adjacent key-1 effect completed |

For every completed-effect row, key 1 changed from
`28292a2b2c2d2e2f3031323334353637` to
`2435465768798a9b3031323334353637`: exactly its first eight bytes changed.
Both exact rows retained all three 16-byte values unchanged.

The selected exact event `vs.replica.v5.b01.r04.exact` installs a tagged,
unsealed, load/store capability over
`[0xffff00000022fd10, 0xffff00000022fd20)`. The store attempts
`[0xffff00000022fd20, 0xffff00000022fd28)` at native PC
`0xffff8000814075dc`, word `0xe2c08274`, and reports ESR `0x9600006a`, FSC
`0x2a`, and zero completed bytes. The normalized record also retains exactly
two accepted class/provider handoffs and the independently reconstructed
protected-site set containing BPF instruction 14.

## Interpretation

- Research formulation: for one controlled case in which relevant `V.a`
  remains sound and only final `V.s` is overridden, selected
  approximation-authorized execution and broad authority complete the target
  effect, while exact independently assigned 16-byte capability authority
  faults first.
- Basic-CS formulation: the sanitizer permits offset 8 because it lies inside
  `{0,8}`; the separate displacement reaches the next element. A capability
  ending at byte 16 faults when the eight-byte store starts there.
- Evidence status: observed twice in a known-outcome, non-independent,
  randomized two-block QEMU replication, with source/image identities,
  normalized `V.a`, before/after bytes, and causal controls retained.
- Conditions: the frozen workload and fault isolation; the selected AEE offset
  mechanism only; mode-specific images; exact two-handoff Cape path; correct
  provider/live-element/extent/lifetime assignment; source/template-derived
  operand relation; checked-image immutability; and trustworthy telemetry.
- Falsifier: an eligible exact row changes a target byte; baseline or broad
  fails to make the exact effect; fixed accepts; relevant `V.a` differs or is
  unsound; the selected sanitizer fails to execute `8 -> 8`; or any bound
  identity/control fails.
- Does not establish: provenance as the sole causal variable; faithful
  whole-AEE behavior or prevention; general AEE behavior; arbitrary-verifier-
  defect tolerance; semantic object correctness; temporal safety; general
  verifier-trust reduction; net TCB reduction; native Morello performance;
  complete production refinement; blinded discovery; or independent
  reproduction.

## Correspondence boundary

The separately validated record `vertical-slice-correspondence-v1.json`
(SHA-256 `1fdaee84b8f3824f76346355fa4c2a1d485f372022f7b39ceaf0428e8dbba5d7`)
connects the selected event through 16 explicit links. It is eligible only as
a bounded conditional correspondence record. It keeps
`claim_eligible_as_closed_vertical_slice=false` because live post-check image
immutability, a direct capability-operand dump, semantic assignment/lifetime,
repository-contained build objects, complete production C/Linux refinement,
and independent reproduction remain open.

A no-write dry assembly that supplied this record failed closed because the
inherited assembler requested a legacy vertical schema absent from V5's frozen
schema allowlist. The failure is retained in
`research/faulty-vs-differential-v5/post-result-vertical-binding-failure-v1.json`.
The frozen runner was not changed or bypassed. Canonical assembly used its
allowed nullable-vertical path, so the canonical result truthfully records a
null vertical binding and `claim_eligibility.vertical_slice=false`. The
post-result package binds the correspondence separately.

## Software comparator and scope

The separately frozen matched trusted-software supplement remains applicable:
its exact width-aware half-open interval guard prevents the same selected
event in both checked boots, while both disabled controls complete the target
effect. It emits 30 additional words (120 bytes) in the retained image. That
result means architectural capability bounds were not necessary for this one
event-level outcome. It establishes no general software/capability equivalence,
dynamic cost, performance result, or TCB advantage.

## Validation and reproduction limits

The authority, gate, root, checker, handoff, certificate and cached integrated
Isabelle checks passed. Three validation failures were also retained: a
preboot-only check rejected an already-consumed run-control record; an isolated
trace test had an import-order dependency masked by the normal Make target;
and the old patch-0035 build receipt did not match the mutable descendant
build directory.

This is a hash-bound historical result. Build and runtime objects were external
to the historical source tree; exact source-release reconstruction and
independent reproduction are not established.

## Primary artifacts

- `experiment-result-v2.json`
- `collection/collection-session.jsonl`
- `collection/schedule-run-summary.json`
- `../result-v5-attempt-v1.jsonl`
- `vertical-slice-correspondence-v1.json`
- `research/faulty-vs-differential-v5/aee-post-result-ledger-v1.json`
- `research/faulty-vs-differential-v5/preregistration-v1.json`
- `research/faulty-vs-differential-v5/deployment-binding-v2.json`
