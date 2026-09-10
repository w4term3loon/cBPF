# Ownership boundary-control design rationale

Date: 6 September 2026. Method: internal AI-assisted source inspection.
This pre-execution design rationale specifies control requirements; it reports no guest execution.

## Minimal sufficient controls

| Control | Required observation | Evidence limit |
|---|---|---|
| Alternate valid A/B arrangement | Normal load acceptance, changed register and forward-branch arrangement, fixed-gate native mapping, B read 42 after A consumption, two releases, baseline references | Demonstrates another member of the admitted grammar, not completeness of the compiler |
| Second acquire with `want_null=1` | A remains live at NULL, acquired stays one, no second bind, ordinary NULL branch releases A, result identifies the branch, references return to one | Demonstrates a NULL result with no new ownership |
| Second acquire with scalar argument 2 | Ordinary verifier acceptance; existing argument guard rejects at the second acquire before a provider increment; continuation contains observable gates and scalar sentinel but is skipped; executive epilogue and wrapper consume A once, cleanup=1, result=0, failed=1, references=1 | Actual restricted-native terminal failure and cleanup; does not dynamically force representability/capacity failure |
| Three trusted resolver controls | Separate private init-only states use production acquire and release, then reject consumed copy read, consumed volatile-spill read, and duplicate release; full public alias remains canonical/tagged while private object tag is zero; failed=1, reads=0, released=1, cleanup=0, references=1 | Trusted kernel resolver observations, not stale BPF execution or restricted-sidecar stale execution |
| Load-only stale BPF cases | Attributable normal-verifier rejection for stale copy, stale spill, and duplicate release; no execution; unexpected load success closes descriptor and aborts before test-run | Normal verifier enforcement remains intact; no runtime tolerance of verifier failure is claimed |

## Boundary decisions

- Existing `admit` accepts defined scalars for acquire; the production gate enforces the Boolean argument. Scalar 2 therefore reaches an already-existing defensive failure path without changing the verifier, instruction templates, or enforcement semantics.
- Keep each trusted stale control to one acquisition and release it before the rejecting call. No live provider references remain at rejection, so these checks need no new cleanup hook. Observations after failure are test-manager inspection, not continuation of modeled program operations.
- Normal verifier rules reject a BPF return with live owning references. Normal valid exits with zero live references plus an actual terminal failure with one cleanup release cover the reachable bounded kernel boundary. Nonzero cleanup on an ordinary return remains supported by the common-loop source argument and model, not a new native observation. Adding a hook solely to manufacture that case is unnecessary.
- All production failure branches in acquire precede the provider increment; source/compiled review must retain this ordering. The argument-2 runtime result supports one path only. Do not describe it as a failed exact-bounds construction or allocation test.
- Trusted controls should be init-only, take no externally supplied state/operation, use ordinary production gate effects to create consumed state, avoid writing cell liveness by hand, and stop each case at its first rejection. They must not become a BPF-callable mutation or execution interface.

## Assertions that matter

Retain exact source and kernel identities, unchanged-verifier evidence, normal load result and verifier output, BPF PCs, per-case native bytes matching the kernel transcript, gate-to-BTF mapping, branch targets, and ordered per-case gate counters. Require no unexpected gate events, malformed/duplicate result lines, warning/Oops/refcount warning, or unexpected negative-case acceptance.

For terminal failure, require `acquire(A) -> reject(second acquire) -> clear(A) -> cleanup(A) -> failed`, with no native continuation gate PC in between or afterwards. At the clear event the private tag is already zero and provider references remain two; at cleanup references become one. The reject event must still show acquired=1 and released=0. Inspect the linked gateway failure branch and shared epilogue as well as the trace: missing events alone cannot prove every scalar instruction was skipped.

For trusted spilled aliases, retain compiled full-capability store/load inspection. Do not equate that C stack location with the protected JIT sidecar; protected ownership execution separately exercises and inspects the sidecar transport.

## Conditional lemma mapping

Unforgeability and complete mediation remain capability/interface properties plus reviewed native-template obligations. Protected cell liveness and invalidation-before-effect have implementation and ordered trace support. Independent A/B behavior remains a protected native observation. Stale identity rejection gains direct production-resolver observations. Termination gains a real restricted-native failure result. Initial root/provider assignment, trusted C/assembly/compiler, inherited exception behavior, synchronous containment, and no cross-invocation alias escape remain premises. Tests do not constitute a kernel refinement proof.

## Evidence status

This record specifies control requirements and their interpretation. Source, build and runtime receipts separately identify the implemented controls and observed results; the rationale alone establishes no guest observation.
