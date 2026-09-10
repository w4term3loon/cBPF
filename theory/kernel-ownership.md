# Mapping the ownership argument to the bounded kernel path

This is a source-level correspondence argument for the existing
[ownership model](ownership.md#three-invariants-and-induction-argument), not a
new theorem or a refinement proof of C, the verifier, JIT, or native code.
The [protected ownership execution receipt](../evidence/current/ownership/README.md)
establishes its one protected A/B execution. Ownership boundary-control
requirements below are distinct from observations; the
[ownership boundary controls receipt](../evidence/current/ownership-closure/README.md)
records their execution status and source identities. The later
[synthetic native trace](../docs/results/ownership-native-trace.md) observes the
stale-failure conjunction through the same production mechanisms.

## State correspondence

The [runtime](../linux/ownership/cbpf_runtime.c) holds one private
`struct cbpf_invocation`, two `struct cbpf_cell` entries, and one permanent
provider object of value 42 and baseline reference count one.

| Abstract state | Concrete representation |
|---|---|
| `n` | `state.acquired`, the number of successful acquisitions. |
| Identity `i` | Cell index plus one: `i = index + 1`; its canonical public capability is `state.views[index]`, not the provider object's address. |
| `L` | Identities below `n` whose private `cells[index].object` capability remains tagged. |
| Register/spill aliases | Full public capabilities copied by native capability moves and stored/reloaded through the one 16-byte stack sidecar. |
| `E = sum_i E[i]` | `state.released - state.cleanup`: explicit provider release effects. |
| `D = sum_i D[i]` | `state.cleanup`: terminal-cleanup provider release effects. |
| `rc` | `refcount_read(&cbpf_object.refs)`. |
| Terminal state | Failure sets `state.failed`; the gateway enters the fixed epilogue. Normal return also reaches that epilogue; the wrapper tears down the invocation. |

The kernel stores aggregate counters; per-identity effects are identified by
cell transitions and trace IDs, not by concrete arrays of `E[i]` and `D[i]`.
At completed operation boundaries the target equation is
`rc = 1 + n - E - D = 1 + |L|`. A `clear` trace precedes the provider decrement:
that intermediate point is not a completed abstract operation boundary.

## Transitions and mediation

`cbpf_gate_impl` operation 1 checks its argument, capacity, and exact public
and object capability construction before incrementing the provider count.
Success publishes the next cell and canonical view; NULL returns zero without
creating an identity or changing `n` or `rc`. The runtime accepts Boolean
arguments 0/1; the compiler admits scalar arguments whose values the gate checks.

Operations 2/3 first compare the full public capability with an invocation's
canonical view, then check its private object's tag. Only then may read load
the scalar field, or release call `cbpf_consume`. Consumption clears the stored
tag before decrementing the provider count. Public aliases retain their tags
and identities; a consumed A therefore fails liveness while independent B
remains eligible. This consumes one acquisition, not the object's allocation.

`cbpf_fail` returns `CBPF_FAILURE` and sets the terminal flag. The native
gateway selects the executive epilogue rather than the next program operation.
That epilogue scrubs program-accessible registers and the sidecar; `cbpf_test_invoke` then
consumes each remaining live cell as cleanup, scrubs cells/views, and clears
the per-CPU active context. No program operation follows terminal failure.

## Premises and their implementation status

| Premise | Basis and remaining condition |
|---|---|
| Fresh acquisition identity | **Interface/check:** `K=2`, a monotonically increasing cell index, no cell reuse within an invocation. Later arena reuse requires the invocation-containment premise. |
| Unforgeable identity and protected state | **Architecture/check:** exact tagged `LOAD\|GLOBAL` public views, full-capability equality, private cell authority, and private-tag validation. Public views have no store or capability-load permission. |
| Complete mediation | **Interface/inspection:** the [bounded compiler](../linux/ownership/cbpf_jit.c), fixed gateway, restricted roots, checked instruction templates, and scalar-only exit. Source/native inspection must establish that admitted uses cannot bypass the gates. |
| Correct assignment and provider effects | **Trust/check:** executive DDC and the trusted provider select the intended permanent object; exact bounds/permissions are checked. Bounds do not prove semantic assignment or allocator provenance. |
| Synchronous ordered consumption | **Interface/trust/inspection:** one unattached test invocation, non-reentrant per-CPU state under disabled local bottom halves, and stored-tag invalidation before decrement. No concurrent revocation claim follows. |
| Invocation containment | **Interface/inspection/trust:** attachment/export exclusions, fixed terminal epilogue, program-accessible register/sidecar scrubbing before arena teardown, and trusted kernel/compiler/architecture behavior. |

## Ownership boundary controls and precise coverage

The [guest](../linux/ownership/guest.c) and
[runner](../tools/run_ownership.sh) specify the following decisive controls.
All execution results belong in the linked receipt, not in this mapping.

| Control | Required observation and bounded meaning |
|---|---|
| Trusted `stale_copy`, `stale_spill`, `duplicate_release` | Three separate init-only local states call the production resolver: acquire A, retain an exact copy or store a full capability, release A, reload the spill when applicable, then attempt one stale read or duplicate release. Require intact tagged/canonical alias, private tag zero, `CBPF_FAILURE`, terminal flag, `n=E=1`, `D=reads=0`, and `rc=1` already before rejection. |
| Protected `ab_spill`, `ab_alternate` | Normally verified native BPF transports full copied/spilled capabilities, consumes A, reads B=42, and releases B. The alternate register/branch arrangement tests structural admission. These programs contain no stale operation. |
| Protected `null_second` | Acquisition argument 1 returns NULL with no second identity/provider effect; the branch explicitly releases A and returns 7. |
| Protected `fail_second` | The normally verified scalar argument 2 reaches the existing production rejection before a second acquisition effect. Require immediate native termination, cleanup of live A, scalar result zero, `n=D=1`, `E=reads=0`, and `rc=1`; no later BPF operation runs. |
| Invalid BPF ownership controls | Stale copy, stale spill, and duplicate release are load-only verifier rejections. Unexpected acceptance aborts the loader without `TEST_RUN`; these are not native stale-use executions. |

The trusted checks explicitly initialize `entered=true` with no native
program; they are resolver observations, not evidence of protected entry or
native alias transport. Their logs identify `native_bpf=0` and
`scope=trusted_resolver`. Each stops after rejection. If a control unexpectedly
fails, trusted teardown releases held references directly, scrubs local state,
and refuses kfunc registration.

Normal return with nonzero cleanup remains inspected/modelled only: the
unchanged verifier rejects leaked references before such a program can run.
Exact-bound construction and capacity failures are inspected pre-effect paths,
not injected runtime coverage. These controls neither transfer the model proof
to machine code nor establish arbitrary verifier/JIT-failure tolerance,
whole-kernel isolation, or composition with the separate spatial study.

## Synthetic native trace: integrated failure and cleanup

The default-off test overlay supplies fixed trusted instruction descriptions
to the actual restricted compiler. It does not modify verifier policy,
production gate decisions or provider effects. All three fixtures use the
production restricted entry, capability spill/reload, sealed gateway, common
epilogue and `cbpf_test_invoke` cleanup wrapper.

The positive fixture consumes A, reads B=42 and consumes B. Each negative
fixture executes that prefix through the read of B, then presents the retained
A alias at PC 17 for a stale read or repeated release. At rejection the public
alias is tagged and canonical, its private object tag is zero, and no requested
effect occurs. Terminal return skips PC 19; cleanup consumes B once. In model
terms, both negatives finish with `n=2`, `E=1`, `D=1`, `reads=1`, `rc=1` and an
empty live set. This is one observed realization of the transition sequence,
not a refinement proof.

Three matching BPF programs remain load-only normal-verifier controls. Their
argument-shape rejections establish admission behavior only and authorize no
execution. The native fixtures are therefore synthetic trusted validation,
not stale verifier-admitted BPF, callback execution or runtime-state injection.

## Trusted callback witness: persistence across trusted callbacks

Trusted callback witness extends the observation boundary with synchronous trusted C callbacks. It
does not extend the accepted BPF grammar. One `cbpf_invocation` and one context
containing full public capabilities span the entire dispatcher call. There
is no new acquisition, cell reuse or liveness reset between callbacks. Each
read/release reaches the existing `cbpf_gate_impl`; a failed callback makes
the dispatcher return immediately, followed only by trusted observation and
teardown.

Under these premises, a callback boundary is a stuttering step for ownership
state: it creates no owning right and changes no cell. Composing callback
operations therefore preserves the existing consume-once invariant. Once A
is consumed, its retained context alias still identifies the same non-live
cell. A subsequent release must fail before another provider decrement. An
independent B remains live until its own consume or terminal cleanup. This is
an application of the existing induction, not a new C/native refinement proof.

Two controls are sufficient for the implementation question: a planned
three-call dispatch stops at the second request with one release, and a
two-call A/B dispatch reads B=42 after A consumption. Their execution status
is recorded separately in the [trusted callback witness receipt](../evidence/current/ownership-callback/README.md).
The callbacks run in trusted kernel C with broad executive authority; this
experiment does not establish protected BPF callback transport, original
helper scheduling, verifier frame ownership or protection from a malicious
callback. The permanent provider excludes reclamation consequences.

Trusted executive stack saves are not explicitly erased by the gateway.
The scrub claim covers program-accessible registers and the sidecar, with
trusted-stack inaccessibility retained as a premise; it does not assert
erasure of every physical capability copy.
