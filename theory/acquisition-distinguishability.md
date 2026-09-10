# Why the runtime must distinguish owning acquisitions

This argument identifies the information required to enforce the studied
eBPF acquisition contract. The
[design synthesis](../docs/research/related-work.md#source-lineage-and-design-rationale)
applies the same criterion to counterfactual spatial grants. The mathematical criterion is elementary;
the contribution is its precise application and connection to the protected
runtime representation and bounded evidence.

## 1. A criterion for a sufficient observation

Let `Q` contain otherwise-supported active read requests through aliases of
successful acquisitions, whether live or consumed. For `q = (sigma, read(h))`
in `Q`, `sigma` is the complete pre-decision context: abstract state, protected
monitor state, and relevant history. Its abstract component is at a completed
operation boundary. Define the total policy `P: Q -> {permit, reject}` to
permit a live acquisition and reject a consumed one. NULL, unsupported, and
non-acquisition reads are outside this proposition's domain. Permitting the
valid request is part of the contract; rejecting everything is not a solution.

Let `O: Q -> Omega` be a fixed total observation function containing **all**
information consulted by a deterministic runtime decision, including any
metadata, provenance, program position, or history.
An observation is sufficient to represent the decision exactly when

```text
O(q1) = O(q2)  implies  P(q1) = P(q2), for every q1, q2 in Q.       (1)
```

**Proposition 1 (decision representability).** A decision function `D` with
`D(O(q)) = P(q)` for every request in `Q` exists if and only if (1) holds.

**Proof.** Necessity follows because equal inputs to `D` have equal outputs.
For sufficiency, assign each observation in `O(Q)` the policy decision of
any request yielding it. Condition (1) makes this assignment well-defined.
Values outside `O(Q)` are irrelevant to this claim. This proves existence of
a decision function. It establishes neither computability nor efficiency,
trustworthy observation collection, complete mediation, nor correct execution
of the allowed effect.

The domain matters. These are requests against the abstract gate contract;
both need not be executable instructions of a verifier-accepted program.
Restricting `Q` to requests already proved live by a trusted verifier changes
the question. This argument supplies no reason to weaken that verifier.

## 2. The same live object is not the same owning right

Consider the valid abstract prefix

```text
acquire(A); acquire(B); release(A)
```

Both acquisitions name the same permanent object. At this completed boundary,
`n = 2`, `L = {B}`, one explicit release has occurred, and `rc = 2` including
the permanent baseline reference. Compare the alternative next requests
`read(A)` and `read(B)` from this **same** context:

| Observation or required result | `read(A)` | `read(B)` |
|---|---|---|
| Provider object, allocation liveness, object bounds | Same, still allocated | Same, still allocated |
| Object pointer type, invocation identity, aggregate `rc` | Same, `rc = 2` | Same, `rc = 2` |
| Acquisition named by the request | A, consumed | B, live |
| Required decision | Reject before the read | Permit the supported read |

**Corollary 1 (object-level observation is insufficient).** A gate that
identifies the requested pointer only by the common object attributes above,
and consults no additional acquisition-sensitive information, cannot satisfy
both decisions. Its observations coincide, whereas the required decisions
differ, contradicting (1).

The corollary includes a gate that also knows the total successful acquisitions
and aggregate releases: those are likewise common to both requests in this
context. Accounting establishes how many rights remain; it does not associate
the requested alias with a remaining right.

**Corollary 2 (identity plus totals is still insufficient).** Start from the
common prefix `acquire(A); acquire(B)`. Compare two alternative histories:
one consumes A, the other consumes B. Both end with `n = 2`, one explicit
release, and `rc = 2`. Query `read(A)` in each resulting active context.
An observer retaining only A's immutable identity, the common object
attributes, and aggregate counts sees equal observations. Yet A is consumed
in the first context and live in the second, violating (1). Thus an identifier
must be associated with current validity, whether through protected state,
provenance, or relevant history. The histories are alternatives, not steps
following a trap.

Protected register provenance, a verifier-derived identity, side metadata,
or an acquisition capability may supply the needed distinction. The argument
does not require private cells, CHERI, a particular encoding, or a metadata-bit
lower bound. It does not diagnose a vulnerability in a complete system.
The two requests are alternatives: rejection of A ends that execution; B is
not subsequently used after a trap.

## 3. How the existing cBPF gate supplies the distinction

The conditional [kernel/model mapping](kernel-ownership.md) already identifies
acquisition `i` with private cell `i-1`. For cell index `j`, write `v_j` for
its canonical public capability and `live_j` for its stored object capability's
tag. In an entered, nonfailed invocation, the supported read decision under
that mapping is

```text
permit(h)  iff  there exists j with 0 <= j < acquired:
                   exact_equal(h, v_j) and live_j.
```

Views are distinct, protected, and never reassigned inside the invocation.
Copies and the supported full-capability spill preserve the view's identity.
The resolver matches the complete public capability using its own protected
table, then checks private liveness before loading the object field. Consuming
A changes its private tag; public aliases retain their identity, and B's
private tag is unchanged. Thus the representation separates exactly the two
requests in Corollary 1, under the existing freshness and mapping premises.

| Obligation | Existing source and evidence | Limit |
|---|---|---|
| Bind the requested alias to its acquisition | [`cbpf_gate_impl`](../linux/ownership/cbpf_runtime.c), canonical-view search, lines 133–140; protected ownership execution and boundary controls full-capability A/B transport | Correct protected state, membership and transport remain premises of the mapping. |
| Consult that acquisition's current validity | Same resolver checks the private object tag before the load, lines 138–144; ownership boundary controls consumed-copy/spill checks | Rejection is observed in trusted init-only resolver calls, not invalid native BPF. |
| Preserve independently live B | [`cbpf_consume`](../linux/ownership/cbpf_runtime.c), selected-cell tag clear before decrement; ownership boundary controls `ab_spill` and `ab_alternate` return 42 | The accepted native controls contain no stale A use. |
| Ensure every supported effect uses this decision | Fixed gates and bounded native path in the [mapping](kernel-ownership.md) and [native review](../evidence/current/ownership-closure/README.md) | Decision representability alone proves no compiler/kernel refinement or whole-kernel isolation. |

These observations are complementary, not one combined execution of the two
alternative requests.
The existing induction establishes protocol preservation under its premises;
the existing object-wide-consumption mutant demonstrates one failed design.
Corollary 1 instead excludes the defined class of indistinguishable observers.

## 4. Acquisition-sensitive validity

Runtime enforcement of the studied eBPF acquisition contract requires the
gate to distinguish a consumed right from an independently live acquisition
to the same object. Object-level observations cannot represent the two
required decisions. The protected acquisition representation supplies the
missing distinction under the stated mapping premises. This is a protocol
argument, not a demonstrated mitigation of a named CVE.

Acquisition identity and shared invalidation are prior art. The focused
comparison below concerns the unit represented by each mechanism, not a
security ranking or a claim that another complete system lacks checks.

| Mechanism | Unit represented / enforcement stage | Relevance to the A/B distinction |
|---|---|---|
| Linux kfunc verifier | Symbolic owning reference identity, tracked at load time | Already distinguishes acquisitions and invalidates matching aliases. The runtime representation is not an invention of that contract. |
| CETS | Per-pointer metadata containing an allocation key and shared lock; runtime temporal checks | Pointers to the same allocation share allocation identity. Allocation liveness alone does not distinguish two owning rights while that allocation remains live. |
| HIVE, June 2026 author description | Pointer-value authentication with invocation/type modifier at runtime | The described modifier is not an acquisition identity. A same-address, same-type, same-invocation comparison motivates the observation question; it does not assess all HIVE mechanisms or versions. |
| Studied cBPF ownership profile | Canonical acquisition view plus protected private liveness, checked by a runtime gate | Distinguishes A/B despite a shared provider object, conditional on the declared mapping and mediation premises. |

Sources: [Linux 6.7 kfunc contract](https://docs.kernel.org/6.7/bpf/kfuncs.html#kf-release-flag)
and [verifier source](https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/verifier.c);
[CETS, §§3.1–3.3 and Figure 2](https://people.cs.rutgers.edu/~sn349/papers/ismm10-cets.pdf);
[HIVE author update, June 2026](https://ebpf.foundation/research-update-isolated-execution-environment-for-ebpf-part-3/).
This focused comparison supports contribution positioning, not a verified
first-in-literature claim. The spatial study remains separate: correct value
bounds do not encode acquisition consumption, and acquisition validity does
not establish correct spatial assignment. The separate [spatial native witness](../docs/results/spatial-native-result.md)
addresses native correspondence for one spatial program.

## 5. Failure precision without another experiment

The acquire branch checks arguments, capacity, and both exact capability
constructions before `refcount_inc`, cell/view publication, and `acquired++`
([runtime](../linux/ownership/cbpf_runtime.c), lines 104–123). A failed attempt
therefore creates no new identity, publishes no new view, and adds no provider
reference. This source-level argument assumes intact protected state,
synchronous execution, and the existing construction/publication assumptions.

Failure can still set `failed` and update trace state. Terminal cleanup can
consume earlier live acquisitions and reduce the reference count. Therefore
the correct postcondition concerns the **attempted acquisition's effects**;
it is not “no state changes” or “the reference count never changes.” The
wrapper cleanup is in `cbpf_test_invoke` (retained ownership boundary controls lines 279–294). Ownership boundary controls dynamically exercises argument
rejection and subsequent cleanup, while exact-construction/capacity failures
retain their source/model basis.

The [software comparison](../docs/research/capability-comparison.md) supplies a concrete
alternative realization using protected register/spill shadow tags and
per-acquisition entries. It satisfies the observation requirement under its
stated premises without requiring CHERI. The current native representation
and its architectural benefits are distinct from this policy-level necessity.
