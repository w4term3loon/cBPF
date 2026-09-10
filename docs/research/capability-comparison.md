# What CHERI contributes to the cBPF policies

**CHERI is not logically necessary for either abstract
policy.** A protected software monitor can enforce selected-value access and
per-acquisition validity. CHERI supplies architectural authority and access
checks; cBPF studies their binding to eBPF effects. This analytical comparison
does not implement the alternative or establish native bisimulation.

## A concrete software alternative

Consider a trusted interpreter for the same bounded operations, retaining
the ordinary verifier. The input is bytecode, not arbitrary native code. The
interpreter owns protected shadow tags for virtual registers and spill slots;
these identify invocation-local descriptor entries. Scalar instructions cannot
create tags, change entries, or turn a guessed integer into a handle. Copy and
supported spill/reload operations preserve the complete shadow identity.
Scalar overwrites clear the corresponding shadow tag.

For spatial access, the trusted provider resolves the actual map/key and
creates a descriptor `(v,n,P)` for logical interval `S=[v,v+n)` and scalar-data
permissions `P`. Stride locates the value; logical size determines its bound.
Every load/store checks the operand's shadow identity, requested permission,
and full access width. For offset `o` and width `w>0`, the non-wrapping check
is `0 <= o`, `w <= n`, and `o <= n-w`, before forming and using the address.
Data memory cannot supply pointer tags. Unsupported operations terminate.

For ownership, every successful acquisition creates a fresh entry with an
object association and private live bit. Public aliases identify that entry.
Every read/release checks provenance, membership and liveness. Release clears
the bit before the provider decrement; consuming A leaves B unchanged even
when both name the same object. Entries are not reused within an invocation.
Failure prevents the attempted effect and terminates execution; trusted
cleanup consumes remaining live entries once. No alias escapes teardown.

Both designs assume correct provider assignment, protected state, synchronous
non-reentrant operation, correct effects and complete mediation. Spatial
allocation lifetime and ownership's permanent baseline reference remain
premises. The interpreter must prevent bytecode access to its metadata and
must execute every operation through its decoder/checks. A native software
version would additionally need justified instrumentation, control-flow and
memory isolation. The existing host C model is not such an isolation result
against hostile native code.

## An abstract state correspondence

Compare spatial and ownership policies separately. Fix the same admitted
grammar, acquisition budget `K`, provider outcomes and preparation success;
restrict spatial comparison to commonly supported, exactly representable
grants and operations. Relate a tagged, unsealed
capability with bounds `S`, cursor `v+o` and permissions `P` to a valid shadow
reference carrying the same descriptor and offset. Copies preserve the
relation. The software predicate and capability bounds/permission rule give
the same policy eligibility for that byte interval and scalar operation.
Invalid provenance or insufficient authority denies the attempted effect.
Other architectural faults, alignment effects, availability differences and
execution traces are not compared.

For ownership, relate canonical capability `view(i)` to shadow handle `h(i)`;
relate the private object's tag to entry `i`'s live bit. Require identical
alias identities, object associations, effect counters and active/terminal
status. The relevant cases are:

| Operation | Matching abstract consequence |
|---|---|
| Successful acquire / NULL | Fresh live identity and one reference increment / no identity or increment. |
| Copy, spill, reload | Same acquisition identity; no liveness change. |
| Read | Permit exactly a live acquisition; preserve ownership state. |
| Release | Clear only that acquisition before one decrement; consumed aliases reject. |
| Return or failure | End execution and consume remaining live acquisitions through cleanup. |

This case analysis compares the [abstract rules](../../theory/ownership.md) under
the stated relation. It establishes no compiler refinement, verified
interpreter, concurrency, cross-invocation reuse or profile-composition result.

## Enforcement, faults and retained trust

| Claim / effect | Software alternative | cBPF capability mechanism | Fault boundary and retained trust |
|---|---|---|---|
| Access stays inside selected `S` | Descriptor bounds/permission check at every access. | Exact grant; architectural check on the actual capability operand. | A wrong runtime offset is contained under either check. Wrong grant assignment is not; provider facts remain trusted. |
| Scalars cannot fabricate a right | Protected shadow tags and mediated copies/spills. | Architectural tags, monotonic derivation, canonical ownership membership. | Neither prevents a trusted component issuing the wrong right. Metadata and transfer paths must remain protected. |
| Consumed A rejects; B remains live | Per-entry live bit checked before effects. | Private-tag state checked by the software gate. | Bounds alone do not encode acquisition validity. Correct identity/state association and ordering are required. |
| Ownership rejection prevents continuation | Interpreter stops; trusted cleanup follows. | Checked gateway/epilogue or trusted callback dispatcher stops. | An unchecked entry or effect defeats mediation; architecture alone does not establish the whole path. |

## Architectural value and actual evidence

CHERI tags distinguish capabilities from ordinary bits; ordinary derivation
cannot enlarge authority. Hardware enforces the bounds and permissions carried
by its capability operand. These are established architectural properties.
[CHERI introduction, §§2.2–2.6](https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-941.pdf).

The reduced spatial grant permits scalar `LOAD|STORE|GLOBAL`, excluding
capability loads/stores and execution. [spatial native witness](../results/spatial-native-result.md) connects its returned
capability to two actual operands. It retains vmalloc-wide RDDC and broader
gateway authority, so it does not establish all-program mediation. The
[ownership profile](../../theory/kernel-ownership.md) instead records untagged
restricted DDC, bounded entry/stack and full-capability alias transport.
[trusted callback witness](../../evidence/current/ownership-callback/README.md) confirms transport through
trusted executive C callbacks, which are not isolated from private state.
Ownership remains a software lifetime manager: public aliases retain their
tags after consumption and are rejected through private state. There is no
automatic global revocation.

## Relationship to existing approaches

**Software bounds checking:** SoftBound separates pointer metadata from data
and checks accesses. The alternative above adds a lookup-selected descriptor
and ownership protocol; this is not a SoftBound eBPF implementation.
[SoftBound, §§3–4](https://people.cs.rutgers.edu/~santosh.nagarakatte/papers/pldi09_softbound.pdf).

**CETS** propagates allocation keys and shared lock locations with pointers,
assuming spatial safety. cBPF's validity instead denotes an acquisition of a
still-live object. Shared invalidation is established; software keys/locks
can also represent acquisitions.
[CETS, §§3.1–3.3](https://people.cs.rutgers.edu/~sn349/papers/ismm10-cets.pdf).

**AEE** already provides object-granularity eBPF spatial enforcement. It checks
execution against verifier approximations while trusting static safety checks
`V.s`; Arm pointer authentication protects its spill/fill metadata. cBPF's
conditional basis is a correct provider grant and its actual use, with
construction and mediation obligations still trusted; a different proof basis
does not itself establish stronger protection.
[AEE, §§5, 7.3 and 8](https://www.usenix.org/system/files/usenixsecurity25-sun-hao.pdf).

**Ordinary Linux verification** already requires release/transfer accounting
and invalidates aliases after `KF_RELEASE`. cBPF retains it and adds bounded
runtime enforcement; it does not introduce the ownership contract.
[Linux 6.7 kfunc contract](https://docs.kernel.org/6.7/bpf/kfuncs.html#kf-release-flag).

## Costs and conclusion

The Morello realization transports 128-bit capabilities, requiring full-width
register/spill preservation and suitable alignment. Exact bounds can fail;
the provider rejects rather than widens, reducing accepted layouts relative
to an unconstrained descriptor. Ownership still needs protected cells,
membership/liveness checks and cleanup. Software needs shadow storage and
per-operation checks. Neither implementation's total cost is measured here.

Current evidence cannot rank actual program security, performance or
trusted-base size. The contribution is the bounded eBPF authority mapping
and inspected effects, with explicit [trust obligations](trust-taxonomy.md).

## Direct predecessor and revocable proxies

Leaf's Morello RFC already identifies capability-aware BPF execution, native
transitions and ABI constraints. Miller and Shapiro's caretaker pattern
provides revocable access through protected state. Selective revocation is
therefore established; cBPF's contribution is its coupling to counted
acquisitions, native transport and ordered effects. See
[related work](related-work.md#direct-predecessor-and-revocable-proxies) for the
primary sources, inherited mechanisms and inference boundary.
