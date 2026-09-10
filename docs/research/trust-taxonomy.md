# Where cBPF's guarantees come from

cBPF distinguishes **predicting state, deciding what is
allowed, constructing authority and enforcing it at the effect**. This taxonomy
locates those obligations in the existing arguments; it adds no native theorem.

## Three meanings of a bound

Let a lookup select the logical byte interval `S = [v, v+n)`. Let `o` be a
program's offset, `w > 0` an access width, and `I` the verifier's predicted
set of possible offsets. These are different facts:

| Quantity | Meaning and origin |
|---|---|
| `I`, predicted offsets | An abstract fact calculated from instructions, branches and tracked register/stack state. It is a prediction about execution. |
| `S`, selected value | The interval assigned by the API operation: actual map identity, checked key, layout and logical `value_size`. Correct kernel metadata and provider interpretation are premises. |
| `B`, capability bounds | The interval encoded in the capability used by the native access. Construction must establish `B = S`; hardware checks accesses against `B`. |

For example, with `n=16` and `w=4`, the legal relative offsets are `0..12`.
A static argument about `I={0}` does not itself constrain an actual offset
of 20. An exact capability for `S` excludes that access when it is the root
actually used. Conversely, bounds containing the surrounding allocation can
admit bytes outside `S`. These are mathematical examples, not execution results.

## AEE's terminology and comparison

AEE calls the verifier's state-approximation component `V.a` and its checks
over that approximation `V.s`. It enforces relevant runtime values against
the approximations, retaining trust in `V.s` and the enforcement. Thus it
does not assume `V.a` soundness for its stated spatial guarantee. Its own
counterexample shows that correct approximations do not rescue an unsound
`V.s`. AEE already provides object-level enforcement and uses Arm pointer
authentication for spill/fill metadata; it is not purely software isolation.
[AEE, §1/Eqs. 3–4, §5, §7.3/Fig. 13 and §8](https://www.usenix.org/system/files/usenixsecurity25-sun-hao.pdf).

For cBPF's covered access, the alternative proof basis is a correct grant
`B=S`, actual use of that capability or a monotonic derivative, and correct
architectural enforcement. This is a comparison of conditional arguments,
not evidence that the complete cBPF implementation tolerates every verifier
failure or has a smaller trusted base.

## The trust layers

These responsibilities can share source routines. Provider runtime validation
is not automatically part of AEE's `V.s`, which denotes verifier safety checks.

| Layer | Responsibility | What remains necessary in cBPF |
|---|---|---|
| **Approximation (`V.a`)** | Track possible values, pointer categories and path/stack state. | Numeric interval soundness is unnecessary for the spatial lemma once grant/use premises hold. The implementation still retains the verifier. |
| **Verifier safety checks (`V.s`)** | Check the abstract state against rules for regions, argument types and other operations. | Correct rules and inputs are distinct obligations. A wrong bounds decision cannot enlarge a correct capability, but may affect admission, translation or paths outside the lemma. |
| **Provider assignment and construction** | Resolve the actual map/key, determine the intended interval, derive exact authority and check its representation. | Correct map association, metadata, arithmetic, lifetime and retained root. A valid capability can encode the wrong grant if these premises fail. |
| **JIT, gateway and execution binding** | Preserve authority through translation, entry, calls, copies and the actual operand; execute the inspected image. | Correct translation/control flow, intact images and trusted transitions. Exactness proves nothing about an access using another root. |
| **CHERI enforcement** | Check tag, bounds and permissions for capability-relative accesses; constrain ordinary derivation monotonically. | Correct architecture and actual use of the checked authority. The hardware does not know the intended map key or whether an owning reference was consumed. |
| **Ownership lifetime manager** | Associate each successful acquisition with protected validity, resolve aliases and consume a right before its provider effect. | Correct software protocol, identity transport, state protection, synchronous ordering and terminal cleanup. Allocation bounds alone do not express this state. |
| **Complete mediation** | Ensure every effect within the claimed boundary passes through its required authority/check. | Exclude alternative roots, unchecked calls, escaping object capabilities and unintended entries. This is a cross-cutting premise, not another bound encoded by hardware. |

The Linux examples are grounded in the pinned
[v6.7 verifier](https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/verifier.c):
`adjust_scalar_min_max_vals`, `check_cond_jmp_op`, `check_mem_region_access`
and `check_map_access`. The cBPF source/effect mappings and retained source
identities are detailed in the [causal analysis](../results/causal-review.md). CHERI's
architectural obligations follow its
[bounds, permissions and monotonicity rules](https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-941.pdf).

## Provider facts are not inferred register intervals

The [array provider](../../linux/spatial/array-authority.patch) checks the gateway's
map-table token, key capability's four-byte read authority, plain array profile,
retained root and actual `u32` index below `max_entries`. Stride locates the
value; logical `map->value_size` bounds it, excluding padding and other values.
Exactness, tag, cursor, base and permissions are checked before return.

`value_size` comes from map creation metadata, not an inferred scalar interval;
its layout and continued integrity are premises. `cbpf_map_area_alloc` derives
the initial root from executive DDC after allocation: this is checked
construction, not allocator-minted provenance.
The [spatial native witness source identities](../../evidence/current/spatial-native/build/patched-sources.sha256)
pin this provider, allocation and gateway implementation.

## Quantifiers and fault-specific guarantees

For any live selected interval `S`, any checked exact capability `C` for `S`,
and any architectural access of positive width through `C` or a monotonic
derivative, [spatial premises 1–4](../../theory/spatial.md#definitions-and-premises)
imply:

```text
correct selected interval and exact grant
  + actual access through that grant or a monotonic derivative
  + correct CHERI enforcement
  => every successful covered access lies within the selected interval.
```

The quantifier ranges over accesses satisfying those premises; it does not
establish that every generated access satisfies them. Extending the conclusion
to every access of every admitted program requires a separate complete-mediation
argument. Numeric interval soundness is absent from the conditional proof:
an incorrect prediction `I` cannot enlarge correctly assigned `B=S`. This
does not assert that arbitrary verifier faults preserve the grant/use premises.

**Assumed:** intended map/key association, intact metadata, allocation lifetime,
image integrity and correct architecture. **Inspected:** provider checks,
linked return transport and spatial native witness's two actual addressing operands. These are
separately examined obligations, not inferred from return value 42.
**Observed:** the [logical extent discriminator](../results/logical-extent.md) records
length seven with stride eight and valid byte-six use. The later
[selective matrix](../results/spatial-selectivity.md) records 30 matched
load/store outcomes: exact-seven rejects padding, the next slot and a crossing
access while wider controls selectively permit them. The earlier eight-byte witness remains separately recorded.
Its vmalloc-wide RDDC and broader gateway authority prevent treating that
witness as general bypass exclusion. [spatial native witness](../results/spatial-native-result.md) did not attempt an
out-of-bounds access. The [historical comparisons](../results/causal-review.md#what-the-historical-comparisons-establish)
record exact/broad outcomes for their particular stages and source/configuration
epochs; neither those observations nor their hashes prove all-program coverage.

| Fault or condition | Conditional conclusion and evidence boundary |
|---|---|
| Wrong numeric prediction, but correct `B=S` and actual use retained | Every out-of-range architectural access through that authority fails to complete its data effect. This follows from the lemma; no new faulty-verifier execution is claimed. |
| Wrong map/key association or oversized grant | Hardware enforces the supplied bounds, not the intended API interval. Semantic assignment or exactness has failed; the selected-value conclusion does not follow. |
| Different native root or unchecked gateway | Actual-use/mediation has failed. Exactness of another capability supplies no guarantee for this access; spatial native witness establishes no general bypass exclusion. |
| Consumed alias reaches the ownership gate with identity/state intact | Canonical membership can still succeed while private liveness fails. The gate rejects the requested read/second decrement; the public alias need not lose its tag. Terminal cleanup may still consume other live acquisitions. |
| Escaped identity, reuse while aliases survive, or concurrent/reentrant operations or reclamation | Invocation containment, fresh identity or synchronous lifetime assumptions fail. The current arguments establish no outcome for these cases. |

## Ownership requires protected software state

Linux already requires aliases of a released reference to become invalid.
[Linux 6.7 kfunc contract](https://docs.kernel.org/6.7/bpf/kfuncs.html#kf-release-flag).
cBPF represents an acquisition with a canonical public capability and a
private cell. The [retained ownership boundary controls runtime](../../evidence/current/ownership-closure/source/cbpf_runtime.c)
matches the full public capability, checks the private object's tag, and only
then reads or releases. Consumption clears the stored private tag before the
provider decrement. Public aliases retain their tags; the software resolver
rejects them because their acquisition is no longer live.

This software lifetime protocol does not globally revoke capabilities. A and
B can share an object with independent validity; consuming A preserves B
until separate consumption or terminal cleanup. The permanent baseline
reference prevents reclamation, so heap use-after-free prevention and
concurrent reclamation do not follow. [Ownership argument](../../theory/ownership.md),
[kernel correspondence](../../theory/kernel-ownership.md).

The ownership induction ranges over **every finite trace of the defined
transition system**, for arbitrary finite acquisition/register/spill bounds,
under its protected-state, complete-mediation and invocation premises.
Atomic model transitions do not prove compiled ordering or native mediation.
The kernel correspondence instead inspects the bounded grammar, transport,
gate and cleanup. The [synthetic native trace](../results/ownership-native-trace.md)
now joins stale rejection to terminal return and cleanup in fixed trusted
fixtures; it is not normally verified stale BPF. Trusted callback witness records two trusted
callback controls within persistent invocations. It supports those transports
and effects, not every callback trace or protection from executive C that
can modify private state. [Claim/evidence scopes](claim-evidence.md#result-quantifiers)
keep these distinct from the model's universal statement.

## What the CVEs establish

| Case | Defect and location | Supported cBPF conclusion |
|---|---|---|
| **CVE-2021-3490** | Incorrect ALU32 bounds tracking: an approximation problem can lead to a wrong admission decision. [Original disclosure](https://www.openwall.com/lists/oss-security/2021/05/11/11). [CVE-2021-3419 is rejected/withdrawn](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2021/3xxx/CVE-2021-3419.json) and is not this case. | Archived exact/broad comparisons show containment of one metadata-read stage. The current selective matrix runs with the historical ALU32 mode disabled, so it is runtime authority evidence rather than a CVE rerun. |
| **CVE-2022-50650** | Synchronous callback reference-state management and release eligibility. The upstream repair forbids a callback's first release of a caller-owned reference and checks callback-local acquisitions. [Linux announcement](https://lists.openwall.net/linux-cve-announce/2025/12/09/30). | cBPF conditionally enforces at most one consume and observes the projected repeated-release failure through its synthetic production path. It implements neither upstream eligibility nor callback-local leak policy, and does not execute the original path. |

The separate [trusted callback witness receipt](../../evidence/current/ownership-callback/README.md)
observes identity persistence across trusted C callbacks: repeated release
rejects and independent B remains readable. It does not execute the original
BPF/helper path. AEE's demonstrated spatial coverage cannot be assumed to cover
this ownership defect merely because both concern verifier state.

The [release-eligibility counterexample](../../theory/acquisition-distinguishability.md#3-live-validity-does-not-determine-release-eligibility)
holds a live acquisition's identity and state fixed while changing only whether
its owning caller or a borrowing callback requests release. Different required
decisions show that acquisition validity is insufficient for the upstream
context policy. This is an analytical boundary, not a callback implementation
or an additional experiment.

The [software comparison](capability-comparison.md) explains how protected
shadow tags and descriptors can enforce the same abstract policies.
The [related-work comparison](related-work.md#defensible-positioning-and-present-evidence) locates the bounded design contribution.
Neither comparison establishes new capability primitives, superiority,
general verifier/JIT fault tolerance or composition of the two studies.
