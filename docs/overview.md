# Research overview: preserving eBPF interface grants

cBPF asks how a capability-aware runtime can preserve the unit of authority granted by an eBPF interface through native execution. A map lookup grants **one selected logical value**, whose extent can be smaller than its storage stride. An owning acquisition grants **one separately consumable right**, whose validity can end while the object remains live.

The study implements these mappings in two separate bounded Linux/Morello profiles in emulation. The normal verifier remains enabled. Construction, native transport and checks at the covered effects show how accepted executions represent the interface contract; the evaluation does not measure tolerance of verifier defects.

Evidence status: both original native-extension packages are published.
The spatial results now pass backing-address, linked-instruction, calibration
and completion checks, with ten admission-only load/store controls in a new
run of the unchanged kernel. Ownership's retained images now pass complete
fixed-image byte/operand/target checks and focused linked terminal-path checks,
with an explicit internal native inspection. Both bounded synthetic results
are published and recheckable; independent external reproduction, general
translation correctness and complete mediation remain unestablished.

## 1. Array maps: which bytes does a lookup authorize?

A lookup selects one logical value inside a larger allocation. Allocation-wide bounds may also admit another value, padding or metadata. The provider must therefore use storage stride to locate the value and logical size to bound its returned capability. Correct construction is useful only if the native access uses that capability.

The current construction witness records a seven-byte capability for a
seven-byte value in an eight-byte stride. A subsequent
[selective matrix](results/spatial-selectivity.md) uses that production grant
and matched trusted eight- and sixteen-byte controls. Across loads and stores,
the exact grant permits valid accesses and faults on padding, the next value
and an access that starts inside but crosses the logical boundary. This is a
fixed trusted native fixture, not execution of invalid eBPF.

The [spatial argument](../theory/spatial.md) gives conditional interval containment. [Logical extent](results/logical-extent.md) records the current discriminator; the [native account](results/spatial-native-result.md) supplies its earlier correspondence context.

### Spatial CVE evidence

Historical CVE-2021-3490 records contrast a selected metadata read under exact
and broader authority. Exact bounds contain that recorded out-of-value effect.
The current reduced profile excludes the historical ALU32 test mode, so the
new matrix is a runtime authority discriminator rather than a CVE rerun.
CVE-2021-3419 is a withdrawn/rejected identifier and is not used for this case.
See the [causal analysis](results/causal-review.md).

## 2. Kfunc ownership: which acquisition is still valid?

Acquisitions A and B can refer to one permanently allocated object while creating separate counted rights. Copying or spilling A preserves A's identity; it creates no new right. Consuming A must invalidate its aliases while independently live B remains usable.

Canonical capabilities identify protected per-acquisition cells. A gate checks
the cell's validity and clears it before a provider decrement. A fixed trusted
[native containment trace](results/ownership-native-trace.md) preserves B after
A consumption, then joins a stale read or repeated release to production-gate
rejection, terminal native return and exactly-once cleanup of B. It is not a
normally verified stale BPF execution.

The [ownership argument](../theory/ownership.md) proves consume-once accounting under its premises. The [observation criterion](../theory/acquisition-distinguishability.md) explains why object address, liveness and total counts cannot replace acquisition-sensitive validity.

### Ownership CVE evidence

The [CVE-2022-50650 case](results/ownership-cve-case.md) projects repeated release
into the ownership protocol. The integrated synthetic trace observes the
projected effect through the production native failure path; trusted C
callbacks separately add callback/context transport. The original vulnerable
BPF/helper path is unexecuted. The studied policy permits one valid consume,
whereas the upstream rule forbids a callback's first release of a caller-owned
reference and separately requires callback-local acquisitions to be discharged.
The [context counterexample](../theory/acquisition-distinguishability.md#3-live-validity-does-not-determine-release-eligibility)
shows that acquisition identity and liveness alone cannot express that rule:
the decision also needs the acquisition-owner/current-context relationship or
an equivalent eligibility fact.

## 3. Why the small examples answer the stated question

Two values expose selected-value versus allocation authority; unequal size and stride distinguish constructor rules. Two acquisitions to one retained object isolate ownership validity from allocation liveness. A retained alias distinguishes copying a right from acquiring another one. The finite model checks its stated instance; its induction does not establish compiler/kernel refinement.

### Falsification conditions

A successful out-of-value effect through the correctly assigned exact root, a second decrement for one acquisition, invalidation of independently live B, or continued program effects after terminal rejection would contradict the corresponding claim under its premises. The [claim map](research/claim-evidence.md) gives the full quantifiers.

## 4. Contribution and scope

The implemented bindings expose four reusable decisions: storage stride locates
a value but logical extent defines its authority; an object is not an
acquisition; preserved identity still needs current validity; and rejection
needs a terminal execution boundary with cleanup. The matched spatial roots
and integrated ownership fixtures make those decisions testable within the
studied profiles.

CHERI bounds, Linux ownership semantics and shared revocation state are established mechanisms. The contribution is their explicit interface mapping, implementation and bounded validation. The [related-work comparison](research/related-work.md#defensible-positioning-and-present-evidence) and [software alternative](research/capability-comparison.md) explain the design contribution.

CHERI protects encoded authority and checks its use. Software still assigns the correct object, maintains acquisition validity and ensures mediation. The profiles retain explicit provider, translation and lifetime assumptions; their composition, concurrency, heap reclamation and comparative performance are outside the findings. The [design synthesis](research/related-work.md#source-lineage-and-design-rationale) connects these choices, while the [claim map](research/claim-evidence.md) identifies their premises and evidence boundaries.

The [earlier findings](results/earlier-findings.md) retain the broader prototype's experiments, formal accounts and negative results. They belong to their recorded source configurations and do not enlarge the claims of these two profiles.
