# Research overview: preserving eBPF interface grants

cBPF asks how a capability-aware runtime can preserve the unit of authority granted by an eBPF interface through native execution. A map lookup grants **one selected logical value**, whose extent can be smaller than its storage stride. An owning acquisition grants **one separately consumable right**, whose validity can end while the object remains live.

The study implements these mappings in two separate bounded Linux/Morello
profiles in emulation. Ordinary verifier safety checks remain active.
Normally verified positive executions and separately labelled synthetic native
controls establish different parts of the result. Neither measures tolerance
of arbitrary verifier defects.

## The runtime solution before its evaluation

| Stage | Selected-value profile | Acquisition profile |
|---|---|---|
| Construction | Retain allocation authority; select the live value using key and stride; derive exact bounds using `map->value_size` | Allocate an invocation-local acquisition cell and canonical public view before the provider increment |
| Transport | Inherited capability-aware JIT/gateway preserves the full lookup return to the covered memory operand | Restricted compiler/gateway preserves full acquisition capabilities through moves and a 16-byte sidecar for the supported logical spill |
| Enforcement | Hardware checks the full access interval against the actual capability, together with permissions and page conditions | Software gate checks exact canonical membership and private validity before reading or consuming the object right |
| Terminal handling | Failed construction returns no usable grant. The inherited BPF exception path redirects covered faults to a zero-result epilogue | Gate failure bypasses continuation; the common epilogue scrubs program-accessible aliases; the wrapper consumes remaining live cells once |

Spatial root-summary metadata assists profile admission, while a separate
JIT analysis selects capability lowering. The provider does **not** construct
bounds from a verifier-predicted numeric range. The
[recorded code-to-native walkthrough](results/logical-extent.md#recorded-code-to-native-walkthrough)
names the actual producer, fields and consumers.

The [implementation inventory and size estimate](research/implementation-scope.md)
separates inherited mechanisms, new enforcement, integration and supporting
machinery. The spatial matrix's test-only fault recovery is outside the
production solution. Ownership's provider is synthetic and kfunc-shaped;
its synchronous invocation/cleanup wrapper is nevertheless part of the
evaluated runtime boundary. No composition of the two profiles is claimed.

## 1. Array maps: which bytes does a lookup authorize?

A lookup selects one logical value inside a larger allocation. Allocation-wide bounds may also admit another value, padding or metadata. The provider must therefore use storage stride to locate the value and logical size to bound its returned capability. Correct construction is useful only if the native access uses that capability.

The [key-one construction/use witness](results/logical-extent.md) records
length seven at stride eight and one normally verified byte-six increment.
The separate [key-zero selective matrix](results/spatial-selectivity.md)
compares that provider policy with wider trusted controls: 22 operations
complete and eight selected operations fault in each recorded 30-case matrix.
This is synthetic native validation, not execution of invalid eBPF.

The [spatial argument](../theory/spatial.md) gives conditional interval containment;
the result pages retain the observations, instruction correspondence and limits.

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

The current result packages are published and recheckable. Encoder self-check,
external receipt checks and authored internal inspection provide distinct
assurance; none proves the checker, compiler or complete runtime correct.
Independent external reproduction remains unestablished.
