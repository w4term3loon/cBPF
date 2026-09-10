# Research overview: preserving eBPF interface grants

cBPF asks how a capability-aware runtime can preserve the unit of authority granted by an eBPF interface through native execution. A map lookup grants **one selected logical value**, whose extent can be smaller than its storage stride. An owning acquisition grants **one separately consumable right**, whose validity can end while the object remains live.

The study implements these mappings in two separate bounded Linux/Morello profiles in emulation. The normal verifier remains enabled. Construction, native transport and checks at the covered effects show how accepted executions represent the interface contract; the evaluation does not measure tolerance of verifier defects.

## 1. Array maps: which bytes does a lookup authorize?

A lookup selects one logical value inside a larger allocation. Allocation-wide bounds may also admit another value, padding or metadata. The provider must therefore use storage stride to locate the value and logical size to bound its returned capability. Correct construction is useful only if the native access uses that capability.

The current witness records a seven-byte capability for a seven-byte value in an eight-byte stride. Its inspected native byte-six read/write increments 41 to 42 and preserves the other logical bytes. Length seven distinguishes the intended constructor from an incorrect stride-based grant; successful readback alone would not. No padding access or bounds fault is executed in this witness.

The [spatial argument](../theory/spatial.md) gives conditional interval containment. [Logical extent](results/logical-extent.md) records the current discriminator; the [native account](results/spatial-native-result.md) supplies its earlier correspondence context.

### Spatial CVE evidence

Historical CVE-2021-3490 records contrast a selected metadata read under exact and broader authority. Exact bounds contain that recorded out-of-value effect. This is archived stage-specific evidence, not a current CVE rerun, verifier repair or whole-vulnerability guarantee. See the [causal analysis](results/causal-review.md).

## 2. Kfunc ownership: which acquisition is still valid?

Acquisitions A and B can refer to one permanently allocated object while creating separate counted rights. Copying or spilling A preserves A's identity; it creates no new right. Consuming A must invalidate its aliases while independently live B remains usable.

Canonical capabilities identify protected per-acquisition cells. A gate checks the cell's validity and clears it before a provider decrement. Valid native controls preserve B after A consumption, including full-capability transport through one spill. Trusted resolver and C callback controls separately reject consumed A. A different verifier-valid native control exercises terminal failure and cleanup. Those observations do not form one complete stale protected-BPF execution.

The [ownership argument](../theory/ownership.md) proves consume-once accounting under its premises. The [observation criterion](../theory/acquisition-distinguishability.md) explains why object address, liveness and total counts cannot replace acquisition-sensitive validity.

### Ownership CVE evidence

The [CVE-2022-50650 case](results/ownership-cve-case.md) projects repeated release into the ownership protocol. Trusted C callbacks add actual alias/context transport and stop after rejection. The original vulnerable BPF/helper path is unexecuted. The studied policy permits one valid consume, whereas the upstream repair forbids the caller-reference release in that callback context. General reclamation and the CVE's acquisition-leak arm are outside the result.

## 3. Why the small examples answer the stated question

Two values expose selected-value versus allocation authority; unequal size and stride distinguish constructor rules. Two acquisitions to one retained object isolate ownership validity from allocation liveness. A retained alias distinguishes copying a right from acquiring another one. The finite model checks its stated instance; its induction does not establish compiler/kernel refinement.

### Falsification conditions

A successful out-of-value effect through the correctly assigned exact root, a second decrement for one acquisition, invalidation of independently live B, or continued program effects after terminal rejection would contradict the corresponding claim under its premises. The [claim map](research/claim-evidence.md) gives the full quantifiers.

## 4. Contribution and scope

The implemented and evaluated bindings support a reusable design and evaluation procedure: identify the interface's grant, preserve the information that distinguishes its rights, follow that representation to the native operand or gate, and select a control that separates it from a plausible incorrect mapping. The seven-byte/eight-byte witness distinguishes two constructors; A, its alias and independent B distinguish copying, acquisition and current validity. These controls make the design choices testable within the studied profiles.

CHERI bounds, Linux ownership semantics and shared revocation state are established mechanisms. The contribution is their explicit interface mapping, implementation and bounded validation. The [related-work comparison](research/related-work.md#defensible-positioning-and-present-evidence) and [software alternative](research/capability-comparison.md) explain the design contribution.

CHERI protects encoded authority and checks its use. Software still assigns the correct object, maintains acquisition validity and ensures mediation. The profiles retain explicit provider, translation and lifetime assumptions; their composition, concurrency, heap reclamation and comparative performance are outside the findings. The [design synthesis](research/related-work.md#source-lineage-and-design-rationale) connects these choices, while the [claim map](research/claim-evidence.md) identifies their premises and evidence boundaries.

The [earlier findings](results/earlier-findings.md) retain the broader prototype's experiments, formal accounts and negative results. They belong to their recorded source configurations and do not enlarge the claims of these two profiles.
