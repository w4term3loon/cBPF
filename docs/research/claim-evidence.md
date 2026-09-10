# cBPF claim-to-premise-to-evidence map

Two separate bounded studies, with conditional arguments,
inspected implementation and current or historical observations. The
[overview][overview] explains the mechanisms; [reproduction][reproduction] distinguishes
source editions. The clean dependency image has a [fresh bounded native replay](../reproduction/native-replay.md).
Independent external reproduction is not established.

The September 10 spatial and ownership extension artifacts are now published.
Spatial backing-address/operand/PC correspondence now passes focused linked
checks and adversarial host regressions; a new run adds store-admission coverage.
Ownership's complete fixed-image checks, focused linked terminal-path checks
and explicit internal native inspection are also retained. The two bounded
synthetic results are now recheckable; publication integrity alone, encoder
self-check and internal inspection are not independent external reproduction.

## Findings at a glance

| Feasibility question | Answer and evidence | Boundary |
|---|---|---|
| Can selected extent survive construction and selectively constrain native use? | The [seven-byte/eight-byte matrix](../results/spatial-selectivity.md) retains 30 operations, 22 permits and eight bounds faults under stronger same-storage and linked-PC/operand checks. Ten admission-only load/store controls give four accepts, six rejections and zero executions. | Fixed trusted native fixture through the production provider; source/build/boot identities and fixed zero relocation are premises. No negative BPF or original CVE execution; all-program mediation remains unestablished. |
| Can acquisition identity survive aliases, preserve B and contain stale use through cleanup? | The [integrated synthetic native trace](../results/ownership-native-trace.md) retains positive, stale-read and repeated-release controls ending at refs=1, with all 479 native words checked and a complete fixed-image/linked-path inspection. | Encoder self-check, external fixed-profile receipt checks and AI-assisted internal inspection are separate assurances, not a compiler proof. No normally verified stale BPF or original ownership-CVE execution. |
| Can acquisition validity alone decide callback release eligibility? | No. The [caller/callback counterexample](../../theory/acquisition-distinguishability.md#3-live-validity-does-not-determine-release-eligibility) gives the same live A identity but different required decisions according to its current and owning contexts. | Conditional representability argument only. cBPF implements no callback-frame policy, and no new experiment or general theorem follows. |
| What remains trusted? | Correct assignment, protected metadata, architecture, native binding, effect ordering and invocation containment. | Neither study proves the whole native implementation or their composition. Software can express the same policy; no comparative ranking follows. |

The detailed premise map below connects each finding to its supporting record.
The [reproduction guide](../reproduction/README.md#current-sources-and-software-controls)
identifies the sources, software controls and locally replayed environment.

### Ownership evidence chain

| Link | Observed evidence | Inspected or assumed boundary |
|---|---|---|
| Native entry | Four verifier-accepted controls and three fixed trusted trace fixtures execute | Restricted roots and fixed entry/return path; trace fixtures are not verified BPF |
| Alias transport | Full-capability A spill/reload; B reads 42 before stale rejection | Preservation across all admitted templates remains a correspondence obligation |
| Stale check | Tagged/canonical A with private tag zero rejects at PC 17 | Production gate; matching BPF negatives remain load-only |
| Terminal exit | Both negative fixtures skip their PC-19 continuation | Common production failure/epilogue path |
| Cleanup | Wrapper consumes live B once; acquired=2, released=2, cleanup=1, refs=1 | Trusted synchronous teardown, not concurrent reclamation |

These rows now form one observed synthetic-native chain through the production
mechanisms. They do not constitute normally verified stale BPF. The
[native trace](../results/ownership-native-trace.md),
[boundary records](../../evidence/current/ownership-closure/README.md) and
[callback records](../../evidence/current/ownership-callback/README.md) retain
their distinct scopes.

Evidence labels: **Conditional argument** = conditional mathematical argument; **Inspection** = inspected
source/native implementation; **Current observation** = retained cBPF observation; **Historical observation** = archived
observation in an earlier source/configuration; **Open obligation** = open obligation.
An observation supports its recorded execution, not all executions. A hash
check establishes artifact identity, not correctness or independent reproduction.


Public evidence is redacted. Recorded execution/source identities refer to
original experimental snapshots; publication checksums identify distributed
copies. The [native replay](../../evidence/current/native-replay/README.md) records
fresh publication-source executions with the clean image; it does not reassign
historical outcomes. Host/model checks are recorded in the [source and software controls](../reproduction/README.md#current-sources-and-software-controls).

Premise labels: **interface** = admitted-language restriction; **check** = runtime
validation; **architecture** = assumed CHERI property; **inspection** = source or
compiled-code obligation; **trust** = retained environmental/provider assumption.

## Result quantifiers

The argument does not infer correct authority or mediation from a successful
control. Those are separate obligations: some remain assumed, some have
source/native inspection support, and selected effects are observed.

| Result | Quantifier and status |
|---|---|
| Conditional spatial containment | **Conditional argument:** for every live `S`, exact authority `C` and positive-width access satisfying premises 1–4, a successful architectural effect through `C` or a monotonic derivative lies in `S`. This is not a statement that every generated access uses `C`. Premise 5 is additionally needed for all accesses in a program boundary. |
| Spatial native witness (exact construction/native correspondence) | **Inspection:** two value operands in one retrieved 392-byte native image and the linked handoff. **Current observation:** one valid execution of that program. Construction telemetry and source/image identity support this witness; they are not independent hardware attestation or a universal native theorem. |
| Archived spatial contrasts | **Historical observation:** the selected accesses in their retained exact/broad configurations, including the named metadata-read stage. These are recorded contrasts, not a quantifier over all programs, all vulnerable executions, or the current reduced kernel. |
| Ownership induction | **Conditional argument:** every finite trace admitted by the model's transition rules, for arbitrary finite `K`, `R`, `S`, under its assumptions. Finite exploration checks one bounded instance; it does not transfer the induction to C/JIT code. |
| Kernel ownership and callback transport | **Inspection:** source/native support for the stated bounded mapping. **Current observation:** selected protected ownership executions and boundary controls and two trusted callback controls. The observations do not prove every native program/callback trace, hostile-callback isolation or general implementation refinement. |

The [fault-specific taxonomy](trust-taxonomy.md#quantifiers-and-fault-specific-guarantees)
explains why bad numeric predictions can be tolerated **conditional on correct
grant/use**, whereas wrong map/key assignment, oversized grants and alternative
roots invalidate different premises. A consumed alias reaching the intact
ownership gate is covered; escape, identity reuse and concurrency are not.

## Analytical contribution and comparison

The [contribution boundary](related-work.md#defensible-positioning-and-present-evidence) identifies selected-extent
binding and acquisition-preserving native transport as the two bounded design
findings. These interpretation claims refer to the construction and native-access claims and the ownership claims below; they do
not add a new native result or first-in-literature claim.

The [software comparison](capability-comparison.md) specifies protected
shadow tags and descriptors and compares their abstract rules with cBPF.
This is **Conditional argument**, under correct provider assignment, protected metadata, matching
supported operations/outcomes and complete mediation. It establishes that
both representations can express the same policy within that domain, not
native bisimulation, identical acceptance, a measured baseline, lower overhead,
a smaller trusted base or stronger actual-program security.

## Selected-value spatial authority

| Bounded claim | Necessary premises and their kind | Implementation and evidence | Established scope / remaining obligation |
|---|---|---|---|
| Any access satisfying the grant/use premises cannot complete outside the selected logical interval. | **Trust:** correct live value assignment. **Check:** tagged, unsealed, exact bounds and permissions. **Architecture:** monotonic derivation and architectural enforcement. **Inspection:** the actual access uses that root. | **Conditional argument:** [containment lemma][spatial-lemma], premises 1–4. Numeric interval soundness is not used; grant/use premises must still hold. Premise 5 is needed to cover every program access. | Conditional architectural containment; excludes speculative effects, lifetime safety, and an implementation refinement theorem. Wrong semantic assignment or an alternative root defeats the premise, not the hardware bounds rule. |
| Allocation containment does not imply value containment. | **Conditional argument:** selected interval is a strict subset of the allocation. | [Counterexample][spatial-counterexample]: `[16,17)` is inside allocation `[0,128)` but outside value `[32,40)`. | A mathematical insufficiency result. |
| Checked construction targets the intended value under the assignment premises. | **Trust:** intact map/provider association, layout, key semantics, allocation lifetime, non-wrapping arithmetic, and correct initial root. **Check:** plain ARRAY, zero flags, expected operations, no record, retained-root shape, and key range. | **Inspection:** [reduced patch][spatial-patch], `cbpf_map_area_alloc` and `cbpf_array_value_cap`. The root is constructed from executive DDC after ordinary allocation. | Checks constrain representation; they do not authenticate semantic assignment or establish allocator-minted provenance. Concurrent free/substitution is outside the lemma. |
| Lookup supplies the logical value's exact bounds and scalar-data permissions. | **Check:** exact construction succeeds; base/address equal selected value, length equals `map->value_size`, and permissions equal `LOAD\|STORE\|GLOBAL`. | **Inspection:** `cbpf_array_value_cap` derives from the retained root; logical size excludes stride padding. Unsupported/inexact construction returns NULL. **Current observation:** [selective spatial enforcement](../results/spatial-selectivity.md) records the production exact-seven root beside separately derived stride-eight and both-slot-sixteen controls. | Exact-seven rejects padding, adjacent-value and crossing accesses while valid controls complete. This is a fixed trusted native fixture; complete mediation and invalid-BPF execution remain unestablished. |
| The two inspected native value accesses use the lookup-returned authority. | **Inspection:** lookup handoff, full-capability transport, final native addressing, and absence of an alternate root for these two accesses. **Trust:** live assignment, executable-image integrity, kernel/compiler/architecture, and synchronous execution. | **Current observation / Inspection:** [spatial native witness receipt][spatial-witness-receipt] binds one normally verified 14-instruction program, all 392 retrieved native bytes, accepted certificate, linked provider/gateway review, and one execution. Native word 72 copies `c0` to `c7`; words 75/77 load/store through unchanged `c7`. Key 1 changes 41→42, with computed return and readback 42. | Observed for one inspected program. **Open obligation:** complete mediation for every admitted program remains unproved. RDDC is vmalloc-wide and the gateway retains broader DDC bounds. Logs report constructed operands, not independent hardware attestation. No out-of-bounds access or CVE was rerun. |
| Exact bounds mattered for selected adjacent-value loads/stores. | **Trust:** archived experiment identities, telemetry, correct live-element assignment, checked-image integrity, and retained correspondence conditions. | **Historical observation:** [archived store][v5-exact] at `[16,24)` and [archived load][v6-exact] at `[16,20)` faulted with exact 16-byte bounds; broader controls completed. [Four-case matrix][spatial-matrix] includes valid load `[8,16)` and store `[12,16)`. | Two historical epochs, widths 8 and 4, with both console blocks now [retained](../results/earlier-findings.md#adjacent-value-controls-and-assignment-limits). Direct live operand correspondence and complete production refinement remain unestablished. |
| Exact authority contained the evaluated CVE-2021-3490 metadata-read stage. | **Trust:** archived pinned kernel/workload, root assignment, native correspondence, and telemetry. | **Historical observation:** [exact log][provider-exact] reports bounds fault at BPF 45/native word 122 with unchanged sink; [broad][provider-broad] and [allocation-wide][provider-wide] logs record metadata in the sink; [valid exact control][provider-valid] returns 42. | The target is inside the allocation but outside the selected value. This is an archived stage-specific result, not a repair of the [verifier ALU32 defect][cve-fix] or complete CVE prevention. The wide receipt has `binding_valid=0`; the broad return record selects `authority=broad_ddc`. |

## Per-acquisition ownership

| Bounded claim | Necessary premises and their kind | Implementation and evidence | Established scope / remaining obligation |
|---|---|---|---|
| Consumption is once per acquisition; A's consumption leaves B live. | **Trust/interface:** unforgeable identities, protected cells, complete mediation, correct provider, synchronous non-reentrant execution, and terminal invocation containment. | **Conditional argument:** [ownership induction][ownership-invariants] proves consumption, alias consistency/independence, and `rc = 1 + n - E - D = 1 + live` under the [model assumptions][ownership-state]. | A proof sketch over transition rules for arbitrary finite bounds; not a mechanized C/JIT/kernel proof. The model makes ordering atomic. |
| Public handles identify acquisitions, not the object. | **Check:** exact canonical view membership. **Architecture/interface:** handles cannot be forged or widened; full-capability copies preserve identity. **Trust:** arena integrity and initial DDC assignment. | **Inspection:** [runtime][runtime], `cbpf_exact` and `cbpf_gate_impl`, prepare 16-byte `LOAD\|GLOBAL` views before incrementing references. **Current observation:** [boot log][ownership-log] has distinct cells ending `f7c0`/`f7d0`, one object, and `public_perms=0x20001`. | Handles exclude store and capability-load authority. This is a private two-cell acquisition ABI, not a general allocator or arbitrary kfunc-pointer ABI. |
| The inspected gate checks membership and private liveness before read/release object use. | **Check:** exact view equality and stored object tag. **Inspection:** no direct-object capability escapes; object field uses checked capability authority. | **Inspection:** `cbpf_gate_impl`; [linked code][linked-runtime] has `CHKEQ` at `0xffff80008003e320`, tag check at `...e3c0`, and capability-addressed `LDURSW` at `...e3ec`. | Gate inspection supports the premise; native mediation separately addresses arrival through the gate. **Current observation:** [ownership boundary controls trusted init controls][ownership-controls] reject consumed copy/spill identities and duplicate release through this resolver. They do not execute invalid restricted BPF. |
| Invalidation precedes the release effect. | **Inspection:** ordered private-tag store before provider decrement. **Trust:** compiler/architecture and synchronous containment; no concurrency claim. | **Inspection:** `cbpf_consume`; [linked code][linked-runtime] clears/stores at `...e7c4`/`...e7c8` before LSE decrement `...e83c` or LL/SC `...e8fc`. **Current observation:** trace sequence 3 clears A with refs=3; sequence 4 releases with refs=2. | Source, compiled ordering, and one observed path agree. This does not prove concurrent linearizability or arbitrary JIT-fault tolerance. |
| B remains usable after A is consumed. | identity, gate checks and ordered consumption; **Trust:** both acquisitions bind the same permanent provider object. | **Current observation:** [protected ownership execution trace][ownership-log]: acquire PCs 1/6; A release PC 11; B read PC 13; B release PC 16; scalar result 42, acquired=2, released=2, refs=1. | Decisive protected A/B observation. A reaches release through copied/spilled/reloaded authority, but no consumed alias is subsequently used. |
| The supported native path mediates object effects. | **Interface:** ≤64 instructions, ≤2 acquisition sites, fixed kfuncs, forward NULL branches, register moves, one spill, scalar return; no maps/subprograms/attachment. **Inspection:** roots and fixed transitions. | **Inspection:** [compiler][jit] `admit`, `body`, `epilogue`; [integration][integration] denies attachment and routes private test entry. [Native bytes][native-code] show full-capability spill/reload and fixed `BLRS c17`; [entry log][ownership-log] records untagged RDDC and 16-byte stack. | Final-word checking shares the generator's encoder: consistency evidence, not independent translation validation. [Boundary review][boundary-review] covers no ordinary fallback; [native review][native-review] is internal code inspection. |
| Return or terminal gate failure accounts for remaining acquisitions. | **Inspection:** common epilogue scrubs program-accessible registers and sidecar, failure skips continuation, wrapper consumes every live cell, then ends the arena. **Trust:** synchronous exception/register preservation. | **Current observation / Inspection:** [synthetic native trace](../results/ownership-native-trace.md) joins stale read/release failure at PC 17 to skipped PC 19 and one cleanup release of B. Kernel `released` includes cleanup; model explicit `E = released - cleanup`, and `D = cleanup`. | Both negatives end acquired=2, released=2, reads=1, cleanup=1, refs=1. Fixed trusted native construction, not verified stale BPF. Nonzero ordinary-return cleanup remains inspected/modelled because leaked ownership is verifier-invalid. |
| NULL/failure adds no unaccounted reference; cells are not reused while aliases survive. | **Check:** NULL branch precedes acquisition, budget/representation checks precede increment. **Interface/trust:** no escape, no reentrancy, arena teardown after supported alias scrub. | **Inspection:** `cbpf_gate_impl` and `cbpf_test_invoke`; two cells allocated once per invocation, no intra-invocation reuse. | **Current observation:** [ownership boundary controls][ownership-controls] observes NULL without a second acquisition and pre-provider argument rejection followed by terminal cleanup. Exact-construction/capacity failure ordering is inspected, not dynamically forced. Cross-invocation aliases, general reclamation and concurrent revocation remain excluded. |
| Admission depends on structure, not fixture identity. | **Interface:** conservative forward type/branch analysis after the ordinary verifier; fixed function addresses, supported templates, rejection of unsupported profiles. | **Inspection:** [compiler][jit], `call_operation`, `cbpf_jit_match`, `admit`. No program-name or whole-fixture match. **Current observation:** one admitted 26-instruction/660-byte program. | **Current observation:** [ownership boundary controls][ownership-controls] also record acceptance of a 27-instruction A/B arrangement with different reference registers and NULL-branch targets; it returns 42. Two controls support bounded structural admission, not compiler correctness. |
| Runtime enforcement must distinguish an acquisition and its current validity. | **Conditional argument:** the observation includes all information used by the gate; supported live requests must be permitted and consumed requests rejected. | **Conditional argument:** [acquisition distinguishability][acquisition-criterion] proves that equal observations must require equal decisions. A/B after A consumption requires different decisions despite common object attributes. Immutable identity plus aggregate totals is also insufficient without associated validity. | An elementary necessity argument for the studied contract. It supplies no implementation refinement theorem, metadata lower bound, or named-CVE result. |
| Acquisition identity and liveness cannot alone represent callback release eligibility. | **Conditional argument:** hold A's identity, live state, object, count and invocation fixed; compare its owning caller's release with a borrowing callback's release. | **Counterexample:** the [same `(A, live)` observation](../../theory/acquisition-distinguishability.md#3-live-validity-does-not-determine-release-eligibility) requires permit for the owner and reject for the borrower. The policy must additionally observe owner/current-context relationship or an equivalent eligibility fact; callback-exit leak checking also needs callback-local live obligations. | Application of the existing decision-representability criterion. No callback-policy implementation, callback experiment, metadata lower bound or new general theorem. |
| Repeated releases of the same acquisition cannot cause a second decrement under the gate premises. | **Trust/interface:** preserved acquisition identity, no cell reuse across projected requests, protected state, complete mediation, correct provider, synchronous terminal invocation. | **Conditional argument:** [ownership CVE case](../results/ownership-cve-case.md) maps CVE-2022-50650's repeated-release arm to consume-once. **Current observation:** model/host projections and the [integrated synthetic native fixture](../results/ownership-native-trace.md) reject the second release, skip continuation and clean B once. | Containment of the projected effect. Original callbacks are unexecuted. Upstream also forbids the first caller-reference release and discharges callback-local acquisitions; cBPF does neither. No leak-arm or reclamation claim. |
| Acquisition validity persists in the two observed trusted C callback controls. | **Trust/interface:** one context and invocation, full-capability aliases, no intervening reset/reuse, unchanged gate, synchronous dispatch terminating at rejection. | **Current observation / Inspection:** [trusted callback witness](../../evidence/current/ownership-callback/README.md): repeated release has two entries, one completion and one decrement; the planned third entry does not occur. Separate A/B callbacks read B=42 after A consumption; both controls restore refs=1. | Trusted kernel C callback transport only. No protected BPF callback support, original helper execution, callback-frame policy, arbitrary-callback isolation or reclamation claim. |

## Keep the evidence levels separate

| Evidence layer | What its receipt supports | What it cannot supply |
|---|---|---|
| [Finite model][model-result] | **Current observation:** 17,828 reachable states and 149,205 transitions at K=2/R=4/S=2; object-wide-consumption mutant fails independence. | Hardware isolation, native ordering, kernel grammar correctness, or refinement. |
| [Host/model conformance][conformance] | **Current observation:** observations agree after selected model histories, with separate branch/scalar controls. | Every concrete C history or a proof transferring the model theorem to C. |
| [CHERI architecture probe][cheri-log] | **Current observation:** separate stale-copy/spill tests terminate with capability-tag faults; independent B and a direct object capability remain readable. | Isolation from arbitrary native callers or Linux kfunc mediation. |
| [Native IR gate][gate-trace] | **Current observation:** stale A traps, B is cleaned up, refs return to one; later listed IR instructions do not execute. [Boot receipt][gate-log] reports 494 matches. | Protected native execution; this trusted interpreter declares `isolation=0 kfunc=0 jit=0`. |
| [Ordinary Linux binding][kfunc-log] | **Current observation:** 45 valid invocations, 82 balanced acquisitions/releases, five invalid load-only rejections. | Protected-state runtime enforcement: this binding declares `runtime_cheri=0`. |
| [Protected ownership execution kernel][ownership-log] | **Current observation / Inspection:** one A/B execution, private capability state, native transport, ordered consumption, scalar result, balanced references. | Exercised stale aliases, NULL/failure, nonzero cleanup, alternate arrangement, or independent reproduction. |
| [ownership boundary controls closure controls][ownership-controls] | **Current observation / Inspection:** four accepted native executions, three trusted resolver checks, three unexecuted verifier rejections; exact accounting and terminal containment within [the mapping][kernel-mapping]. | Restricted-native stale BPF execution, forced construction failure, nonzero ordinary-return cleanup, or external reproduction. |
| [local reproduction rehearsal][local-reproduction-result] | **Current observation:** fresh frozen-source rebuild and existing controls pass; five kernel outputs/four native images match ownership boundary controls, three spatial objects/configuration match spatial provider reduction; default checks pass. | External provisioning/reproduction, a new spatial runtime claim, or correctness from byte equality. |
| [Initial spatial native witness][spatial-witness-receipt] | **Current observation / Inspection:** fresh reduced kernel, exact eight-byte selected-value capability, inspected 392-byte native image, one valid read/add/store, return/readback 42. | Out-of-bounds containment observation, general JIT mediation, independent hardware attestation, a fresh CVE result, or composition with ownership. |
| [Logical extent discriminator](../results/logical-extent.md) | **Current observation / Inspection:** logical size 7, stride 8, length 7; two inspected byte-six operands and one valid 41→42 invocation, preserving six other logical bytes. | An observed padding fault, independent hardware attestation, complete mediation, a new CVE result or ownership composition. |
| [Selective spatial enforcement](../results/spatial-selectivity.md) | **Current observation / Focused receipt checks:** 30 load/store cases across exact-seven, stride-eight and both-slot roots; 22 permit and eight fault with FSC `0x2a`. The original five-load edition is retained; the new ten-control load/store admission edition executes zero times. | Verifier-admitted invalid eBPF, original-CVE execution, complete mediation, speculative leakage or ownership composition. |
| [Archived spatial selection][historical-selection] | **Historical observation:** preserved comparisons and their original provenance/limitations. | A new run of the reduced patch, recovered omitted artifacts, or an untested spatial/ownership composition. |
| [ownership CVE case](../results/ownership-cve-case.md) | **Conditional argument / Inspection / Current observation:** primary-source causal mapping, conditional argument and two projected controls against both host C paths. Prior ownership boundary controls records support the resolver mechanism. | Original callback/CVE execution, a new kernel run, complete upstream policy, the leak arm, or heap reclamation. |
| [Release-eligibility counterexample](../../theory/acquisition-distinguishability.md#3-live-validity-does-not-determine-release-eligibility) | **Conditional argument:** one live identity requires different owner/borrower release decisions, so liveness alone cannot encode the upstream callback rule. | Any implementation or experiment, a complete callback policy, a new theorem or a claim that the bounded cBPF profile is defective. |
| [trusted callbacks](../../evidence/current/ownership-callback/README.md) | **Current observation / Inspection:** two actual C callback controls through the production resolver, with retained context and exact effect accounting. | BPF callback integration, original-CVE execution, or protection from a malicious callback. |
| [Synthetic native ownership trace](../results/ownership-native-trace.md) | **Current observation / Inspection:** fixed positive, stale-read and repeated-release images use restricted entry, production gate, epilogue and cleanup; both negatives preserve B before rejection and end refs=1. | Normally verified stale BPF, original callback/helper execution, callback-frame release policy, leak prevention or reclamation. |

## Supporting controls and unresolved technical obligations

| Property | Supporting evidence and current limit |
|---|---|
| Ownership boundary controls: aliases and consume-once | Three trusted production-resolver controls reject with an intact tagged canonical public alias, private tag zero, reads=0, one release, and refs=1. Three corresponding invalid BPF fixtures are verifier-only rejections. See [ownership boundary controls][ownership-controls]. |
| Ownership boundary controls: NULL/failure and termination | NULL creates no second identity; scalar 2 is rejected before provider effect, and native terminal cleanup releases A once with no continuation effects. Construction/capacity and nonzero ordinary-return cleanup retain the [explicit source/model premises][kernel-mapping]. |
| Ownership boundary controls: structural admission | Original 26-instruction and alternate 27-instruction A/B programs both pass normal verification and protected execution. Their native bytes, maps, and final reviews are retained under [ownership boundary controls][ownership-controls]. |
| Integrated stale ownership path | Fixed trusted native stale-read and repeated-release records join identity, rejection, terminal return and exactly-once cleanup; complete fixed-image inspection and focused external instruction/target checks now support the connection. Three separate existing admission controls are rejected without execution; their diagnostics are not ownership-rule evidence. |
| Local reproduction | The retained implementation and reproduction source editions identified 234 and 334 files, respectively. Full archives are retained privately; the [history description](../../evidence/history/README.md) records their scope. Published [receipts][local-reproduction-result] are redacted copies of same-host validation, not independent reproduction. |
| Reduced spatial runtime claim | [spatial native witness][spatial-witness] closes the single-program native witness with a fresh value receipt, full-capability handoff and valid read/write. Its conditional argument and archived containment observations remain distinct evidence layers. General native mediation remains open. |
| CVE-specific evidence | Spatial has the archived CVE-2021-3490 metadata-read-stage result plus a distinct current selective runtime matrix; rejected CVE-2021-3419 is not used. Ownership supplies conditional and integrated synthetic-native containment of the CVE-2022-50650 repeated-release projection. Neither original vulnerable path is rerun. |

Neither part proves the other: correct bounds do not encode acquisition
consumption, and acquisition liveness does not authenticate spatial assignment.
No combined kernel theorem, new general enforcement mechanism, performance superiority,
arbitrary verifier/JIT-fault tolerance, or allocation-level use-after-free result
follows from this evidence selection.

[overview]: ../overview.md
[spatial-witness]: ../results/spatial-native-result.md
[spatial-witness-receipt]: ../../evidence/current/spatial-native/README.md
[acquisition-criterion]: ../../theory/acquisition-distinguishability.md
[cve-fix]: https://github.com/torvalds/linux/commit/049c4e13714ecbca567b4d5f6d563f05d431c80e
[spatial-lemma]: ../../theory/spatial.md#containment-lemma-and-proof
[spatial-counterexample]: ../../theory/spatial.md#why-allocation-bounds-are-insufficient
[spatial-patch]: ../../linux/spatial/array-authority.patch
[spatial-objects]: ../../evidence/current/spatial/object-verification.json
[spatial-manifest]: ../../evidence/current/spatial/manifest.json
[v5-exact]: ../../evidence/prior/spatial/adjacent-v5/vs.replica.v5.b01.r04.exact.console.txt
[v6-exact]: ../../evidence/prior/spatial/adjacent-v6/memop.v6.b01.r03.oobload.exact.console.txt
[spatial-matrix]: ../../evidence/prior/spatial/adjacent-v6/memory-operation-robustness-matrix-result-v1.json
[provider-exact]: ../../evidence/prior/spatial/provider/morello-exact-unsafe.log
[provider-broad]: ../../evidence/prior/spatial/provider/morello-broad-unsafe.log
[provider-wide]: ../../evidence/prior/spatial/provider/morello-wide-unsafe.log
[provider-valid]: ../../evidence/prior/spatial/provider/morello-exact-valid.log
[ownership-invariants]: ../../theory/ownership.md#three-invariants-and-induction-argument
[ownership-state]: ../../theory/ownership.md#state-and-assumptions
[runtime]: ../../linux/ownership/cbpf_runtime.c
[ownership-log]: ../../evidence/current/ownership/boot.log
[linked-runtime]: ../../evidence/current/ownership/audit/runtime-linked-range.txt
[jit]: ../../linux/ownership/cbpf_jit.c
[integration]: ../../linux/ownership/integration.patch
[native-code]: ../../evidence/current/ownership/native-disassembly.txt
[boundary-review]: ../../evidence/current/ownership/audit/boundary-review.json
[native-review]: ../../evidence/current/ownership/audit/native-review.json
[model-result]: ../../evidence/current/model-check.json
[conformance]: ../results/conformance.md
[cheri-log]: ../../evidence/current/cheri-boot.log
[gate-trace]: ../../evidence/current/gate/trace.txt
[gate-log]: ../../evidence/current/gate/boot.log
[kfunc-log]: ../../evidence/current/kfunc/boot.log
[historical-selection]: ../../evidence/prior/spatial/README.md

[ownership-controls]: ../../evidence/current/ownership-closure/README.md
[kernel-mapping]: ../../theory/kernel-ownership.md
[reproduction]: ../reproduction/README.md
[local-reproduction-result]: ../../evidence/current/local-reproduction/reproduction/reproduction.json

Trusted executive stack saves are not explicitly erased by the gateway.
The scrub claim covers program-accessible registers and the sidecar, with
trusted-stack inaccessibility retained as a premise; it does not assert
erasure of every physical capability copy.
