# Causal analysis of the spatial and ownership evidence

The analysis uses **conditional argument** for a consequence of explicit
premises, **inspection** for checks of source and native instructions, and
**record** for retained telemetry. These evidence classes do not establish a
general native refinement proof.

Source/hash comparisons describe the inspection recorded on 7 September 2026.
Public copies redact personal paths; their checksums are distinct from the
original experimental identities listed here.

## The two CVE mappings side by side

The mapping separates original defects, represented events and intercepted
effects. Trusted callback observations supplement the earlier evidence while
retaining their distinct source identities and execution scope.

| Causal question | CVE-2021-3490: selected-value spatial authority | CVE-2022-50650: per-acquisition ownership |
|---|---|---|
| Original failure | The verifier did not correctly update ALU32 bounds for bitwise operations, enabling out-of-bounds kernel accesses. This was a verifier defect, not an array-allocation defect. [Original disclosure](https://www.openwall.com/lists/oss-security/2021/05/11/11). | The verifier accounted for one synchronous callback execution while a helper could repeat it. Caller-owned aliases could therefore cause repeated releases; repeated acquisitions also caused leaks. [Linux announcement](https://lists.openwall.net/linux-cve-announce/2025/12/09/30). |
| Represented events | In the historical stage: lookup selects a value, the returned authority reaches an eight-byte metadata read outside that value but inside its allocation, and a later sink records the result if the read succeeds. | ownership CVE case: acquire A, retain/reload its alias, consume A, request another consume through the same identity. Trusted callback witness: retain that identity and one invocation/context across actual trusted C callbacks making the two requests. |
| Intercepted effect | Exact authority produces the recorded bounds fault at BPF 45/native word 122 before the metadata read completes; the sink remains unchanged. Broad and allocation-wide returns allow metadata to reach the sink. | The first valid consume clears private liveness before one decrement. The repeated request fails its liveness check before another decrement; rejection terminates the invocation/dispatch. |
| Evidence class | **Historical observation:** exact/broad/wide stage contrasts and a valid exact control. **Initial native inspection/observation:** spatial native witness connects a correct eight-byte grant to a valid read/add/store returning and reading back 42; it supplies no new rejection or CVE run. | **Conditional argument:** consume-once invariant under identity, state, mediation and lifetime premises. **Host observation:** two ownership CVE case projections, four model/C matches. **Kernel inspection/observation:** trusted callback witness's trusted callback transport and production-gate checks; not BPF callback execution. |
| Omitted boundaries and policy differences | No repair of ALU32 analysis, containment of every CVE stage, arbitrary-program mediation, lifetime safety or transfer of the historical outcome to current spatial native witness. Historical and current sources/configurations remain distinct. | No original BPF/helper path, hostile-callback isolation, complete callback-frame policy, leak-arm result or heap reclamation. Upstream forbids the **first** callback release of a caller-owned reference; cBPF permits one valid consume and blocks repetition. [Upstream repair](https://github.com/torvalds/linux/commit/9d9d00ac29d0ef7ce426964de46fa6b380357d0a). |

**Spatial conclusion:** the archived comparison supports containment of one
CVE-linked metadata-read stage under its retained conditions. Spatial native witness separately
establishes current valid-use correspondence. **Ownership conclusion:** ownership CVE case
establishes conditional repeated-release-effect containment, and trusted callback witness observes
the necessary identity persistence and rejection across trusted C callbacks.
Neither conclusion establishes that cBPF fixed both original CVEs in their
original kernel execution paths.

## Selected-value spatial authority

The conditional argument and historical contrasts are separate from spatial native witness's
current source/native correspondence for one valid program.

### Spatial native witness source to effect

Line references identify the reduced spatial patch and retained spatial native witness image.

| Link | Support inspected | Necessary boundary |
|---|---|---|
| Selected map and key → intended live value | **Inspection:** the reduced lookup checks the map-table token and key capability, then calls `cbpf_array_value_cap`. The provider checks plain ARRAY, expected operations, zero flags, no value record, retained-root shape and index range. See [patch](../../linux/spatial/array-authority.patch), lines 61–72 and 190–225. | The trusted provider/map association, intact metadata, layout, non-wrapping arithmetic and live allocation give these checks their semantic meaning. They do not authenticate an arbitrary substituted provider. |
| Allocation → retained root | **Inspection:** `cbpf_map_area_alloc` derives exact allocation bounds from executive DDC, reduces permissions, checks the result and saves the full capability in array auxiliary state. Patch lines 262–275 and 326–354. | This is checked retention of a trusted initial assignment, not allocator-minted provenance. Writable auxiliary state remains trusted. |
| Retained root → exact selected value | **Inspection:** cursor derivation uses element stride, but bounds use logical `value_size`; tag, sealing, base, cursor, length and exactly `LOAD \| STORE \| GLOBAL` are checked before return. Patch lines 217–227. Linked provider has `SCVALUE` at `0xffff8000801c1f58` and `SCBNDSE` at `...1f5c`, followed by checks, full-capability preservation across logging and return. [Linked code](../../evidence/current/spatial-native/review/linked-disassembly.txt), lines 413–507. | Exact construction may reject representability/profile failures. This inspection covers the equal-size/stride witness. The later [logical extent discriminator](logical-extent.md) observes length seven and stride eight; no padding fault is executed. |
| Provider return → actual memory operand | **Inspection:** operation zero dispatches lookup and preserves returned `c0`; native word 72 copies the full capability into `c7`. Words 75 and 77 perform eight-byte load/store through unchanged `c7`. The complete 98-word image has no other selected-value write or alternate root for these accesses. [Native disassembly](../../evidence/current/spatial-native/review/jit-disassembly.txt), lines 65–82; linked gateway/lookup, lines 6–112. | This is the particular image retrieved from the held program FD. Image integrity, source/launch binding, compiler/architecture and synchronous invocation remain trusted. |
| Exact root → bounded effect | **Conditional argument:** CHERI monotonicity and access checks imply that a successful access through this root lies inside the selected interval. [Spatial lemma](../../theory/spatial.md), premises 1–4. | Applying the conclusion to every admitted program requires premise 5: complete mediation. Exactness of one returned capability does not establish it. |
| Inspected program → observed valid effect | **Record:** one normal-verifier `TEST_RUN`; selected key 1 changes 41→42; scalar return and ordinary readback equal 42. Provider records eight-byte exact authority with tag 1, sealing 0 and permissions `0x30001`. [Boot log](../../evidence/current/spatial-native/run/boot.log), lines 550–562. | Valid-use and correspondence evidence, not an observed out-of-bounds rejection. Provider logging is source-backed telemetry, not independent hardware attestation. |

For exact source correspondence, the inspected spatial native witness tree is
`build/spatial-s5-build.Z4e3mc/source/`. Its `arch/arm64/net/bpf_jit_comp.c`
contains the reduced lookup at lines 584–614, gateway at 751–829 and ambient
root setup at 858–965. Its `kernel/bpf/arraymap.c` provider is at lines 38–81.
The [source hash list](../../evidence/current/spatial-native/build/patched-sources.sha256)
identifies these files, including the observation overlay; all six entries
matched the retained local source at the recorded inspection.

### Broader authority is a real premise

The inherited entry sets RDDC to the vmalloc region (source lines 961–965);
the gateway sentry retains executive DDC, recorded with base zero and maximal
length. Sealing controls entry but does not narrow that authority to the
selected value. Trusted gateway code also converts checked capability cursors
to ordinary pointers for metadata/key access.

The covered load/store use `c7`, preserving their correspondence. This does
not exclude alternative roots, helper paths or provider corruption for every
accepted program. Neither the permission mask nor the accepted certificate
proves mediation. No bypass was constructed; exploitability is not assessed.

### What the historical comparisons establish

The [upstream repair](https://github.com/torvalds/linux/commit/049c4e13714ecbca567b4d5f6d563f05d431c80e)
corrects ALU32 verifier state. cBPF's evaluated protection acts later, at one
memory access; it does not repair that analysis.

| Retained contrast | Causal reading |
|---|---|
| [Exact provider](../../evidence/prior/spatial/provider/morello-exact-unsafe.log), lines 592–602 | Returned bounds cover only the 4,919-byte value. The eight-byte metadata read faults with FSC `0x2a`, native word `e2c00453`, root `c2`, cursor at the allocation base, 272 bytes before the selected value; the monitored sink remains unchanged. |
| [Broad return](../../evidence/prior/spatial/provider/morello-broad-unsafe.log), lines 592–600 | An exact *candidate* receipt exists, but the actual return record says `authority=broad_ddc`. Metadata reaches the sink. Treating the candidate as the returned authority would reverse the interpretation. |
| [Allocation-wide return](../../evidence/prior/spatial/provider/morello-wide-unsafe.log), lines 592–600 | The returned 5,240-byte root includes allocation metadata; the same recorded stage completes. `binding_valid=0` marks deliberate ineligibility for the exact-binding claim. This is a granularity contrast, not a failed exact implementation. |
| [Valid exact control](../../evidence/prior/spatial/provider/morello-exact-valid.log), lines 430–434 | The valid program returns 42 under exact authority, countering the explanation that exact mode simply disables useful execution. |

In each mode, certificate lines 571–574 map BPF 45 to native word 122, an
eight-byte load. Sink line 290 starts with `word_at_8=0xc3c3d4d4a5a5b6b6`
and FNV `36c487aa1ff6bccf`. Exact line 601 retains both; broad/wide line 599
records `word_at_8=0xffff800080b57fb0`, matching the logged provider-operations
address, with FNV `e128940966d77a21`. These byte/effect checks distinguish a
bounds fault from mere lack of a completion message.

The original manifest binds the same canonical stage and target access across
these modes, but records different native image hashes: they are matched
experimental conditions, not byte-identical kernels/images. Historical
configuration explicitly enabled the ALU32 test mode. Current spatial native witness disables it
and leaves the inherited verifier unchanged. Historical permissions were
`0x34dfd`; current reduced permissions are `0x30001`. Spatial native witness therefore does not
repeat or automatically inherit the archived CVE observation.

The adjacent-value [matrix](../../evidence/prior/spatial/adjacent-v6/memory-operation-robustness-matrix-result-v1.json)
adds exact/broad contrasts for an eight-byte store and four-byte load, with
valid accesses ending at the 16-byte value boundary. Its separate epochs,
selected first-block consoles and conditional operand/image correspondence
remain explicit. These records support logical-value boundaries, not general
JIT correctness or superiority over software checks.

### Spatial artifact identities

At the recorded inspection, size/SHA-256 checks matched all 53 spatial
native witness files and 23 historical spatial files. The then-active reduced
patch matched its recorded copy. The following hashes identify original
experimental artifacts, not editorially redacted publication copies:

- Pinned inherited tree: `e6c69574c16bc2b9bce06329f9ac3f4b3269e79a`
  (source identity, not a correctness result).
- Reduced patch SHA-256: `ac74717a7dbd2c61760115c1b8b719e52d27d60d02957a2b73c3ff155206c4ac`.
- spatial native witness native bytes SHA-256: `97d2bc5287edec817d679e8d740ea5bf51f695b3157e8683152b364afe48710d`.
- spatial native witness raw boot SHA-256: `1cf96d964db77ae3e6caf588f7129573dc3436477707de92ef62deff7b0d7b02`.
- Historical provider manifest SHA-256: `916f48167572a703a4f0435ce8315844e19e5e1a5fe5ccb43de062953c2236ae`.

The [spatial native witness manifest](../../evidence/current/spatial-native/manifest.json) and
[historical selection manifest](../../evidence/prior/spatial/manifest.json)
supply every selected file identity. Integrity checks establish correspondence
to those receipts, not independent reproduction or verification of omitted
historical binaries.

**Spatial evidence boundary.** Conditional containment, archived stage
contrasts and the native witness retain distinct evidence levels. Complete
native mediation, whole-CVE mitigation, temporal safety and composition remain
unestablished.

## Per-acquisition ownership

The [ownership induction](../../theory/ownership.md#three-invariants-and-induction-argument)
establishes consume-once and independent-B preservation before terminal failure
for its abstract rules. Acquisition distinguishability explains the need for acquisition-sensitive validity.
Both are conditional arguments, independent of comparison counts.

### Ownership boundary controls source to effect

Line references below identify the retained ownership boundary controls runtime. Trusted callback witness's later init-only
callback controls have a [separate build/run receipt](../../evidence/current/ownership-callback/README.md);
the production gate is unchanged.

| Link | Support inspected | Necessary boundary |
|---|---|---|
| Successful acquire → fresh owning identity | **Inspection:** [ownership boundary controls runtime](../../evidence/current/ownership-closure/source/cbpf_runtime.c), lines 104–129, checks arguments/capacity and exact view/object construction before incrementing the provider reference. The next private cell and canonical view are published once; the index increases and is not reused inside the invocation. | Two cells, one permanent object. Executive DDC assignment, private state integrity and containment of aliases within the invocation remain premises. A capability authenticates its representation, not the correctness of the provider's choice. |
| Identity → retained alias | **Inspection:** [compiler](../../linux/ownership/cbpf_jit.c) admits only defined register copies and the fixed spill/reload forms, lines 123–145. [ownership boundary controls native image](../../evidence/current/ownership-closure/audit/native-disassembly-ab_spill.txt) has full-capability store/load at offsets `0x10c`/`0x13c`. **Record:** the accepted A/B program releases A through this transport and subsequently reads B. | Supported transport only. The trusted stale-spill control uses a different C stack location; it is not an execution of stale authority through the restricted sidecar. |
| Supplied alias → checked private validity | **Inspection:** runtime lines 131–150 compare the complete capability against the canonical views, then check the selected cell's private object tag before the read or consume. [Linked resolver](../../evidence/current/ownership-closure/audit/runtime-linked-range.txt), lines 113–174, orders `CHKEQ`, private-capability load/tag check, then field load or consume call. | Every covered effect must reach this resolver. The public view is never used to dereference the cell. Checks do not prove that arbitrary native instructions cannot reach some other effect path. |
| Valid release → one ordered provider effect | **Inspection:** runtime lines 75–88 clear and store the private capability tag before the reference decrement. Linked lines 422–454 and 502–505 preserve that order for the two decrement alternatives. **Record:** ownership boundary controls logs private tag zero at `clear` while the old count remains, then one decrement at `release`. | Synchronous, non-reentrant execution. The intermediate `clear` trace is not a completed model transition. The decrement targets the trusted fixed provider object; this is not arbitrary-object deallocation through a bounded capability or a concurrent linearizability result. |
| Rejected operation → terminal invocation and cleanup | **Inspection:** runtime lines 333–363 route the failure sentinel to the fixed executive epilogue, and lines 279–294 clean remaining live cells and tear down the arena. [ownership boundary controls native review](../../evidence/current/ownership-closure/audit/native-review.json) binds the epilogue and linked wrapper ordering. **Record:** `fail_second` rejects before a second acquire effect and cleans A once. | The actual failure is scalar argument 2. Construction/capacity failures and nonzero cleanup after ordinary return retain their source/model basis. No restricted operation follows failure; cleanup is trusted teardown. |

Untagged RDDC, a 16-byte sidecar, fixed gates, restricted instructions,
scalar-only return and attachment exclusions support this profile's mediation
argument. These differ from the wider spatial roots. The final-word check
uses the compiler's own encoder, so it is not an independent native validator.
Compiler, gateway, kernel, exception preservation and architecture remain trusted.

### Decisive observations and the CVE projection

| Existing control | Observation in the raw record | What it resolves |
|---|---|---|
| Native `ab_spill` and `ab_alternate` | [ownership boundary controls boot](../../evidence/current/ownership-closure/boot.log), lines 671–682 and 1110–1121: two distinct acquisitions; A's private tag clears; B reads 42; both releases complete; final references equal one. | A release does not invalidate all rights to the object. These runs contain no later stale A use. |
| Trusted `stale_copy`, `stale_spill`, `duplicate_release` | Same log, lines 224–244: the supplied public alias remains tagged and canonical, its private tag is zero, the resolver rejects, reads stay zero and exactly one release has occurred. | Rejection depends on private acquisition validity rather than a destroyed public alias. The duplicate request causes no second decrement. All three records explicitly identify `native_bpf=0`. |
| Native `fail_second` | Same log, lines 1974–1981: acquire A → reject PC6 → clear A → cleanup A → failed; scalar result zero and final references one. Linked gateway and epilogue inspection corroborate skipped continuation. | A real admitted native failure reaches terminal cleanup. It is a separate execution from the trusted stale checks. |
| Ownership CVE case retained-alias projection | [Results](../../evidence/current/ownership-cve/results.json): acquire, spill, reload, release, reload, rejected release; one explicit release, no cleanup and no read. The separate A/B control reads 42 and releases twice. | Two projected controls agree with both host C paths. They do not execute callbacks or native BPF. |
| Trusted callback transport | [trusted callback witness boot](../../evidence/current/ownership-callback/run/boot.log), lines 245–266: the repeated A alias remains tagged/canonical across two callbacks; private liveness changes from one to zero, with one decrement and no third callback. Separate A/B callbacks read B=42 and finish with refs=1. | Actual function-pointer dispatch and persistent context/state support callback transport through the production gate. [Linked inspection](../../evidence/current/ownership-callback/review/linked-review.json) checks full-capability loads, call targets and failure edges. These are trusted executive C callbacks, not protected BPF callbacks or the original helper. |

The ownership CVE case driver, [lines 43–67](../../theory/check_ownership_cve.py), retains one model
state per case, checks terminal/count outcomes and compares complete observations
through `require_match`. Its trailing `-17` return is unreachable after rejection.

The conditional ownership CVE case invariant allows at most one effect for any finite proposed
number of repeated requests: the first repetition rejects and terminates.
The [source audit](../../evidence/current/ownership-cve/source-audit.json) records
the upstream callback repair in the current base. As the opening mapping
states, that repair forbids the first caller-reference consume; cBPF allows
one. Trusted callback witness adds trusted C transport, leaving original-path mitigation, callback
policy equivalence, the leak arm and reclamation unestablished. Independent
B tests precision; it is not required by this CVE.

### Ownership artifact identities

The source checks preceding the trusted callback witness matched all eight
relevant ownership boundary controls source/tool identities, eight ownership CVE case source
identities and both ownership CVE case host-library identities. The retained-evidence
verifier passed its existing protected ownership execution and boundary controls/ownership CVE case file-integrity checks.

- Retained ownership boundary controls runtime SHA-256: `a70dfb8b78ec3f6bd6d97afc3ad4c67a8cc63741955bd1005897942776b86296`.
- Restricted compiler SHA-256: `a1a3c2476380325100a9b361f213bb06db9e9dd24543ae8e12a5354ddd8dd753`.
- ownership boundary controls raw boot SHA-256: `b0fe5332e9a52e53ac6a3f452d2f8e86bfe4a1d27a79dbc368aa1843194e1b8d`.

**Ownership evidence boundary.** The conditional argument, inspected
implementation and complementary observations support their stated portions
of the acquisition protocol; they do not prove defect absence.

## Supported causal claims

| Claim | Evidence boundary |
|---|---|
| Exact selected authority contains covered accesses. | Supported conditionally; current native correspondence is limited to spatial native witness's inspected program. |
| Consuming A rejects its later mediated effects while independent B remains live. | Supported by the abstract argument and complementary bounded controls; B is evaluated before any terminal failure. |
| The two contributions are relevant to documented CVEs. | Supported, with archived spatial-stage evidence and a projected ownership case distinguished. |
| cBPF repaired both original CVEs, proves all-program mediation or combines both mechanisms safely. | Not established by the evaluated evidence. |

The [contribution boundary](../research/related-work.md#defensible-positioning-and-present-evidence) relates these
bounded findings to prior work.
