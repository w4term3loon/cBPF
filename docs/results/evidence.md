# cBPF evidence

cBPF studies two units of authority: a selected array-map
value and an independently acquired kfunc reference. The
[research overview](../overview.md) explains their motivation and
CVE relationship; the [claim table](../research/claim-evidence.md) identifies each
argument, implementation premise, observation, and remaining obligation.

The spatial evidence includes archived containment comparisons, a fresh benign
native witness and a [selective spatial matrix](spatial-selectivity.md) over
length-seven, stride-eight values. Ownership includes protocol arguments,
model checks, bounded native controls and one integrated
[synthetic native containment trace](ownership-native-trace.md). The principal
spatial CVE study retains an experimental observation of one archived metadata-read stage.
The [earlier findings](earlier-findings.md) distinguish additional historical cases and their fidelity.
The ownership CVE case does not execute the original
callback path. Neither part establishes the composition of the two mechanisms.

The [contribution boundary](../research/related-work.md#defensible-positioning-and-present-evidence) and
[protected software comparison](../research/capability-comparison.md) interpret these
results. Their matched abstract rules are analytical reasoning, not a new
baseline implementation, experiment or comparative security measurement.
The [result quantifiers](../research/claim-evidence.md#result-quantifiers),
[CVE causal mapping](causal-review.md#the-two-cve-mappings-side-by-side) and
[minimal-witness falsifiers](../overview.md#falsification-conditions)
likewise interpret existing evidence at its original scope.

Publication copies redact personal paths. Original records and complete old
repository archives are retained privately. The publication identity manifest
separates original experimental hashes from public-copy checksums; the source identities of recorded executions remain distinct from
publication checksums.
The [native dependency replay](../reproduction/native-replay.md) separately records fresh
builds and offline runs of both bounded kernel profiles with the clean image.

## Current evidence

| Layer | Recorded result | Interpretation |
|---|---|---|
| Portable ownership model | 17,828 reachable states, 149,205 transitions; the object-wide-consumption mutant violates acquisition independence. | Exhaustive finite exploration and a separate induction argument over the stated model. |
| Host/model conformance | 161,389 generated host executions match status, fault location/reason, reads, release accounting, and emitted events. | Bounded agreement between implementations; no model-to-C refinement theorem. |
| CHERI architecture probe | Consumed-copy and consumed-spill cases produce capability-tag faults; independent B and a direct object capability still read 42. | User-mode architectural evidence with a trusted C manager. |
| Native IR gate | 494 native case pairs match the reference and separate expected outcomes; the host gate matches 161,389 comparisons. | Native trusted-interpreter semantics; terminal violations use cleanup rather than hardware signals. |
| Ordinary Linux kfunc binding | 45 valid invocations; 82 acquisitions and releases, 38 reads, no remaining handles; five invalid programs rejected without execution. | Normal-verifier Linux kfunc/JIT integration using ordinary kernel pointers. |
| Reduced spatial provider build | Reduced patch applies to its verified inherited tree; all three changed kernel objects compile. | Source/object feasibility; inherited verifier unchanged. |
| Protected ownership execution | One 26-instruction program executes as 660 native bytes: distinct A/B cells, A consumed, B reads 42, two releases, baseline refs=1. | A bounded protected kernel path with full-capability transport. |
| Ownership boundary controls | Four accepted native executions, three trusted resolver checks, three load-only verifier rejections. | Alternate arrangement, NULL, terminal failure/cleanup, consumed-alias rejection and consume-once checks, each at its declared boundary. |
| Local reproduction | Fresh frozen-source ownership build/run and spatial object check pass; selected output bytes match ownership boundary controls and spatial provider reduction. | Repeatability on the same host/toolchain; internal validation, not external reproduction. |
| Initial spatial native witness | One normally verified 14-instruction/392-native-byte control; exact eight-byte capability; key 1 changes 41→42; return/readback 42. | Fresh selected-value construction, handoff and native access correspondence for two inspected accesses. |
| Logical extent discriminator | Logical size 7, stride 8, exact capability length 7; inspected byte-six increment 41→42 and six unchanged logical bytes. | Construction discrimination and valid native correspondence; no padding access or bounds-fault observation. |
| Selective spatial matrix | Thirty matched load/store observations: 22 permits and 8 Morello bounds faults across exact-7, stride-8 and both-slot-16 roots. | Selected synthetic native enforcement through the production provider; no verifier-admitted invalid eBPF or original-CVE execution. |
| Acquisition distinguishability argument | Object attributes and aggregate counts cannot distinguish consumed A from live B; immutable identity also requires associated validity. | A necessary observation criterion for runtime enforcement of the existing acquisition contract. |
| Release-eligibility counterexample | One live A has identical identity/liveness when released by its owning caller or a borrowing callback, but the upstream decisions differ. | Analytical requirement for owner/current-context information; no callback implementation, experiment or new theorem. |
| Ownership CVE case | Conditional repeated-release argument for CVE-2022-50650; two projected model/host controls, four matches. | A named-CVE causal mapping and bounded software checks, with prior ownership boundary controls mechanism evidence; no original callback/CVE execution. |
| Trusted callback witness | Two kernel C callback controls preserve context and capability identity; repeated release is rejected, while independent B reads 42. | Actual trusted callback transport through the existing production gate; no BPF callback, original-CVE path or hostile-callback isolation. |
| Synthetic native ownership trace | Positive, stale-read and repeated-release fixtures traverse restricted entry, transport, production gate, epilogue and cleanup; B reads 42 before both negative rejections and refs end at 1. | Integrated production-path mechanism evidence from fixed trusted native fixtures; not normally verified stale eBPF or the original callback path. |

The [conformance report](conformance.md) divides its coverage into 149,205
model edges after one shortest history per active state, 12,180 forward-branch
cases, and four scalar-boundary cases. Separate C controls cover the
64-instruction/66-event boundary and malformed unreachable instructions.
These results concern the defined instruction language; integer tokens do not
isolate ordinary C memory.

Detailed receipts are indexed under [current evidence](../../evidence/current/README.md).
The [architecture probe](cheri-probe.md), [native gate](native-gate.md), and
[ordinary kfunc binding](kfunc-integration.md) are distinct experiments. The
ordinary binding relies on verifier ownership tracking; it establishes no
runtime defense after a verifier failure. Protected ownership execution and boundary controls supply the separate
[protected ownership path](../../linux/ownership/README.md) and
[kernel/model mapping](../../theory/kernel-ownership.md).

The [spatial native witness result](spatial-native-result.md) adds a fresh linked and booted spatial kernel to
spatial provider reduction's earlier object-build result. The returned capability has tag 1, sealed 0,
base/cursor equal the selected value, length 8, and
`LOAD | STORE | GLOBAL` permissions. The held program's complete retrieved
native image matches its accepted certificate. Linked inspection connects
the reduced provider to the gateway return and the two native accesses.
RDDC remains vmalloc-wide, and the gateway retains broader authority; this
single witness does not establish all-program mediation or independent
hardware attestation. Spatial native witness performs no out-of-bounds access or CVE rerun.

## CVE and neighboring-value evidence

CVE-2021-3490 concerned incorrect ALU32 bitwise bounds tracking in the Linux
verifier. Its upstream fix corrects that tracking. The spatial case study
instead measures containment of one resulting out-of-value metadata-read
stage. [Original disclosure](https://www.openwall.com/lists/oss-security/2021/05/11/11),
[upstream fix](https://github.com/torvalds/linux/commit/049c4e13714ecbca567b4d5f6d563f05d431c80e).

[CVE-2021-3419](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2021/3xxx/CVE-2021-3419.json)
is rejected and records that it was withdrawn by its assigning authority. It
must not identify this study. The historical workload enabled
`CONFIG_CAPEBPF_TEST_VULNERABLE_ALU32`; the current reduced/selectivity profile
explicitly disables that mode and leaves the inherited verifier unchanged.

The [archived provider result](../../evidence/prior/spatial-result.md) records a
read of coallocated map metadata: outside the selected value but inside its
allocation. Exact selected-value authority caused an architectural bounds
fault and left the export sink unchanged. Broad authority and the
allocation-wide root permitted the recorded read; an exact-authority
in-bounds control returned 42. This is a stage-specific mitigation result,
not a repair of the verifier defect or proof that every CVE exploitation path
is prevented.

The separate adjacent-value records concern neighboring array values. Exact 16-byte
value bounds stopped the tested eight-byte store and four-byte load into the
next value, while broader controls completed. Valid boundary-ending accesses
succeeded. These are spatial differential controls, not additional CVE
reproductions. Earlier matched software bounds also stop the selected spatial
effect; hardware superiority is not established.

The [historical spatial selection](../../evidence/prior/spatial/README.md)
publishes redacted copies of 23 earlier logs and identity records.
That original selection retains representative first-block consoles and aggregate
reports. The [supplementary archive](../../evidence/prior/legacy-spatial/README.md)
completes both adjacent-value blocks and adds historical comparator records;
[earlier findings](earlier-findings.md) index the wider retained results.
Original validators and experiments were not rerun during selection;
omitted dependencies and unverified transitive hashes are recorded in its
manifest. Historical runtime results are not executions of spatial provider reduction's reduced patch
or spatial native witness's observation overlay.

[ownership CVE case study](ownership-cve-case.md) supplies a CVE-specific mapping for
the repeated-release arm of CVE-2022-50650. The
[receipt](../../evidence/current/ownership-cve/README.md) records two current
model/host controls and identifies prior ownership boundary controls trusted resolver evidence. These
support conditional consume-once containment of the projected effect. No
callback or original-CVE execution occurs; the upstream callback ownership
policy and acquisition-leak arm are not implemented by this case. The permanent
provider object is never freed, so heap use-after-free prevention does not follow.

[trusted callback witness](../../evidence/current/ownership-callback/README.md) is a separate current
kernel observation: actual trusted C callbacks retain one acquisition across
release requests. The second request rejects after one decrement and prevents
a third callback. A separate A/B control reads B=42 after A consumption. This
adds callback/context transport; it does not execute the vulnerable BPF/helper
path or establish its full ownership policy.

The [synthetic native ownership trace](ownership-native-trace.md) adds the
previously separate native links in one bounded execution: A/B acquisition,
alias spill/reload, A consumption, successful B read, stale gate rejection,
terminal continuation and cleanup of B. The matching verifier programs remain
load-only; their argument-shape diagnostics are not treated as ownership-rule
evidence. This strengthens the production-path mechanism observation without
turning it into original-CVE or verifier-admitted stale-BPF execution.

The [release-eligibility analysis](../../theory/acquisition-distinguishability.md#3-live-validity-does-not-determine-release-eligibility)
separately shows why this consume-once result cannot implement the upstream
callback rule by itself. Identity plus live validity answers whether A has been
consumed; owner/current-context information is additionally required to decide
whether a borrowing callback may consume live A. Callback-local leak checking
adds an exit obligation. This is a counterexample over policy observations,
not another runtime result.

## Historical ownership evidence

[Provenance](../../evidence/provenance.json) binds the original planning sources,
inactive native overlay, validator summary, six decisive console logs, and
spatial-result record. Original earlier-prototype sources are retained privately.

| Retained case | Earlier fixed-profile observation |
|---|---|
| `05-valid.log` | Acquisition, spill/reload, field read and release succeed. |
| `07-stale_s.log` | The supported consumed spill alias faults after release. |
| `08-direct.log` | A direct capability still reads the live object after that acquisition is released. |
| `09-independent.log` | A/B identify one object through distinct cells; B remains usable after A consumption; later stale A faults. |
| `10-double.log` | The injected second consume causes no second release effect. This fixture skips that effect; the current model terminates the invalid execution. |
| `22-mutation-35.log` | One attempted direct-authority escape mutation is rejected. |

The historical implementation recognizes exact named programs and supports
two static acquisitions, one private spill, and one field read. Cells are
not reclaimed; construction failure can leak a reference. Public handles
retain capability-load permission, making native template confinement part
of its argument. These limits do not describe the later reduced protected ownership execution and boundary controls path,
whose public views exclude capability loads and whose effects resolve through
protected membership and liveness checks.

The earlier validator report covers 22 receipts, including 12 negative
mutations. The publication integrity check validates the distributed copies;
it does not repeat those experiments. A separate older full adjacent-value
package check failed because an external build configuration was absent,
although 60 selected raw/normalized files matched their recorded hashes.
The current selection does not claim recovery of omitted build dependencies.

## Preservation and evidence limits

The original local reproduction used a 234-file implementation source edition
and a 334-file reproduction edition. Complete archives and unredacted originals are retained
privately; the [history description](../../evidence/history/README.md) records
their scope. Public evidence and source snapshots are editorially redacted.
Their publication identities do not replace the original execution identities
or change the experimental conclusions.

[Reproduction instructions](../reproduction/README.md) distinguish archived-edition
integrity from current evidence integrity. Hash equality establishes identity,
not correctness or independent reproduction. Dynamic mitigation of the
original ownership CVE remains unestablished. The ownership CVE case supplies
a conditional repeated-release projection and separate bounded controls.
