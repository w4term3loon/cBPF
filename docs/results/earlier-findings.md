# Earlier cBPF findings and their evidence

The earlier cBPF prototype explored a wider set of mechanisms than the two maintained kernel profiles. This account preserves its completed findings, negative results and relevant evidence limits. It separates historical source configurations, reported formal results and directly retained observations from current cBPF behavior. Original experiments are not rerun or incorporated into the maintained execution targets.

The public records are selected technical copies. The [publication manifest](../../evidence/publication-manifest.json) distinguishes their original identities from redacted bytes; some records refer to underlying artifacts retained only with the original research. Retaining a result here does not establish independent reproduction or a stronger claim than its evidence supports.

## Historical spatial and helper boundaries

Earlier Linux experiments established four historical vulnerable/fixed validation boundaries and compared exact with deliberately broader array-value authority. Exact authority faulted at selected direct spatial effects; broader authority allowed those effects. Their fidelity differs, as recorded in the [source-fidelity map](../../evidence/prior/legacy-spatial/cve/fidelity.json) and [case records](../../evidence/prior/legacy-spatial/cve/replay-evidence.json).

| Case | Relationship to the original vulnerability | Bounded finding |
|---|---|---|
| CVE-2021-3490 | Exact public 43-instruction verifier-confusion primitive followed by a five-instruction monitored adjacent-store suffix. | The historical vulnerable parent and broad Morello control changed the adjacent value; fixed and exact-authority controls did not. This differs from the separately retained later metadata-read study. |
| CVE-2023-2163 | Official 28-instruction reproducer, apart from map-descriptor relocation. | Historical vulnerable/fixed admission differed; exact authority faulted and broader authority permitted the selected direct access. |
| CVE-2020-8835 | A public spatial primitive specialized to one read with a controlled return. | Exact authority contained this spatial consequence. The separate official nontermination consequence remains outside capability-bounds protection and was not rerun. |
| CVE-2022-23222 | Public nullable-pointer bug sequence with a substituted direct map-access consequence. | The adapted spatial consequence distinguished exact and broad authority; it is not an exact full-CVE reproduction. |
| CVE-2021-4204 | Official 14-instruction shifted ring-buffer-submit program. | A trusted capability-aware gateway rejected the shifted record pointer; the original-pointer control passed. This is software protocol enforcement, distinct from a hardware bounds fault. |

The [primary instruction-attribution record](../../evidence/prior/legacy-spatial/cve/instruction-attribution.json) retains bytecode identities, native fault mapping, source revisions and build identities. Modern Morello historical-case runs used test instrumentation to restore the relevant verifier defect; these are earlier controlled observations, not results of the current normal-verifier cBPF controls. They establish neither whole-CVE prevention nor arbitrary-verifier-defect tolerance.

A separate [direct ring-buffer report](../../evidence/prior/legacy-spatial/cve/ringbuf-direct-report.json) describes an exact-16-byte versus wide-32-byte payload control; its raw consoles were not located, so it is retained as historical report information rather than a directly retained native observation.

## Software checks and the location of enforcement

A [matched three-variant comparison](../../evidence/prior/legacy-spatial/cve/matched-defenses.json) used one historical source tree and the same four direct-spatial workloads. Exact capabilities faulted, broad controls executed, and post-verifier scalar guards returned 77 before the unwanted access. The guard added 40 native bytes per checked access plus one shared eight-byte failure stub. Valid controls passed. The comparator supported zero-static-offset map accesses and obtained trusted base/length metadata from capabilities; it was neither a portable software-isolation implementation nor AEE. Its result concerns functional behavior and emitted code size, not measured hardware speed or a smaller total trusted computing base.

A later [width-aware software comparison](../../evidence/prior/legacy-spatial/software-bounds/result.json) addressed the adjacent-value store used in the final-decision study. In each of two blocks, the enabled configuration returned 77 before the outside store and left all monitored bytes unchanged; the disabled control returned 42 and changed exactly the next value's first eight bytes. The enabled image had 30 additional words, or 120 bytes. This was a compound configuration change involving root encoding, guards, failure handling and checker profile 4. It does not isolate one instruction or authority provenance as the sole cause, and profile 4 was outside the retained Isabelle coverage. Its earlier checker-code-11 integration failure remains a separate ineligible result. Both comparisons show that correctly placed software checks can enforce the selected interval; neither establishes capability superiority.

## Adjacent-value controls and assignment limits

Across the [original selection](../../evidence/prior/spatial/README.md) and [additional consoles](../../evidence/prior/legacy-spatial/README.md), all ten store-study and twenty load-study consoles are retained. Each condition has two fresh-boot observations. The store study compared fixed admission, a faulty baseline, one source-mapped AEE offset-sanitization mechanism, exact authority and broad authority. The selected sanitizer preserved offset eight; a separate displacement and width still placed the eight-byte store outside the assigned 16-byte value. Exact authority faulted before the effect. This isolates a bounded difference under the chosen final-decision fault; it is not an evaluation of faithful whole-system AEE.

The subsequent load epoch retains the four-byte outside load and valid load/store controls. Exact bounds prevented the outside load and its dependent completion, while permitting the tested accesses ending at the value boundary. Store and load epochs have different source/native images. Their correspondence remains conditional on correct provider, element, extent and lifetime assignment, trustworthy telemetry, checked-image integrity and the live capability operand; complete production refinement and direct live operand correspondence were not established.

The separate [provider metadata-read result](../../evidence/prior/spatial-result.md) retains another important negative boundary: lookup-time narrowing was demonstrated, but the initial companion allocation capability came from executive DDC in the hybrid allocator. It was not allocator-authenticated provenance. Exact representability, correct initial bounds, provider association, restricted permissions and full capability transport remain substantive conditions, not facts inferred solely from a successful bounds fault.


## Historical lifetime experiments

The earlier [ring-buffer lifetime record](../../evidence/prior/legacy-ownership/ring-buffer-lifetime.json) reports four controls: valid spill/reload, consumed register use, consumed spill use, and a direct-capability control. The mediated consumed uses faulted while the direct capability remained usable; six native-template mutations were rejected. This predecessor used a ring-buffer analogue, not actual BTF kfunc ownership. Its source manifest is preserved as a selected technical record; its referenced logs and binaries are not distributed or revalidated here. Exact profiles skipped constant blinding despite the runtime hardening setting, and neither an independent ring-buffer consumer nor physical Morello hardware supplied an additional oracle.

The later [22-case native record](../../evidence/prior/native-validation.json) bound an actual BTF acquire/release pair. The added [consumed-register console](../../evidence/prior/legacy-ownership/native-stale-register.log) complements the retained spill case: one release preceded a tag fault and a zero return. These historical native negative controls used fixed test-only post-verification transformations; ordinary invalid source programs were separately rejected by the verifier. They do not establish the missing consumed-alias failure path in the current normally verified profile. Historical cells were unreclaimed, construction failure could leak a reference, object authority originated from executive DDC, and exact native templates and synchronous confinement remained trusted. The twelve mutations targeted acquisition A, without a dedicated B-path mutation. A calibration that ended in a PID-1 panic was excluded and the full schedule restarted; an earlier interpreter calibration was unsupported because the kernel required JIT compilation for kfunc calls. Trusted temporary capabilities were not globally erased. Historical second-release suppression skipped the effect, whereas the current protocol terminates an invalid invocation.

## Upstream repair comparison

The archived provider study's [x86 parent console](../../evidence/prior/legacy-ownership/provider-x86-parent.log) records the metadata-read stage executing and changing its sink; the [fixed-revision console](../../evidence/prior/legacy-ownership/provider-x86-fixed.log) records verifier rejection of the same canonical input, without execution. These passive records support the historical study's relationship to the upstream repair. They do not extend the spatial result beyond its recorded metadata-read stage or constitute a new CVE execution.


## Earlier implementation and evaluation findings

These observations belong to earlier source configurations. They explain the
research trajectory but do not enlarge the claims of the two maintained
kernel profiles. The records below are passive evidence; no earlier harness,
fault-injection mechanism or proof toolchain is part of the maintained build.

### uBPF precursor

The [host records](../../evidence/prior/legacy-evaluation/ubpf/host.jsonl) and
[CHERI records](../../evidence/prior/legacy-evaluation/ubpf/cheri.jsonl) retain
32 baseline and 44 capability-backend outcomes. Fifteen supported valid cases
return their expected values. Thirteen spatial out-of-bounds effects that
complete in the baseline instead report capability-bounds faults; four stale
ring-buffer protocol cases report tag faults after **explicit modeled
invalidation**. These are reduced effects and protocol models, not original
Linux CVE reproductions or general temporal safety. Twelve broad/bounded
comparisons and sixteen single-provider-call observations retain the causal
controls.

The [paired validator results](../../evidence/prior/legacy-evaluation/ubpf/validator-policies.jsonl)
cover 37 cases under each reduced policy. The
[translator matrix](../../evidence/prior/legacy-evaluation/ubpf/cheri-jit-feature-matrix.jsonl)
distinguishes 14 supported, 11 rejected and six explicitly untested features.
The [10,000-program host differential](../../evidence/prior/legacy-evaluation/ubpf/jit-differential-host.json)
reports no interpreter/JIT mismatches. The
[1,000-program host prefix](../../evidence/prior/legacy-evaluation/ubpf/jit-differential-host-prefix.json)
and [CHERI run](../../evidence/prior/legacy-evaluation/ubpf/jit-differential-cheri.json)
have matching recorded corpus and result hashes. These results concern their
generated subset; they are not a translation proof.

### Formal argument and assignment pilot

Earlier [local formal validation](../../evidence/prior/legacy-evaluation/formal/checker-validation.json)
checked 31 complete-envelope witnesses and 592 body instructions, alongside a
conditional trace argument. The
[helper receipt](../../evidence/prior/legacy-evaluation/formal/helper-validation.json)
records three limited generated-C refinements at its historical source
version. The [scope account](../../evidence/prior/legacy-evaluation/formal/scope.json)
preserves the later accepted-direction fact-gate result and its explicit
record, disjointness and storage-coherence premises. Full checker/JIT
refinement, universal live-runtime correspondence and Linux-adapter
composition remain unproved. The later fact-gate account is source-reported;
its raw proof-build transcript is not included here.

The [assignment pilot](../../evidence/prior/legacy-evaluation/pilot/results.json)
contains 165 runnable observations and 15 explicit N/A rows across three modes
and three boots. Four verifier-report corruptions reject before root use. For
both spatial containment and intended-object identity, the exact mode remains
sensitive to provider binding, selected element and extent assignment.
**Both empirical delegated-dependency sets are empty** relative to the
evaluated disabled baseline. Static obligation labels therefore cannot be
cited as a measured reduction in verifier trust. The
[design](../../evidence/prior/legacy-evaluation/pilot/design.json) discloses prior
knowledge of one direction; the pilot was not wholly outcome-blind. The
[attempt index](../../evidence/prior/legacy-evaluation/pilot/attempts.json)
preserves 188 earlier failed rows before the complete final attempt.
Separate larger studies remained at
[0/2,940](../../evidence/prior/legacy-evaluation/pilot/uncollected-original-study.json)
and [0/936](../../evidence/prior/legacy-evaluation/pilot/compact-schedule-summary.json)
and contribute no observations.

### Compatibility and cost boundaries

The [predeclared selection rule](../../evidence/prior/legacy-evaluation/corpus/selection-policy.json)
includes every structurally eligible function from five pinned Linux selftest
files. Its [selection report](../../evidence/prior/legacy-evaluation/corpus/selection-report.json)
retains 28 included and 21 excluded functions. The
[recorded execution](../../evidence/prior/legacy-evaluation/corpus/morello.log)
contains ten valid JIT executions, twelve expected verifier rejections and six
valid cases rejected as unsupported: two pointer-bounds cases and four loops.
This discloses compatibility within a small fixed frame, not representative
eBPF coverage.

The [five-boot x86 verifier record](../../evidence/prior/legacy-evaluation/performance/x86-verifier.log)
counts eligible checks from one to 128 accesses, while processed instructions
and state counts remain unchanged. Median-of-boot-median strict/delegated
times are 13/10, 13/13, 19/18 and 40/39 microseconds. Small and inconsistent
differences do not establish meaningful verifier speedup. The x86 delegated
mode stops after verification because it has no capability backend.

The [balanced QEMU study](../../evidence/prior/legacy-evaluation/performance/steady-state.json)
retains five boots per variant, 34 within-emulator comparisons and seven code
size comparisons. The [recovery study](../../evidence/prior/legacy-evaluation/performance/recovery.json)
records 35 measured fault calls returning zero, followed by 35 controls
returning 42. These are functional-emulation observations, not physical
Morello performance, intrinsic trap latency, rollback or availability
guarantees. Failed collections remain indexed separately. The
[source accounting](../../evidence/prior/legacy-evaluation/performance/review-surface.json)
reports a declared common lower bound of 1,472 nonblank/noncomment lines
(1,317 semantic lines), with overlapping variant regions reported separately.
It measures a specified review surface, not total TCB size or security strength.

The imported collection receipts preserve identities of lower-level records.
Full pilot consoles, proof sources/build logs, QEMU per-sample records and
build dependencies remain in the retained original archive; this subset
supports inspection of the reported findings but is not independently
reproducible from these records alone. Historical source hashes and checksums
of redacted publication copies identify different bytes.
