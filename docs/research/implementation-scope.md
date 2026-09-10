# Implementation inventory and engineering scope

The solution comprises **two separate bounded runtime profiles**, not an entire
new kernel or a combined spatial/ownership runtime. “Production” below means the
enforcement path of the evaluated prototype. Ownership uses a synthetic,
kfunc-shaped provider and a synchronous test-run entry; it is not a conversion
of existing production kfunc providers.

Read the [mechanism overview](../overview.md) before the experiment records.
The [claim map](claim-evidence.md) distinguishes implementation inspection,
execution, arguments and architectural premises.

## Core inventory

| Component and source location | Runtime responsibility | Origin | Classification |
|---|---|---|---|
| Linux map metadata, array layout and verifier; pinned `kernel/bpf/{arraymap,verifier}.c` | Own live map storage; record logical size; check map accesses and NULL refinement | Linux/Morello, with inherited prototype root-summary instrumentation | Inherited production substrate |
| [Array provider patch](../../linux/spatial/array-authority.patch): `cbpf_map_area_alloc`, `cbpf_array_authority`, `cbpf_array_value_cap`; allocation/free/accounting integration | Retain allocation authority; select by stride; bound by `map->value_size`; reject unsupported or inexact grants; retire the retained root | Reduced provider implementation on the inherited prototype | New/modified production enforcement |
| Same patch: `bpf_cheri_map_lookup_impl`, header and configuration guards | Route checked lookup arguments to the provider; exclude delegation and historical mutation modes | New integration using the inherited gateway | Production integration |
| Inherited `arch/arm64/net/bpf_jit_comp.c`: `bpf_jit_validate_prog`, `bpf_cheri_build_authority`, `build_insn`, capability emitters, helper gateway and entry | Consume root-summary contract; reconstruct per-instruction authority; preserve full capabilities; emit capability operands and sealed transitions | Earlier cBPF/Arm–Linaro Morello substrate | Inherited production compilation/transport |
| Same inherited JIT: `add_exception_handler`, `ex_handler_bpf`, epilogue | For covered BPF memory faults, select a zero-result terminal epilogue instead of the next BPF effect | Inherited prototype extension of Linux exception handling | Production terminal handling; source/native inspection is separate from the synthetic fixture's recovery |
| [Ownership runtime](../../linux/ownership/cbpf_runtime.c): `cbpf_exact`, `cbpf_gate_impl`, `cbpf_consume`, `cbpf_fail` | Construct exact acquisition views; check canonical identity and private validity; invalidate before decrement; mark terminal failure | Acquisition-specific implementation using established capability/state mechanisms | Production enforcement within the synthetic provider profile |
| Same runtime: BTF entry bodies, registration and [header](../../linux/ownership/cbpf.h) | Expose fixed acquire/read/release identities and verifier contracts; ordinary bodies have no provider effects | New interface integration with inherited BTF/kfunc machinery | Production interface |
| Same runtime: `cbpf_enter`, `cbpf_gateway`, `cbpf_test_invoke` | Install restricted roots; preserve capabilities across hybrid calls; route failure to the common exit; clean remaining live cells once and restore caller state | New bounded integration; transition framing derives from Arm–Linaro and the earlier prototype | Production entry/transport/terminal handling, despite the wrapper's “test” name |
| [Ownership compiler](../../linux/ownership/cbpf_jit.c): call classification, `admit`, emitters, `cbpf_jit_compile` | Restrict the grammar; preserve aliases and a full-capability spill; bind calls; check emitted words with its own encoder; publish the executable image | New bounded compiler using inherited encodings and transition conventions | Production compilation and internal consistency checks |
| [Ownership integration](../../linux/ownership/integration.patch) | Select that compiler; forbid fallback, attachment and program-map insertion; establish synchronous entry | New integration | Production boundary enforcement |
| [Platform extraction](../../linux/ownership/platform.patch) | Preserve restricted/capability registers across kernel transitions and enable sealed branches | Extracted unchanged in substance from the earlier prototype | Inherited platform support, reported separately |

The ownership core has 25 C function definitions (15 compiler, 10 runtime)
plus one assembly gateway. The runtime count includes the three inert BTF bodies
and the production part of registration, but excludes the trace function and
four trusted-control functions. The spatial provider changes seven functional
sites: three new functions, the replacement lookup branch, and allocation,
free and memory-accounting integration. Preprocessor/configuration integration
is additional. These are source scopes, not a measure of independent algorithms.

## Reproducible size estimate

Audit snapshot: repository commit
`89c0ece6e6c6967ad7adfa2c069d7217116136b6`.
Spatial comparison baseline: inherited kernel tree
`e6c69574c16bc2b9bce06329f9ac3f4b3269e79a`.
Ownership comparison baseline: Morello Linux commit
`b96da308ef1a054c3c04c9445e5ed70259b7c397`.
The unavailable historical replay commit is not substituted for the verified tree.

| Scope | Added/source lines | Deleted lines | Interpretation |
|---|---:|---:|---|
| Spatial provider and integration, five kernel paths | 193 | 1 | Exact patch delta against the inherited tree, including declarations, configuration and guards |
| Ownership runtime, core-classified spans | 330 | 0 | New source relative to Morello base; includes gateway/entry/wrapper |
| Ownership compiler, excluding diagnostic output | 435 | 0 | New bounded compiler source; inherited design/encodings remain attributed |
| Ownership header | 27 | 0 | New interface declarations |
| Ownership integration, seven kernel paths | 49 | 0 | Build/configuration, selection and boundary hooks |
| **Ownership core estimate** | **841** | **0** | Three new files plus seven modified kernel paths; excludes platform extraction and support below |
| Inherited ownership platform extraction, ten paths | 51 | 24 | Dependency delta against Morello, not newly invented enforcement |

Counts are physical source lines, including comments and blank lines, not
logical SLOC. Git represents replacements as additions and deletions; the
table does not infer an exact number of semantically “modified” statements.
Patch headers and context lines are excluded. New C files are counted once,
not again in retained build/evidence copies.

Reproduce the patch figures from the repository root:

```sh
git apply --numstat linux/spatial/array-authority.patch
git apply --numstat linux/ownership/integration.patch
git apply --numstat linux/ownership/platform.patch
```

For mixed files, the following inclusive line exclusions refer to the frozen
audit snapshot, so subsequent comment edits cannot silently change the result:

```sh
git show 89c0ece:linux/ownership/cbpf_runtime.c | awk '
NR==22 { unused++; next }
(NR>=56&&NR<=64)||NR==70||NR==83||(NR>=86&&NR<=88)||NR==107||
(NR>=124&&NR<=128)||(NR>=146&&NR<=147)||(NR>=179&&NR<=363)||
(NR>=368&&NR<=373)||(NR>=400&&NR<=403)||(NR>=534&&NR<=536) { support++; next }
{ core++ }
END { print "runtime core",core,"support",support,"unused",unused }'
git show 89c0ece:linux/ownership/cbpf_jit.c | awk '
(NR>=419&&NR<=427)||NR==443 { support++; next }
{ core++ }
END { print "compiler core",core,"support",support }'
git show 89c0ece:linux/ownership/cbpf.h | wc -l
```

Expected: runtime 330 core / 220 support / one unused definition; compiler
435 core / 10 support; header 27. The closure pass removes only that unused
`CBPF_SYS` definition. It has no references and expands nowhere, so no
executable behavior or retained native image is changed.

The 841-line figure is a **rough, conservative classification**, not a
standalone extracted build: mixed declarations and signatures stay in the core
when they also serve enforcement. For example, `acquired` controls the budget
and `released` participates in completion checking, while fields sharing their
declaration also support telemetry. No fractional line count is invented.
The inherited spatial JIT is not charged as new provider work. Its earlier
tree includes other profiles and dormant tests, so counting its entire diff
would not yield a precise spatial-policy size.

## Supporting infrastructure, counted separately

| Scope | Size at the audit snapshot | Counted canonical sources |
|---|---:|---|
| Spatial fixtures and observation overlays | 417 additions, zero deletions | `native-observation.patch` (16) and `selectivity-test.patch` (401) |
| Spatial guests and build/run/check support | 2,208 physical lines | Two guests; `check_spatial.sh`; spatial-native build/run/check; selectivity build/run/prepare/check |
| Ownership native-trace overlay | 251 additions, four deletions | `native-trace.patch` |
| Ownership embedded controls/observations | 230 physical lines | The excluded spans above, including 191 lines of trusted controls/registration calls |
| Ownership guests and build/run/check support | 1,897 physical lines | Two guests; ownership kernel/run; trace build/run/prepare/check; `ownership_native_checks.py` |
| Shared native receipt/integrity support | 158 physical lines | `native_receipt_common.py`, `recheck_native_evidence.py`, `verify_evidence.py` |

Reproduce the direct support-source totals at the frozen snapshot:

```sh
# Spatial: 2208
for scope_file in linux/spatial/native-guest.c linux/spatial/selectivity-guest.c \
  tools/check_spatial.sh tools/build_spatial_native.sh tools/run_spatial_native.sh \
  tools/check_spatial_native.py tools/build_spatial_selectivity.sh \
  tools/run_spatial_selectivity.sh tools/prepare_spatial_selectivity.py \
  tools/check_spatial_selectivity.py; do git show "89c0ece:$scope_file"; done | wc -l
# Ownership: 1897
for scope_file in linux/ownership/guest.c linux/ownership/native-trace-guest.c \
  tools/build_ownership_kernel.sh tools/run_ownership.sh tools/build_ownership_trace.sh \
  tools/run_ownership_trace.sh tools/prepare_ownership_inspection.py \
  tools/check_ownership_trace.py tools/ownership_native_checks.py; do
  git show "89c0ece:$scope_file"; done | wc -l
# Shared: 158
for scope_file in tools/native_receipt_common.py tools/recheck_native_evidence.py \
  tools/verify_evidence.py; do git show "89c0ece:$scope_file"; done | wc -l
```

Overlay figures use `git apply --numstat`. These support
totals cover the native studies' direct path, not every repository utility:
portable models/host implementations, host regression tests and documentation
rendering are additional supporting work. Logs, binaries, generated files and
copied evidence contribute **zero to the core estimate** and are not silently
deleted to reduce the repository's apparent size.

## Minimality review

The retained root and exact-value checks enforce different obligations from
transport; the ownership membership check and private validity check likewise
answer different questions. The compiler's grammar checks, no-fallback hooks,
failure routing and cleanup are necessary parts of the stated boundary.
The init controls and logging share files with that solution but do not define
its policy. Their separation here is analytical, not a late file-layout
refactor. Apart from the unused macro, no production removal was justified.
Neither line counts nor this review prove simplicity, security or novelty.

## Bounded closure review

The three finite passes addressed core separation, claim/evidence correspondence,
and consolidation. The principal corrections were:

- The [key-one witness](../results/logical-extent.md) is one normally verified
  valid execution; the [key-zero matrix](../results/spatial-selectivity.md) is a
  separate synthetic experiment. Its test-only recovery is not production enforcement.
- The verifier's root-summary contract, separate JIT authority reconstruction
  and runtime `map->value_size` are now distinguished explicitly. No nonexistent
  transfer of complete verifier state to runtime bounds is claimed.
- The [ownership trace](../results/ownership-native-trace.md) joins production
  mechanisms in fixed trusted native fixtures. Separate PC-13 admission controls
  are not matched counterparts to its PC-17 negatives. PC 19 releases B; PC 20
  is the unexecuted scalar marker.
- Encoder self-check, external receipt checks and authored internal inspection
  remain separate from external reproduction and compiler/runtime correctness.
  Rechecking retained bytes adds no native execution.
- The overview explains mechanisms; canonical result pages explain executions;
  the claim map supplies quantifiers; the evidence index preserves provenance.
  Repeated narrative was reduced without deleting immutable records.

At this scope, the study is complete: two implemented interface bindings with
discriminating observations and stated premises. No new subsystem, callback
policy, baseline kernel or broader research programme is required by this closure.

Closure checks on 10 September 2026: documentation builds and local-link checks
passed; all 897 publication files matched their manifest; offline retained-native
rechecks and all 27 checker regressions passed. The sole code edit removes an
unreferenced macro, so no kernel rebuild or native rerun was needed or performed.
Evidence identities and original executed scripts remain unchanged.
