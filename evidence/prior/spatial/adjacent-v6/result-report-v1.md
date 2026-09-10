# Historical array-map memory-operation results

Publication copy of the historical memory-operation study (V6); see [redaction and identity scope](../../../README.md).

Date: 2026-09-02  
Scope: spatial safety for the closed array-map direct-memory profile

## Result

The four-case matrix contains one out-of-bounds store, one out-of-bounds
load, one valid load and one valid store. It covers widths 4 and 8 and four
effective intervals. No second map configuration or object arrangement was
tested. The recorded completeness decision remains conditional on final
package validation and both no-write recomputations passing.

Across the scheduled memory-operation cases, exact capability authority
prevented selected verifier-missed spatial loads and stores from completing,
while broader authority allowed the same operations to complete. This
demonstrates bounded delegation of spatial enforcement for the tested eBPF
memory operations.

The store and load observations belong to distinct, explicitly retained patch
epochs. V5 supplies the store row; V6 supplies the load and valid controls.
They are combined only by the prospective four-case matrix and stopping rule.

## Recorded observations

| Matrix case | Modes used for the result | Repetitions | Observation |
|---|---|---:|---|
| V5 OOB store, width 8, `[16,24)` | fixed, faulty baseline, selected AEE-offset sanitizer, Cape broad, Cape exact | 2 per condition; 10 fresh boots total | Baseline, selected sanitizer, and broad replaced exactly key-1 bytes 0--7 with `2435465768798a9b`; exact faulted at the mapped store before any monitored byte changed. |
| V6 OOB load, width 4, `[16,20)` | fixed, faulty baseline, Cape broad, Cape exact | 2 per condition; 8 fresh boots | Baseline and broad completed the load and dependent copy and returned `724183336` (`0x2b2a2928`); exact reported FSC `0x2a` at the mapped `CHERI_LDRW`, with `completed=0`, no dependent copy, and zero fault-path return. |
| V6 valid load, width 8, `[8,16)` | faulty baseline, Cape broad, Cape exact | 2 per condition; 6 fresh boots | All modes completed and returned `454695192` (`0x1b1a1918`); every monitored byte was unchanged. |
| V6 valid store, width 4, `[12,16)` | faulty baseline, Cape broad, Cape exact | 2 per condition; 6 fresh boots | All modes changed exactly key-0 bytes 12--15 to `24354657`, returned 43, and left every other monitored byte unchanged. |

V6 therefore retained 20/20 scheduled observations, all claim-eligible, in two
fresh-boot blocks with no replacement or majority vote. V5 separately retained
10 scheduled fresh boots in two blocks. “Ten boots” does not mean ten
repetitions per condition: each scheduled condition has two repetitions.

The V6 load completion claim does not rely on unchanged memory. Site 15 copies
the site-14 load result into the program-visible return only after the load.
Baseline and broad returned the expected key-1 value; exact fault recovery
skipped that instruction.

## Causal controls

The recorded V6 controls pass:

- all eight OOB rows match the frozen relevant `V.a` values and normalized
  semantic digest `53b904826fe240c7bb31e12cabc2da9dc101d54462f37d7cc483dbc68048050c`;
- all six fault-armed OOB rows report one identical `final_range_only`
  final-decision override, while fixed rows report no override;
- canonical BPF bytes and object initialization agree within each case;
- the Cape broad and exact target permissions agree;
- fixed rejects, baseline and broad complete, and both exact rows fault at the
  intended site-14 native load;
- load cases retain value-dependent completion evidence and complete
  before/after snapshots; store cases retain exact byte recomputation; and
- every condition agrees across the two frozen blocks.

V5 independently validates the corresponding relevant-`V.a`, injected-fault,
identity, live-effect, target-fault, successor, and byte controls for its store
case. Cross-epoch raw records and native images are not asserted to be equal.

## Correspondence status

The selected exact load event is
`memop.v6.b01.r03.oobload.exact`. Its correspondence record contains 11 links:
ten are `yes`, and `operands_and_effective_address` is `indeterminate` because
the direct live capability-operand/register relation is template-derived rather
than observed. Canonical vertical eligibility remains false.

The record connects amended final BPF and relevant verifier facts, the
one-shot faulty final decision, accepted gate handoffs, key-0 assignment,
installed tagged 16-byte capability, reconstructed checked native
`CHERI_LDRW`, attempted interval `[base+16,base+20)`, target PC/word, FSC
`0x2a`, and absence of the dependent copy. It is a bounded conditional witness,
not complete production refinement.

Remaining premises are final-BPF and binding authenticity beyond retained
telemetry; complete production C/Linux/JIT refinement; checked-image
immutability; direct live operand/register correspondence; semantic provider,
element, extent, lifetime, and non-reuse correctness; and faithful telemetry
and architecture behavior.

## Calibrated finding

**Research formulation.** Under fixed relevant verifier analysis and a fault
confined to the final spatial decision, do broader and exact capability
authority produce different completion outcomes for selected direct eBPF loads
and stores?

**Basic-CS formulation.** A pointer authorized beyond a 16-byte array element
can read or write the next element. A capability bounded to the selected
16-byte element traps when the same selected access starts at byte 16, while
still permitting tested accesses ending at byte 16.

**Evidence status.** Runtime observation in two separately recorded source epochs,
with two fresh-boot repetitions per condition; machine-recomputed byte and
completion oracles; conditional load/store correspondence; not an
unconditional production proof.

**Conditions.** The frozen V5 and V6 experimental protocols and identities validate; the
relevant `V.a` premise is sound; only the final spatial decision is faulty;
kernel provider/element/extent inputs identify the intended live interval; the
checked image is the executed image; and the retained completion, fault, and
byte telemetry are faithful.

**Falsifier.** The finding is refuted or made ineligible if an eligible exact
OOB row completes its target or dependent effect, a baseline/broad OOB row
cannot establish the declared live operation, a valid control fails, relevant
`V.a` or the injected fault differs across a central comparison, a target fault
maps to another instruction, or any primary hash/no-write recomputation fails.

**Does not establish.** It does not establish all-eBPF memory-operation
coverage; delegation of every verifier spatial obligation; verifier removal or
net TCB reduction; semantic object correctness; temporal safety; complete
production correspondence; whole-AEE correctness; superiority to a software
bounds check; native Morello performance; provenance-only causation; a second
map layout; or independent reproduction.

**Primary artifact paths.** The primary records are:

- `linux/benchmarks/faulty-vs-differential/artifacts/result-v5/experiment-result-v2.json`
- `linux/benchmarks/faulty-vs-differential/artifacts/result-v6/experiment-result-v1.json`
- `linux/benchmarks/faulty-vs-differential/artifacts/result-v6/memory-operation-robustness-matrix-result-v1.json`
- `linux/benchmarks/faulty-vs-differential/artifacts/result-v6/load-correspondence-v1.json`
- `linux/benchmarks/faulty-vs-differential/artifacts/result-v6/stopping-rule-decision-v1.json`
- `research/faulty-vs-differential-v6/implementation-conformance-amendment-v1.json`
- `linux/research/faulty-vs-memory-operations/source-build-runtime-identity-receipt-v1.json`

## Validation and reproduction limits

The recorded package-validation command is
`tools/faulty-vs-differential-v6/validate_package.py --full-recompute`. It must
validate the receipt and manifest and recompute both V5 and V6 results without
writing. The historical completeness decision is conditional on these checks;
missing validation is not treated as success.

Historical build and runtime objects were external to the source tree, limiting
exact source-release reconstruction and independent reproduction. The 15
exploratory failure/calibration consoles were retained under
`result-v6/exploratory/`; they remain excluded from the scheduled aggregates.
