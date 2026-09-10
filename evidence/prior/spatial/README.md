# Selected historical spatial evidence

This directory publishes copies of **23 historical files**, originally
765,817 bytes and selected on 6 September 2026. The experiments occurred in the earlier repositories on
2–5 September. The original selection comprised copying, checksum verification and
documentation; later [publication redaction](../../README.md) removes host paths. No experiment or historical validator was rerun.

The existing [spatial result](../spatial-result.md) supplies the provider-study
narrative; it is not duplicated. [manifest.json](manifest.json) records every
selected file's original size, SHA-256 and purpose, with source paths redacted.
The publication manifest verifies the edited shareable copies.

| Retained group | Observation supported by the selected records |
|---|---|
| [Provider exact](provider/morello-exact-unsafe.log), [broad](provider/morello-broad-unsafe.log), [allocation-wide](provider/morello-wide-unsafe.log) | The same recorded metadata-read stage faulted with exact selected-value authority; broad and allocation-wide authority allowed its recorded completion. The allocation-wide receipt was ineligible for the exact binding claim. |
| [Provider valid control](provider/morello-exact-valid.log) | The exact-authority in-bounds control returned 42. |
| [V5 exact store](adjacent-v5/vs.replica.v5.b01.r04.exact.console.txt), [broad store](adjacent-v5/vs.replica.v5.b01.r05.broad.console.txt) | One first-block comparison: the 8-byte access at `[16,24)` faulted with exact 16-byte value bounds; broad authority allowed changes to the next value's first eight bytes. |
| [V6 exact load](adjacent-v6/memop.v6.b01.r03.oobload.exact.console.txt), [broad load](adjacent-v6/memop.v6.b01.r04.oobload.broad.console.txt) | One first-block comparison: the 4-byte access at `[16,20)` faulted before dependent completion with exact bounds; broad authority returned the recorded next-value data. |
| [V6 valid load](adjacent-v6/memop.v6.b01.r10.validload.exact.console.txt), [valid store](adjacent-v6/memop.v6.b01.r08.validstore.exact.console.txt) | Exact bounds permitted the tested accesses ending at byte 16. |

The original provider [manifest](provider/experiment-manifest.json),
[source/config audit](provider/source-config-audit.txt),
[provider disassembly](provider/provider-authority-disassembly.txt) and tool
identities preserve source/build attribution. The original V5/V6 result and
correspondence records preserve their log hashes, deployment identities and
limitations. The [four-case matrix](adjacent-v6/memory-operation-robustness-matrix-result-v1.json)
combines the separate store and load epochs without asserting that their native
images or patch states were identical.

At selection time, every copy was compared byte for byte with its original. All **27
existing checksum references covering 19 selected files matched**. The manifest
lists four files for which the selected historical records contain no prior
checksum; their original/copy equality and selection hashes were
checked. The historical [validator output](provider/final-validation.log) is
retained as a publication copy of that report, not a new validation result. Transitive hashes
for omitted artifacts were not checked.

Selection omissions and limits:

- This original selection contains representative first-block adjacent-value
  consoles. The [supplementary spatial archive](../legacy-spatial/README.md)
  completes the ten store and twenty load consoles, including fixed, baseline
  and selected-sanitizer controls, and retains the software comparison.
  [Earlier findings](../../../docs/results/earlier-findings.md) also link the
  x86 parent/fixed controls. These records were copied without rerunning the experiments.
- Executables, kernel images, initramfs archives, exploit fixtures, vulnerable
  kernel patches, runner scripts and bulk normalized observations are omitted.
  Archived commands and instruction telemetry inside passive records remain
  historical data; this directory supplies no reproduction target.
- Original metadata retains references to omitted files, with external
  build paths replaced by role markers. This is a selected evidence set, not a portable
  build package, full-package validation or independent reproduction.
- The provider study demonstrates lookup-time narrowing of a retained root.
  Its initial root came from executive DDC; correct provider association and
  initial bounds remain trusted premises.
- The adjacent-value correspondence records remain conditional: direct live
  operand correspondence, checked-image immutability, semantic assignment and
  lifetime, and complete production refinement were not established. V5 and V6
  are distinct historical epochs. These spatial results establish no ownership
  or temporal-safety claim and are separate from current cBPF implementation results.
