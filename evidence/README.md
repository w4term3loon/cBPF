# Publication evidence and original identities

The shareable evidence is a **publication copy**, not a byte-identical copy
of every original record. Personal source/cache paths and named temporary
locations have been replaced by role markers such as `${REPOSITORY}`,
`${TOOLCHAIN_CACHE}`, `${PRIOR_PROVIDER_EVIDENCE}` and `${TEMP_ROOT}`. These
markers identify historical roles; they are not recorded execution locations
or working reproduction commands. Generic guest/container paths, technical
symbols, register names, instruction bytes and reported outcomes are retained.

[publication-manifest.json](publication-manifest.json) records original and
publication byte counts and SHA-256 identities separately. Original digests
inside earlier manifests, checksum lists and review receipts remain historical
metadata. They must not be used to assert that edited publication copies have
the original bytes. `python3 tools/verify_evidence.py`, from the repository
root, checks the publication identities without executing an experiment.

Exact originals were privately preserved and verified before redaction,
outside the repository and served documentation. The three full-repository
source/edition archives are withheld from this publication because they embed
personal paths and obsolete document packages. Their original identities
remain recorded. The publication does not support reconstructing those exact
private archives from sanitized files. Clean native instruction images and
the retained initramfs remain available with their unchanged identities.

Path replacement preserves line counts in source, assembly and console
records. Publication copies omit administrative approval bindings; recorded
commands, experimental conditions, observations and original identities remain.
These edits do not establish a new run, semantic revalidation, independent
reproduction or stronger security result.

## September 10 native-extension publication

- [Selective spatial evidence](current/spatial-selectivity/README.md): original
  matrix and matching calibration, build/launch identities and complete helper
  bytes/disassembly derived after the run; separately identified strengthened
  revalidation and a new ten-control admission run on the unchanged kernel.
- [Integrated ownership evidence](current/ownership-native-trace/README.md):
  original three native controls, full native images and later complete decoder
  listings of the images and relevant linked production functions.

These packages preserve original checker outcomes with their known limits.
The spatial [revalidation](current/spatial-selectivity/revalidation/README.md)
passes stronger backing-address, linked-PC, operand, calibration and completion
checks. Ownership's focused native correspondence checks and explicit inspection
remain pending; its new recheck improves completion checks only. Publication
and extraction alone do not establish experimental closure. Each package
separates original records from timestamped `derivation/` and `revalidation/`
records; the new spatial guest execution is retained separately in `matrix-v2/`.
The large NUL-delimited source-tree inventories are losslessly gzip-compressed;
their original hashes apply to decompressed bytes. Original native binaries and
initramfs are unchanged; the new spatial guest has its own source and initramfs
identities. Full kernel/toolchain distributions remain external.

Original filenames and technical provenance retain historical edition identifiers.
Current descriptive metadata uses study names. The identifiers remaining in
original records have these meanings:

| Identifier | Research work |
|---|---|
| M1 | Spatial provider reduction |
| M2 | Protected ownership execution |
| M3 | Ownership boundary controls |
| M4 | Local reproduction |
| R1 | Acquisition distinguishability |
| R2 | Ownership CVE case |
| S5 | Spatial native witness |
| C1 | Trusted callback witness |

These research labels do not rename architectural registers or runtime symbols.

## Earlier research records

[Earlier findings](../docs/results/earlier-findings.md) connect the broader prototype's
results to their retained records and distinguish them from the maintained profiles.

- [Spatial records](prior/legacy-spatial/README.md): historical CVE-stage controls,
  complete adjacent-value console blocks and matched software comparisons.
- [Lifetime record](prior/legacy-ownership/ring-buffer-lifetime.json),
  [native consumed-register console](prior/legacy-ownership/native-stale-register.log)
  and x86 [parent](prior/legacy-ownership/provider-x86-parent.log)/[fixed](prior/legacy-ownership/provider-x86-fixed.log) controls.
- [Earlier evaluation](../docs/results/earlier-findings.md#earlier-implementation-and-evaluation-findings):
  uBPF, formal receipts, assignment pilot, compatibility and cost observations.

These are passive publication copies. Referenced dependencies not included in the
selection remain with the original research; report-only findings are identified
as such. Their inclusion does not rerun an experiment or prove a current-profile result.

The research used AI-assisted implementation, analysis and internal source/native
inspection. These activities and the local rebuilds do not establish independent
external review or reproduction. Method and independence limits are stated separately from numerical results.
