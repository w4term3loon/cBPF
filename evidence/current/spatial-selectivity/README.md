# Selective spatial enforcement: published evidence

This package publishes the original 10 September 2026 matrix and its matching
calibration. The original checker reports 30 native observations (22 permitted,
eight bounds rejections), plus five verifier admission controls (two admitted,
three rejected, none executed). These are fixed trusted native accesses through
the production provider, not verifier-admitted invalid BPF or a CVE replay.

## Status and limits

Publication and the strengthened spatial receipt revalidation are complete.
The [revalidation index](revalidation/README.md) separates the unchanged
original records from current checks and the new ten-control admission run.
The new run used the same kernel and overlays, with five added store submissions;
it reports 30 native observations and ten admission controls (four accepted,
six rejected, none executed).

The original checker does not bind every comparator base to the provider's
selected address, or runtime PCs/register operands to the linked helper.
Its object-disassembly and shutdown checks retain the limitations described on
the [result page](../../../docs/results/spatial-selectivity.md). Current checks
bind all bases/cursors, four fixed access forms and fault PCs to the complete
linked helper, and require actual powerdown plus QEMU exit zero. They do not
constitute a general validator or independent external reproduction.

The original matrix, calibration, executed scripts and results are preserved.
The `derivation/` files were created later, at the timestamp in their receipt.
Their byte/decoder correspondence checks are extraction checks, not a semantic
native inspection, new execution or stronger experimental closure.

## Inspectable records

- Matrix: [raw console](run/boot.log), [original result](run/results.json),
  [original checker](run/check_spatial_selectivity.executed.py),
  [executed runner](run/run-script.executed.sh), [guest source](run/guest.c).
- Matching calibration: [raw console](calibration/boot.log),
  [original result](calibration/results.json), [input identities](calibration/inputs.sha256).
  Its native cases are one valid load and one recovered bounds fault; they do
  not demonstrate unrelated-fault rejection.
- Matrix launch: [command](run/qemu-command.sh), [exit status](run/qemu-exit.txt),
  [input identities](run/inputs.sha256), [tool versions](run/toolchain.txt),
  [initramfs](run/initramfs.cpio.gz). The console records actual kernel powerdown.
- Calibration launch: [command](calibration/qemu-command.sh),
  [exit status](calibration/qemu-exit.txt), [initramfs](calibration/initramfs.cpio.gz).
- Build: [source pins](build/source-pins.json), [configuration](build/kernel.config),
  [builder identity](build/builder-image.txt), [output identities](build/outputs.sha256),
  [patched-source identities](build/patched-sources.sha256),
  [executed builder](build/build_spatial_selectivity.executed.sh),
  [production patch](build/array-authority.patch),
  [observation patch](build/native-observation.patch), [test overlay](build/selectivity-test.patch).
- Later extraction: [receipt](derivation/receipt.json),
  [complete linked listing](derivation/complete-linked-disassembly.txt),
  [exact helper bytes](derivation/cbpf_selectivity_native_access.bin),
  [ELF ranges and hashes](derivation/linked-ranges.json),
  [commands](derivation/commands.json), [decoder identities](derivation/toolchain.txt).

The source Git tree inventory is [losslessly compressed](build/source-tree.manifest.gz).
It is NUL-delimited, not an ordinary line-oriented text file. Decompression
recovers its original bytes and original SHA-256, recorded in the source pins
and publication manifest.

The run and calibration checksum lists bind the same kernel `Image` and
`vmlinux`. The full kernel images, source Git objects and tool distributions
remain external; their hashes, source pins and build/launch commands are
retained. Kernel reproduction uses the [dependency guide](../../../docs/reproduction/native-dependencies.md).

## Publication identities

The [global manifest](../../publication-manifest.json) covers every file here.
Original and publication hashes differ where host paths were replaced with
role markers or the source inventory was compressed. Embedded checksum lists
still describe original files; do not run them as checks of edited copies.
Exact private originals were copied and verified before publication.

From the repository root, `make evidence` checks publication-file integrity.
It does not rerun the native experiment or establish semantic correspondence.
`make evidence-recheck` separately checks the current spatial receipts offline.
The [packaging tool](../../../tools/package_native_extension.py) records the
original export procedure; the exact executed version is retained under
`derivation/`. The later export has its own snapshot under `revalidation/`.
