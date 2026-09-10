# Integrated ownership trace: published original evidence

This package publishes the original 10 September 2026 positive, stale-read and
repeated-release controls. The original checker reports two acquisitions and
two releases per control, with one cleanup release in each negative and final
reference count one. These are fixed trusted native fixtures through production
mechanisms, not normally verified stale BPF or the original callback CVE path.

## Status and limits

Publication is complete; focused native correspondence checks and explicit
inspection remain pending. The ordered event checks are stronger than the
original native-byte checks. The latter verify envelopes and selected marker
instructions, not the entire prologue, branch targets or terminal epilogue.
The emitter's complete re-encoding check uses its own encoder and is a separate
internal-consistency assurance. See the [result page](../../../docs/results/ownership-native-trace.md).

Original files and results are preserved. The `derivation/` records were
generated later, with their actual timestamp. They contain complete byte-bound
decoder listings, not a completed semantic inspection or a new execution.
LLVM MC prints branch displacements; listing address columns use the recorded
native entry. Later target checks must resolve those displacements explicitly.

## Inspectable records

- Run: [raw console](run/boot.log), [original result](run/results.json),
  [original checker](run/check_ownership_trace.executed.py),
  [executed runner](run/run_ownership_trace.executed.sh), [guest source](run/guest.c).
- Launch: [QEMU command](run/qemu-command.sh), [exit status](run/qemu-exit.txt),
  [input identities](run/inputs.sha256), [tool versions](run/toolchain.txt),
  [initramfs](run/initramfs.cpio.gz). Actual kernel powerdown appears in the console.
- Native images: [positive](run/native-positive.bin), [stale read](run/native-stale_read.bin),
  [repeated release](run/native-repeated_release.bin).
- Complete decoded images: [positive](derivation/native-positive-disassembly.txt),
  [stale read](derivation/native-stale_read-disassembly.txt),
  [repeated release](derivation/native-repeated_release-disassembly.txt),
  [byte/decode receipt](derivation/native-decode.json).
- Build: [source commit](build/source-commit.txt), [configuration](build/kernel.config),
  [builder identity](build/builder-image.txt), [output identities](build/outputs.sha256),
  [patched-source identities](build/patched-sources.sha256),
  [executed builder](build/build_ownership_trace.executed.sh),
  [runtime source before test overlay](build/cbpf_runtime.c),
  [emitter source before test overlay](build/cbpf_jit.c), [test overlay](build/native-trace.patch).
- Linked production code: [complete listing](derivation/complete-linked-disassembly.txt),
  [ELF ranges and exact-byte identities](derivation/linked-ranges.json),
  [derivation receipt](derivation/receipt.json), [commands](derivation/commands.json),
  [decoder identities](derivation/toolchain.txt). Each named range also has a binary
  alongside the listing. The zero-sized assembly gateway label uses the next
  linked function, `cbpf_gate_impl`, as its recorded exclusive boundary.

The [compressed source Git tree inventory](build/source-tree.manifest.gz) is
lossless and NUL-delimited. Decompression recovers its original bytes/hash.
Full kernel images, source Git objects and tool distributions remain external;
identities and original build/launch commands are retained. See the
[dependency guide](../../../docs/reproduction/native-dependencies.md).

The three verifier submissions are separate existing stale-copy, stale-spill
and repeated-release admission controls, all rejected without execution.
They are not matched counterparts of the native fixtures.

## Publication identities

The [global manifest](../../publication-manifest.json) covers every file here,
distinguishing original hashes from path-redacted or compressed publication
copies. Embedded checksums retain their original meaning. Exact private
originals were copied and verified before publication.

From the repository root, `make evidence` checks publication integrity only.
The [packaging tool](../../../tools/package_native_extension.py) records the
export procedure; its executed version is retained under `derivation/`.
