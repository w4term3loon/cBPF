# Spatial native witness

This is a [publication copy](../../README.md). Original identities are retained
as metadata; the publication manifest verifies the redacted files.

**PASS, 6 September 2026.** The fresh reduced spatial kernel executed the
single benign control once. Array key 1 changed from **41 to 42**, the program
returned the computed **42**, and ordinary map readback confirmed **42**.
The observed returned capability was tagged, unsealed, exactly eight bytes,
with `LOAD | STORE | GLOBAL` (`0x30001`).

This completes the bounded spatial witness for the inspected program. Read the
[result addendum](../../../docs/spatial-native-result.md) for its interpretation and
[result.json](result.json) for the identities, observations and limits.
This later result does not change the earlier local-reproduction claim table.

## What the receipt connects

The program is a normally verified, 14-instruction socket filter using a plain
two-entry ARRAY, four-byte key, eight-byte value, zero map/program flags, and
no BTF value metadata or attachment. The loader initialized key 1 to 41 and
held the same map/program FDs throughout review and execution.

| Link | Recorded evidence |
|---|---|
| Current source and running kernel | Verified inherited tree, unchanged reduced provider patch, two-site observation overlay, fresh Image/vmlinux hashes and exact QEMU launch |
| Admitted native image | All 392 bytes from the retained program FD match the complete accepted certificate transcript |
| Selected logical value | Map ID 1, key 1, values base `0xffff000000df9310`, selected address `0xffff000000df9318` |
| Exact returned authority | Base and cursor equal the selected address, length 8, tag 1, sealed 0, permissions `0x30001` |
| Native transport and access | `BLRS c17`, capability move `c0` to `c7`, then word 75 `LDUR x0,[c7]`, word 76 add one, word 77 `STUR x0,[c7]` |
| Entry ranges | Restricted base `0xffff8000813f79f0`, length 224; executive return base `0xffff8000813f7ad0`, length 56 |
| Single effect and termination | One TEST_RUN, one initialization update, return/readback 42, no reported fault or kernel warning, clean poweroff, QEMU exit 0 |

The preflight byte/certificate checks and manual source/Morello instruction
review preceded the execution token. Postflight reconciled those expectations
with the construction records and effect. The inspection used AI assistance
within the research environment and was not independent external review or
reproduction.

## Retained files

- `build/`: build recipe, patches, source pins, configuration, compiler
  identities, output hashes and complete compile log.
- `run/`: exact guest source and binary, initramfs, runner, QEMU command,
  input hashes, complete boot log and exit status. The original checker
  snapshot and corrected checker actually used for review are separate.
- `review/`: successful pre/post reports, pre-execution manual review,
  392 native bytes and disassembly, linked code, and the failed first check.
  Named-symbol extraction stops at some ELF mapping labels; the separate
  complete allocator and exception-handler ranges include those continuations.
- `attempt-before-jit/`: the preliminary boot that stopped with zero TEST_RUNs.
- `validation/`: the passing host checks and original local-reproduction integrity check.

`copy-origins.json` identifies original inputs through redacted role markers.
`manifest.json` and `SHA256SUMS` preserve original identities. Large Image/vmlinux files and
the complete source-tree manifest remain in the fresh local build directory;
`result.json` records their locations, sizes and SHA-256 hashes. The existing
local-reproduction source/runtime record supplies the pinned substrate. This is a local
receipt, not independently provisioned reproduction.

## Preparation history

The first guest stopped at `program_info_size`: the inherited source sets
`bpf_jit_enable=0` despite `CONFIG_BPF_JIT_DEFAULT_ON=y`. No native program ran.
The second boot used the ordinary `sysctl.net.core.bpf_jit_enable=1` kernel
parameter with the same Image and fixture.

The first host preflight expected an ORR-form register move. Inspection of
`bpf_jit.h` showed `A64_MOV` emits ADD-immediate zero, matching native word 0
`0x910003c9`. One expected constant and its explanatory comment were corrected.
The failed check and original checker retain their historical identities; the held FDs, native
bytes, program, verifier and kernel did not change. See
[review/commands.md](review/commands.md) for the actual review sequence.

## Claim boundary

The observation overlay adds 16 logging lines at two sites. It changes no
enforcement rule or verifier check. All test/offload modes remain disabled.
The offline guest had no network, disks or host filesystem share.

The chain is a source-backed correspondence witness for these two selected
body accesses, conditional on correct live assignment, trusted architecture,
kernel/compiler/image integrity and synchronous execution. Some provider
getter results can be constant-folded after successful checks; logging is
not independent hardware attestation. RDDC remains vmalloc-wide and the
helper sentry retains inherited DDC bounds. The configured KASLR could not
activate because firmware supplied no seed; observed relocation was zero.

This control does not exercise padding exclusion or out-of-bounds faults,
establish complete mediation for every accepted program, rerun a historical
CVE, or compose spatial authority with ownership. Those broader results do
not follow from its success.
