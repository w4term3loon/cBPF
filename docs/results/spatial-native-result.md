# Spatial native witness

**The spatial native witness passed for one inspected program on 6 September 2026.** The
[evidence package](../../evidence/current/spatial-native/README.md) and
[structured result](../../evidence/current/spatial-native/result.json) preserve the
build, attempts, native review, and post-execution reconciliation.

The result concerns the original recorded sources and execution. Public
records redact local paths; publication checksums and experimental source
identities refer to different bytes.

The subsequent [native dependency replay](../reproduction/native-replay.md) freshly builds
the active spatial profile and repeats the same valid control. Its exact
eight-byte authority and 41-to-42 return/readback pass, with separate
source/image/review identities. It adds no negative access or CVE-stage replay.

## Discrimination provided by the witness

The eight-byte experiment recorded here has logical size equal to stride. A
constructor that incorrectly used stride would pass this witness. Exact
length telemetry discriminates this grant from allocation-wide authority,
and inspection connects the grant to actual operands. Padding exclusion is
therefore a source-inspected requirement, not a current observed result.
The subsequent [logical extent discriminator](logical-extent.md) passed with
size seven and stride eight, reusing the clean-replay kernel. It supplies
construction discrimination and valid byte-six use, with separate receipts.
Neither experiment claims an observed padding fault.

## Claim and observed result

Build `spatial-s5-build.Z4e3mc` applied the frozen reduced array-authority patch
and a two-site observation overlay to the pinned inherited tree. Kernel
`6.7.0-cbpf-spatial-s5` retained the inherited verifier unchanged, with spatial
offload and historical test modes disabled. No ownership mechanism was added.

Run `spatial-s5-run.ZR5f2h` used one normally verified, 14-instruction
socket-filter program and one plain two-entry array: key size 4, value size 8,
zero map/program flags, and no BTF value record. Key 1 was initialized and
read back as 41. After review, exactly one `TEST_RUN`, with `repeat=1`, loaded
that value, added one, and stored through the same lookup-returned capability.
Its computed return and ordinary map readback were both 42. There was no
attachment; the guest powered off cleanly and QEMU exited zero.

The single reduced-provider record identified map 1/key 1, value-array base
`0xffff000000df9310`, stride 8, and selected address `0xffff000000df9318`.
Returned capability base and cursor equalled that selected address; length
was 8, tag 1, sealed 0, and permissions `0x30001` (`LOAD | STORE | GLOBAL`).

## Native correspondence

Before execution, the same held program FD supplied all 14 translated
instructions, all 392 native bytes, and entry `0xffff8000813f7988`. The native
entry and bytes matched the complete certificate transcript with accepted
final decision.
The guest then waited for the explicit execution token while retaining the
same map/program FDs. Manual review covered all 98 native words and
the relevant linked entry, gateway, provider and exception paths before
the execution token was supplied.

Critical native words use zero-based indices:

| Word | Encoding | Role |
|---|---|---|
| 71 | `c2c23222` | `BLRS c17`, the sole lookup gateway call. |
| 72 | `c2c1d007` | Full capability copy from returned `c0` to `c7`. |
| 75 | `e2c004e0` | Eight-byte `LDUR x0,[c7]`. |
| 76 | `91000400` | Add one to the loaded scalar. |
| 77 | `e2c000e0` | Eight-byte `STUR x0,[c7]`. |

After word 72, `c7` is unchanged through word 77. The reviewed body has
no second helper or alternate selected-value write. Linked inspection connects
the gateway's operation-zero dispatch to the reduced provider and preserves
its `c0` return across logging and gateway exit.

Construction records matched the pre-execution predictions: restricted code
base/cursor `0xffff8000813f79f0`, length 224, and executive-return base/cursor
`0xffff8000813f7ad0`, length 56; both were tagged and sealed. The tagged, sealed
gateway cursor was `0xffff800080037800`, with inherited DDC bounds rather than
exact gateway bounds. Post-execution reconciliation passed.

## Retained attempts and limits

The earlier `spatial-s5-run.KvglJV` stopped at native-image validation with
`test_run_count=0`: the inherited runtime JIT setting was zero. The next boot
selected standard `sysctl.net.core.bpf_jit_enable=1`. Verifier protections were
retained. Before execution, the checker expectation for the caller-cursor
move was corrected from ORR encoding `0xaa1e03e9` to the inherited ADD-zero
encoding `0x910003c9`. Original and corrected checker records remain retained;
the fixture, kernel and native bytes were unchanged by that correction.

This establishes fresh valid-use and source/native correspondence evidence
for the two inspected selected-value accesses, conditional on trusted provider
assignment, kernel behavior and image integrity. RDDC remains vmalloc-wide;
the gateway retains broader authority. Construction logs are not independent
hardware attestation. KASLR remained configured, but this boot lacked a firmware
seed and used relocation zero. Retrieved JIT bytes exclude appended PLT-target
data and the exception table; their source/linked handling was reviewed.

Final linked-code review was internal; no external replication or independent
hardware attestation is claimed. The witness does not test padding exclusion or out-of-bounds accesses,
or establish all-program mediation, fresh CVE mitigation, performance advantage,
or spatial/ownership composition. The [admission procedure](spatial-native-scope.md)
records the source and image checks required before execution.
