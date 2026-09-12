# Selective spatial enforcement

Both retained spatial matrix runs pass strengthened receipt checks: the
original 10 September 2026 run and a later admission-extension run. Each made 30 native
load/store observations over two disposable seven-byte array values stored at
an eight-byte stride. Twenty-two accesses completed and eight produced the
Morello bounds fault FSC `0x2a`, exactly as predicted.

The [published evidence package](../../evidence/current/spatial-selectivity/README.md)
preserves the original records, their [stronger revalidation](../../evidence/current/spatial-selectivity/revalidation/README.md)
and the [new ten-control admission run](../../evidence/current/spatial-selectivity/matrix-v2/results.json).
The current checker requires every capability base to equal the production
provider's selected address, and every cursor to equal that address plus the
case offset. Each recorded access PC must identify the expected byte/halfword
load/store in the complete linked helper, with scalar `w8`, capability `c2`
and zero displacement. It also checks the preceding full-capability operand
capture, the logged root register and, for rejections, the same fault PC/word.
These are focused checks for four fixed access forms, not a general validator.

The production provider supplied the exact seven-byte capability. Two
harness-only controls were derived separately from trusted retained authority:
an eight-byte stride capability and a sixteen-byte capability covering both
value slots. They used the same backing bytes, scalar permissions and access
instructions. No returned exact capability was widened.

Offset eight distinguishes **per-value authority** from authority over the
**whole value-storage region**. The sixteen-byte root covers A, B and the two
padding bytes; it does not cover allocation metadata. Exact-seven and
stride-eight roots based at A reject the first byte of B, whereas the
both-slot root permits it. All three are capability controls. This comparison
is not a genuine non-capability baseline, and relabelling its extent requires
no new metadata experiment or matrix execution.

| Offset, width | Meaning | Exact 7 | Stride 8 | Both slots 16 |
|---|---|---|---|---|
| 6, 1 | Last logical byte | Permit | Permit | Permit |
| 7, 1 | Padding | Reject | Permit | Permit |
| 8, 1 | Next value | Reject | Reject | Permit |
| 4, 2 | In-bounds halfword | Permit | Permit | Permit |
| 6, 2 | Starts in-bounds, ends in padding | Reject | Permit | Permit |

The same matrix passed for loads and stores. Permitted loads returned the
fixture bytes, and permitted stores changed only their requested bytes.
Rejected loads left their destination sentinel unchanged; rejected stores
left all sixteen fixture bytes unchanged in the original records. Each rejected
observation reports capability base, cursor and length, instruction, width and
fault PC, now reconciled with the linked helper. Resetting the fixture before
every case prevents one case from
supplying another case's expected result. The width-two case at offset six
also shows that enforcement covers the complete memory operation, not merely
its starting address.

## Selection binding and the actual operand

Exact bounds protect the region named by the capability actually supplied to
the instruction. Correct assignment must also connect that region to the
intended map and key. Two different mistakes must be distinguished:

- An inconsistent retained allocation root is rejected if it fails the
  production provider's tag, sealing, allocation base/cursor, recorded extent,
  permissions or layout-size checks. This is **source inspection**, not a new
  corruption experiment; it does not cover every possible wrong root.
- A valid exact B capability, independently obtained through key one and then
  substituted for intended A, still authorizes accesses inside B. For a byte
  load at relative offset six, B's `0x87` is expected rather than A's `0x29`,
  with no hardware fault and a binding mismatch. This analytically expected
  counterexample was **observed** in the fixed trusted control below; it is
  not correct assignment.

The fixed substitution mode uses the existing access helper for correct A,
legitimate B and intended-A/actual-B cases, resetting all sixteen bytes before
each. Intended map/key are recorded separately from the provider key and
captured operand. Its [separate checker](../../tools/check_spatial_substitution.py)
requires the mismatching binding for the third case to pass. The original
selectivity checker remains unchanged and still rejects any comparator base
that differs from its single selected A address.

**Observed on 12 September 2026, under Morello QEMU.** One new kernel build,
its two-case calibration and one three-load substitution boot passed. No
extent matrix or normally verified witness was rerun. The provider,
observation overlay, native access helper, exception handling and verifier
were unchanged. The [receipt](../../evidence/current/spatial-selectivity/substitution/refinement-receipt.json)
records revision `51a61c6b1da2cda047eac28092c918b97b47a8a4`, matching `presi`,
the pre-existing presentation edits, and exact executed source identities.

| Trusted case | Intended key | Actual provider key | Returned byte | Binding |
|---|---:|---:|---|---|
| Correct A | 0 | 0 | `0x29` | Match |
| Legitimate B | 1 | 1 | `0x87` | Match |
| Substituted B | 0 | 1 | `0x87` | **Mismatch, as required** |

All three loads completed without a fault and left the entire reset fixture
`11223344556629a781828384858687bf` unchanged. Each captured operand was tagged,
unsealed, length seven, with permissions `0x30001` (`LOAD|STORE|GLOBAL`). A's
base/cursor at the load were `0xffff000000c60f10` / `0xffff000000c60f16`;
B's were `0xffff000000c60f18` / `0xffff000000c60f1e`. The intended map/key and
actual provider key are separate fields in the [console](../../evidence/current/spatial-selectivity/substitution/boot.log)
and [checked result](../../evidence/current/spatial-selectivity/substitution/results.json).
The fixture records its actual map address; its `map_id=0` is not a registered
userspace map ID.

The [complete linked helper](../../evidence/current/spatial-selectivity/substitution/linked/complete-linked-disassembly.txt)
contains the same captured-operand byte load at the same PC in all three cases:

```text
ffff8000801c4b04: c2c1d041  mov   c1, c2
ffff8000801c4b08: e2000448  ldurb w8, [c2, #0x0]
```

These are actual extracted instructions. The relative offset six is already
in the capability cursor; the instruction displacement is zero. The original
console SHA-256 is `95681262d03a1b3518192229d365135c80ab7b90cf6e4ad64d4d3802886154dc`.
The [unchanged guest](../../linux/spatial/selectivity-guest.c) also performed ten
admission-only controls: four accepted, six rejected, zero BPF executions.

To reproduce only this control, use the build and calibration steps below,
then replace the final matrix command with:

```sh
bash tools/run_spatial_selectivity.sh "$CBPF_SPATIAL_SELECTIVITY_BUILD" --substitution
```

The [conditional argument](../../theory/spatial.md#retained-root-consistency-and-wrong-value-substitution)
explains why this violates an assignment/operand-use premise, while containment
through B remains valid. The trusted substitution does not execute invalid BPF
and does not establish a reachable exploit or automatic semantic authentication.

## Execution boundary

The original run submitted five load programs to the unchanged normal verifier.
The admission-extension guest added the five store variants: ten admission-only submissions,
four accepted and six rejected, with zero executions. Both operations admit
the offset-6 byte and offset-4 halfword controls and reject the three forbidden
access shapes. The guest rejects `BPF_PROG_TEST_RUN` without a syscall. Unexpected
acceptance of a negative would close its file descriptor and fail the test;
it would never authorize `BPF_PROG_TEST_RUN`.

Hardware rejection is therefore observed only in the fixed trusted native
fixture. That fixture calls the unchanged production provider and uses a
narrow test-only exception recovery site. It is **synthetic native validation
through the production provider**, not verifier-admitted invalid eBPF and not
reproduction of a vulnerable program. CHERI tags are separate integrity
metadata; offset seven is ordinary array-layout padding, not a tag byte.

The [test overlay](../../linux/spatial/selectivity-test.patch),
[guest](../../linux/spatial/selectivity-guest.c), [builder](../../tools/build_spatial_selectivity.sh),
[runner](../../tools/run_spatial_selectivity.sh) and
[checker](../../tools/check_spatial_selectivity.py) define the complete
fixture and acceptance criteria. The checker emits `results.json` in its
fresh run directory.

## Validation identity

The ten-control admission-extension run reused the exact retained kernel `Image`, `vmlinux`, configuration
and provider/test overlays; no kernel was rebuilt. Its console SHA-256 is
`30313660bc4e14c8749e6e45040115ad442dbc3bba0b391f411634ce0d6c32e8`.
The [batch receipt](../../evidence/current/spatial-selectivity/revalidation/receipt.json)
records one new boot and no ownership rerun. The launch's first checker rejected
compatible EFI/kernel `nokaslr` messages after clean powerdown; its failure is
preserved. The corrected checker accepted the saved run without another boot.

Original boots explicitly reported KASLR disabled for lack of seed. New fixture
boots use explicit `nokaslr`; zero relocation requires matching command and
kernel observations, with an optional consistent EFI message. Unknown or
contradictory relocation evidence fails. This fixed-placement test condition
does not disable the verifier or change the provider.

The table below identifies original v1 artifacts, not current checkers or necessarily their
path-redacted publication copies. The
[publication manifest](../../evidence/publication-manifest.json) records both
identities. The original object disassembly is retained as such; the
[complete linked helper listing](../../evidence/current/spatial-selectivity/derivation/complete-linked-disassembly.txt)
was extracted later from the hash-matched `vmlinux`, without booting a guest.

The passing local run used kernel release
`6.7.0-cbpf-spatial-selectivity` over inherited tree
`e6c69574c16bc2b9bce06329f9ac3f4b3269e79a`. Its verifier was unchanged from
that substrate, historical test modes were disabled, QEMU exited zero and the
guest powered down cleanly.

| Artifact | SHA-256 |
|---|---|
| Test overlay | `b605b96b977f9be988fff2522323f043e87023155f3cec935b320c1f2e0a7c65` |
| Checker | `f6e8c418556c854074c89d2f0df58381d4bfd91e9026d475e876b25e09a41f47` |
| Raw boot log | `5dca0836801a2d10ed5b2c9514f2731a09e85a13f85aaa92765d8fd31b168f0a` |
| Structured result | `3eee2b6a1cccfb45e15b39cfa773b89c735a74fd907e7087714028f093c685bb` |
| Access disassembly | `46ef695216e2481d542c6d9000e368a60761330a789da6f74c071579bed09e85` |

```sh
make spatial-selectivity-kernel
export CBPF_SPATIAL_SELECTIVITY_BUILD=/absolute/path/printed/by/the/build
make spatial-selectivity-calibration
export CBPF_SPATIAL_SELECTIVITY_CALIBRATION=/absolute/path/printed/by/the/calibration
make spatial-selectivity
```

The matrix launcher rechecks the calibration and its saved PASS receipt before
boot, requires matching kernel/configuration/overlay identities, and retains a
copy with the new matrix. Calibration establishes one permitted load and one
recovered bounds fault. Unrelated-syndrome rejection is tested on the host.
Both checkers require QEMU exit zero, actual kernel powerdown and no failure
markers. `make checker-tests` runs host regressions; `make evidence-recheck`
rechecks the publication without Docker, QEMU or downloads. Both are included
in `make check`.

The result tests selected architectural accesses, including padding,
neighboring storage and a crossing access. It does not establish complete
mediation, speculative noninterference, allocation lifetime safety or
execution of the historical CVE workload.
