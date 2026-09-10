# Selective spatial enforcement

The selective spatial matrix passes strengthened receipt checks for both the
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

## Execution boundary

The original run submitted five load programs to the unchanged normal verifier.
The new guest adds the five store variants: ten admission-only submissions,
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

The new run reused the exact retained kernel `Image`, `vmlinux`, configuration
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
