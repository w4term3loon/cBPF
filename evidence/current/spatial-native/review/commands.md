# Spatial native witness review sequence

All commands ran from `${REPOSITORY}`. The guest runner held
the program and map at READY before TEST_RUN. Commands below document the
completed run; no automatic execution follows a checker PASS.

1. `bash tools/build_spatial_native.sh` produced
   `build/spatial-s5-build.Z4e3mc`, with a successful Image link and matching
   purecap UAPI header installation.
2. The initial `bash tools/run_spatial_native.sh build/spatial-s5-build.Z4e3mc`
   produced `build/spatial-s5-run.KvglJV`, safely ending before TEST_RUN.
   The runner then gained the standard JIT-enable boot parameter described
   in the receipt. A second invocation produced `build/spatial-s5-run.ZR5f2h`.
3. The following preflight initially stopped at the mistaken expected
   register-move encoding. Its failed report is retained as `failed-pre.json`.

```bash
python3 tools/check_spatial_native.py pre \
  --log build/spatial-s5-run.ZR5f2h/boot.log \
  --vmlinux build/spatial-s5-build.Z4e3mc/objects/vmlinux \
  --output build/spatial-s5-review/ZR5f2h-pre
```

4. Source-confirmed ADD-immediate-zero correction: expected `0xaa1e03e9`
   became `0x910003c9`, plus one explanatory comment. The corrected checker
   was saved separately as `run/check_spatial_native.reviewed.py`. Repeating the
   command with output `build/spatial-s5-review/ZR5f2h-pre2` passed. It bound
   exactly the same pre-execution log prefix and native image.
5. Manual inspection covered all 98 native words and linked entry, gateway,
   lookup, provider and array allocation. The checker used the pinned offline
   builder's `llvm-nm`, `llvm-mc --disassemble --triple=aarch64 --mattr=+morello
   --show-encoding`, and `llvm-objdump -d --mattr=+morello` with the named
   symbols. Supplemental `llvm-nm --print-size --defined-only --numeric-sort`
   identified full function extents. Complete range dumps used:

```text
llvm-objdump -d --mattr=+morello
  --start-address=0xffff800080184088 --stop-address=0xffff8000801841cc /kernel/vmlinux
llvm-objdump -d --mattr=+morello,+lse
  --start-address=0xffff800080038d9c --stop-address=0xffff800080039018 /kernel/vmlinux
```

These commands ran inside the same immutable builder, with no network,
all capabilities dropped, no-new-privileges, and the fresh objects directory
mounted read-only at `/kernel`. LSE decoding identifies the existing alternate
atomic instruction; it does not change the kernel or its selected code.

6. All run-input hashes passed again. `manual-review.json` was written at
   `2026-09-06T21:43:04.567279+00:00`, recording zero executions, reviewed
   artifact hashes and the exact expected roots and selected value. The
   single `CBPF_S5_EXECUTE` line was then sent to the paused guest.
   The guest ran once and powered off successfully.
7. Postflight passed with the same corrected checker:

```bash
python3 tools/check_spatial_native.py post \
  --log build/spatial-s5-run.ZR5f2h/boot.log \
  --preflight build/spatial-s5-review/ZR5f2h-pre2/pre.json \
  --output build/spatial-s5-review/ZR5f2h-post
```

The full boot log was separately checked for faults/warnings and clean
poweroff. QEMU exited zero; the runner reverified every captured input hash.
`make check` passed for this spatial native witness. The frozen local-reproduction SHA-256 selection
also passed unchanged. No additional BPF invocation followed.

The original checker had separate synthetic parser controls, retained in
`build/spatial-s5-review/tool-check`. Those checks concern that original
checker version and are not runtime evidence for this witness.
