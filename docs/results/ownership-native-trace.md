# Synthetic native ownership containment trace

The original checker reports a passing integrated ownership trace on
10 September 2026. Three fixed
trusted native fixtures reused the production restricted entry, capability
transport, gateway, ownership gate, epilogue and cleanup wrapper. The test
overlay changes none of the production provider's decisions or effects.

The [published evidence package](../../evidence/current/ownership-native-trace/README.md)
contains the original logs, results and native images, plus newly extracted
complete disassembly. **Stronger native correspondence checks and explicit
image inspection remain pending.** Publication makes the reported observations
available for assessment; it is not itself experimental closure.

| Fixture | Ordered decisive observation | Final accounting |
|---|---|---|
| Positive | Acquire A and B; spill/reload A; release A; read B as 42; release B; return 42 | acquired 2, released 2, reads 1, cleanup 0, refs 1 |
| Stale read | Same prefix through B's successful read; at PC 17 the A alias is tagged and canonical but privately invalid; read rejects | acquired 2, released 2, reads 1, cleanup 1, refs 1 |
| Repeated release | Same prefix; at PC 17 the same consumed A alias requests release and rejects before a second decrement | acquired 2, released 2, reads 1, cleanup 1, refs 1 |

The negative fixtures contain a later explicit B release at PC 19 and scalar
return marker at PC 20.
Neither executes. Rejection reaches the production failure return, the native
continuation terminates, and trusted cleanup consumes still-live B exactly
once. Thus each negative run has two acquisitions, one explicit A release,
one cleanup B release and the permanent baseline reference count of one. The
stale read performs no second read, and the repeated release performs no
second decrement. B's read of 42 before rejection rules out indiscriminate
object-wide invalidation.

The production emitter re-encodes and compares every word using its own encoder;
this is internal consistency checking. The original external checker validates
ordered events, image/map envelopes and selected spill/reload/gateway words,
not the complete prologue, branch targets or epilogue. Complete byte-bound
disassembly is now available for the pending native inspection and focused
checks. The positive image contains 612 bytes; each negative image contains
652 bytes. The original runner checks QEMU's exit status separately from the
checker's shutdown and failure-marker checks; the standalone checker's
`qemu_exit` field is not an independent exit-status check.

## Admission and claim boundary

Three separate existing BPF admission controls (stale copy, stale spill and
repeated release) are submitted only to the unchanged normal verifier. Their
invalid requests occur at PC 13, unlike the native negatives at PC 17; there
is no matching positive admission control. All three are rejected and none
executes. Their observed diagnostics
are classified as argument-shape rejection, so those outcomes establish only
admission behavior—not a particular ownership rule. An unexpectedly accepted
negative is closed without test execution.

The native controls are deliberately marked `verified_bpf=0` and
`scope=synthetic_native_production_path`. They are fixed trusted instruction
descriptions compiled by the real restricted emitter; they are not normally
verified eBPF, a relaxed-verifier path or a patched accepted image. The result
is therefore one integrated **synthetic native containment trace** through the
relevant production mechanisms. It does not execute an original stale BPF
program, the CVE's callback/helper path, callback-frame ownership policy,
concurrent reclamation or heap use-after-free.

The [test overlay](../../linux/ownership/native-trace.patch),
[load-only guest](../../linux/ownership/native-trace-guest.c),
[builder](../../tools/build_ownership_trace.sh),
[runner](../../tools/run_ownership_trace.sh) and
[checker](../../tools/check_ownership_trace.py) define the construction and
acceptance checks. The checker emits `results.json` and the extracted native
images in its fresh run directory.

## Validation identity

The hashes below identify original artifacts. The
[publication manifest](../../evidence/publication-manifest.json) separately
identifies path-redacted publication copies. Complete native and linked
disassembly in the package's `derivation/` directory was generated after the
original run; it is neither a new execution nor a completed semantic review.

The passing local run used kernel release
`6.7.0-cbpf-ownership-native-trace` over Morello Linux commit
`b96da308ef1a054c3c04c9445e5ed70259b7c397`. The ordinary verifier was
byte-unchanged, the production-provider overlay was unchanged, QEMU exited
zero and the guest powered down cleanly.

| Artifact | SHA-256 |
|---|---|
| Test overlay | `a99109e2dafa5d50875770e4cc0666426ad0f3439a9a6afb5fa121f8df2c5558` |
| Checker | `42c2d9c8c544b6ab5914919fff344d595c066b5f185d9f8d02d2f0378c69efd0` |
| Raw boot log | `b65c0dd73011830c7e7c2c823e10b0c23c9b9eba92b806528f041de571cdd20e` |
| Structured result | `265ccc50bfd55b2860480ed065a6549ba186a1596cd4b17cff4c7b394dcd96cf` |
| Positive native image | `47f78cef8fc40b2a7c9775a9a8e00e47c4d89ac9ce46be848de584c07fead40b` |
| Stale-read native image | `77606aef40132126b179f4e03e7349239a72f3c7be964970914bb4a3743369f7` |
| Repeated-release native image | `7215175ce34102dcb34742d5ed3654f5f702e9f8b8bd0f797cc5904af45c0cc8` |

```sh
make ownership-trace-kernel
export CBPF_OWNERSHIP_TRACE_BUILD=/absolute/path/printed/by/the/build
make ownership-trace
```
