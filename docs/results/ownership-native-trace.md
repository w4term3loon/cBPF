# Synthetic native ownership containment trace

The retained integrated ownership trace from 10 September 2026 passes
strengthened byte, operand, target and ordered-event checks. Three fixed
trusted native fixtures reused the production restricted entry, capability
transport, gateway, ownership gate, epilogue and cleanup wrapper. The test
overlay changes none of the production provider's decisions or effects.

The [published evidence package](../../evidence/current/ownership-native-trace/README.md)
contains the original logs, results and native images, complete disassembly,
and a later [native inspection and recheck](../../evidence/current/ownership-native-trace/inspection/README.md).
All 479 words across the three fixed images are checked, including framing,
register transport, source/native intervals and branch targets. The complete
gateway and selected compiled gate/entry/cleanup sequences also pass focused
checks. This is internally inspected, independently inspectable evidence—not
independent external reproduction or a general native validator.

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

## Native route behind the observations

The fixed negative images preserve A at native word 67 (`str c19,[csp,#0]`)
and reload it at word 79 (`ldr c21,[csp,#0]`), then reload A again at word 93
for the stale request. These are full sixteen-byte capability operations for
the supported logical eight-byte spill. The gate consults canonical identity
and private validity; consuming A does not erase its public aliases' tags.

The [complete linked inspection](../../evidence/current/ownership-native-trace/inspection/native-review.md)
follows failure through the gateway:

```text
cmn x0, #1       // failure sentinel
b.ne ...         // success skips failure selection
mov c14, c13     // failure selects the fixed return path
...              // saved-state restoration, omitted here
retr c14
```

This is an excerpt, not a complete gateway or a new image. In both negative
images the restricted-return stub reaches the common executive epilogue at
word 117. That epilogue clears program-accessible registers and the sidecar;
after native return the production wrapper consumes live B exactly once.
The software gate rejects before an object effect; a hardware tag fault is
neither required nor reported for this decision. Trusted executive stack
copies are not all explicitly erased and remain outside program authority.

## Assurance and revalidation

Three assurance sources must be distinguished. The production emitter
re-encodes and compares every word using its own encoder: internal consistency,
not independent decoding. The current external checker uses fixed-profile
byte/operand/target checks and retained LLVM decoding, without invoking that
encoder. The [authored inspection](../../evidence/current/ownership-native-trace/inspection/native-review.md)
explains the complete fixed images and selected linked failure path. It is
AI-assisted internal review, not a compiler correctness proof or external review.

The original checker remains preserved with its weaker envelope/marker checks.
The positive image contains 612 bytes; each negative contains 652 bytes.
The new checks reject the review's mostly-NOP image, NOP epilogue, misdirected
branches and wrong capability/register operands. Constructed host mutations
test validation logic; they are not runtime bypass observations.

The current checker now requires an explicit exit-status file, combines it
with actual kernel powerdown and rejects the same failure markers as the
spatial checker. The [completion recheck](../../evidence/current/ownership-native-trace/revalidation/completion.json)
preserves the original observations without another native run. The subsequent
[full fixed-image recheck](../../evidence/current/ownership-native-trace/inspection/results.json)
adds instruction correspondence without changing those observations. No
ownership kernel was rebuilt and no ownership guest was rerun.

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
[checker](../../tools/check_ownership_trace.py), with its
[fixed instruction checks](../../tools/ownership_native_checks.py), define the
construction and acceptance checks. The runner retains complete post-run
disassembly before validation. The checker emits `results.json` and extracted
native images; it requires the run inputs, configuration and complete inspection
directory. A changed compiled layout requires renewed inspection rather than
automatic acceptance.

## Validation identity

The hashes below identify original artifacts. The
[publication manifest](../../evidence/publication-manifest.json) separately
identifies path-redacted publication copies. Complete native and linked
disassembly in the package's `derivation/` directory was generated after the
original run; its original receipt records extraction only. The later authored
inspection and revalidation live separately in `inspection/`, with their own
timestamps and source identities. A fresh offline decode reproduced the
complete listings byte-for-byte; it was not another guest execution.

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

For the published records, `make evidence-recheck` and `make checker-tests`
need no Docker, QEMU or downloads. Both are part of `make check`; `make evidence`
separately checks publication hashes. Linked checks use the recorded zero
relocation and reviewed non-BTI/non-PAC layout. Protected private state,
truthful observations, architecture behavior and synchronous execution remain
premises; all-program mediation and normally verified stale BPF remain outside
the result.
