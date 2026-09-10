# Fixed ownership images: instruction and terminal-path review

This is an AI-assisted internal inspection performed after the retained run.
It is not independent external review. The [receipt](receipt.json) binds its
date, source snapshots and inputs. It accompanies, rather than substitutes for,
the ordered native observations and current external checks.

## Inputs and coverage

The complete [positive](../derivation/native-positive-disassembly.txt),
[stale-read](../derivation/native-stale_read-disassembly.txt) and
[repeated-release](../derivation/native-repeated_release-disassembly.txt)
listings contain 153, 163 and 163 words respectively. Every word is inspected
as part of the common framing or the case-specific body below, and checked
against the logged bytes, preserved binary and LLVM operand text. The
[linked listing](../derivation/complete-linked-disassembly.txt) retains all
952 words in eight relevant functions, including mapping-label-separated
blocks and both atomic alternatives. Their [ELF range record](../derivation/linked-ranges.json)
uses full function sizes; the zero-sized gateway ends at `cbpf_gate_impl`.

The kernel's recorded KASLR-disabled message supplies zero linked relocation.
JIT addresses come from each logged image entry; LLVM MC branch operands are
displacements from the instruction address, not absolute targets. The checks
decode signed branch/ADR fields and resolve their targets explicitly.

| Image | Entry | Restricted return | Executive common epilogue | Final sealed return |
|---|---|---|---|---|
| Positive | `0xffff800081271204` | word 106, `0xffff8000812713ac` | word 107, `0xffff8000812713b0` | word 151, `retr c16` |
| Stale read | `0xffff80008110720c` | word 116, `0xffff8000811073dc` | word 117, `0xffff8000811073e0` | word 161, `retr c16` |
| Repeated release | `0xffff800081109bf4` | word 116, `0xffff800081109dc4` | word 117, `0xffff800081109dc8` | word 161, `retr c16` |

## Common prologue: words 0–55

Words 0–12 retain the outer integer return address, preserve the stock NOP
entry slot, save integer callee-saved registers, reserve a sixteen-byte sealed
caller slot and a separate sixteen-byte capability spill sidecar. This fixed
kernel has no BTI/PAC-generated framing; different configurations fail closed.

At word 13, `adr x2` names the exact executive epilogue in the table. Word 14
supplies its 184-byte extent. Words 16–19 materialize the program cookie;
the external check establishes a nonzero aligned scalar, while its actual
identity is checked by trusted `cbpf_enter` against the active invocation.
Words 20–24 materialize and call linked `cbpf_enter` at
`0xffff80008003ef78`, not an arbitrary address occurring somewhere in the image.

Successful entry resumes at word 25 with zero status and branches to word 28.
The separate entry-error path zeroes x7 at word 26 and branches directly from
word 27 to the executive epilogue. The logged restricted bounds start exactly
at word 25 and end immediately before that epilogue. Words 28–55 clear x0–x29
except the trusted stack/gateway registers x15/c17. The body starts at word 56;
there is no unaccounted gap before its first map interval.

## All mapped body instructions

Register assignment is BPF r0→c7, r1→c0, r6→c19, r7→c20, r8→c21 and r9→c22.
MOV-register operations use full-capability moves; MOV-immediate operations
use all four scalar MOVZ/MOVK parts. The only spill is `str c19, [csp, #0]`;
reloads are `ldr c21, [csp, #0]`. The capability-width sidecar is distinct from
the original BPF eight-byte spill syntax.

| BPF PC(s) | Native words, inclusive | Inspected effect |
|---|---|---|
| 0–2 | 56–65, all cases | Zero argument; acquire A at words 60–64; null test |
| 3–4 | 66–67, all cases | Retain A in c19 and spill its full capability |
| 5–7 | 68–77, all cases | Zero argument; acquire B at words 72–76; null test |
| 8–10 | 78–80, all cases | Retain B in c20, reload A into c21, pass A in c0 |
| 11 | 81–85, all cases | Release A: operation 3, PC 11, sealed call and full result move |
| 12–14 | 86–92, all cases | Pass B, read with operation 2/PC 13, retain result in c22 |
| Positive 15–18 | 93–100 | Pass B, release at PC 16, restore saved result to c7, branch to word 106 |
| Positive 19–20 | 101–105 | Null-return scalar zero and branch to word 106 |
| Negatives 15–17 | 93–99 | Reload A, pass c21 in c0, stale operation at PC 17 |
| Negatives 18–21 | 100–110 | Later B release at PC 19, scalar marker 99 at PC 20, branch to word 116 |
| Negatives 22–23 | 111–115 | Null-return scalar zero and branch to word 116 |

Every call interval is exactly five words: operation into x4, source PC into
x5, `mov c13, c30`, `blrs c17`, then `mov c7, c0`. Thus c13 retains the fixed
epilogue sentry while c30 becomes the call continuation. Positive null branches
at words 65/77 target word 101; negative null branches target word 111. All
BPF exits target the restricted return, with no branch into a partial cleanup
sequence. The two negatives differ in the stale operation at word 95 (2 for
read, 3 for release), their native placement and program cookie—not in their
failure handling.

The positive trace reaches B's release and returns 42. Each negative reaches
the stale call at word 98. Its normal return address would be word 99, but the
failure path below selects the executive epilogue instead. Consequently the
later release at word 104 and marker at words 106–109 are not reached. This
interpretation agrees with the absence of additional gate effects and the
zero wrapper return; absence of effects alone is not treated as a PC trace.

## Linked rejection and gateway return

The production [runtime source](../build/cbpf_runtime.c), plus the
[observation-only overlay](../build/native-trace.patch), explains the compiled
gate. Exact identity checks at `cbpf_gate_impl+0xb8` and `+0x1e0` compare the
public capability with private views. At `+0x1fc`–`+0x208`, the private object
capability is loaded, its tag examined, and zero branches to rejection at
`+0x26c`. This precedes the object read at `+0x230` and the consume call at
`+0x258`. The rejection block records identity, sets failed state at `+0x2f8`,
and returns a null-derived scalar -1 through `+0x348`–`+0x360`. The compiler
inlines this failure return; the standalone `cbpf_fail` listing is not claimed
to be the executed stale-return site.

The entire 56-word gateway at `0xffff80008003e370` was inspected and is checked.
It switches to trusted stack storage, saves full c13/c17/c19–c22/c30, moves
the operation and PC into the C argument registers, and calls the actual
`cbpf_gate_impl` at `0xffff80008003e450`. It restores the sealed continuation
to c14 and the fixed epilogue sentry to c13. At `+0x6c`, `cmn x0, #1` tests
the failure sentinel; `b.ne` at `+0x70` targets exactly `+0x80` for success.
Failure falls through `mov c14, c13` at `+0x74`, zeroes the scalar result and
then reaches the common scrub. Both routes restore the fixed sentry in c30,
clear the listed scratch registers and execute `retr c14` at `+0xdc`.
Success therefore returns to the call continuation; failure returns directly
to the executive epilogue, not to another BPF instruction.

Linked entry constructs and seals the restricted code, executive epilogue,
caller and gateway capabilities. At `cbpf_enter+0x204`, ADR selects this same
gateway. Its final block installs RCSP and null RDDC, reloads the restricted
code and epilogue capabilities, restores SP/x15, sets c17 to the gateway,
c30 to the epilogue and branches restricted through c1. These last twelve
words are checked, together with the gateway address selection. Trusted exact
construction, saved context and architecture semantics remain premises.

## Common epilogue and ownership cleanup

Normal BPF exit first executes the restricted `ret c30`; gate rejection reaches
the executive epilogue directly. Its first two scalar stores clear the complete
sixteen-byte sidecar. It scalarizes x7 and clears all x0–x29 except x7, then
discards the sidecar, reloads the sealed caller into c16 and restores integer
callee-saved registers. After transferring the result to x0 it tests c16's tag:
the tagged route executes `retr c16`; the untagged entry-error route branches
over that instruction to the final ordinary return. The full 184-byte
executive sequence and that final target are checked. Trusted executive stack
copies are not claimed to be erased by the program-visible scrub.

In `cbpf_test_invoke`, the native call returns before the cleanup loop at
`+0x31c`–`+0x35c`. The loop visits each acquired private cell once, skips a zero
tag, and calls `cbpf_consume` with its index, PC `U64_MAX` and cleanup flag one.
The consume call at `+0x354` targets `0xffff80008003ea28`; both the skip and loop
backedges are retained in checked sequences. Since A was invalidated and B is
live, this consumes B once. `cbpf_consume+0x40` clears the stored capability
tag before either compiled atomic-decrement alternative. Its release counter
always increments and its cleanup counter increments only for the cleanup
flag. Those critical sequences are also checked. This agrees with the ordered
clear-A/release-A/read-B/reject/clear-B/cleanup-B/failed records.

The wrapper checks balance, clears both cells/views, ends the active invocation,
restores RDDC/RCSP from full-capability saves and selects return zero when failed.
The full wrapper and relevant trace/consume/entry listings were inspected;
machine checks cover the named critical sequences, not arbitrary compiled C
control flow, refcount library internals, logging correctness or the whole kernel.

## Conclusion and premises

The retained records, complete image inspection and focused external checks
support one integrated synthetic-native containment trace for each selected
stale request. The checker no longer accepts the review's mostly-NOP image or
a NOP epilogue. Encoder self-check, decoder-backed receipt checks and this
inspection are separate assurances, not independent proofs of the compiler.

Trusted assignment, private validity, actual gate/operand use, synchronous
effect ordering, preserved architecture state, truthful logging and terminal
cleanup remain premises. No new native execution follows from this review.
Normally verified stale BPF, callback ownership policy, speculative leakage,
general reclamation and independent external reproduction remain untested.
