# Logical extent versus array stride

**Passed, 7 September 2026.** A seven-byte array value received exact
length-seven capability authority despite its eight-byte storage stride.
One inspected native byte-six operation changed 41 to 42, preserving the
other six logical bytes. The [receipt](../../evidence/current/logical-extent/README.md)
retains the program, observations and pre-execution review.

## Construction discriminator

The earlier [eight-byte witness](spatial-native-result.md) used equal logical
size and stride. Both a correct logical-size constructor and an incorrect
stride-based constructor could satisfy that observation. This witness makes
those quantities differ while retaining one normally verified valid access.

| Quantity | Required and observed |
|---|---|
| Map profile | Plain ARRAY, two entries, four-byte key, zero flags, no BTF value record |
| Selected key and address | Key 1; value-array base plus eight bytes |
| Logical size / storage stride / capability length | 7 / 8 / 7 bytes |
| Capability | Tagged, unsealed, base = cursor = selected address, permissions `0x30001` |
| Initial logical bytes (hex) | `11 22 33 44 55 66 29` |
| Access | One-byte load and store at offset 6 |
| Final logical bytes (hex) | `11 22 33 44 55 66 2a` |
| Return / readback / invocation count | 42 / 42 / one `TEST_RUN` |

The decisive discriminator is the returned length together with inspected
native use. Successful readback alone would also pass under length eight.
A separate copy of the telemetry with only the provider length changed to
eight fails the checker. That demonstrates oracle sensitivity; no mutated
constructor was executed.

## Execution and correspondence

The guest reused the byte-identical spatial kernel from the clean-dependency
[native replay](../reproduction/native-replay.md). Kernel sources, provider enforcement,
verifier and configuration were unchanged; no kernel rebuild was necessary.
The fixture and its fixed checker changed. All 18 guest-input hashes were
verified before execution and again after the run.

Before the execution token, the same held program FD supplied all 14 BPF
instructions and 392 native bytes, matching its complete accepted certificate.
The preflight and manual review were recorded at execution count zero.
Word 72 copies full `c0` to `c7`; words 75 and 77 execute
`LDURB w0,[c7,#6]` and `STURB w0,[c7,#6]`. No intervening instruction
rewrites `c7`. Only those two words and one per-program map-table address
immediate differ from the previous native image.

The complete linked-kernel review was reused by exact image/disassembly
identity, and the provider size/stride and transport paths were reinspected.
The provider uses stride for address arithmetic and logical size for exact
bounds, checks the result and preserves the full capability across logging.
The one invocation passed postflight; the offline Morello QEMU guest powered
down with exit zero. It had no network, disk or BPF attachment.

## Recorded code-to-native walkthrough

This walkthrough explains the **key-one valid witness** above. Source excerpts
come from the verified inherited tree
`e6c69574c16bc2b9bce06329f9ac3f4b3269e79a` plus the
[provider patch](../../linux/spatial/array-authority.patch); the
[source pins](../../evidence/current/spatial/source-pins.json) identify that
baseline. The retained [guest](../../evidence/current/logical-extent/run/guest.c),
[verifier/native transcript](../../evidence/current/logical-extent/run/boot.log)
and [disassembly](../../evidence/current/logical-extent/review/jit-disassembly.txt)
identify this particular program. Ellipses below omit surrounding checks;
the short excerpts are not substitute implementations.

### A–B. Input and ordinary analysis

The fixture writes key 1 on the BPF stack, loads the map reference and calls
lookup. Its decisive BPF instructions, as retained in the verifier transcript,
are:

```text
5: call bpf_map_lookup_elem#1
6: if r0 == 0x0 goto pc+5
7: r1 = *(u8 *)(r0 +6)
8: r1 += 1
9: *(u8 *)(r0 +6) = r1
10: r0 = r1
11: exit
```

The alternative branch returns zero. The map has two entries, four-byte keys,
logical `value_size=7`, stride eight and zero flags. Ordinary analysis records
`R0_w=map_value_or_null(id=1,off=0,ks=4,vs=7,imm=0)` after lookup,
then `R0_w=map_value(off=0,ks=4,vs=7,imm=0)` on the non-NULL path.
Those are observed verifier states. The normal map-size/access-width and NULL
checks remain enabled. The reduced provider patch changes none of this
verifier source; the inherited prototype already contains additional
root-summary instrumentation.

### C. What actually crosses the compilation boundary

| Producer | Retained field | Consumer and consequence |
|---|---|---|
| Verifier `save_aux_ptr_type` and `finalize_bpf_jit_memory_roots` | `prog->aux->jit_memory_roots`, summarized from `env->insn_aux_data[].ptr_type` | `bpf_jit_validate_prog` checks the supported root profile; the JIT's reconstructed roots must agree |
| Successful verifier completion | `jit_memory_contract_version`, `jit_memory_contract_valid` | `bpf_jit_validate_prog` rejects a missing/incompatible contract |
| Verifier map/call preparation | `prog->aux->used_maps`, `used_map_cnt`, rewritten map/call instructions | `bpf_cheri_map_index` / `bpf_cheri_helper_call` bind the supported map token and lookup operation |
| Separate JIT `bpf_cheri_build_authority` | `jit_ctx.authority[pc].regs[r].kind` | `build_insn` chooses full-capability transport and capability memory encodings; certificate checks consume the same JIT analysis |

The root-summary assignment and emission decision are separate source sites:

```c
/* kernel/bpf/verifier.c: finalize_bpf_jit_memory_roots */
env->prog->aux->jit_memory_roots = roots;
/* arch/arm64/net/bpf_jit_comp.c: build_insn, load case */
if (bpf_cheri_cap_kind(authority->regs[insn->src_reg].kind)) {
    /* ... switch on BPF_SIZE(code), omitted ... */
    emit_cheri_cap_memory(cap_operation, dst, src, off, tmp, ctx);
    goto cheri_stack_load_done;
}
```

Exact source locators below use line numbers in that pinned tree **before
the provider and observation overlays**, not a later build directory:

- `kernel/bpf/verifier.c`, blob `b8b7c93456bc614023f4a904670b610e4d352790`:
  `save_aux_ptr_type` records the category and accumulates roots at lines
  17535–17547; `finalize_bpf_jit_memory_roots` scans and assigns the summary at
  17513–17532. Successful completion sets the version/valid fields and calls
  JIT validation at 21146–21153. Map retention and pseudo-instruction
  conversion are at 21112–21143.
- `arch/arm64/net/bpf_jit_comp.c`, blob `87e82badd8d06c0412197d2357a9c21dc31059bb`:
  `bpf_jit_validate_prog` consumes the contract/profile at 2070–2109;
  `bpf_cheri_build_authority` reconstructs kinds at 1795–2058 and compares its
  roots with the verifier summary at 2053–2058. JIT compilation fills
  `ctx.authority` at 4143; `build_insn` reads its per-instruction state at
  2260 and selects/emits the capability load at 2706–2738. Map/helper binding
  is at 1698–1728, and lookup-result capability transport at 2631–2636.

These tree/path/blob locators can be inspected using the retained source
objects in the [dependency bundle](../reproduction/native-dependencies.md).
The spatial pin is a verified tree, not a claim that its historical commit
was recovered. The excerpts identify inherited instrumentation and JIT
analysis; they do not attribute those mechanisms to the new provider.

The JIT analysis independently reconstructs map-value and nullable kinds,
including refinement at the zero comparison. **No per-instruction verifier
numeric interval or complete verifier state is exported as the runtime bound.**
The logged `vs=7` and the eventual seven-byte capability both refer to the map
contract; one is not a serialized bound passed to the other. This handoff is
source inspection, supported by the retained instruction correspondence, not
an additional execution or independent proof of the analyses.

### D. Runtime extent and selected address

Conventional array lookup already uses `array->elem_size` to locate a value.
That inherited layout is unchanged. The new provider retains an allocation
root at allocation time and derives the returned authority from it. The
[provider C](../../linux/spatial/array-authority.patch) appears beside the
existing [linked construction instructions](../../evidence/current/logical-extent/review/complete-linked-disassembly.txt),
lines 414–448. Offsets below are relative to `cbpf_array_value_cap` at
`0xffff8000801c1e78`; the non-contiguous excerpts omit intervening checks:

| Actual C expression or statement | Extracted linked instruction |
|---|---|
| `cap = authority->root;` | `+0x5c  ldr c7, [x8, #0x60]` |
| `array->elem_size` (stride) | `+0xac  ldr w4, [x0, #0x100]` |
| `array->index_mask` | `+0xcc  ldr w9, [x0, #0x104]` |
| `(unsigned long)array->value` | `+0xd0  add x5, x0, #0x110` |
| `map->value_size` (logical extent) | `+0xd4  ldr w3, [x0, #0x20]` |
| `index & array->index_mask` | `+0xd8  and x9, x9, x2` |
| `value = (unsigned long)array->value + (u64)array->elem_size * (index & array->index_mask);` | `+0xdc  umaddl x6, w9, w4, x5` |
| `cap = cheri_address_set(cap, value);` | `+0xe0  scvalue c1, c7, x6` |
| `cap = cheri_bounds_set_exact(cap, map->value_size);` | `+0xe4  scbndse c1, c1, x3` |

Here `x0` addresses the map, `x2` holds the loaded key, `c7` holds the
retained allocation root and `x6` is the selected address. The 32-bit stride
load feeds the multiply; the separate 32-bit logical-size load supplies
`x3` (zero-extended) to exact bounding of `c1`. These are extracted provider
instructions, unlike the illustrative conventional forms below.

For this run, values start at `0xffff000000df8310`; key 1 selects
`v=0xffff000000df8318`. Logical extent comes from **`map->value_size`**,
not stride or a verifier-predicted offset. Descriptor checks require
base/cursor `v`, length seven, tag one, unsealed state and permissions
`0x30001`. Unsupported construction returns no usable grant.

The [linked inspection](../../evidence/current/logical-extent/review/manual-review.json)
records this size/stride correspondence and the subsequent descriptor checks
and full-capability preservation across logging. Initial root assignment
remains trusted; a narrow bound does not prove correct object selection.

### E–F. Transport and actual instructions

The inherited gateway preserves capabilities across hybrid kernel calls.
The JIT emits a full capability move for lookup's return in `c0`, not just
its integer address. The retained program contains:

```text
word 72  0xffff8000813f7e18  c2c1d007  mov   c7, c0
word 75  0xffff8000813f7e24  e20064e0  ldurb w0, [c7, #6]
word 77  0xffff8000813f7e2c  e20060e0  sturb w0, [c7, #6]
```

`c7` is the capability base operand; `w0` carries scalar data; each access
is one byte at displacement six. The intervening NULL comparison and scalar
increment do not replace `c7`. This is inspected correspondence for these
operands in this image.

For comparison only, the conventional AArch64 address-based forms are
`ldrb w0,[x7,#6]` and `strb w0,[x7,#6]`. These are **illustrative forms
consistent with ordinary arm64 lowering, not extracted from a newly built
baseline**. The changed enforcement input is the explicit capability operand.
On Morello, address-based accesses instead use ambient DDC authority; they
are not necessarily unchecked.

The pinned conventional lowering source is Morello Linux commit
`b96da308ef1a054c3c04c9445e5ed70259b7c397`,
`arch/arm64/net/bpf_jit_comp.c`, blob `7d4af64e398286d2036c4cdbfbbab0f6611e12de`.
In `build_insn`, the unsigned byte-load case uses `A64_LDRBI` at lines
1211–1223, and the byte register-store case uses `A64_STRBI` at 1332–1338.
Those source cases support the illustrative immediate-offset forms; the
shown registers are aligned for comparison, not evidence of a compiled
baseline image. This commit is also retained in the dependency bundle.

### G. Effect and the separate rejection experiment

One normal `TEST_RUN` changes `11 22 33 44 55 66 29` to
`11 22 33 44 55 66 2a`, returns 42 and preserves the six-byte prefix.
No padding access occurs in this execution.

The separate [synthetic key-zero matrix](spatial-selectivity.md) supplies the
rejection contrast. For example, its published `matrix-v2` case 3 attempts a
one-byte load at offset seven through length-seven authority. It records
`c2` as the operand, PC/fault PC `0xffff8000801c4780`, instruction
`e2000448` (`ldurb w8,[c2]`), and bounds FSC `0x2a`; the destination
sentinel and fixture remain unchanged. Here the cursor already includes the
offset, so the native displacement is zero. Wider trusted controls at the
same selected address permit the padding read. That fixture's recovery is
test-only; it is not the production BPF exception path or invalid BPF execution.

## Interpretation and evidence limits

The result supports a reusable design decision: **allocation layout locates
an object; the API's logical extent defines its authority.** The later
[selective spatial matrix](spatial-selectivity.md) executes the corresponding
padding, adjacent-value and crossing-access discriminators. The
[design synthesis](../research/related-work.md#source-lineage-and-design-rationale)
states that decision alongside object/acquisition distinction, current
validity and terminal handling, with their costs. The
[architecture diagram](../research/authority-architecture.svg)
keeps the two evaluated kernel profiles separate.

This particular witness is construction discrimination and valid native
correspondence, not an observed padding fault. The subsequent matrix supplies
that selected synthetic-native observation under a separate execution identity.
Construction logs remain source-backed observations, not independent hardware
attestation. Broader ambient roots, trusted assignment and local review still
limit the claim. Original-CVE execution and composition are outside this
witness.
