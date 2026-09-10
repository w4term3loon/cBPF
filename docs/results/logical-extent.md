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
come from the verified inherited tree `e6c69574c16b…` plus the
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
root at allocation time and derives the returned authority from it:

```c
value = (unsigned long)array->value +
        (u64)array->elem_size * (index & array->index_mask);
/* cap already holds the checked retained allocation root */
cap = cheri_address_set(cap, value);
cap = cheri_bounds_set_exact(cap, map->value_size);
```

For this run, values start at `0xffff000000df8310`; key 1 selects
`v=0xffff000000df8318`. Logical extent comes from **`map->value_size`**,
not stride or a verifier-predicted offset. Descriptor checks require
base/cursor `v`, length seven, tag one, unsealed state and permissions
`0x30001`. Unsupported construction returns no usable grant.

The [linked inspection](../../evidence/current/logical-extent/review/manual-review.json)
identifies the distinct stride and logical-size loads before address selection
and exact bounding. Initial root assignment remains trusted; a narrow bound
does not prove that the provider selected the correct object.

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
