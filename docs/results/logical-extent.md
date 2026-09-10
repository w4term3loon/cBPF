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
