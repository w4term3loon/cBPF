# Governed results

Publication copy of the historical report; see [redaction and identity scope](../README.md).

Verdict: **CONDITIONAL GO / DOWNGRADED CLAIM**.

The functional spatial result passed.  The strong provenance result did not:
the provider retains and later narrows an allocation-event capability, but the
pinned hybrid allocator returns an integer pointer, so the companion root is
initially constructed from executive DDC.  Exact base and provider association
therefore remain TCB premises rather than allocator-authenticated facts.

## Causal matrix

Every execution row used a fresh boot.  All unsafe rows attest the same canonical
48-instruction pre-relocation input (SHA-256
`b4a259d244c84345298d3efdb22d6b405dc0842644532c3bfb4582ead365db3e`;
FNV-1a `de1904150ca961f9`).

| Case | Governed observation | Outcome |
|---|---|---|
| Official vulnerable x86 parent | Loaded, JIT length 596, executed; sink word changed from `0xc3c3d4d4a5a5b6b6` to `0xffffffff9e4197c0` | PASS |
| Official fixed x86 revision | Rejected with `errno=13`; no JIT image, execution record, or post-state | PASS |
| Morello vulnerable, broad DDC | Loaded and executed; exported the selected map's actual `ops`, `0xffff800080b57fb0` | PASS |
| Morello vulnerable, exact selected value | Architectural bounds fault at the certified load; sink remained `0xc3c3d4d4a5a5b6b6` | PASS |
| Morello exact, valid in-bounds | Returned `42`; no fault | PASS |
| Morello allocation-wide root | Receipt declared `binding_valid=0`; unsafe stage again exported `0xffff800080b57fb0` | PASS as negative control; ineligible for the exact claim |
| Validator bound mutation | Changed value-size contract was rejected | PASS |
| Validator evidence-hash mutation | Changed exact-run log hash was rejected | PASS |

The validator accepted all six real cases and rejected both mutations while
binding 58 files.  Broad, exact, and wide unsafe native images have 142 words;
their entire BPF body, epilogue, PLT, source ranges, and unsafe load are
byte-identical.  Only decoded prologue immediates that materialize the per-boot
map table and build-specific compartment-entry address differ.

## Exact architectural observation

For the claim-eligible unsafe exact boot:

- provider/map/key identity: provider `1`, map `1`, key `0`;
- retained allocation root: tag `1`, base `0xffff000000c78000`, length
  `5240`, permissions `0x34dfd`;
- selected value capability: tag `1`, base/address `0xffff000000c78110`,
  length `4919`, permissions `0x34dfd`;
- source BPF instruction: zero-based instruction `45`;
- final native range/word/root: `[122,123)`, `0xe2c00453`, `c2`;
- exception: `ESR_EL1=0x000000009600002a`, `FSC=0x2a`,
  `FAR_EL1=0xffff000000c78000`, faulting
  `PC=0xffff8000813f7a70`;
- target metadata: selected map `ops=0xffff800080b57fb0`;
- victim/export sink: sentinel unchanged before and after.

The exact configuration has the inherited software map-bounds option unset.
The certificate's software-stub interval is empty (`[124,124)`), and the same
native BPF body executes in broad and wide modes.  The failure is therefore the
architectural capability-bounds exception at the intended load, not verifier
rejection, JIT rejection, or an inserted offset comparison.

## Authority provenance

Final disassembly establishes both sides of the downgrade:

1. `bpf_map_area_alloc_with_cap()` obtains DDC once after allocation, sets the
   returned allocation address and bound, removes execute/executive and
   capability-store permissions, and stores the companion root.
2. Exact `bpf_array_provider_value_cap()` loads that retained capability,
   validates the attached provider record, then uses `SCVALUE` and `SCBNDS` to
   derive the selected 4,919-byte value capability.  Its successful path does
   not read DDC.
3. The exact lookup gateway returns that result as the JIT architectural root.
   Its error-only DDC read is immediately tag-cleared.
4. Broad mode deliberately reconstructs the final capability from DDC; wide
   mode deliberately returns the 5,240-byte retained allocation root.  Both
   disclose `ops`.

Thus lookup-time monotonic derivation is observed, but genuine
allocator-minted provenance is not.  Achieving the latter in this hybrid tree
requires a capability-returning allocator/kernel ABI or equivalent generalized
allocator support and was stopped as outside the minimal experiment.

## Security meaning

`bpf_map->ops` is trusted provider control metadata outside the map-value API
authority and is used by the pinned public exploit's later chain.  Containing
this read is materially stronger than containing a key-0-to-key-1 effect, but
the metadata is coallocated with the value.  This is containment of the public
exploit's first direct out-of-value metadata-read primitive, not protection of
an independent principal, complete exploitation, or the CVE itself.

## Evidence boundary

Observed evidence comprises two governed x86 boots, four governed Morello
boots, full JIT certificate transcripts, capability/provider receipts, the
architectural fault, build receipts, final disassembly, and validator
mutations.  The machine-readable manifest binds exact revisions, trees,
configurations, images, initramfs archives, fixture binaries, compiled JIT
objects, full native-image hashes, and raw logs.
