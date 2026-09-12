# cBPF selected-value spatial containment

This is a conditional argument for one live, plain array-map value. It states
the obligation for the reduced cBPF provider path; it is not a proof of its
compiled implementation or a new native observation.

## Definitions and premises

Let the selected value's logical byte interval be `S = [v, v + n)`, with
`n > 0`. This interval excludes allocation metadata, element padding, and
other values. All interval calculations use non-wrapping integer arithmetic.

The argument assumes:

1. **Correct live provider binding.** The map, checked key, value address `v`,
   and logical size `n` identify the intended value. The provider record and
   map layout remain intact, and the map stays allocated throughout the
   synchronous access. Concurrent free, substitution, and reentrancy are
   excluded.
2. **Valid retained authority.** A tagged, unsealed capability `R` belongs to
   this allocation and contains `S`. Its base, extent, permissions, and
   association with the provider are trusted. In the inherited hybrid design,
   `R` is initially constructed from executive DDC after an ordinary allocation;
   retention does not establish allocator-minted provenance.
3. **Checked exact narrowing.** Monotonic derivation from `R` produces `C` with
   tag set, no sealing, address and base equal to `v`, and length exactly `n`.
   The implementation checks those properties and rejects an unsupported
   profile or unrepresentable exact bound instead of delivering wider
   authority. The reduced path requires exactly `LOAD|STORE|GLOBAL`, excluding
   capability-load/store, execution, and system-register permissions.
   Derivation never adds permissions.
4. **Actual access authority.** Each covered native load or store uses `C`, or
   a capability monotonically derived from `C`, as its architectural addressing
   root. CHERI tag, bounds, and permission enforcement operate correctly.
5. **Complete mediation.** To extend the result to every covered program
   access, no alternative root, scalar/DDC addressing path, capability loaded
   from data, helper return, or entry inside a checked operation may bypass
   premise 4. Writable provider state and retained wider roots remain trusted.
   A reduced permission mask alone does not prove this premise.

## Containment lemma and proof

Under premises 1–4, every successful covered access of positive width `w` at
address `a` satisfies `v <= a` and `a + w <= v + n`. An attempted access whose
byte interval is not contained in `S` cannot complete its architectural data
effect through that root. With premise 5, this holds for every mediated access
in the stated program boundary.

For a root `D` derived monotonically from `C`, `bounds(D)` is a subset of
`bounds(C) = S`, and its permissions cannot exceed `C`'s. Successful access
requires the complete accessed interval to lie within `bounds(D)` and requires
the relevant permissions and tag. Therefore that interval lies within `S`.
Changing a cursor cannot enlarge these bounds. If exact construction fails,
premise 3 supplies no usable root. This concerns architectural access effects,
not speculative behavior or side channels.

## Per-value versus whole-value-storage authority

The [existing selectivity fixture](../docs/results/spatial-selectivity.md) has
two logical seven-byte values at stride eight. Relative to the start of value
A, A occupies `[0,7)`, B occupies `[8,15)`, and their storage occupies `[0,16)`.
The exact-seven and stride-eight capabilities exclude the byte at offset eight;
the both-slot-sixteen capability permits it. This observed result separates
selected-value authority from authority over the whole value-storage region.
The latter includes both slots and their padding, but excludes allocation
metadata. It is a broad **capability** control, not a non-capability baseline.

The offset-six width-one/width-two pair answers a different question. Exact
seven permits `[6,7)` and rejects `[6,8)`: the entire access must fit, including
its final byte. No additional metadata-access experiment is needed for either
distinction.

## Retained-root consistency and wrong-value substitution

These are separate mechanisms. The [production provider](../linux/spatial/array-authority.patch)
checks its retained root's tag, unsealed state, base and cursor against the
array allocation, length against the recorded allocation size, exact
permissions, and sufficient extent for the layout. An inconsistent retained
allocation root that fails these checks is rejected. This is a source-derived
statement about those predicates, not an observed corruption experiment or a
claim that every possible wrong root is detected. The allocation record and
its association remain trusted under premise 2.

**Analytical counterexample to implicit value authentication.** Let `C_A` and
`C_B` be independently returned exact capabilities for keys zero and one in
that same live array. A trusted caller intends A but supplies `C_B` to the
same one-byte load at relative offset six. Its actual interval is `[B+6,B+7)`,
which fits B's bounds and permissions. Hardware therefore permits the access
and, for the fixture bytes, returns `0x87` rather than A's `0x29`. The capability
is valid; its use is inconsistent with the recorded intent to select A.

This substitution does not involve a malformed allocation root or widening A.
It violates the intended-selection/actual-operand correspondence in premises
1 and 4. The containment lemma still holds when instantiated for B. Bounds
constrain accesses through the supplied capability; trustworthy assignment and
actual operand use determine whether that capability protects the intended
value. A valid tag and exact extent do not authenticate that intent. This
counterexample supplies neither a reachable BPF exploit nor complete mediation.

The [bounded native control](../docs/results/spatial-selectivity.md#selection-binding-and-the-actual-operand)
observed this expected result under Morello QEMU: correct A returned `0x29`,
legitimate B and substituted B returned `0x87`, all at the same load PC with
unchanged storage. Only the substituted case reported a binding mismatch.
This observation illustrates the analytical premise; it is trusted synthetic
execution, separate from normally verified BPF.

CHERI's bounds and monotonicity are established primitives. The candidate
eBPF contribution is the mapping from a provider-selected logical value to
the root actually used by native accesses, with its assumptions and evidence
made explicit. Preserved legacy observations concern their original fixed
path. The [logical-extent witness](../docs/results/logical-extent.md) adds
reduced-source native correspondence for one normally verified key-one
seven-byte read/write control, distinct from the trusted selectivity fixture. It does not
establish premise 5 for every accepted program. This argument
establishes neither temporal safety nor per-acquisition reference validity,
and makes no composition claim with the ownership mechanism.
