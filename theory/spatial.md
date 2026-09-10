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

## Why allocation bounds are insufficient

Consider an allocation interval `[0, 128)` and a selected value `[32, 40)`.
A one-byte access at address `16` is inside the allocation but outside the
value. Allocation-wide bounds alone permit that interval; selected-value
bounds exclude it. Thus allocation containment does not imply containment to
the API-authorized value, even while the whole allocation remains live.

CHERI's bounds and monotonicity are established primitives. The candidate
eBPF contribution is the mapping from a provider-selected logical value to
the root actually used by native accesses, with its assumptions and evidence
made explicit. Preserved legacy observations concern their original fixed
path. The [spatial native witness receipt](../docs/results/spatial-native-result.md) adds reduced-source native
correspondence for one inspected eight-byte read/write control. It does not
establish premise 5 for every accepted program. This argument
establishes neither temporal safety nor per-acquisition reference validity,
and makes no composition claim with the ownership mechanism.
