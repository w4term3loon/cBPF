# cBPF ownership: semantics and argument

This document describes an ideal reference machine and the finite-state check
in `check_model.py`. Neither is a proof of the host C implementation, a Linux
eBPF verifier/JIT, or CHERI native code. The host implementation is an
executable specification candidate; its integer tokens are not hardware
capabilities.

The target is runtime enforcement of an existing Linux contract:
[`KF_RELEASE` invalidates aliases of the released reference](https://docs.kernel.org/bpf/kfuncs.html#kf-release-flag).
The mechanism is not claimed as novel. [CETS](https://people.cs.rutgers.edu/~sn349/papers/ismm10-cets.pdf)
already uses shared lock/key invalidation and disjoint pointer metadata.
The research distinction to investigate is an owning **acquisition**, not an
allocation: two acquisitions may name one still-live object but carry
independently consumable rights. HIVE's [June 2026 description](https://ebpf.foundation/research-update-isolated-execution-environment-for-ebpf-part-3/)
permits same-type substitution within an invocation and explicitly omits
per-pointer freshness; this is a comparison boundary, not proof of novelty
or of a vulnerability in HIVE.

## State and assumptions

There is one object, with constant readable value `42` and a permanent
baseline reference count of `1`. It is never freed in this model.
For acquisition budget `K`, reference-register count `R`, and spill count `S`,
the state is:

```text
n                   successful acquisitions so far, 0 <= n <= K
L                   subset of {1,...,n}: live acquisition identities
registers[R]        NULL (0) or an acquisition identity
spills[S]           NULL (0) or an acquisition identity
E[i], D[i]          explicit and terminal-cleanup release effects for identity i
rc                  the provider's object reference count
terminal            active, returned, or trapped with a reason
```

Initially `n = 0`, all aliases are NULL, `rc = 1`, and execution is active.
An identity is a token, not the object's address. Identity `n+1` is fresh;
cells are never reused during an invocation. Overwriting the last alias of a
live acquisition does not release it: the cell still records the owned
reference, and terminal cleanup must consume it.

The argument assumes:

- **Unforgeable identity and protected state.** Programs cannot manufacture
  non-NULL tokens, change a token's acquisition identity except by copying an
  existing token, or edit cell/effect/provider state. The Python model makes
  this true by its transition rules; hostile native C code is not isolated by
  the host implementation.
- **Complete mediation.** Every read and release goes through the token's
  liveness check. No usable direct object pointer escapes a resolution.
- **Correct provider and trusted runtime.** Successful acquire adds one
  reference; release drops exactly one; the fixed read returns `42`.
- **Synchronous, non-reentrant execution.** No observer or callback can
  interleave with release or cleanup. Consumption occurs before the provider
  decrement. The model collapses these ordered actions into one atomic
  transition; it does not verify native instruction ordering or concurrent
  linearizability.
- **Invocation containment.** Terminal states cannot execute further program
  operations, and aliases cannot escape to a later invocation. Retained
  terminal aliases are inert model data, not evidence of register/stack
  scrubbing or hardware revocation.

These assumptions are precisely the obligations a CHERI-backed design and
native-code checker would have to justify. They are not results of this model
checker.

## Transitions

All operations below are enabled only in active states.

| Operation | Semantics |
|---|---|
| `acquire(r)`, success | If `n < K`, create fresh identity `n+1`, mark it live, set `registers[r]` to it, initialize its effect counters to zero, and increment `rc`. Otherwise trap for exhaustion before acquisition; perform terminal cleanup. |
| `acquire(r)`, NULL | Set `registers[r] = 0`. Do not create a cell, consume budget, or change `rc`, even when the budget is exhausted. |
| `copy(dst, src)` | Copy the token between registers; preserve identity even for NULL or consumed tokens. |
| `spill(slot, r)` / `reload(r, slot)` | Copy the complete token between register and spill slot, preserving its identity. |
| `read(r)` | If its token is in `L`, return `42` without changing ownership. Otherwise trap before the read and perform terminal cleanup. |
| `release(r)` | If its token `i` is in `L`, remove `i` from `L` before its provider effect; increment `E[i]` and decrement `rc`. Leave all aliases unchanged. Otherwise trap before an explicit release and perform terminal cleanup. |
| `finish` | Terminate normally and consume every remaining live identity once through cleanup: remove it from `L`, increment `D[i]`, and decrement `rc`. |

All traps are terminal. A failed read or release has no effect **for the
attempted operation**. Cleanup may still release other live acquisitions;
this is why explicit and cleanup effects are counted separately. No cell is
reclaimed and reused within this state machine.

For example, one valid execution is `acquire(A); acquire(B); release(A);
read(B); read(A)`. The last read traps; cleanup then consumes B. An attempted
second release of A is a separate terminal test, not an instruction executed
after the trapped read.

## Three invariants and induction argument

At completed operation boundaries, for every successful acquisition `i`:

1. **Consumption.** `E[i] + D[i]` is either zero or one, and
   `i in L` iff this sum is zero. A successful read requires `i in L`; a
   release through any consumed alias traps before another explicit effect.
2. **Alias consistency and independence.** Every non-NULL alias names an
   existing acquisition. Copies/spills/reloads preserve that identity.
   Explicit release of `i` changes neither liveness nor effect counts of any
   `j != i`, even though both refer to the same object. Reacquisition never
   changes the meaning of an older token.
3. **Reference-count accounting.**

   ```text
   rc = 1 + n - sum_i E[i] - sum_i D[i] = 1 + |L|
   ```

   Consequently the object stays allocated, and after return/trap cleanup,
   `rc = 1` and every acquired reference has exactly one release effect.

The base case satisfies all three. A successful acquire extends the identity
domain with a fresh live member, adds zero counters, and increments `rc`, so
it preserves the equations and cannot change old aliases. A NULL acquisition
or token copy only changes the appropriate alias. A valid read changes no
state. A valid release can select only a live identity whose effect sum is
zero; removing that identity and recording one effect preserves both
consumption and accounting while leaving other identities untouched. An
invalid read/release cannot take this transition. On a return or trap,
cleanup visits exactly the remaining live identities; the same release
argument applies to each, and the terminal state has no outgoing execution.

Thus the invariants hold by induction for every finite sequence admitted by
these transition rules, for arbitrary finite `K`, `R`, and `S`, under the
assumptions above. Alias independence is checked at the explicit release
boundary: a later terminal cleanup may legitimately consume other identities.
This is a mathematical proof sketch, not a mechanized theorem. Its scope is
ownership-protocol safety, not allocation-level use-after-free prevention,
race freedom, confidentiality, or availability.

## Exhaustive finite check

Run with Python 3.10 or later; no external packages are required:

```sh
python3 theory/check_model.py --mutation-check
```

The default bounds match the host machine's **slot counts**: two successful
acquisitions, four reference registers, two spill slots, one still-live
object. Breadth-first exploration enumerates every modeled operation and
operand at every reachable active state. It merges identical states, keeping
one shortest predecessor history. The output derives state/transition counts;
there are no expected fixture results or hardcoded state counts in the checker.

Recorded run of this version:

| Bounds | Reachable states | Terminal states | Transitions checked |
|---|---:|---:|---:|
| `K=2, R=4, S=2` (default) | 17,828 | 14,783 | 149,205 |
| `K=2, R=2, S=1` | 624 | 499 | 2,125 |

Counts include labeled self-loops and different operands producing the same
successor; terminal states have no outgoing transitions. The graph is finite
because the identity budget and alias sets are bounded, and each effect
counter can change at most once. Successful reads and repeated copies add no
history-dependent state. There is no trace-length cutoff: cycles are covered
by visiting their constituent states and outgoing edges. This establishes the
checked safety properties for the reachable graph, not termination of
arbitrary operation sequences.

The checker validates state invariants and transition effects separately
from transition construction. Its one optional mutation deliberately
consumes **all live acquisitions to the object** on release, also adjusting
effect counts and `rc`. Consumption/accounting still hold, but alias
independence must fail. The explorer finds a shortest counterexample:

```text
acquire(0): success
acquire(1): success
release(0): consumed     # incorrectly also consumes acquisition 2
```

`--mutation-check` exits nonzero if the normal model violates an invariant or
the mutant has no counterexample. It requires a budget of two to distinguish
independent acquisitions; at a one-acquisition bound, inability to distinguish
the mutant is expected and is not evidence of stronger protection.

The model explores arbitrary compositions of the operations rather than the
C parser or particular bytecode programs. Forward NULL branches are omitted
because they only select which modeled operation occurs next; scalar return
values are irrelevant to ownership. This exploration includes sequences that
need not occur in a valid C-machine program. It does **not** validate the C
validator's forward-branch rules, its 64-instruction limit, instruction
decoding, return-value semantics, pointer ABI, native mediation, memory
isolation, or correspondence between either executable implementation and
these rules. The differential comparison below is a separate result; a
refinement theorem cannot be inferred from passing this finite check.

## Independent oracle controls and C observations

`check_oracle.py` supplies explicit valid and malformed successors without
using the transition constructors. It checks that a successful acquire creates
a live identity with zero effects, that finish actually terminates, and that
trap reasons, observations, and identity-domain changes match the operation.
State invariants alone do not suffice: an acquisition born already consumed
can satisfy the accounting equation while violating the acquire transition.
These controls strengthen the executable checker, not the induction argument.

The separate `check_conformance.py` compares host-C results with the model
through a test-only adapter. It covers every outgoing edge after one shortest
history to each reachable active abstract state, adds terminal cleanup, and
compares the observable trace and per-acquisition effects. Forward NULL
branches and scalar returns are checked separately. See
[the exact coverage and limits](../docs/results/conformance.md).

This does not merge concrete C states or explore every C program. In
particular, two histories reaching the same abstract state can have different
concrete counters and program counters. The finite-model induction result
cannot be transferred to arbitrary C histories by this comparison alone.
