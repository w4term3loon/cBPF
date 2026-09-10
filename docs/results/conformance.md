# Bounded host-C/model correspondence

The executable C model and independent Python semantics have a direct,
reproducible observation comparison. It tests the implementation of defensive
ownership rules using only cBPF's tiny local instruction language. It loads no
eBPF programs, invokes no kernel experiments, and targets no external system.

```sh
make conformance
make gate-conformance    # the host cell-gate implementation, same model oracle
```

Both targets are part of `make check`. They build a small test-only shared
library from `src/cbpf.c` and `tools/conformance_bridge.c` (plus `src/gate.c`
for the gate variant), then call it through
Python's standard-library `ctypes`. The adapter reads the actual C constants
and serializes results into fixed-width integers; Python does not guess enum,
structure, or padding layouts. It neither changes runtime semantics nor exposes
mutable acquisition state. There are no additional downloaded dependencies.

## What is compared

Breadth-first exploration keeps one shortest operation history to each active
abstract state. For each outgoing edge, the checker translates that history
and operation into a structurally valid C-machine program. Active results are
followed by scalar return and modeled cleanup. A trapping operation is followed
by a valid but unreachable scalar return; its execution would change the
expected outcome and fail the comparison.

Expected ownership effects come from `check_model.py`, independently of the C
execution. Model state and edge invariants are checked before comparing C
observations. Each comparison includes:

- Return/trap status, reason and instruction position, scalar result, and read
  count/value.
- Acquisition count, explicit and cleanup release totals, individual cell
  effect counts, and final provider reference count.
- Every step/trap/cleanup event, including opcode, program counter, acquisition
  token, and reference count. Cleanup events are projected in the C machine's
  declared cell-index order, separately from the attempted operation's effect.

At each active state, a forward NULL branch is checked for each register.
Its two exits return different scalars so direction is observable. Consumed
tokens must remain non-NULL: the NULL branch does not test ownership liveness.
Four additional returns cover zero, minus one, and the signed 64-bit endpoints.

## Recorded coverage

The [original recorded result](../../evidence/current/host-conformance.json) uses the
documented bounds `K=2, R=4, S=2`, one live object with value 42, and baseline
reference count one. Counts are derived from exploration, not used as expected
test outcomes.

| Coverage | Observed count |
|---|---:|
| Active abstract states | 3,045 |
| Terminal abstract states | 14,783 |
| Model edges replayed in C | 149,205 |
| Forward-branch cases | 12,180 |
| Scalar-boundary cases | 4 |
| Total generated executions compared | 161,389 |
| Longest generated program | 12 instructions |

All comparisons matched. Branch cases comprise 4,148 NULL, 4,016 live, and
4,016 consumed-token inputs. The model edges include separate terminal stale
read and stale release cases; execution never resumes after an ownership trap.

The host gate matched the same coverage; its later result is retained in
[`gate/host-conformance.json`](../../evidence/current/gate/host-conformance.json).
The adapter reports which implementation it calls and includes the gate source
hashes for that variant. The original snapshot and its earlier adapter/checker
identities are preserved. Neither host comparison constitutes native CHERI
execution; the [native gate corpus](native-gate.md) is a separate result.

`make demo` separately checks the full 64-instruction limit and all 66 event
slots, early-return containment, and rejection of malformed unreachable code
before effects. `make oracle` independently accepts 13 valid edges and rejects
16 malformed edges, including invariant-preserving violations of acquisition
and termination semantics.

## Evidence limits

This is a bounded observation comparison, not an exhaustive enumeration of C
programs or a refinement theorem. One abstract state's shortest history does
not represent all concrete C states: PCs, repeated reads, and event histories
are abstracted away. Generated model histories are at most 12 instructions
after adding exits; the maximum-length boundary is a separate control.
Branch checks cover one branch after every retained prefix, not all multi-branch
control-flow graphs. The oracle, translation, adapter, compiler, and observation
comparison can themselves have defects.

The result does not establish native memory isolation, correctness of every C
execution, CHERI protection, or Linux eBPF/JIT/kfunc correctness. It supplies a
compact regression baseline and makes an implementation-to-model connection
explicit. Native mediation requires separate implementation and interface
premises, stated in the [kernel mapping](../../theory/kernel-ownership.md).

The JSON records source and loaded-library hashes, Python version, and machine
architecture. The recorded compiler was Ubuntu GCC 13.3.0
(`13.3.0-6ubuntu2~24.04.1`), using the default Makefile command (`cc`, `-O2`,
strict C11 warnings, `-fPIC -shared`); a library hash alone does not promise
bit-identical builds on another toolchain. `make conformance` prints a fresh
result and leaves the recorded snapshot unchanged.
