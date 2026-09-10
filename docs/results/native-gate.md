# CHERI-backed interpretation of the supported subset

cBPF executes its validated instruction language using capability-valued
acquisition handles in a purecap user-mode program. On 6 September 2026,
**494 cases matched the software reference in the Morello guest**. Each case
compares every result and event field and checks separate expected outcomes.
The direct-object control still reads A and B as 42 after A's modeled release.

This study evaluates native feasibility using cBPF IR rather than Linux
kfunc execution. All C code remains trusted. The interpreter uses
semantic terminal traps and cleanup; it does not deliberately dereference
invalid capabilities. The earlier [architecture probe](cheri-probe.md) retains
its separate observations of actual capability-tag faults.

## Run and compare

```sh
make gate               # host software-cell implementation and focused cases
make gate-conformance   # host gate against the independent Python model
make cheri-gate         # same focused cases with actual Morello capabilities
```

`make check` includes both host targets. `make cheri-gate` uses the same cached
compiler, purecap runtime, emulator and unchanged kernel as `make cheri`.
The runner builds a fresh initramfs, boots one virtual CPU with networking
disabled and no host filesystem attached, and requires explicit guest poweroff
within the existing 60-second limit. It downloads nothing and modifies no
kernel or external source tree. See [toolchain locations](cheri-probe.md).

| Control | Representation and purpose |
|---|---|
| `cbpf_run`, compiled into the guest | Software integer identities implement the same ownership policy; this remains the reference control. |
| `cbpf_gate_run`, ordinary host build | Private cells and ordinary pointer aliases check the gate algorithm without capability claims. |
| `cbpf_gate_run`, purecap guest build | Exact-bounds cell handles and tag-based consumption exercise the CHERI representation. |
| Separate direct-object baseline | The object remains allocated; direct A authority still reads 42 after release of that acquisition. This control intentionally lacks acquisition-state mediation. |

All controls use value 42 and baseline reference count one. No hardware
superiority, timing advantage or isolation equivalence follows from them.

## Implementation and supported programs

[`gate.c`](../../src/gate.c) supplies small acquisition, read, release and cleanup
functions behind trusted instruction dispatch. It calls the existing structural
validator before any provider effect. There is no recognition of program names
or complete fixture bodies. It accepts the same eight operations, forward
branches and fixed bounds as the reference machine.

In purecap, each public view has exact cell bounds and exactly `LOAD|GLOBAL`
permissions. Bounds, tag, cursor and permissions are checked before publication.
The views have no capability-load, store or execute permission. Trusted table
membership resolves them to private cell authority, and only scalar field
values leave a read gate. Copies and spills retain complete cell capabilities.
Consumption clears the private cell's stored object-capability tag before the
modeled provider decrement. B has a distinct cell even when it shares A's object.

The [mediation argument](../../theory/gate-mediation.md) explains the IR boundary,
terminal semantics, non-escape assumptions, and invocation lifetime. It also
states the limitations of source-level reasoning about compiled C.

## Observed cases and evidence

The corpus has ten families, each generated for all 24 distinct register-role
permutations and both spill slots: valid A/B use, stale copied and spilled A
after B succeeds, repeated release, NULL acquisition with a forward branch,
branching on a consumed non-NULL token, overwritten aliases, exhaustion, NULL
read and NULL release. Thirteen malformed-input controls and one maximum-length
case bring the total to 494. The latter fills all 66 event slots and returns the
minimum signed 64-bit value.

The host gate also matched the independent Python model on **161,389 generated
executions** using the previously documented [bounded comparison](conformance.md).
That larger comparison is host-only; it was not run in QEMU.

The retained [gate evidence](../../evidence/current/gate/manifest.json) includes
the raw guest console, summary, source/tool/binary hashes, tool versions,
optimized gate assembly, ELF metadata, a source-to-effect trace, and host
comparison output. These files have their own integrity manifest and leave
the original experimental conclusions intact. Public records are redacted
copies; original snapshots are retained privately.

In the retained native trace, acquisition 1 is released at PC 4, acquisition 2
reads successfully at PC 5, and the spilled alias of acquisition 1 traps at PC
7. Cleanup consumes acquisition 2 and restores reference count one. PC 8's
explicit release and PC 9's return do not execute.

Observed native representation sizes are **16 bytes per cell and per handle**:
two cells, four register aliases and two spill aliases, plus two private
canonical views and ordinary runtime/accounting state. The ELF symbol size for
`cbpf_gate_run` is **1,616 bytes**; it excludes the shared validator, C runtime,
reference implementation and test harness. The complete static test binary's
reported text/data/BSS sizes are 45,822/3,240/2,112 bytes. These are toolchain-
specific code/data measurements, not performance results.

The retained optimized assembly contains the bounds/permission operations and
tag tests. In both explicit-release and cleanup paths, the `clrtag` result is
stored to the private cell before the reference decrement. This inspection is
supporting evidence for the declared ordering, not a whole-binary proof.

## Relationship to the kernel studies

The historical fixed-profile prototype path recognizes fixed instruction profiles. The
[ordinary Linux binding](kfunc-integration.md) supplies kfunc admission on a
pristine pinned kernel. The separate [protected ownership execution and boundary controls implementation](../../linux/ownership/README.md)
adds the bounded protected A/B path, private capability state and checked
operations. Its NULL, failure, cleanup and alternate-arrangement controls
retain their own kernel evidence.

This user-mode gate supplies a semantics and regression baseline. It is not
a substitute for the kernel path or a named-CVE mitigation demonstration.
