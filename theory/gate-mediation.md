# Mediation in the cBPF trusted interpreter

This argument concerns `src/gate.c` interpreting the validated cBPF instruction
language. It is a source-level argument under a trusted C implementation and
compiler. It is not a proof about Linux eBPF machine code, a JIT, arbitrary
native callers, or capability compartments.

## Boundary and representation

The entry point accepts only an immutable instruction array and its length.
It validates every instruction before acquisition or object effects, including
unreachable instructions. The resource bounds remain two successful
acquisitions, four reference registers, two spills, and 64 instructions.
Registers and spills contain cell pointers; in a purecap build they are
capabilities. Each invocation owns its private cell arena and one still-live
object with value 42 and baseline reference count one.

Each successful acquisition creates a fresh cell view. In the purecap build,
its bounds cover exactly that cell and its permissions are exactly data load
and global use. A source capability lacking either required permission is
rejected; permissions are never added. It has no store, capability-load, or execute
permission. The runtime checks the representation before publishing the
handle or recording an acquisition effect. This permission choice differs
from the earlier architecture probe, which retains capability-load permission.
See the [Morello permission description](https://www.morello-project.org/resources/morello-linux-morelloie/)
and the pinned `cheriintrin.h` hash in the native run's input manifest.

Writable cell authority and the object capability stay inside trusted code.
The gate resolves a handle against the invocation's private cell table, then
uses private cell authority. It never loads an object capability through the
restricted public handle. Its read operation returns only an integer value.
Diagnostic output records acquisition numbers and counts, not capabilities.

## Operation correspondence

| IR operation | Representation and mediation obligation |
|---|---|
| Successful acquire | Prepare a fresh cell/view within the fixed budget, then add exactly one reference. A representation failure creates no new provider effect. |
| NULL acquire | Write a NULL handle without allocating a cell or changing the reference count. |
| Copy, spill, reload | Copy the complete cell handle; retain the acquisition identity. |
| NULL branch | Inspect the handle's NULL value, not cell liveness. A consumed acquisition remains non-NULL. |
| Read | Resolve the invocation-local handle and check the private cell's object capability tag, then load one scalar field through live object authority. |
| Release | Resolve and check the same cell, clear its stored object capability's tag, then perform the modeled decrement exactly once. |
| Return or trap | Stop instruction dispatch and consume all remaining live cells through trusted cleanup, recording cleanup separately. |

The host fallback uses ordinary cell pointers and clears the stored object
pointer to NULL. It is a software gate control and supplies no hardware
protection. The original integer-token `cbpf_run` remains a separate software
reference implementation, including when compiled into the purecap guest.

## Why the supported language mediates every use

Only acquire creates non-NULL handles; copying operations preserve them.
Instructions contain bounded register/slot operands and scalar immediates,
not arbitrary addresses. The only operations that use object authority are
the fixed read and release gates. The instruction language contains no
operation to return a handle, load a cell's object pointer, perform pointer
arithmetic, or export authority to a map, callback, or later invocation.

Validated branch destinations identify complete IR instructions. Execution is
a trusted interpreter dispatch, so an IR branch cannot enter partway through
a C gate. This statement depends on that interpreter boundary; it supplies no
control-flow-integrity result for attacker-controlled native instructions.

All aliases of A resolve the same private cell. Clearing the tag stored in
that cell makes later supported reads and releases reject A. A separate B
cell retains its own tagged copy of the same object's authority, so B remains
usable. The cell is never reissued during the invocation. This is acquisition
consumption, not deallocation of the object or global revocation of every
capability to its allocation.

The tag test causes a semantic terminal trap before the invalid operation's
object effect; it does not intentionally dereference an invalid capability.
Cleanup can still consume other live acquisitions. The existing architecture
probe's actual `SIGSEGV` observations remain separate evidence.

## Invocation lifetime and remaining assumptions

Return and trap clean up live cells before the private arena leaves scope.
Only scalar results and trace records leave the entry point. Under the
supported IR and synchronous, non-reentrant execution, no program alias can
survive to a later invocation. This does not establish stack scrubbing or
revoke capabilities obtained by arbitrary native code outside that boundary.

The trusted base includes structural validation, dispatch and gates, event
accounting, C/compiler correctness, stack/object construction, the provider
model, the CHERI ABI/runtime, and the emulator. The caller must supply valid,
non-overlapping C buffers and must not mutate the program concurrently.
Capability bounds and permissions constrain the constructed handles; they do
not isolate the whole trusted interpreter from arbitrary native C.

The native tests can establish observations of the implemented representation
and compare them with the software reference. They cannot discharge these
assumptions or establish the Linux ownership claim by themselves. The separate
[protected ownership execution and boundary controls kernel path](../linux/ownership/README.md) now supplies bounded admission,
kfunc/provider binding, native mediation and cleanup observations. Its
[kernel/model mapping](kernel-ownership.md) identifies the correspondence and
remaining premises; a general C/JIT/native refinement is still unproved.
