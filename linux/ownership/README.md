# Bounded protected kfunc execution

The provider is a synthetic kfunc-shaped acquire/read/release interface. Its registered BTF bodies have no provider effects; the custom native gates supply them. Existing production kfunc providers are not evaluated.

Two acquisitions can refer to the same live kernel object while granting
independently consumable rights. Releasing A must invalidate every alias of A
while leaving B usable. Object address, allocation bounds and reference count
alone cannot identify which right was consumed. cBPF represents each
acquisition with protected validity state and checks it at every admitted
read or release. The [research overview](../../docs/overview.md)
and [necessity argument](../../theory/acquisition-distinguishability.md)
explain this distinction.

The [contribution assessment](../../docs/research/related-work.md#defensible-positioning-and-present-evidence) identifies
acquisition-preserving alias transport and ordered consumption as the concrete
design obligations. The [software comparison](../../docs/research/capability-comparison.md)
shows that protected descriptors can express the same policy. CHERI protects
the capability representation; trusted software still maintains liveness.

The target is runtime enforcement of the existing
[Linux 6.7 kfunc ownership contract](https://docs.kernel.org/6.7/bpf/kfuncs.html#kf-release-flag).
The evidence contains a conditional protocol proof and bounded kernel
controls. [ownership CVE case](../../docs/results/ownership-cve-case.md) adds a conditional case for
CVE-2022-50650's repeated-release effect, with two projected model/host
controls. **The original callback/CVE path remains unexecuted.** The object remains allocated
with a permanent baseline reference; the studied property is acquisition
use-after-release protection, not heap use-after-free prevention.

Protected ownership execution connects a normal-verifier-accepted `SCHED_CLS` program to a small native
Morello compiler and private acquisition gates. The original protected ownership execution control
acquires A and B, copies and spills A, consumes A, reads B, consumes B, and
returns the scalar 42. **Protected ownership execution passed on 6 September 2026:** the kernel built, and
the first guest execution completed with two acquisitions, two releases,
B's successful read after A consumption, and baseline reference count one.
The [retained evidence](../../evidence/current/ownership/README.md) includes
the 660-byte native image, ordered gate trace, and source/assembly reviews.

**Ownership boundary controls passed on 6 September 2026:** its [closure receipt](../../evidence/current/ownership-closure/README.md)
adds an alternate native A/B arrangement, NULL and terminal-failure paths,
three trusted production-resolver checks, and three unexecuted verifier
rejections. [The kernel/model mapping](../../theory/kernel-ownership.md)
states their precise coverage and remaining premises.

## Boundary and representation

The accepted grammar is deliberately small: 64-bit immediate and register
moves, one full-width spill/reload at logical stack offset -8, forward NULL
branches, the three fixed kfunc identities, and scalar exit. The compiler
checks structure and types after ordinary Linux verification. Unsupported
instructions, maps, subprograms, function BTF metadata, or requested constant blinding cause rejection;
the compiler does not disable hardening. It never rewrites verified bytecode.
Programs have at most 64 instructions and two acquisition call sites; the
gate checks that the scalar acquisition argument is Boolean. NULL refinement must be established by the
compiler's simple forward type analysis, which is deliberately conservative.

The built-in BTF functions declare acquire/nullable, trusted-read, and release
contracts. Their public BTF structure contains an inert pointer so the verifier
does not treat it as scalar-only memory. The native compiler binds the resolved
function addresses to the three gates. BPF's logical pointer is represented
internally by a 128-bit capability, including across copies and the 16-byte
native sidecar used for the one logical 8-byte spill. This is a restricted
calling convention, not a general change to Linux's kfunc ABI.

Ordinary calls to those BTF entry bodies have no provider effects. Matching
programs must compile through the protected path. Typed attachment and
program-map insertion are rejected; entry additionally requires the private
context established by the synchronous test-run wrapper. The supplied loader
never attaches a program.

Each invocation owns two private cells outside the restricted stack. BPF gets
an exact cell view with only `LOAD | GLOBAL`: no cell write, capability load,
or object authority. Trusted gates compare the full public capability with a
canonical invocation-local view before accessing private state. Read loads
the field through the cell's object capability. Release clears its stored tag
before decrementing the provider's reference count. Both acquisitions refer
to one permanent object, whose baseline reference remains one.

## Native mediation and lifetime

The restricted entry installs an untagged RDDC, exact code bounds, an exact
16-byte stack, and a sealed gateway. It publishes no context, map, or private
arena capability. The admitted instruction templates cannot manufacture a
tagged handle, alter reserved gateway registers, access arbitrary memory, or
branch into a gate's interior. Forward targets refer to complete translated
BPF instructions. The only native memory operations in the body transfer a
full capability to/from the fixed stack sidecar.

Every emitted word is checked against the admitted templates and fixed
transition envelope before publication as a read-only executable program. This
uses the same encoder as generation; it is a consistency check, not an
independent compiler proof. Inspection of the final emitted code and linked
gateway is a separate evidence obligation.

All normal exits and terminal gate failures converge on the executive
epilogue. It clears the sidecar and native aliases before returning a scalar.
Only then does the trusted wrapper release any remaining references, clear
the arena, and restore the caller's restricted registers. Cells are never
reused during an invocation. The old fixed-profile prototype cell-allocation leaks and mutation
paths are not imported.

The [ownership argument](../../theory/ownership.md) remains conditional on
correct provider assignment from executive DDC, trusted C/assembly/compiler,
correct architectural enforcement, and synchronous non-reentrant invocation
containment. This bounded native path does not prove arbitrary verifier/JIT
fault tolerance, whole-kernel isolation, or composition with the spatial path.

## Source and reproduction

The base is official Morello Linux commit
`b96da308ef1a054c3c04c9445e5ed70259b7c397`. `platform.patch` extracts only
restricted-mode platform support from the earlier cBPF prototype tree
`e6c69574c16bc2b9bce06329f9ac3f4b3269e79a`: exception handling, restricted
register preservation, and sealed capability branches. It excludes research
configuration and verifier changes. `integration.patch` wires the new compiler,
test-run entry, and attachment restrictions into that base.

The runtime and compiler derive transition framing from the Arm/Linaro
Morello BPF RFC and the corrected earlier cBPF prototype replay. Existing copyright and
GPL-2.0-only notices are preserved. These inherited primitives support the
acquisition-validity mechanism; the ownership contract and shared invalidation
also have prior art. The [focused comparison](../../docs/research/related-work.md)
states the candidate contribution and its limits.

Trusted callback witness adds only init-only trusted C callback controls to the runtime. The
production resolver, wrapper/assembly, restricted compiler and BPF grammar
remain unchanged. One context retains canonical public capabilities across
indirect callback calls; dispatch ends on the first failure. The two controls
and their source/build/run identities are reported in the
[trusted callback witness receipt](../../evidence/current/ownership-callback/README.md). They test
callback transport and state persistence in trusted C, not protected BPF
callback support or mitigation of the original CVE path.

The existing 186-line guest loader still contains four verifier-accepted
execution controls and three load-only rejections. Trusted callback witness reuses this loader
while checking its two boot-time callback controls separately. Build and
evidence support remain separate from the enforcement mechanism.

```sh
make ownership-kernel
make ownership-run
```

These optional targets use cached dependencies and an offline build container.
The kernel configuration differs from the retained stock-kfunc configuration
only by enabling this feature and changing the release name. The ordinary
verifier source must remain unchanged. Each source export is verified against
the pinned tree before patching; generated source and receipts are preserved
between build attempts. Dependencies and their current locations follow the
[ordinary kfunc build](../../docs/results/kfunc-integration.md).

The runner prepares a fresh initramfs with one benign loader, then uses one
virtual CPU, no network or host filesystem, and a 60-second timeout. It binds
the BTF IDs to the matching kernel and retains bytecode, verifier output,
native bytes, ordered gate events, input hashes, and clean-poweroff status.
Current targets use `build/ownership-callback-*`; earlier outputs retain their recorded identities.
The portable `make check` remains separate. No CVE fixture or invalid ownership
program is executed by protected ownership execution or ownership boundary controls.

The ownership boundary controls' consumed-copy/spill and duplicate-release checks are init-only trusted
kernel C calls to the production resolver; they do not execute invalid BPF.
The scalar-2 acquisition control exercises existing pre-provider rejection
and actual terminal native cleanup. Construction/capacity failure ordering
and nonzero ordinary-return cleanup remain inspected/modelled paths; the
normal verifier forbids returning with a leaked owning reference.

Trusted executive stack saves are not explicitly erased by the gateway.
The scrub claim covers program-accessible registers and the sidecar, with
trusted-stack inaccessibility retained as a premise; it does not assert
erasure of every physical capability copy.
