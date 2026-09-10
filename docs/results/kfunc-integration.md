# cBPF ordinary Linux kfunc binding

This step binds acquisition, read, and release to real Linux kfuncs while
retaining the normal verifier. It is a Linux integration control for the
ownership contract. It does not implement the CHERI-protected consumed cells
from the [native gate](native-gate.md).

## Observed result

On 6 September 2026, run `build/kfunc-run.iheJqD` passed under the freshly built
stock Morello kernel. The [retained summary](../../evidence/current/kfunc/summary.txt)
and [boot log](../../evidence/current/kfunc/boot.log) record:

| Check | Observed result |
|---|---|
| 13 distinct valid cases | Accepted, JIT compiled, and executed through `BPF_PROG_TEST_RUN` |
| 32 additional executions of one loaded valid program | Balanced acquisition/release accounting after every execution |
| 5 invalid ownership cases | Rejected at load, with attributable verifier diagnostics and zero executions/provider effects |
| Valid execution totals | 45 executions; 82 acquisitions, 82 releases, 38 reads |
| Final state | No live acquisition allocations; shared object reference count one |

QEMU exited with status zero after clean poweroff, without a kernel warning or
Oops. Reported JIT lengths were 288 bytes for copied-alias cases, 296 bytes for
spill cases, and 160 bytes for the first-NULL case. These are fixture-specific
code sizes, not performance measurements. The matching module BTF identified
acquire/read/release as 80850/80852/80854 and represented the public handle as
16 bytes and its enclosing cell as 24 bytes. These IDs and layouts describe
this build; the runner derives IDs anew for each module build.

The 13 valid cases cover two register placements, copied aliases and two spill
offsets, two independent acquisitions, a NULL second acquisition, and a NULL
first acquisition. The repeated case reads acquisition B after releasing A.
The five rejection probes cover a consumed copied alias, a consumed spilled
alias, duplicate release, missing NULL refinement, and a leaked reference.

Only the valid-case function can call `BPF_PROG_TEST_RUN`. The rejection path
closes any unexpectedly accepted program without executing it and marks the
run failed. Negative probes are never attached or run. Successful rejection
also requires a relevant verifier diagnostic and unchanged provider counters;
an unrelated load failure does not count as ownership enforcement.

## Provider contract

The [provider](../../linux/kfunc/cbpf_kfunc.c) registers one kfunc set for
`BPF_PROG_TYPE_SCHED_CLS`, with the module as its owner:

| Kfunc | Flags | Effect |
|---|---|---|
| `cbpf_ref_acquire` | `KF_ACQUIRE \| KF_RET_NULL` | Allocate a distinct acquisition cell and increment the shared object's references; NULL has no ownership effect |
| `cbpf_ref_read` | `KF_TRUSTED_ARGS` | Read the value 42 through a live, unmodified acquisition pointer |
| `cbpf_ref_release` | `KF_RELEASE` | Decrement the object's references and free this acquisition cell |

All acquisitions refer to one statically allocated object with a permanent
baseline reference. Independently live acquisitions have distinct cells.
Releasing A consumes A's verifier identity and its aliases while B remains
usable. The underlying object remains alive throughout these tests.

The public BTF handle contains an acquisition number and an inert, reserved
pointer that is always NULL. That pointer makes the BTF structure non-scalar:
the pinned verifier's scalar-structure argument fallback must not admit
ordinary memory as an accessor argument. The reserved field carries no object
authority. The actual object pointer remains in the provider's private
enclosing cell. The acquisition number is diagnostic metadata, not a runtime
authentication mechanism.

The module publishes read-only acquisition, release, read, live-cell, and
object-reference counters. They have no setters. Individual counters are
atomic; the group is not an atomic snapshot. The runner samples them only
between synchronous executions and checks the expected deltas and restored
baseline after each valid run. Owning BPF programs pin the module. The supplied
programs do not export handles, and the normal verifier requires releases on
every return path. Module unload and arbitrary concurrent workloads are not
tested here.

## Pinned stock kernel

The build uses official Morello Linux commit
`b96da308ef1a054c3c04c9445e5ed70259b7c397`, version 6.7.0, exported from retained
Git objects into `build/kfunc-kernel-source`. No research kernel patches are
applied. Each build verifies every source blob and its type/executable mode
against that commit and rejects additional files or symlinks.

The configuration starts from stock `morello_pcuabi_defconfig`, removes
unneeded device/filesystem families, and enables ordinary BPF, JIT, module
BTF, and the proc/sysfs facilities used by the loader. The resulting release
is `6.7.0-cbpf-kfunc-stock`. Unprivileged BPF remains disabled by default.
There are no `CONFIG_CAPEBPF_*` options or BTF mismatch allowances. On this
kernel, kfunc invocation requires JIT; the runner checks a nonzero JIT image
length before executing valid cases.

The [build recipe](../../tools/build_kfunc_kernel.sh) uses the retained Morello
Clang 17 builder and pahole 1.25. Source and dependency mounts are read-only;
the build container uses the host user's UID, no network, and at most four
build jobs. The source manifest, executed recipe snapshot, configuration,
compiler and builder identities, and artifact hashes are retained in
`build/kfunc-build/`. The snapshot records the recipe that built this kernel;
the reusable recipe subsequently added Docker's `--pull=never` option.
The generated `Image`, `vmlinux`, `Module.symvers`, and UAPI headers belong to
the same build. The runner checks their recorded hashes before building the
provider. It resolves function BTF IDs from that module against its matching
`vmlinux`, then selects the loaded module's BTF descriptor in the guest.

## Reproduction on this machine

```sh
make check          # portable model and gate checks
make kfunc          # verify/build stock kernel, build provider, run local guest
```

`make kfunc-kernel` performs only the kernel/header build. A first build takes
several minutes; later invocations reuse the verified source and build output.
This optional target needs the already loaded Morello builder image, host
`bpftool`, the retained pahole runtime, and the cached compiler, linker, QEMU,
firmware, and purecap musl runtime described in [the CHERI probe](cheri-probe.md).
Fresh-machine dependency provisioning is not automated.

Set `CBPF_KFUNC_SOURCE_GIT` to the restored kernel Git store and
`CBPF_KFUNC_PAHOLE_RUNTIME` to the restored pahole directory. Both are read-only
inputs. Other settings are `CBPF_KFUNC_BUILDER`,
`CBPF_KFUNC_PAHOLE_RUNTIME`, `CBPF_KFUNC_BUILD_JOBS` (1–4), and
`CBPF_NATIVE_ROOT`. The pinned source commit is fixed by the recipe. The
runner uses the newly built stock kernel; historical research Images are not
selected by this target.

The [runner](../../tools/run_kfunc.sh) creates a fresh initramfs containing only
the [guest loader](../../linux/kfunc/guest.c), module, and required mount/device
entries. QEMU uses one vCPU, no network interface, and a 60-second timeout.
Programs are tested synchronously without attachment to a live hook. The
loader requires PID 1 and the expected kernel release before module loading
or poweroff. It uses ordinary module loading without force flags.

Each `build/kfunc-run.*` directory retains compile and module-build logs,
module BTF, generated IDs, input hashes, boot output, and a checked summary.
A reported pass requires exact expected accounting, all five load rejections,
successful poweroff, and no kernel panic, Oops, warning, or refcount diagnostic.

## Evidentiary boundary

This binding relies on the normal verifier for reference lifetime. Release
frees the acquisition allocation: stale native pointers are not made safe,
and invalid ownership programs are never executed. Allocator reuse across
completed runs therefore does not establish protection against stale aliases.

The userspace loader is purecap so that it exercises the Morello userspace
syscall ABI. This does not make the kfunc handles capability-protected or
establish CHERI enforcement inside the kernel. The runtime marker explicitly
reports `runtime_cheri=0 normal_verifier=1`.

The bounded fixtures do not establish a general subset compiler, structural
admission proof, complete native mediation, resilience to verifier failures,
or a kernel isolation theorem. The protected Linux enforcement boundary is evaluated separately. Protected ownership execution provides [the separate protected A/B path](../../linux/ownership/README.md),
and [ownership boundary controls](../../evidence/current/ownership-closure/README.md) adds its bounded closure controls.
This evidence concerns ordinary Linux kfunc binding and verifier ownership
checks, alongside separately scoped host-model, user-mode CHERI and protected
kernel results. None constitutes a demonstrated named ownership-CVE mitigation.
