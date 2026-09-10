# cBPF CHERI architecture probe

The optional [purecap C probe](../../src/cheri_demo.c) supplies a small architectural observation alongside the portable reference machine. It is not Linux eBPF bytecode, a JIT, a kfunc implementation, or a sandbox for arbitrary native code.

## Observed result

On 6 September 2026, the probe completed under Morello QEMU with a retained Morello Linux kernel:

```text
distinct acquisition cells, same live object
valid A and B reads: 42
consume A: one simulated provider effect; repeated consume: no effect
surviving B and direct object capability: 42
stale copied alias: SIGSEGV, SEGV_CAPTAGERR (10)
stale spilled alias: SIGSEGV, SEGV_CAPTAGERR (10)
final reference count: baseline 1; total release effects: 2
```

Release clears the tag in A's cell while retaining the original nonzero object cursor. A later capability load through either alias obtains that untagged object capability, and dereferencing it produces the reported tag fault. This distinguishes the observation from an ordinary NULL-pointer fault. The still-valid direct capability is an intentional control.

Each fault runs in its own child process, whose signal handler reports the fault and exits. The parent observes the outcome and runs a separate case; the faulting child never resumes its instruction stream. The labels “copy” and “spill” describe C aliases; they do not establish a particular physical register assignment or the eBPF spill ABI.

The test manager has writable cell authority, initially gives out bounded read-only cell views, and performs the simulated provider effects. The entire C program remains trusted and retains direct object authority. No claim of non-escape, per-compartment isolation, or protection against arbitrary native C follows. Unlike the host model's terminal rejection, the manager's repeated-consume function returns failure without another effect. These are separately scoped demonstrations, not a refinement proof.

## Reproduction

```sh
make cheri
```

The script compiles a static purecap binary, creates a fresh tiny initramfs under `build/`, boots with one vCPU and networking disabled, and requires explicit poweroff and the expected signal outcomes. Each run has a 60-second timeout. It neither downloads tools nor rebuilds/modifies the retained kernel.

The compiler and emulator were selectively extracted from a retained builder archive into an external cache selected by `CBPF_NATIVE_ROOT`. They are dependencies, not cBPF source or committed artifacts. The selected tool versions are Morello Clang 17 at `7956a8d20652883f845a41094645174eb92d1960` and QEMU 7.0.0.

`CBPF_NATIVE_ROOT` can override the cache directory. It must contain:

```text
opt/cheri/output/morello-sdk/bin/{clang,ld.lld} and their targets
opt/cheri/output/morello-sdk/lib/clang/17/include/
opt/cheri/output/sdk/bin/qemu-system-morello
opt/cheri/output/sdk/share/qemu/edk2-aarch64-code.fd
musl-sysroot/{include,lib}/
libclang_rt.builtins-aarch64.a
```

`CBPF_KERNEL` can override the retained kernel Image. Its default is recorded directly in `tools/run_cheri.sh`. The dependency sources remain in the earlier provider-evidence `packages/` directory: the builder Docker archive, purecap musl sysroot archive, compiler builtins, and `exact/Image`. No Docker daemon is needed for the current cached run. Fresh-machine runtime provisioning is not automated by cBPF.

The runner retains source, compiler, linker, emulator, firmware, runtime-library, kernel, binary and initramfs hashes with each log. Generated run directories are under ignored `build/`; the retained log, summary and hashes are in `evidence/current/`.

This probe supplies architectural evidence for private-cell invalidation.
The separate [protected ownership kernel study](../../linux/ownership/README.md)
connects the acquisition discipline to a bounded native eBPF path; neither
result enlarges the scope of the other.

The subsequent [native gate interpreter](native-gate.md) uses
`make cheri-gate` through the same runner with an explicit `gate` mode.
The default `make cheri` still runs this original architecture probe. The
gate rejects invalid uses semantically and performs cleanup; it does not
replace or relabel this probe's hardware-fault observations.
