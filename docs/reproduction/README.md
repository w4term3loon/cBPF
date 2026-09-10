# Reproduction and evidence integrity

The repository supplies the maintained research sources and redacted evidence.
Recorded executions remain tied to their original source and configuration
identities. The [research overview](../overview.md) and
[claim table](../research/claim-evidence.md) distinguish the two kernel profiles,
host controls and historical observations. Complete original experimental
snapshots and archives are retained privately.

## Current sources and software controls

From the repository root, with Make, a C compiler and Python 3.10+:

```sh
make check ownership-case
make docs
```

Documentation additionally requires `markdown-it-py`; see the
[root README](../../README.md). These commands exercise the host model,
conformance controls and evidence inventory, then build the documentation.
They execute no kernel or BPF program. The finite model contains 17,828 states
and 149,205 transitions; each host variant checks 161,389 comparisons, and the
ownership-case target checks four projected controls. These counts describe
the specified checks, not arbitrary native traces. Use `make evidence` to
check publication evidence integrity alone.

The [native dependencies](native-dependencies.md) are delivered separately.
They contain toolchains and platform dependencies; use this repository for
maintained research sources and the retained evidence for original inputs. The
[eight-byte replay sources](../../output/sources/spatial-replay/README.md)
match the [native-replay receipt](../../evidence/current/native-replay/results.json).
The active spatial fixture instead uses a seven-byte value with eight-byte
stride. Rebuilding either produces new artifacts requiring their own receipts.

## What is frozen

The original implementation freeze identified 234 files by content, size and
mode; the final local reproduction edition identified 334 selected files.
Those counts and original hashes describe the experimental editions, not the
current publication tree. The [history description](../../evidence/history/README.md)
records their scope. Complete old repository archives are not public downloads.

The [local reproduction receipt](../../evidence/current/local-reproduction/README.md)
records execution of the frozen initial implementation on 6 September 2026,
on the same host and toolchain. A separate spatial native witness later
supplied one benign execution. The publication identity manifest associates
original identities with published copies. Public-copy checksums identify
redacted files; original experimental hashes identify privately retained
originals. They are not interchangeable. Historical CVE material is passive
evidence and is not executed by the software checks.

## Durable dependencies

The [native dependency bundle](native-dependencies.md) has recorded local
restoration and tool checks. A subsequent [bounded native replay](native-replay.md)
freshly built and ran both kernel profiles. The archive is excluded from Git
and the documentation site. Source alone cannot reproduce native results;
local restoration and replay do not establish external reproduction.

Restore the external dependency bundle into a location selected by
`CBPF_DEPENDENCY_ROOT`.
The [current dependency receipt](../native-dependencies.json) identifies the clean
export. The [historical inventory](../../evidence/current/local-reproduction/dependency-inventory.json)
retains the earlier private package identities. Transfer the prepared archive
with its checksum file; it contains its own README and SHA256SUMS including:

- `linux-source.pack`: the exact base commit object and both complete source
  trees, without unrelated commit history; 87,448 objects.
- `native-runtime.tar.gz`: the compiler, linker, QEMU, firmware, musl sysroot,
  builtins, and pahole runtime, with a restored-file inventory.
- `builder.docker.tar`: the new reduced Docker image, plus its file and image inventories.
The source tree and evidence are supplied separately; the dependency bundle contains no document/source edition.

Follow that directory's README to restore into a new location. The resulting
source store has no remote. The recipes prohibit lazy Git fetches and Docker
pulls and check every exported source blob and mode against the pinned tree.
The image ID records the OCI manifest; its config has a separate digest.
The dependency receipt verifies the index, manifest, config, and every layer blob.
Existing Linux and dependency notices remain in their source/image archives.

The local rehearsal host is Ubuntu 24.04.4 on x86-64; its exact tools and
compiler/QEMU dynamic-library dependencies are in `host-requirements.txt`.
Those host libraries are prerequisites, not bundled runtime components;
portability to another host remains for external reproduction.
The tested Docker is 29.8.0 with the containerd image store; confirm the
manifest image ID after archive loading. Other Docker configurations are
not established by this receipt. The host also requires Docker access,
Git, Make, Bash, a C compiler,
Python 3.10 or newer, and `bpftool` (recorded version 7.7.0/libbpf 1.7).
The recipes restrict build parallelism to four jobs. The ownership container
has a 12 GiB limit; spatial object-only compilation has a 4 GiB limit and the
full spatial kernel recipe has a 12 GiB limit. Allow sufficient
disk for two exported kernel trees and a full ownership build, in addition
to the separately retained dependencies.

## Reproduce the initial implementation from the frozen source

Exact replay of the original frozen edition requires its privately retained
source archive and recorded dependencies; the public history supplies its
description. Running the active recipes instead produces new artifacts from
the publication source and requires fresh evidence. Preserve existing build
outputs and configure the restored dependency location:

```sh
dependency_dir="${CBPF_DEPENDENCY_ROOT:?Set the restored dependency directory}"
export CBPF_OWNERSHIP_SOURCE_GIT="$dependency_dir/linux-source.git"
export CBPF_SPATIAL_SOURCE_GIT="$dependency_dir/linux-source.git"
export CBPF_OWNERSHIP_PAHOLE_RUNTIME="$dependency_dir/runtime/pahole-runtime"
export CBPF_NATIVE_ROOT="$dependency_dir/runtime/morello"
make ownership-kernel
make ownership-run
make spatial-check
make check
```

The full kernel build creates `build/ownership-callback-{source,kernel,headers,build}`.
The ownership runner creates a new `build/ownership-callback-run.*`; preserve its
raw log, native binaries, input hashes, results, and build receipts. The
spatial check creates `build/spatial-check.*` and compiles three objects only.
It does not link or boot a spatial kernel. Each command must complete before
the next dependent command; stop and retain evidence if a check fails.

Expected bounded outcomes:

| Control | Required observation |
|---|---|
| Original and alternate A/B | Both return 42; separate acquisitions, A consumed, B readable; provider refs return to one. |
| NULL second acquisition | No B identity; A explicitly released; return 7, refs one. |
| Rejected second argument | Gate rejects before provider effect; skips restricted continuation, cleans A once; return zero, refs one. |
| Three trusted resolver checks | Consumed copy/spill and duplicate release rejected before object effects; public identity remains tagged, private authority cleared. |
| Three invalid BPF loads | Normal verifier rejects; no test execution or native entry. Unexpected acceptance aborts. |
| Spatial source/object check | Reduced patch applies, inherited verifier unchanged, defensive configuration, all three requested objects compile. |
| Default checks | Existing host/model/conformance and historical/current evidence integrity checks pass. |

The ownership log accounts for 38 gate events: 12 from trusted init checks
and 26 from the four accepted programs. Program effects are six acquisitions,
five explicit releases, one cleanup, and two reads. Keep trusted checks
separate from restricted-native execution and load-only negative controls.

## Local rehearsal result

All four commands passed from the original frozen selection.
[The retained receipt](../../evidence/current/local-reproduction/reproduction/reproduction.json)
binds the exact commands, inputs, comparisons, and raw results.

All five ownership kernel outputs and all four native binaries match ownership boundary controls
byte-for-byte. The spatial check's three objects and configuration match spatial provider reduction.
Raw ownership boot logs differ in elapsed/clock values, a boot-notice ordering,
and execution addresses; these differences are preserved and classified.
The structured results and 64 decisive log rows match after removing elapsed
timestamps. This supports repeatability of the selected observations on the
same host, without proving correctness or portability.

The ownership build used its existing cached source/pahole paths; their exact
contents were restored and checked in the dependency package. The guest actually
used the restored runtime, and the spatial check used the restored source
store. The restored pahole wrapper was also checked in its required builder
mount. The image archive's OCI identity and layer contents were verified;
a fresh external Docker installation/load is still part of external review.

## Spatial native witness supplement

Spatial native witness is not part of the local reproduction source freeze. Its [result](../results/spatial-native-result.md) and
[retained package](../../evidence/current/spatial-native/README.md) bind the reduced
patch, two-site observation overlay, fresh kernel, loader, native review and
single execution. The program contains 14 BPF instructions and 392 native
bytes. Its lookup returns an exact eight-byte capability; the inspected load
and store change key 1 from 41 to 42, with computed return/readback 42.

The current fixture is the later [logical extent discriminator](../results/logical-extent.md):
seven-byte value, eight-byte stride, exact length seven, one byte-six increment
41→42 and six unchanged logical bytes. It reuses the verified replay kernel;
its executed fixture/checker identities are retained separately from the
initial eight-byte experiment. The [eight-byte replay inputs](../../output/sources/spatial-replay/README.md) retain
the exact earlier fixture/checker sources and their identities.
The active review procedure is
[spatial native scope](../results/spatial-native-scope.md).

`tools/build_spatial_native.sh` builds a fresh Image from the pinned inherited
tree, unchanged spatial provider reduction patch and observation overlay. Its container requires
12 GiB, separately from spatial provider reduction's four-GiB object check. The matching
`tools/run_spatial_native.sh` prepares the one benign guest and pauses with held
map/program descriptors before `TEST_RUN`. Execution requires successful
native preflight and complete linked-path inspection; a checker result alone
does not authorize it. The [recorded sequence](../../evidence/current/spatial-native/review/commands.md)
identifies the preflight, manual review, execution and postflight stages.
Fresh reproduction must substitute its own build/run identities and preserve
its own review record before the execution token.

Spatial native witness itself does not exercise out-of-bounds behavior. The
later [selective spatial enforcement](../results/spatial-selectivity.md) uses a
separate default-off trusted native fixture:

```sh
make spatial-selectivity-kernel
export CBPF_SPATIAL_SELECTIVITY_BUILD=/absolute/path/printed/by/the/build
make spatial-selectivity-calibration
make spatial-selectivity
```

Calibration must first prove that the narrow recovery site handles the expected
Morello bounds fault and rejects unrelated faults. The full run checks 30
exact/stride/both-slot operations and five load-only verifier controls. It
reruns no archived CVE. The spatial and ownership kernels remain separate
experiments.

## Ownership CVE case controls

Ownership CVE case's [case study](../results/ownership-cve-case.md) maps a documented repeated-release
failure onto the existing acquisition interface. Its two software controls use
the default host dependencies:

```sh
make ownership-case
make evidence
```

Expect four model/host matches: repeated stored-alias release traps after one
decrement, while the separate A/B control reads B as 42 and releases each
acquisition once. Both restore reference count one. The
[receipt](../../evidence/current/ownership-cve/README.md) binds the original execution source
identities and separately identifies prior ownership boundary controls mechanism observations. The
target executes no BPF, callback, native CHERI or vulnerable kernel. It does
not reproduce the original CVE trigger or the upstream callback ownership policy.

## Independent reproduction

Local reproduction and the spatial native witness provide internal validation
on the implementation host. External reproduction requires a separately
provisioned environment, retained commands and source identities, raw results,
and assessment of differences against the [claim table](../research/claim-evidence.md).
Byte equality strengthens identity evidence; it is not a correctness proof.

## Trusted callback witness supplement

The current `make ownership-kernel` and `make ownership-run` targets create
`build/ownership-callback-{source,kernel,headers,build}` and a fresh
`build/ownership-callback-run.*`. Original recipes and outputs retain their recorded identities in the private
archive; active recipes use publication names. Preserve prior build directories; the builder refuses to replace its
source export or receipt.

Trusted callback witness reuses the normal-verifier kernel, existing guest loader and offline
execution restrictions. Two additional init-only trusted C callback controls
must pass before kfunc registration. The runner checks persistent context and
identity, exact gate effects, immediate dispatch termination on rejection,
and the existing ownership boundary controls outcomes separately. The [trusted callback witness receipt](../../evidence/current/ownership-callback/README.md)
records build/run identities and linked callback transport inspection. Its
manifest verifies retained files without repeating a kernel experiment.

## Synthetic native ownership trace supplement

The default-off [integrated trace](../results/ownership-native-trace.md) builds
from the pinned Morello base plus the same production platform, integration,
compiler and runtime sources. It requires the restored ownership source Git
store and pahole runtime:

```sh
make ownership-trace-kernel
export CBPF_OWNERSHIP_TRACE_BUILD=/absolute/path/printed/by/the/build
make ownership-trace
```

The builder requires an unchanged verifier and limits its test overlay to
Kconfig, one header, the restricted compiler and runtime. The runner uses one
offline CPU, no network or host filesystem, and verifies all source/build
identities before boot. It checks positive, stale-read and repeated-release
native fixtures, plus three load-only verifier rejections. The fixtures are
fixed trusted native descriptions through the production path; they do not
authorize invalid BPF execution or reproduce the original callback CVE.
