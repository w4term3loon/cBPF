# Native dependency bundle

`cbpf-native-dependencies.tar.gz` contains the pinned Linux source objects,
Morello runtime, reduced builder image, required notices, inventories and
original restoration records. It is delivered separately and excluded from
Git and the documentation site. The [checksum](../../output/native-dependency-SHA256SUMS)
and [receipt](../native-dependencies.json) identify it. The current repository
supplies the research sources and evidence separately.

## Contents and identity

The Linux pack contains 87,448 objects: the base commit and both complete source
trees, without unrelated history. The 461 runtime files or symlinks and the
builder image retain the bytes identified in the restoration records.
The builder manifest is:

```text
sha256:76c8ca062c30aa59b8eb072f30620a2a7e9604515aefe84d64161bf9eb644038
```

Archive owners and timestamps are normalized. The builder contains a selected
filesystem with generated SSH keys, user homes, guest disks, caches and machine
identity files excluded. Public GnuTLS self-test keys are retained with their
upstream provenance. The package contains Linux and dependency notices and does
not relicense those components. Its privacy checks cover known identity strings,
credential indicators and selected decoded content; they are not a universal
secret-detection guarantee.

## Restore the dependencies

Use Ubuntu 24.04 on x86-64 with Git, tar, Make, a C compiler, Python 3.10+ and
Docker access. The recorded daemon is Docker 29.8.0 with the containerd image
store. Host shared libraries remain prerequisites in `host-requirements.txt`.
Allow at least 8 GB for extraction, objects/runtime and image, plus the separate
kernel build requirements in the [reproduction guide](README.md#durable-dependencies).

Put the archive and checksum file together, then restore into a new directory:

```sh
sha256sum -c native-dependency-SHA256SUMS
tar -xzf cbpf-native-dependencies.tar.gz
cd cbpf-native-dependencies
sha256sum -c SHA256SUMS

git -c init.templateDir= init --bare linux-source.git
git --git-dir=linux-source.git index-pack --stdin < linux-source.pack
printf '%s\n' b96da308ef1a054c3c04c9445e5ed70259b7c397 > linux-source.git/HEAD
git --git-dir=linux-source.git update-ref refs/tags/cbpf-spatial-tree e6c69574c16bc2b9bce06329f9ac3f4b3269e79a
mkdir runtime
tar -xzf native-runtime.tar.gz --no-same-owner -C runtime
docker image load -i builder.docker.tar
docker image inspect --format '{{.Id}}' sha256:76c8ca062c30aa59b8eb072f30620a2a7e9604515aefe84d64161bf9eb644038
export CBPF_DEPENDENCY_ROOT="$PWD"
```

The source store has no remote and omits parent history; missing-parent reports
from history traversal are expected. The build recipes prohibit lazy Git
fetches and Docker pulls, and verify the pinned source tree and modes.
From the separately supplied research source tree, `make check ownership-case`
runs the software controls. Native procedures are documented separately.

## Observations and limits

The original local restoration verified both source trees, the pack, all runtime
entries and the builder OCI/config/layer identities. Tool checks compiled a host
program, encoded BTF, compiled and linked Morello purecap ELF files, and inspected
them without execution. QEMU was invoked only for its version during that step.

The [native replay](native-replay.md) subsequently built and booted two offline
kernels for existing valid controls. The [logical extent witness](../results/logical-extent.md)
used the same spatial kernel for one seven-byte invocation. No original CVE
trigger was executed. These are separate observations with their own input hashes.

The dependency-only delivery preserves the recorded dependency bytes; its
packaging check does not rerun those experiments or establish external
reproduction. The [source delivery guide](README.md#current-sources-and-software-controls) distinguishes
current sources, retained replay inputs and original experimental identities.
