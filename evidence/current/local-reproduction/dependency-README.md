# Local reproduction pinned dependencies

This is a [publication copy](../../README.md) of historical restoration notes.
The dependency assets remain external; this repository publishes their identities.

Local handoff, 6 September 2026. These assets support the existing benign provider/ownership
recipes. They are kept outside CBPF to avoid importing a kernel or toolchain
into the thesis mechanism. This is a reproducibility package, not a new SDK.

- `linux-source.pack`: 87,448 selected Git objects, including complete source
  trees for Morello Linux commit `b96da308ef1a054c3c04c9445e5ed70259b7c397`
  (tree `0fc9d44a60944f77000cc125779c6207a37fa74d`) and the inherited spatial
  tree `e6c69574c16bc2b9bce06329f9ac3f4b3269e79a`. It contains the commit
  object required by the recipe but deliberately omits parent history.
  This is a build object store, not a complete historical Git clone.
- `native-runtime.tar.gz`: the existing Morello compiler/linker, QEMU and
  firmware, musl sysroot, compiler builtins, and pahole runtime. Restored
  files and symlinks are listed in `runtime-files.json`; all 461 match their
  existing local inputs. The unrelated compile-smoke executable is omitted.
- `builder.docker.tar`: the exact cached image used by the recipes,
  `sha256:b4de3680a00e3ac68ccc56bd87131b97c1fffcd5e016c2d1a54d7e3386d9fc6e`.
  The inspected image ID identifies its OCI manifest; the distinct config
  digest is `c94781e9984326cf9db883cd0b14c7b97cff894501cb7d437ef66bc77adb58c7`.
  The index, manifest, config, and all layer blobs were verified separately.
- `host-requirements.txt`: observed Ubuntu 24.04.4 host tools and dynamic
  library dependencies of the compiler/linker/QEMU. These host libraries are
  prerequisites, not bundled in the runtime archive; other hosts remain
  untested.
- `manifest.json` and `SHA256SUMS`: identities of the portable assets.
  Expanded `linux-source.git/` and `runtime/` are convenience restorations.

The source trees retain Linux `COPYING`, `LICENSES/`, and individual notices;
the CBPF kernel additions retain their GPL-2.0-only identifiers. Dependency
archives keep their existing contents and ownership. No upstream license is
replaced by CBPF, and this local handoff grants no new redistribution rights.
The image includes its existing distribution/package notices. Source provenance
and compiler versions are also retained in the CBPF build/run receipts.

Restore the portable assets into a new directory (after verifying SHA256SUMS):

```sh
git init --bare linux-source.git
git --git-dir=linux-source.git index-pack --stdin < linux-source.pack
printf '%s\n' b96da308ef1a054c3c04c9445e5ed70259b7c397 > linux-source.git/HEAD
git --git-dir=linux-source.git update-ref refs/tags/cbpf-spatial-tree e6c69574c16bc2b9bce06329f9ac3f4b3269e79a
mkdir runtime
tar -xzf native-runtime.tar.gz -C runtime
docker image load -i builder.docker.tar
docker image inspect --format '{{.Id}}' sha256:b4de3680a00e3ac68ccc56bd87131b97c1fffcd5e016c2d1a54d7e3386d9fc6e
```

The tested Docker version is 29.8.0 with the containerd image store
(`overlayfs`, `io.containerd.snapshotter.v1`). It resolves the recipe
image ID as the OCI manifest digest. Other Docker storage/version behavior
is not established; verify that exact ID after loading before reproduction.

The pahole wrapper uses `/opt/gate4-pahole` inside the builder container.
The existing ownership recipe supplies that read-only mount automatically.
The restored wrapper reports v1.25 in that container; direct host invocation
is not its supported entry point.

There is no configured Git remote and no network retrieval is needed by the
recipes. Missing-parent reports from history traversal are expected; compare
`ls-tree` and use the recipe's full content/mode verification for the two pins.
Neither fetching omitted history nor executing historical exploit material is
part of reproduction. See CBPF `docs/reproduction.md` for the bounded commands.
