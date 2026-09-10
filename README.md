# cBPF

**Preserving eBPF interface grants through capability-aware native execution.**

cBPF is a defensive research proof of concept with two separate studies. A map lookup grants one value's logical bytes. An owning acquisition creates one consumable right, even when another acquisition refers to the same live object. The studies investigate how to represent these rights, preserve them across the native interface and check them at selected effects using CHERI/Morello capabilities and protected state.

## Start here

1. [Research overview](docs/overview.md): what was done, why, and what the results establish.
2. [Claim and evidence map](docs/research/claim-evidence.md): observed results, conditional arguments and remaining assumptions.
3. [Documentation map](docs/README.md): research, results, reproduction and implementation.
4. [Presentation](docs/presentation/index.html#title): the existing 27-slide hardware and research walkthrough ([guide and sources](docs/presentation/README.md)).

The public documentation records the research arguments, implementation, observations and limitations. [Related work and attribution](docs/research/related-work.md) distinguish inherited mechanisms, project contributions and assistance.

[Earlier findings](docs/results/earlier-findings.md) preserve the broader prototype's results and supporting records separately from the two maintained studies.

## Browse locally

Run `make docs-serve` to start the documentation server. `make help` lists common targets.

```sh
make docs-serve
```

Open [cBPF documentation](http://127.0.0.1:8767/). The site includes search, section navigation, linked references, figures, source files and evidence. Run `make docs` after editing Markdown. The server binds only to this computer; stop it with Ctrl+C.

The builder uses Git's public file list in the working repository, or `SOURCE-MANIFEST.json` in a delivered source selection without Git history. It needs Python 3.10+ and `markdown-it-py`. If necessary, use an isolated environment:

```sh
python3 -m venv build/docs-env
build/docs-env/bin/pip install -r tools/docs/requirements.txt
make docs-serve PYTHON=build/docs-env/bin/python
```

## Repository map

| Directory | Purpose |
|---|---|
| `docs/` | Topic guides, findings, reproduction |
| `theory/` | Conditional arguments and finite-model checks |
| `src/` | Portable ownership model and trusted gate |
| `linux/` | Spatial and ownership kernel mechanisms; ordinary kfunc integration |
| `evidence/` | Publication evidence with original and public-copy identities |
| `tools/` | Existing checks, build/run procedures and Markdown site builder |
| `output/` | Native dependencies and historical replay inputs |
| `build/`, `tmp/` | Ignored working material; not documentation or publication sources |

The [delivery catalogue](output/README.md) identifies the native dependencies and retained replay sources.

## Verify locally

```sh
make check
make ownership-case
```

These existing checks exercise the host model and verify publication evidence; they execute no kernel or BPF. Native procedures and dependencies are separate in the [reproduction guide](docs/reproduction/README.md).

The research does not establish general verifier replacement, heap reclamation, composition of the two profiles or whole-CVE mitigation. Historical CVE-stage evidence retains its original scope. Current kernel controls retain the normal verifier and use an offline guest. [Claim boundaries](docs/research/claim-evidence.md) and [publication provenance](evidence/README.md) explain these distinctions.

File-level license and copyright notices are retained. The [GPL version 2 text](LICENSES/GPL-2.0.txt) accompanies sources carrying that license; it does not assign a blanket license to the repository.
The retained guest executable also includes musl and LLVM compiler-runtime code; their [musl copyright](LICENSES/musl-COPYRIGHT.txt) and [LLVM license](LICENSES/llvm-LICENSE.txt) notices are included. These upstream notices do not establish the exact fork revisions used by the recorded build.
