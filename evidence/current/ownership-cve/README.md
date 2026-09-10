# Ownership CVE case

This is a [publication copy](../../README.md). Original receipt hashes remain
historical identities; the publication manifest verifies the shareable files.

7 September 2026. The [case study](../../../docs/ownership-cve-case.md)
connects the repeated-release arm of CVE-2022-50650 to CBPF's conditional
consume-once invariant. This receipt records two current model/host controls
and inspection of already-retained kernel mechanism evidence. It does not
record execution of the CVE's callback path.

| Control | Recorded result |
|---|---|
| `duplicate_release_projection` | A stored alias is reloaded for two release requests. The second traps; one explicit release, no cleanup release or read, final reference count one. |
| `independent_acquisition_control` | A and B acquire the same permanent object. After A is released, B reads 42 and is released; two explicit releases, no cleanup, final reference count one. |

Both cases match the Python model's complete observations in each existing
host C path: four comparisons. The trailing return in the rejected control
does not execute. These are software model/interpreter/gate results, with no
native CHERI, BPF, callback, or vulnerable-kernel execution.

- [Results](results.json) retain operations, outcomes and source/library hashes.
- [Source audit](source-audit.json) records primary-source identities, upstream
  policy, the unchanged repaired verifier, and ownership boundary-control identities.
- [Manifest](manifest.json) and [checksums](SHA256SUMS) retain original identities.

The prior kernel `duplicate_release` check uses the trusted production
resolver and records one decrement followed by rejection, with baseline
references unchanged. Its raw records remain in their original locations;
they have not been relabeled as a CVE execution. The separate native A/B
controls support acquisition independence. The projected case adds no kernel source changes
or new kernel runs.

From the repository root, reproduce the host controls with:

```sh
make ownership-case
python3 tools/verify_evidence.py
```

The target uses the existing C11/Make/Python dependencies and writes current
results to standard output. Hashes establish artifact identity; reproducing
the observations is a separate check. The retained result was produced by
`make -s ownership-case`. Original source hashes identify the executed implementations;
binary hashes may differ under another compiler.

The upstream repair forbids even a callback's first release of a caller-owned
reference. CBPF's narrower gate permits one consume and rejects repetition.
Callbacks remain unsupported, and the same acquisition cell must persist
through all projected events. The CVE's acquisition-leak arm, original
trigger mitigation, heap reclamation, and full callback ownership policy
remain outside this result.
