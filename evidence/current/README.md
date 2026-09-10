# CBPF retained results

This index separates the model, native, kernel and
reproduction evidence. The [research overview](../../docs/research-overview.md)
explains the two contributions; the [claim table](../../docs/claim-evidence.md)
identifies the exact conclusions supported by each layer.

These are [publication copies](../README.md). Host paths are redacted;
original hashes are historical identities, while the publication manifest
verifies the shareable bytes.

| Selection | Retained result |
|---|---|
| `host-demo.txt` | Portable C reference-machine output: seven IR examples, a conceptual direct-object control and structural rejection checks. |
| `model-check.json` | Exhaustive finite-model result and the object-wide-consumption counterexample; no C/native refinement claim. |
| `host-conformance.json` | Bounded C/model comparison with coverage, source/library hashes and scope limits; see [conformance](../../docs/conformance.md). |
| `cheri-boot.log`, `cheri-summary.txt` | Purecap user-mode architecture probe with the expected consumed-alias tag faults and clean guest poweroff. |
| `cheri-inputs.sha256`, `cheri-toolchain.txt` | Architecture-probe identities and tool versions; large dependencies remain external. |
| [`gate/`](gate/manifest.json) | Native trusted-interpreter evidence, mediation trace, assembly, integrity manifest and host gate/model comparison; see [native gate](../../docs/native-gate.md). |
| [`kfunc/`](kfunc/manifest.json) | Ordinary Linux kfunc binding: 45 valid invocations and five unexecuted verifier rejections, with source/BTF/build/configuration/console identities; see [kfunc integration](../../docs/kfunc-integration.md). |
| [`spatial/`](spatial/manifest.json) | Spatial provider reduction: patch application and three compiled kernel objects; no linked Image or guest execution at this stage. |
| [`ownership/`](ownership/README.md) | Protected ownership execution: distinct A/B cells, B readable after A consumption, balanced references and native/source inspection. |
| [`ownership-closure/`](ownership-closure/README.md) | Ownership boundary controls: four accepted native executions, three trusted resolver checks and three unexecuted verifier rejections, with ordered traces and code inspection. |
| [`closure/`](local-reproduction/README.md) | Local reproduction: frozen-source identities, dependency records and same-host repetition; exact archives are privately retained. |
| [`spatial-s5/`](spatial-native/README.md) | Spatial native witness: one 14-instruction/392-native-byte program, exact eight-byte authority, valid 41→42 read/add/store, return/readback 42 and clean exit. |
| [`ownership-cve/`](ownership-cve/README.md) | Ownership CVE case: repeated-release mapping and conditional argument; two projected controls with four model/host matches. No callback or original-CVE execution. |
| [`ownership-callback/`](ownership-callback/README.md) | Trusted callback witness: two kernel C controls, persistent capability/context transport, repeated-release rejection and independent B=42. No BPF callbacks or original-CVE execution. |
| [`spatial-selectivity/`](spatial-selectivity/README.md) | Original 30-case matrix and calibration, complete linked helper and passing stronger backing-address/PC/operand checks. Original five-load and new ten-control admission runs are separate. |
| [`ownership-native-trace/`](ownership-native-trace/README.md) | Original integrated positive/stale-read/repeated-release traces and native images; later complete decoder listings, authored internal inspection and passing fixed-image/terminal-path checks. Encoder self-check, external receipt checks and inspection are distinct assurances. |

The architecture probe and native gate are user-mode CHERI observations. The
ordinary `kfunc/` binding uses normal verifier tracking and kernel pointers.
The ownership execution and boundary controls exercise the protected kernel path. Their provider
object remains allocated; consumed aliases are checked by trusted resolver
controls, while invalid BPF is rejected without execution.

The spatial native witness supplies source/native correspondence for two inspected
accesses. It performs no out-of-bounds access and does not establish general
JIT mediation. The [archived spatial selection](../prior/spatial/README.md)
separately contains neighboring-value controls and CVE-2021-3490
metadata-read-stage containment. Ownership has a named-CVE conditional case
and projected software controls; no original callback-path mitigation is observed.
The two kernels do not establish spatial/ownership composition.

The original 334-file local-reproduction edition is privately preserved;
its [historical identity](../history/m4-final-20260906.json) remains public.
Current prose incorporates later results. The [reproduction guide](../../docs/reproduction.md)
distinguishes existing observations from new runs; original edition checksums
do not verify sanitized publication copies or revised documentation.

The [contribution assessment](../../docs/novelty-assessment.md) and
[software comparison](../../docs/capability-comparison.md) are analytical
interpretations. They add no experimental receipt or measured advantage over
a protected software implementation.
The [fault-specific claim scope](../../docs/trust-taxonomy.md#quantifiers-and-fault-specific-guarantees),
[causal CVE mapping](../../docs/causal-review.md#the-two-cve-mappings-side-by-side)
and [witness adequacy](../../docs/research-overview.md#3-why-the-small-examples-answer-the-stated-question)
are also analytical responses using these existing receipts.

`make check` runs existing host/model/oracle/conformance checks and the
publication integrity checks implemented by `tools/verify_evidence.py`.
Retained `SHA256SUMS` files record original identities. `make ownership-case`
reruns only the ownership case's two model/host controls. Optional native targets create separate
run directories; their execution is distinct from inspecting retained evidence.
None of these internal checks constitutes external reproduction.
