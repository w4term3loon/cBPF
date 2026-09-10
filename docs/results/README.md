# Results and supporting observations

The two core findings concern different units of authority. Their evidence is separate; they do not establish a composed runtime.

| Question | Main account | Supporting detail |
|---|---|---|
| Does logical value size selectively determine native access? | [Selective spatial enforcement](spatial-selectivity.md) | [Seven-byte construction](logical-extent.md), [pre-execution admission procedure](spatial-native-scope.md) |
| Does stale ownership rejection terminate and clean up? | [Synthetic native containment trace](ownership-native-trace.md) | [Ownership runtime](../../linux/ownership/README.md), [kernel/model mapping](../../theory/kernel-ownership.md) |
| What does the CVE evidence establish? | [Causal analysis](causal-review.md), [ownership CVE case](ownership-cve-case.md) | [Archived spatial observations](../../evidence/prior/spatial/README.md), [trusted callbacks](../../evidence/current/ownership-callback/README.md) |
| What other experiments support the account? | [Evidence survey](evidence.md) | [Host conformance](conformance.md), [CHERI probe](cheri-probe.md), [native interpreter gate](native-gate.md), [ordinary Linux kfunc binding](kfunc-integration.md) |
| What did the earlier prototype establish? | [Earlier findings](earlier-findings.md) | Historical spatial and lifetime controls, formal results, assignment limits, compatibility and cost observations |

The spatial matrix observes permitted interior accesses and bounds-fault
rejection of padding, the adjacent value and a crossing access. The ownership
matrix joins stale identity, native termination and cleanup in fixed trusted
fixtures. Both are synthetic native validations through production mechanisms;
neither executes verifier-admitted invalid eBPF. The [claim map](../research/claim-evidence.md)
states the corresponding premises and limits.
