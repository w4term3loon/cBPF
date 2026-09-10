#!/usr/bin/env python3
"""Two CVE-derived ownership effect controls; no BPF or callback execution."""

from pathlib import Path
import hashlib
import json

from check_model import State, transitions
from check_conformance import Host, Replay, append_edge, require_match


ROOT = Path(__file__).resolve().parents[1]
CASES = (
    ("duplicate_release_projection", (
        ("acquire", (0,)), ("spill", (0, 0)), ("reload", (1, 0)),
        ("release", (1,)), ("reload", (1, 0)), ("release", (1,)),
    ), "stale_release", (1,), 0),
    ("independent_acquisition_control", (
        ("acquire", (0,)), ("acquire", (1,)), ("release", (0,)),
        ("read", (1,)), ("release", (1,)), ("finish", ()),
    ), "return", (1, 1), 1),
)


def identity(path):
    data = path.read_bytes()
    return {"file": str(path.relative_to(ROOT)), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def main():
    libraries = [ROOT / "build/cbpf-conformance.so",
                 ROOT / "build/cbpf-gate-conformance.so"]
    hosts = [Host(path) for path in libraries]
    if [h.info["implementation"] for h in hosts] != [0, 1]:
        raise RuntimeError("Expected separate host interpreter and host gate")
    ids = hosts[0].info
    if any(h.info[k] != v for h in hosts for k, v in ids.items()
           if k != "implementation"):
        raise RuntimeError("Host instruction/observation schemas differ")
    results = []
    for name, operations, terminal, explicit, reads in CASES:
        run = Replay(State((), (0,) * ids["registers"],
                           (0,) * ids["spills"], (), ()))
        steps = []
        for kind, args in operations:
            edges = [e for e in transitions(run.state, ids["acquisitions"])
                     if (e.kind, e.args) == (kind, args)]
            if len(edges) != 1:
                raise RuntimeError(f"{name}: missing/ambiguous active transition")
            run = append_edge(run, edges[0], ids, scalar=42)
            steps.append({"operation": kind, "args": args,
                          "result": edges[0].result,
                          "explicit": run.state.explicit,
                          "live": run.state.live,
                          "refs": run.state.refcount})
        state = run.state
        if (state.terminal != terminal or state.explicit != explicit or
                any(state.cleanup) or state.refcount != 1 or run.reads != reads):
            raise RuntimeError(f"{name}: decisive outcome differs")
        if list(transitions(state, ids["acquisitions"])):
            raise RuntimeError(f"{name}: terminal model continued")
        # The C IR requires a final return. After a trap it must be unreachable.
        code = run.code if terminal == "return" else run.code + (
            (ids["finish"], 0, 0, -17),)
        for host in hosts:
            require_match(host, code, run, name)
        results.append({"case": name, "status": "PASS", "steps": steps,
                        "terminal": terminal, "reads": reads,
                        "explicit_releases": sum(explicit),
                        "cleanup_releases": sum(state.cleanup),
                        "final_refs": state.refcount,
                        "model_host_matches": 2})
    sources = ("theory/check_ownership_cve.py", "theory/check_model.py",
               "theory/check_conformance.py", "src/cbpf.c", "src/cbpf.h",
               "src/gate.c", "src/gate.h", "tools/conformance_bridge.c")
    print(json.dumps({
        "study": "ownership CVE case", "cve": "CVE-2022-50650", "status": "PASS",
        "scope": "Duplicate-release effect projection and independent acquisition control",
        "cases": results, "model_host_comparisons": 4,
        "sources": [identity(ROOT / p) for p in sources],
        "host_libraries": [identity(p) for p in libraries],
        "limits": [
            "These are current Python-model/host-C controls, not native CHERI or BPF.",
            "No callback, vulnerable kernel, verifier bypass, or CVE trigger executes.",
            "The projection preserves one acquisition identity in one invocation.",
            "Upstream forbids a callback's first release of a caller-owned reference; "
            "CBPF permits the first consume and rejects the second.",
            "The independent A/B control is not a requirement of this CVE trigger.",
            "No claim for the separate acquisition-leak arm or heap reclamation.",
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
