#!/usr/bin/env python3
"""Replay finite-model edges in host C; bounded observations, not a refinement proof."""

from __future__ import annotations

import argparse
from collections import Counter, deque
import ctypes
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import platform

from check_model import Edge, State, edge_error, state_error, terminate, transitions


INFO_NAMES = (
    "registers", "spills", "acquisitions", "max_insns", "max_events",
    "acquire", "copy", "spill", "reload", "read", "release", "br_null", "finish",
    "returned", "trapped", "invalid", "none", "null", "stale", "exhaustion",
    "step", "trap", "cleanup", "implementation",
)


class Host:
    def __init__(self, path: Path):
        self.lib = ctypes.CDLL(str(path.resolve()))
        pointer = ctypes.POINTER(ctypes.c_int64)
        self.lib.cbpf_conformance_info.argtypes = [pointer, ctypes.c_size_t]
        self.lib.cbpf_conformance_info.restype = ctypes.c_size_t
        info = (ctypes.c_int64 * len(INFO_NAMES))()
        if self.lib.cbpf_conformance_info(info, len(info)) != len(info):
            raise RuntimeError("C adapter metadata does not match the observer schema")
        self.info = dict(zip(INFO_NAMES, info))
        self.lib.cbpf_conformance_run.argtypes = [pointer, ctypes.c_size_t,
                                                pointer, ctypes.c_size_t]
        self.lib.cbpf_conformance_run.restype = ctypes.c_size_t
        self.input = (ctypes.c_int64 * (4 * self.info["max_insns"]))()
        self.output = (ctypes.c_int64 * (11 + 2 * self.info["acquisitions"]
                                       + 5 * self.info["max_events"]))()

    def observe(self, code: tuple) -> tuple[int, ...]:
        if len(code) > self.info["max_insns"]:
            raise RuntimeError("generated program exceeds the C instruction bound")
        for pc, insn in enumerate(code):
            self.input[4 * pc:4 * pc + 4] = insn
        count = self.lib.cbpf_conformance_run(self.input, len(code), self.output,
                                             len(self.output))
        if not count or count > len(self.output):
            raise RuntimeError("C adapter rejected the observation request")
        return tuple(self.output[:count])


@dataclass(frozen=True)
class Replay:
    state: State
    code: tuple = ()
    events: tuple = ()
    reads: int = 0
    scalar: int = 0


def finish(state: State) -> Edge:
    return Edge("finish", (), "return", terminate(state, "return"))


def append_edge(run: Replay, edge: Edge, ids: dict, scalar: int = 0) -> Replay:
    """Translate an independently constructed model edge, including terminal cleanup."""
    before, after = run.state, edge.target
    error = state_error(after, ids["acquisitions"]) or edge_error(
        before, edge, ids["acquisitions"])
    if error:
        raise RuntimeError(f"invalid oracle edge {edge.label()}: {error}")
    kind, args, pc = edge.kind, edge.args, len(run.code)
    op = ids["acquire" if kind == "acquire_null" else kind]
    dst, src, imm, token = (args + (0, 0))[:2] + (0, 0)
    if kind == "acquire":
        imm = 1
        token = len(after.live) if not after.terminal else 0
    elif kind in ("copy", "reload"):
        token = after.registers[dst]
    elif kind == "spill":
        token = after.spills[dst]
    elif kind in ("read", "release"):
        token = before.registers[dst]
    elif kind == "finish":
        imm = scalar
    trapped = bool(after.terminal and after.terminal != "return")
    refs = before.refcount if after.terminal else after.refcount
    events = run.events + ((ids["trap" if trapped else "step"], op, pc, token, refs),)
    if after.terminal:
        for i, live in enumerate(before.live):
            if live:
                refs -= 1
                events += ((ids["cleanup"], ids["release"], pc, i + 1, refs),)
    return Replay(after, run.code + ((op, dst, src, imm),), events,
                  run.reads + int(kind == "read" and edge.result == "42"),
                  scalar if kind == "finish" else 0)


def expected(run: Replay, ids: dict) -> tuple[int, ...]:
    state = run.state
    if not state.terminal:
        raise RuntimeError("an observation needs a terminal model state")
    status = ids["returned" if state.terminal == "return" else "trapped"]
    trap = ids["none" if state.terminal == "return" else state.terminal.split("_")[0]]
    # Cleanup records carry the same PC as the return/trap that caused them.
    pc = run.events[-1][2]
    padding = (0,) * (ids["acquisitions"] - len(state.live))
    header = (status, trap, pc, run.scalar, len(state.live), run.reads,
              sum(state.explicit), sum(state.cleanup), 42 if run.reads else 0,
              state.refcount) + state.explicit + padding + state.cleanup + padding
    return header + (len(run.events),) + tuple(x for event in run.events for x in event)


def require_match(host: Host, code: tuple, run: Replay, label: str) -> None:
    actual, wanted = host.observe(code), expected(run, host.info)
    if actual != wanted:
        raise RuntimeError(json.dumps({"case": label, "program": code,
                                       "expected": wanted, "actual": actual}, indent=2))


def branch_case(host: Host, run: Replay, register: int) -> str:
    ids, pc = host.info, len(run.code)
    token = run.state.registers[register]
    # Separate scalar exits make the branch direction observable. Consumed
    # tokens remain non-NULL: BR_NULL is not an ownership/liveness check.
    branch = (ids["br_null"], register, 0, pc + 2)
    code = run.code + (branch, (ids["finish"], 0, 0, -17),
                      (ids["finish"], 0, 0, 23))
    taken = token == 0
    prefix = code[:pc + (2 if taken else 1)]
    branched = Replay(run.state, prefix,
                      run.events + ((ids["step"], ids["br_null"], pc,
                                     token, run.state.refcount),), run.reads)
    completed = append_edge(branched, finish(run.state), ids, 23 if taken else -17)
    require_match(host, code, completed, f"br_null r{register}")
    return "null" if taken else "live" if run.state.live[token - 1] else "consumed"


def check(host: Host) -> dict:
    ids = host.info
    if (ids["registers"], ids["spills"], ids["acquisitions"]) != (4, 2, 2):
        raise RuntimeError("this evidence run requires the documented K=2, R=4, S=2 bounds")
    initial = State((), (0,) * ids["registers"], (0,) * ids["spills"], (), ())
    queue = deque([Replay(initial)])
    seen = {initial}
    active_states, terminal_states, edge_count, max_length = 0, set(), 0, 0
    branches, observations = Counter(), Counter()
    while queue:
        run = queue.popleft()
        active_states += 1
        for edge in transitions(run.state, ids["acquisitions"]):
            successor = append_edge(run, edge, ids, scalar=7)
            completed = successor if successor.state.terminal else append_edge(
                successor, finish(successor.state), ids, scalar=7)
            # A final scalar return also follows a trap, but must never execute.
            code = completed.code
            if completed.state.terminal != "return":
                code += ((ids["finish"], 0, 0, 99),)
            require_match(host, code, completed, edge.label())
            edge_count += 1
            observations[completed.state.terminal] += 1
            max_length = max(max_length, len(code))
            if successor.state.terminal:
                terminal_states.add(successor.state)
            elif successor.state not in seen:
                seen.add(successor.state)
                queue.append(successor)
        for register in range(ids["registers"]):
            branches[branch_case(host, run, register)] += 1
            max_length = max(max_length, len(run.code) + 3)
    scalar_controls = (-(1 << 63), -1, 0, (1 << 63) - 1)
    for scalar in scalar_controls:
        completed = append_edge(Replay(initial), finish(initial), ids, scalar)
        require_match(host, completed.code, completed, f"scalar return {scalar}")
    return {"matched": True, "active_states": active_states,
            "reachable_states": len(seen) + len(terminal_states),
            "terminal_states": len(terminal_states), "model_edges": edge_count,
            "branch_cases": dict(sorted(branches.items())),
            "scalar_boundary_cases": len(scalar_controls),
            "programs_compared": edge_count + sum(branches.values()) + len(scalar_controls),
            "maximum_generated_instructions": max_length,
            "terminal_outcomes": dict(sorted(observations.items()))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, default=Path("build/cbpf-conformance.so"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    host = Host(args.library)
    implementation = {0: "reference", 1: "gate"}.get(host.info["implementation"])
    if implementation is None:
        raise RuntimeError("unknown C implementation in adapter metadata")
    sources = ("src/cbpf.c", "src/cbpf.h", "tools/conformance_bridge.c",
               "theory/check_model.py", "theory/check_conformance.py")
    if implementation == "gate":
        sources += ("src/gate.c", "src/gate.h")
    result = {"scope": "bounded host-C observations against finite ownership semantics",
              "implementation": implementation,
              "bounds": {key: host.info[key] for key in INFO_NAMES[:5]},
              "check": check(host),
              "environment": {"python": platform.python_version(),
                              "machine": platform.machine()},
              "source_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                                for name in sources},
              "library_sha256": hashlib.sha256(args.library.read_bytes()).hexdigest(),
              "limitations": ["One shortest history per reachable abstract active state; "
                              "not every program or concrete C state.",
                              "No C/native refinement proof or hardware isolation result.",
                              "No kernel, eBPF/JIT, CHERI, or external-system execution."]}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
