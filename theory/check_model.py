#!/usr/bin/env python3
"""Exhaustively check a finite ownership model, not C or native-code refinement."""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass, replace
import json


@dataclass(frozen=True)
class State:
    # Token 0 is NULL; token i+1 names acquisition i, never an object address.
    live: tuple[bool, ...]
    registers: tuple[int, ...]
    spills: tuple[int, ...]
    explicit: tuple[int, ...]
    cleanup: tuple[int, ...]
    refcount: int = 1
    terminal: str = ""


@dataclass(frozen=True)
class Edge:
    kind: str
    args: tuple[int, ...]
    result: str
    target: State

    def label(self) -> str:
        operands = ",".join(str(x) for x in self.args)
        return f"{self.kind}({operands}): {self.result}"


def updated(values: tuple, index: int, value) -> tuple:
    return values[:index] + (value,) + values[index + 1:]


def terminate(state: State, reason: str) -> State:
    """Only LIVE acquisitions are dropped; aliases need not be erased by this model."""
    return replace(
        state,
        live=(False,) * len(state.live),
        cleanup=tuple(n + int(live) for n, live in zip(state.cleanup, state.live)),
        refcount=state.refcount - sum(state.live),
        terminal=reason,
    )


def transitions(state: State, capacity: int, mutation: bool = False):
    if state.terminal:
        return
    nr, ns = len(state.registers), len(state.spills)
    # Prioritizing empty registers merely makes the shortest counterexample readable.
    for r in sorted(range(nr), key=lambda i: state.registers[i] != 0):
        if len(state.live) == capacity:
            yield Edge("acquire", (r,), "exhaustion", terminate(state, "exhaustion"))
        else:
            token = len(state.live) + 1
            yield Edge("acquire", (r,), "success", replace(
                state, live=state.live + (True,),
                registers=updated(state.registers, r, token),
                explicit=state.explicit + (0,), cleanup=state.cleanup + (0,),
                refcount=state.refcount + 1,
            ))
        # A provider NULL result creates no reference or cell, including at capacity.
        yield Edge("acquire_null", (r,), "null", replace(
            state, registers=updated(state.registers, r, 0)))
    for dst in range(nr):
        for src in range(nr):
            yield Edge("copy", (dst, src), "copied", replace(
                state, registers=updated(state.registers, dst, state.registers[src])))
        for slot in range(ns):
            yield Edge("reload", (dst, slot), "copied", replace(
                state, registers=updated(state.registers, dst, state.spills[slot])))
    for slot in range(ns):
        for r in range(nr):
            yield Edge("spill", (slot, r), "copied", replace(
                state, spills=updated(state.spills, slot, state.registers[r])))
    for r, token in enumerate(state.registers):
        valid = token != 0 and state.live[token - 1]
        reason = "null" if token == 0 else "stale"
        yield Edge("read", (r,), "42" if valid else reason,
                   state if valid else terminate(state, reason + "_read"))
        if not valid:
            yield Edge("release", (r,), reason, terminate(state, reason + "_release"))
            continue
        # Mutation: object-wide consumption wrongly revokes independent acquisitions.
        victims = tuple(i for i, live in enumerate(state.live)
                        if live and (mutation or i == token - 1))
        yield Edge("release", (r,), "consumed", replace(
            state,
            live=tuple(live and i not in victims for i, live in enumerate(state.live)),
            explicit=tuple(n + int(i in victims) for i, n in enumerate(state.explicit)),
            refcount=state.refcount - len(victims),
        ))
    yield Edge("finish", (), "return", terminate(state, "return"))


def state_error(state: State, capacity: int) -> str | None:
    n = len(state.live)
    if n > capacity or len(state.explicit) != n or len(state.cleanup) != n:
        return "cell budget or metadata dimensions"
    if any(token < 0 or token > n for token in state.registers + state.spills):
        return "alias names an identity that was never acquired"
    if any(x < 0 for x in state.explicit + state.cleanup):
        return "negative provider-effect count"
    for i, live in enumerate(state.live):
        drops = state.explicit[i] + state.cleanup[i]
        if drops not in (0, 1) or live != (drops == 0):
            return f"consumption: acquisition {i + 1} has inconsistent effects/liveness"
    if state.refcount != 1 + n - sum(state.explicit) - sum(state.cleanup):
        return "provider reference-count accounting"
    if state.refcount != 1 + sum(state.live):
        return "reference count differs from the baseline plus live acquisitions"
    if state.terminal and (any(state.live) or state.refcount != 1):
        return "terminal cleanup did not restore the baseline"
    if not state.terminal and any(state.cleanup):
        return "cleanup effect in an active invocation"
    return None


def edge_error(before: State, edge: Edge, capacity: int) -> str | None:
    """Check observations/effects separately from the transition constructors."""
    after, kind = edge.target, edge.kind
    if before.terminal:
        return "terminal execution resumed"
    n = len(before.live)
    if len(after.live) < n:
        return "acquisition identities were reused or discarded"
    if kind != "acquire" and len(after.live) != n:
        return "an operation other than acquisition created an identity"
    if kind == "finish" and (after.terminal != "return" or edge.result != "return"):
        return "finish did not terminate normally"
    if after.terminal:
        if (after.registers, after.spills) != (before.registers, before.spills):
            return "terminal cleanup changed an alias identity"
        if after.explicit != before.explicit:
            return "failed operation or finish performed an explicit release"
        for i in range(n):
            if after.cleanup[i] - before.cleanup[i] != int(before.live[i]):
                return "cleanup did not consume exactly the remaining live acquisitions"
    if kind in ("read", "release"):
        if (after.registers, after.spills) != (before.registers, before.spills):
            return "read/release changed an alias identity"
        token = before.registers[edge.args[0]]
        valid = token != 0 and before.live[token - 1]
        if not valid and not after.terminal:
            return "consumed or NULL authority was used without trapping"
        if valid and after.terminal:
            return "a live acquisition was incorrectly rejected"
        if not valid:
            reason = "null" if token == 0 else "stale"
            if after.terminal != reason + "_" + kind or edge.result != reason:
                return "failed read/release reported the wrong trap reason"
        if kind == "read" and valid and (edge.result != "42" or after != before):
            return "live read changed state or returned the wrong object value"
        if kind == "release" and valid:
            if edge.result != "consumed":
                return "successful release reported the wrong result"
            target = token - 1
            for i in range(n):
                expected = int(i == target)
                if after.explicit[i] - before.explicit[i] != expected:
                    return f"alias independence: release of {token} also affects acquisition {i + 1}"
                if i != target and after.live[i] != before.live[i]:
                    return f"alias independence: acquisition {i + 1} changed with release of {token}"
            if after.live[target] or after.cleanup != before.cleanup:
                return "release failed to consume its token without cleanup"
    if kind in ("copy", "spill", "reload", "acquire_null"):
        if after.terminal:
            return "token manipulation or NULL acquisition incorrectly trapped"
        if edge.result != ("null" if kind == "acquire_null" else "copied"):
            return "token manipulation or NULL acquisition reported the wrong result"
        if (after.live, after.explicit, after.cleanup, after.refcount) != (
                before.live, before.explicit, before.cleanup, before.refcount):
            return "alias manipulation changed ownership"
        expected_regs, expected_spills = list(before.registers), list(before.spills)
        dst = edge.args[0]
        if kind == "copy":
            expected_regs[dst] = before.registers[edge.args[1]]
        elif kind == "spill":
            expected_spills[dst] = before.registers[edge.args[1]]
        elif kind == "reload":
            expected_regs[dst] = before.spills[edge.args[1]]
        else:
            expected_regs[dst] = 0
        if after.registers != tuple(expected_regs) or after.spills != tuple(expected_spills):
            return "copy/spill/reload did not preserve the source identity"
    if kind == "acquire" and bool(after.terminal) != (n == capacity):
        return "acquisition exhaustion does not match the cell budget"
    if kind == "acquire" and after.terminal:
        if after.terminal != "exhaustion" or edge.result != "exhaustion":
            return "exhausted acquisition reported the wrong trap reason"
    if kind == "acquire" and not after.terminal:
        if len(after.live) != n + 1 or after.registers[edge.args[0]] != n + 1:
            return "acquisition did not create a fresh identity"
        if (not after.live[n] or after.explicit[n] != 0 or after.cleanup[n] != 0
                or after.refcount != before.refcount + 1):
            return "acquisition did not create one live, unconsumed reference"
        if edge.result != "success":
            return "successful acquisition reported the wrong result"
        expected_regs = list(before.registers)
        expected_regs[edge.args[0]] = n + 1
        if after.registers != tuple(expected_regs) or after.spills != before.spills:
            return "acquisition changed an unrelated alias"
        if (after.live[:n], after.explicit[:n], after.cleanup[:n]) != (
                before.live, before.explicit, before.cleanup):
            return "acquisition changed an existing ownership token"
    return None


def explore(registers: int, spills: int, capacity: int, mutation: bool = False) -> dict:
    initial = State((), (0,) * registers, (0,) * spills, (), ())
    initial_error = state_error(initial, capacity)
    if initial_error:
        return {"verified": False, "error": initial_error, "counterexample": []}
    queue = deque([initial])
    # Parent pointers retain one shortest history; equivalent abstract states merge.
    parents: dict[State, tuple[State, str] | None] = {initial: None}
    edge_count = 0
    terminal_count = 0
    while queue:
        state = queue.popleft()
        terminal_count += bool(state.terminal)
        for edge in transitions(state, capacity, mutation):
            edge_count += 1
            error = state_error(edge.target, capacity) or edge_error(state, edge, capacity)
            if error:
                history = [edge.label()]
                cursor = state
                while parents[cursor] is not None:
                    cursor, label = parents[cursor]
                    history.append(label)
                return {"verified": False, "error": error,
                        "counterexample": list(reversed(history)),
                        "states_discovered_before_failure": len(parents),
                        "transitions_checked": edge_count}
            if edge.target not in parents:
                parents[edge.target] = (state, edge.label())
                queue.append(edge.target)
    return {"verified": True, "reachable_states": len(parents),
            "terminal_states": terminal_count, "transitions_checked": edge_count}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registers", type=int, choices=range(1, 5), default=4)
    parser.add_argument("--spills", type=int, choices=range(0, 3), default=2)
    parser.add_argument("--acquisitions", type=int, choices=(1, 2), default=2)
    parser.add_argument("--mutation-check", action="store_true",
                        help="also require a counterexample to object-wide revocation")
    args = parser.parse_args()
    bounds = {"registers": args.registers, "spills": args.spills,
              "successful_acquisitions": args.acquisitions, "objects": 1,
              "object_value": 42, "baseline_refcount": 1}
    result = {"model": "per-acquisition ownership", "bounds": bounds,
              "check": explore(args.registers, args.spills, args.acquisitions)}
    okay = result["check"]["verified"]
    if args.mutation_check:
        mutant = explore(args.registers, args.spills, args.acquisitions, mutation=True)
        result["object_wide_revocation_mutant"] = mutant
        # One acquisition has no independent acquisition to distinguish the mutant.
        result["mutation_killed"] = not mutant["verified"]
        okay = okay and result["mutation_killed"]
    print(json.dumps(result, indent=2))
    return 0 if okay else 1


if __name__ == "__main__":
    raise SystemExit(main())
