#!/usr/bin/env python3
"""Focused controls for the ownership model's independent transition oracle."""

from dataclasses import replace

from check_model import Edge, State, edge_error, state_error


def main() -> int:
    capacity = 2
    empty = State((), (0, 0), (0,), (), ())
    live = State((True,), (1, 0), (0,), (0,), (0,), refcount=2)
    consumed = replace(live, live=(False,), explicit=(1,), refcount=1)
    full = State((True, True), (1, 2), (0,), (0, 0), (0, 0), refcount=3)
    finished = replace(full, live=(False, False), cleanup=(1, 1),
                       refcount=1, terminal="return")
    spilled = replace(live, spills=(1,))

    # These expected edges are supplied directly, without using transitions().
    controls = [
        ("live acquisition", empty, Edge("acquire", (0,), "success", live), False),
        ("NULL overwrite", live, Edge("acquire_null", (0,), "null",
                                     replace(live, registers=(0, 0))), False),
        ("copy", live, Edge("copy", (1, 0), "copied",
                           replace(live, registers=(1, 1))), False),
        ("spill", live, Edge("spill", (0, 0), "copied", spilled), False),
        ("reload", spilled, Edge("reload", (1, 0), "copied",
                                replace(spilled, registers=(1, 1))), False),
        ("live read", live, Edge("read", (0,), "42", live), False),
        ("live release", live, Edge("release", (0,), "consumed", consumed), False),
        ("finish cleanup", full, Edge("finish", (), "return", finished), False),
        ("exhaustion cleanup", full, Edge("acquire", (0,), "exhaustion",
                                        replace(finished, terminal="exhaustion")), False),
        ("consumed acquisition", empty,
         Edge("acquire", (0,), "success", consumed), True),
        ("finish remains active", empty, Edge("finish", (), "return", empty), True),
        ("finish reports a trap", full, Edge("finish", (), "return",
                                           replace(finished, terminal="exhaustion")), True),
        ("exhaustion reports return", full,
         Edge("acquire", (0,), "exhaustion", finished), True),
        ("acquisition reports failure", empty,
         Edge("acquire", (0,), "exhaustion", live), True),
        ("release reports failure", live,
         Edge("release", (0,), "stale", consumed), True),
        ("copy reports NULL", live,
         Edge("copy", (0, 0), "null", live), True),
        ("read creates an identity", empty,
         Edge("read", (0,), "42", live), True),
    ]
    for reason, before in (("null", empty), ("stale", consumed)):
        for kind in ("read", "release"):
            valid = Edge(kind, (0,), reason,
                         replace(before, terminal=reason + "_" + kind))
            controls.append((reason + " " + kind, before, valid, False))
            controls.append((reason + " " + kind + " wrong terminal reason", before,
                             replace(valid, target=replace(valid.target, terminal="return")), True))
            controls.append((reason + " " + kind + " wrong result", before,
                             replace(valid, result="42"), True))

    for name, before, edge, reject in controls:
        invariant_error = state_error(before, capacity) or state_error(edge.target, capacity)
        if invariant_error:
            raise RuntimeError(f"{name}: control fails a state invariant: {invariant_error}")
        # Malformed successors preserve the state invariants: the edge oracle
        # must independently distinguish the actual operation's obligations.
        error = edge_error(before, edge, capacity)
        if bool(error) != reject:
            raise RuntimeError(f"{name}: expected {'rejection' if reject else 'acceptance'}, "
                               f"received {error!r}")
    rejected = sum(reject for _, _, _, reject in controls)
    print(f"CBPF oracle controls: passed; {len(controls) - rejected} valid edges accepted, "
          f"{rejected} malformed edges rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
