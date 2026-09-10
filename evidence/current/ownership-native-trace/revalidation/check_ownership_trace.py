#!/usr/bin/env python3
"""Validate the fixed synthetic-native ownership containment trace."""
import argparse
import hashlib
import json
import pathlib
import re
import struct
from native_receipt_common import validate_completion, digest


END_PC = 2**64 - 1
NAMES = ["positive", "stale_read", "repeated_release"]


def require(condition, message):
    if not condition:
        raise SystemExit("CBPF ownership native trace validation failed: " + message)


def normalize(log):
    return [re.sub(r"^\[\s*\d+\.\d+\]\s*", "", row)
            for row in log.replace("\r", "").splitlines()]


def native_sections(rows):
    result = {}
    active = None
    begin = re.compile(
        r"CBPF_OWNERSHIP_TRACE case=(\w+) phase=begin verified_bpf=0 "
        r"scope=synthetic_native_production_path")
    for row in rows:
        match = begin.fullmatch(row)
        if match:
            require(active is None and match[1] in NAMES and match[1] not in result,
                    "duplicate or nested native case")
            active = match[1]
            result[active] = []
        if active is not None:
            result[active].append(row)
            if row.startswith("CBPF_OWNERSHIP_TRACE case=" + active + " phase=end "):
                active = None
    require(active is None and list(result) == NAMES,
            "missing or unordered native cases")
    require(sum(row.startswith("CBPF_OWNERSHIP_TRACE case=") for row in rows) == 6,
            "unexpected native case marker")
    return result


def verifier_sections(rows):
    names = ["stale_copy", "stale_spill", "repeated_release"]
    result = {}
    active = None
    begin = re.compile(
        r"CBPF_TRACE_VERIFY case=(\w+) phase=begin expected=reject execution=forbidden")
    for row in rows:
        match = begin.fullmatch(row)
        if match:
            require(active is None and match[1] in names and match[1] not in result,
                    "duplicate or nested verifier case")
            active = match[1]
            result[active] = []
        if active is not None:
            result[active].append(row)
            if row.startswith("CBPF_TRACE_VERIFY case=" + active + " phase=end "):
                active = None
    require(active is None and list(result) == names,
            "missing or unordered verifier cases")
    return result


def bpf_rows(lines, prefix, case):
    pattern = re.compile(
        re.escape(prefix) + r"(?: bpf)? case=" + case +
        r" pc=(\d+) code=([0-9a-f]{2}) dst=(\d+) src=(\d+) off=(-?\d+) imm=(-?\d+)")
    matches = [pattern.fullmatch(row) for row in lines
               if row.startswith(prefix) and " pc=" in row]
    require(matches and all(matches), case + " malformed BPF receipt")
    require([int(match[1]) for match in matches] == list(range(len(matches))),
            case + " BPF PC sequence")
    return [tuple([match[2], *(int(match[index]) for index in range(3, 7))])
            for match in matches]


def expected_native_bpf(case):
    imm = lambda dst, value: ("b7", dst, 0, 0, value)
    copy = lambda dst, src: ("bf", dst, src, 0, 0)
    call = lambda op: ("85", 0, 2, 0, op)
    null = lambda off: ("15", 0, 0, off, 0)
    spill = ("7b", 10, 6, -8, 0)
    reload_8 = ("79", 8, 10, -8, 0)
    exit_insn = ("95", 0, 0, 0, 0)
    common = [imm(1, 0), call(1), null(16 if case == "positive" else 19),
              copy(6, 0), spill, imm(1, 0), call(1),
              null(11 if case == "positive" else 14), copy(7, 0),
              reload_8, copy(1, 8), call(3), copy(1, 7), call(2), copy(9, 0)]
    if case == "positive":
        return common + [copy(1, 7), call(3), copy(0, 9), exit_insn,
                         imm(0, 0), exit_insn]
    stale = call(2 if case == "stale_read" else 3)
    return common + [reload_8, copy(1, 8), stale, copy(1, 7), call(3),
                     imm(0, 99), exit_insn, imm(0, 0), exit_insn]


def gate_rows(lines):
    pattern = re.compile(
        r"CBPF_GATE seq=(\d+) event=(\w+) pc=(\d+) id=(\d+) acquired=(\d+) "
        r"released=(\d+) reads=(\d+) cleanup=(\d+) refs=(\d+) tagA=(\d+) tagB=(\d+)")
    matches = [pattern.fullmatch(row) for row in lines if row.startswith("CBPF_GATE ")]
    require(all(matches), "malformed gate event")
    return [tuple([int(match[1]), match[2],
                   *(int(match[index]) for index in range(3, 12))])
            for match in matches]


def expected_gates(case):
    prefix = [
        (1, "acquire", 1, 1, 1, 0, 0, 0, 2, 1, 0),
        (2, "acquire", 6, 2, 2, 0, 0, 0, 3, 1, 1),
        (3, "clear", 11, 1, 2, 0, 0, 0, 3, 0, 1),
        (4, "release", 11, 1, 2, 1, 0, 0, 2, 0, 1),
        (5, "read", 13, 2, 2, 1, 1, 0, 2, 0, 1),
    ]
    if case == "positive":
        return prefix + [
            (6, "clear", 16, 2, 2, 1, 1, 0, 2, 0, 0),
            (7, "release", 16, 2, 2, 2, 1, 0, 1, 0, 0),
            (8, "exit", END_PC, 0, 2, 2, 1, 0, 1, 0, 0),
        ]
    return prefix + [
        (6, "reject", 17, 0, 2, 1, 1, 0, 2, 0, 1),
        (7, "clear", END_PC, 2, 2, 1, 1, 0, 2, 0, 0),
        (8, "cleanup", END_PC, 2, 2, 2, 1, 1, 1, 0, 0),
        (9, "failed", END_PC, 0, 2, 2, 1, 1, 1, 0, 0),
    ]


def validate_bindings(lines):
    pattern = re.compile(
        r"CBPF_BIND pc=(\d+) id=(\d+) cell=([0-9a-f]+) object=([0-9a-f]+) "
        r"public_tag=1 public_base=0x([0-9a-f]+) public_length=16 public_perms=0x20001")
    matches = [pattern.fullmatch(row) for row in lines if row.startswith("CBPF_BIND ")]
    require(len(matches) == 2 and all(matches), "two exact public bindings")
    require([(int(match[1]), int(match[2])) for match in matches] == [(1, 1), (6, 2)],
            "binding PC and identity")
    require(all(int(match[3], 16) == int(match[5], 16) for match in matches),
            "binding base equals cell")
    require(len({match[4] for match in matches}) == 1, "one provider object")
    require(abs(int(matches[0][3], 16) - int(matches[1][3], 16)) >= 16,
            "distinct acquisition cells")


def validate_native(case, lines, output_directory):
    bpf = bpf_rows(lines, "CBPF_TRACE_BPF", case)
    require(bpf == expected_native_bpf(case), case + " fixed trusted fixture")
    accepted_pattern = re.compile(
        r"CBPF_NATIVE accepted insns=(\d+) words=(\d+) entry=([0-9a-f]+) "
        r"restricted_exit=(\d+) executive_exit=(\d+) template_check=pass")
    accepted = [accepted_pattern.fullmatch(row) for row in lines
                if row.startswith("CBPF_NATIVE accepted ")]
    require(len(accepted) == 1 and accepted[0], case + " native acceptance")
    count, word_count, image, restricted, executive = accepted[0].groups()
    count, word_count, restricted, executive = map(int,
                                                    (count, word_count, restricted, executive))
    require(count == len(bpf) and 0 < restricted < executive < word_count and
            executive == restricted + 1, case + " native envelope")
    map_pattern = re.compile(
        r"CBPF_NATIVE map pc=(\d+) begin=(\d+) end=(\d+) code=([0-9a-f]{2}) op=(\d+)")
    maps = [map_pattern.fullmatch(row) for row in lines if row.startswith("CBPF_NATIVE map ")]
    require(len(maps) == len(bpf) and all(maps), case + " source/native map")
    require([int(match[1]) for match in maps] == list(range(len(bpf))),
            case + " map PC sequence")
    for index, (match, instruction) in enumerate(zip(maps, bpf)):
        pc, begin, end, code, operation = match.groups()
        expected_operation = instruction[4] if instruction[0] == "85" else 0
        require(code == instruction[0] and int(operation) == expected_operation,
                case + " map operation at " + pc)
        require(0 <= int(begin) < int(end) <= restricted,
                case + " map range at " + pc)
        if index:
            require(int(begin) == int(maps[index - 1][3]),
                    case + " contiguous map")
    word_pattern = re.compile(r"CBPF_NATIVE word index=(\d+) value=([0-9a-f]{8})")
    words = [word_pattern.fullmatch(row) for row in lines if row.startswith("CBPF_NATIVE word ")]
    require(len(words) == word_count and all(words), case + " native words")
    require([int(match[1]) for match in words] == list(range(word_count)),
            case + " native word indices")
    values = [int(match[2], 16) for match in words]
    require(values[int(maps[4][2])] == 0x824003F3,
            case + " full-capability A spill")
    for pc in ([9] if case == "positive" else [9, 15]):
        require(values[int(maps[pc][2])] == 0x826003F5,
                case + " full-capability A reload at PC " + str(pc))
    for index, instruction in enumerate(bpf):
        if instruction[0] == "85":
            begin, end = int(maps[index][2]), int(maps[index][3])
            require(0xC2C23222 in values[begin:end],
                    case + " sealed gateway call at PC " + str(index))
    native = b"".join(struct.pack("<I", value) for value in values)
    target = output_directory / ("native-" + case + ".bin")
    target.write_bytes(native)
    entry = int(image, 16)
    enter_pattern = re.compile(
        r"CBPF_ENTER restricted_base=0x([0-9a-f]+) restricted_size=(\d+) "
        r"executive_base=0x([0-9a-f]+) executive_size=(\d+) stack_base=0x([0-9a-f]+) "
        r"stack_size=16 rddc_tag=0 gate_sealed=1")
    enters = [enter_pattern.fullmatch(row) for row in lines if row.startswith("CBPF_ENTER ")]
    require(len(enters) == 1 and enters[0], case + " restricted entry")
    base, size, exit_base, exit_size, stack = enters[0].groups()
    require(int(base, 16) + int(size) == int(exit_base, 16) and
            int(exit_base, 16) == entry + 4 * executive and
            int(exit_size) == 4 * (word_count - executive) and
            int(stack, 16) % 16 == 0, case + " entry bounds")
    return {
        "bpf_instructions": len(bpf),
        "native_bytes": len(native),
        "native_sha256": hashlib.sha256(native).hexdigest(),
        "restricted_exit_word": restricted,
        "executive_exit_word": executive,
    }


def validate_verifier(cases):
    bytecodes = {}
    diagnostics = {}
    end_pattern = re.compile(
        r"CBPF_TRACE_VERIFY case=(\w+) phase=end result=PASS loaded=0 executed=0 "
        r"load_errno=(13|22) diagnostic=(argument_shape|other)")
    for name, lines in cases.items():
        bytecodes[name] = bpf_rows(lines, "CBPF_TRACE_VERIFY", name)
        ends = [end_pattern.fullmatch(row) for row in lines
                if row.startswith("CBPF_TRACE_VERIFY case=" + name + " phase=end ")]
        require(len(ends) == 1 and ends[0], name + " load-only rejection")
        require(any(row == "CBPF_TRACE_VERIFY verifier_begin case=" + name for row in lines) and
                any(row == "CBPF_TRACE_VERIFY verifier_end case=" + name for row in lines),
                name + " verifier diagnostic boundaries")
        require(any(re.match(r"^13: \(85\) call cbpf_cap_(?:read|release)#", row)
                    for row in lines), name + " verifier call PC")
        require(not any(row.startswith(("CBPF_GATE ", "CBPF_BIND ", "CBPF_ENTER ",
                                        "CBPF_RESULT ", "CBPF_NATIVE ")) for row in lines),
                name + " was not executed")
        diagnostics[name] = ends[0][3]
    require(all(len(code) == 26 for code in bytecodes.values()),
            "26-instruction verifier fixtures")
    stale_copy = bytecodes["stale_copy"]
    stale_spill = bytecodes["stale_spill"]
    repeated = bytecodes["repeated_release"]
    require(stale_copy[12] == ("bf", 1, 6, 0, 0), "stale copy shape")
    require(stale_spill[12] == ("79", 1, 10, -8, 0), "stale spill shape")
    require(repeated[12] == stale_copy[12], "repeated release alias shape")
    require(stale_copy[:12] == stale_spill[:12] == repeated[:12] and
            stale_copy[14:] == stale_spill[14:] == repeated[14:],
            "controlled verifier fixture differences")
    require(stale_copy[13][4] == stale_spill[13][4] and
            repeated[13][4] == repeated[11][4] == repeated[16][4] == repeated[21][4] and
            repeated[13][4] != stale_copy[13][4], "read/release BTF identities")
    return diagnostics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, type=pathlib.Path)
    parser.add_argument("--linked-disassembly", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--native-directory", required=True, type=pathlib.Path)
    parser.add_argument("--qemu-exit", required=True, type=pathlib.Path)
    args = parser.parse_args()
    raw = args.log.read_text(errors="replace")
    rows = normalize(raw)
    native = native_sections(rows)
    results = []
    for name, lines in native.items():
        validate_bindings(lines)
        require(gate_rows(lines) == expected_gates(name), name + " exact ordered effects")
        identity = [row for row in lines if row.startswith("CBPF_TRACE_IDENTITY ")]
        if name == "positive":
            require(not identity, "positive has no rejection")
            expected_end = (42, 0, 0, 0, 0, 0)
        else:
            operation = 2 if name == "stale_read" else 3
            require(identity == [
                f"CBPF_TRACE_IDENTITY case={name} pc=17 id=1 operation={operation} "
                "public_tag=1 canonical=1 private_tag=0"], name + " stale identity")
            expected_end = (0, 1, 1, 1, 0, operation)
        retval, failed, cleanup, observed, private, operation = expected_end
        end = (f"CBPF_OWNERSHIP_TRACE case={name} phase=end result=PASS retval={retval} "
               f"entered=1 failed={failed} acquired=2 released=2 reads=1 cleanup={cleanup} "
               f"refs=1 tagA=0 tagB=0 identity_observed={observed} public_tag={observed} "
               f"canonical={observed} private_tag={private} rejected_operation={operation} "
               "verified_bpf=0 scope=synthetic_native_production_path")
        require(lines[-1] == end, name + " final accounting")
        require([row for row in lines if row.startswith("CBPF_RESULT ")] == [
            f"CBPF_RESULT value={retval} entered=1 failed={failed} balanced=1"],
            name + " production wrapper result")
        native_result = validate_native(name, lines, args.native_directory)
        native_result.update({"case": name, "result": "PASS", "retval": retval,
                              "acquired": 2, "released": 2, "reads": 1,
                              "cleanup": cleanup, "refs": 1,
                              "identity_observed": bool(observed)})
        results.append(native_result)
    verify = verifier_sections(rows)
    diagnostics = validate_verifier(verify)
    require(rows.count("CBPF_TRACE_VERIFY kernel=6.7.0-cbpf-ownership-native-trace normal_verifier=1 attached=0") == 1,
            "guest/kernel identity")
    require(rows.count("CBPF_TRACE_VERIFY result=PASS rejected=3 executed=0") == 1,
            "three load-only verifier controls")
    require(sum(row.startswith("CBPF_ENTER ") for row in rows) == 3 and
            sum(row.startswith("CBPF_RESULT ") for row in rows) == 3 and
            sum(row.startswith("CBPF_NATIVE accepted ") for row in rows) == 3,
            "exactly three native fixture executions")
    completion = validate_completion(raw, args.qemu_exit.read_text())
    linked = args.linked_disassembly.read_text(errors="replace").lower()
    for symbol in ("cbpf_gateway", "cbpf_gate_impl", "cbpf_test_invoke", "cbpf_enter",
                   "cbpf_ownership_trace_program"):
        require("<" + symbol + ">:" in linked, "linked symbol " + symbol)
    require("chkeq" in linked and "rddc_el0" in linked and "rcsp_el0" in linked and
            "retr" in linked, "linked identity/entry/return instructions")
    output = {
        "study": "synthetic native ownership containment trace",
        "result": "PASS",
        "cases": results,
        "verifier_load_only": {"result": "PASS", "rejected": 3,
                               "executed": 0, "diagnostics": diagnostics},
        "qemu_exit": completion["qemu_exit"],
        "completion": completion,
        "qemu_exit_sha256": digest(args.qemu_exit),
        "scope": "fixed trusted native fixtures through the production provider, restricted entry, gateway, epilogue and cleanup wrapper",
        "limits": [
            "The three native fixtures are not normally verified eBPF.",
            "Verifier rejection diagnostics are admission observations, not evidence for a specific ownership rule.",
            "The trace projects repeated-release containment; it does not execute the original callback CVE path or implement callback-frame release policy.",
        ],
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print("CBPF ownership native trace validation PASS: native=3 verifier_rejected=3 verifier_executed=0")


if __name__ == "__main__":
    main()
