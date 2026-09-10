#!/usr/bin/env python3
"""Validate the fixed native selectivity matrix and load-only verifier controls."""
import argparse
import json
import re
from pathlib import Path


INITIAL = bytes.fromhex("11223344556629a781828384858687bf")
SENTINEL = 0xFEEDFACECAFEBEEF
DATA_PERMS = 0x30001
ACCESSES = ((6, 1), (7, 1), (8, 1), (4, 2), (6, 2))
ROOTS = (("exact7", 7), ("stride8", 8), ("both16", 16))
MNEMONICS = {
    ("load", 1): "ldurb",
    ("load", 2): "ldurh",
    ("store", 1): "sturb",
    ("store", 2): "sturh",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fields(line):
    pairs = re.findall(r"([A-Za-z_][A-Za-z_0-9]*)=([^\s]+)", line)
    require(len(pairs) == len(dict(pairs)), "duplicate field: " + line)
    return dict(pairs)


def number(record, key, base=0):
    return int(record[key], base)


def selected(lines, marker):
    return [fields(line) for line in lines if marker in line]


def one(lines, marker):
    records = selected(lines, marker)
    require(len(records) == 1, f"expected exactly one {marker}, got {len(records)}")
    return records[0]


def expected_native(mode):
    if mode == "calibration":
        return [
            (0, "load", "exact7", 7, 6, 1),
            (1, "load", "exact7", 7, 7, 1),
        ]
    result = []
    case = 0
    for operation in ("load", "store"):
        for offset, width in ACCESSES:
            for root, length in ROOTS:
                result.append((case, operation, root, length, offset, width))
                case += 1
    return result


def disassembly_words(text):
    result = {}
    for line in text.splitlines():
        match = re.match(r"\s*[0-9a-f]+:\s+([0-9a-f]{8})\s+(\S+)", line)
        if match:
            result[int(match.group(1), 16)] = match.group(2)
    return result


def validate_native(lines, mode, disassembly):
    begin = one(lines, "CBPF_SPATIAL_SELECTIVITY_BEGIN ")
    require(begin["mode"] == mode, "native begin mode")
    for key, expected in {
        "key": 0, "key_size": 4, "value_size": 7, "stride": 8,
        "max_entries": 2, "roots_valid": 1,
    }.items():
        require(number(begin, key) == expected, "native begin " + key)
    require(begin["fixture"] == INITIAL.hex(), "initial fixture")

    provider = one(lines, "CBPF_SPATIAL_NATIVE_VALUE ")
    for key, expected in {"index": 0, "value_size": 7, "stride": 8,
                          "tag": 1, "sealed": 0, "length": 7}.items():
        require(number(provider, key) == expected, "provider " + key)
    require(number(provider, "perms", 0) == DATA_PERMS, "provider permissions")
    require(number(provider, "base", 0) == number(provider, "cursor", 0) ==
            number(provider, "selected", 0), "provider selected bounds")

    records = selected(lines, "CBPF_SPATIAL_SELECTIVITY_CASE ")
    expected = expected_native(mode)
    require(len(records) == len(expected), "native case count")
    indexed = {number(record, "case"): record for record in records}
    require(len(indexed) == len(records), "duplicate native case")
    instruction_sets = {}
    normalized = []
    permits = rejects = 0

    for case, operation, root, length, offset, width in expected:
        require(case in indexed, "missing native case " + str(case))
        record = indexed[case]
        permit = offset + width <= length
        require(record["mode"] == mode and record["op"] == operation and
                record["root"] == root, "native case identity " + str(case))
        require(number(record, "offset") == offset and
                number(record, "width") == width, "native access " + str(case))
        require(record["expected"] == ("permit" if permit else "reject"),
                "native expectation " + str(case))
        require(record["observed"] == record["expected"] and
                record["result"] == "PASS", "native outcome " + str(case))
        require(record["before"] == INITIAL.hex(), "fixture reset " + str(case))
        require(number(record, "operand_match") == 1 and
                number(record, "cap_tag") == 1 and
                number(record, "cap_sealed") == 0,
                "capability validity " + str(case))
        base = number(record, "cap_base", 0)
        require(number(record, "cap_address", 0) == base + offset and
                number(record, "cap_length") == length and
                number(record, "cap_perms", 0) == DATA_PERMS,
                "capability metadata " + str(case))

        instruction = number(record, "insn", 0)
        require(instruction in disassembly, "instruction absent from linked disassembly")
        require(disassembly[instruction] == MNEMONICS[(operation, width)],
                "instruction kind " + str(case))
        instruction_sets.setdefault((operation, width), set()).add(instruction)

        expected_after = bytearray(INITIAL)
        if operation == "store" and permit:
            expected_after[offset] = 0xD1
            if width == 2:
                expected_after[offset + 1] = 0xD2
        require(record["after"] == expected_after.hex(),
                "fixture effect " + str(case))
        value = number(record, "value", 0)
        if operation == "load":
            expected_value = int.from_bytes(INITIAL[offset:offset + width], "little")
            require(value == (expected_value if permit else SENTINEL),
                    "load destination " + str(case))
        else:
            require(value == (0xD1 if width == 1 else 0xD2D1),
                    "store marker " + str(case))

        if permit:
            permits += 1
            require(number(record, "err") == 0 and
                    number(record, "fault_count") == 0 and
                    number(record, "fault_overflow") == 0 and
                    number(record, "fsc", 0) == 0 and
                    number(record, "fault_pc", 0) == 0 and
                    number(record, "fault_insn", 0) == 0,
                    "unexpected permitted fault " + str(case))
        else:
            rejects += 1
            require(number(record, "err") == -14 and
                    number(record, "fault_count") == 1 and
                    number(record, "fault_overflow") == 0 and
                    number(record, "fsc", 0) == 0x2A,
                    "rejection fault " + str(case))
            require(number(record, "wnr") == (operation == "store") and
                    number(record, "pc", 0) == number(record, "fault_pc", 0) and
                    instruction == number(record, "fault_insn", 0),
                    "fault location " + str(case))
        normalized.append({
            "case": case, "operation": operation, "root": root,
            "offset": offset, "width": width,
            "expected": record["expected"], "observed": record["observed"],
            "instruction": f"0x{instruction:08x}",
            "fault_pc": record["fault_pc"], "fsc": record["fsc"],
            "cap_base": record["cap_base"],
            "cap_address": record["cap_address"], "cap_length": length,
            "before": record["before"], "after": record["after"],
        })

    require(all(len(words) == 1 for words in instruction_sets.values()),
            "access instruction changed across roots or offsets")
    summary = one(lines, "CBPF_SPATIAL_SELECTIVITY_SUMMARY ")
    expected_counts = (2, 1, 1) if mode == "calibration" else (30, 22, 8)
    require(summary["mode"] == mode and summary["result"] == "PASS",
            "native summary result")
    require((number(summary, "cases"), number(summary, "permits"),
             number(summary, "rejects")) == expected_counts,
            "native summary counts")
    require(number(summary, "failures") == 0 and
            summary["provider"] == "production" and
            summary["comparators"] == "trusted" and
            number(summary, "verifier_execution") == 0,
            "native summary scope")
    return {"observations": len(records), "permits": permits,
            "rejects": rejects, "cases": normalized}


def validate_bpf_programs(lines):
    rows = selected(lines, "CBPF_SPATIAL_ADMISSION_BPF ")
    require(len(rows) == 50, "BPF instruction receipt count")
    by_case = {case: [] for case in range(5)}
    for row in rows:
        by_case[number(row, "case")].append(row)
    map_fds = set()
    for case, (offset, width) in enumerate(ACCESSES):
        program = sorted(by_case[case], key=lambda row: number(row, "pc"))
        require([number(row, "pc") for row in program] == list(range(10)),
                "BPF PCs " + str(case))
        observed = [(number(row, "code", 16), number(row, "dst"),
                     number(row, "src"), number(row, "off"),
                     number(row, "imm")) for row in program]
        map_fd = observed[3][4]
        map_fds.add(map_fd)
        expected = [
            (0x62, 10, 0, -4, 0), (0xBF, 2, 10, 0, 0),
            (0x07, 2, 0, 0, -4), (0x18, 1, 1, 0, map_fd),
            (0x00, 0, 0, 0, 0), (0x85, 0, 0, 0, 1),
            (0x15, 0, 0, 2, 0),
            (0x71 if width == 1 else 0x69, 1, 0, offset, 0),
            (0xBF, 0, 1, 0, 0), (0x95, 0, 0, 0, 0),
        ]
        require(observed == expected, "fixed BPF fixture " + str(case))
    require(len(map_fds) == 1 and next(iter(map_fds)) >= 0, "BPF map reference")


def verifier_sections(text):
    pattern = re.compile(
        r"CBPF_SPATIAL_ADMISSION_VERIFIER_BEGIN case=(\d+)\n(.*?)"
        r"CBPF_SPATIAL_ADMISSION_VERIFIER_END case=\1", re.S)
    return {int(match.group(1)): match.group(2) for match in pattern.finditer(text)}


def validate_admission(lines, text):
    begin = one(lines, "CBPF_SPATIAL_ADMISSION_BEGIN ")
    for key, expected in {"cases": 5, "key": 0, "key_size": 4,
                          "value_size": 7, "max_entries": 2,
                          "execution": 0}.items():
        require(number(begin, key) == expected, "admission begin " + key)
    validate_bpf_programs(lines)
    sections = verifier_sections(text)
    require(set(sections) == set(range(5)), "verifier log sections")
    records = selected(lines, "CBPF_SPATIAL_ADMISSION_CASE ")
    require(len(records) == 5, "admission case count")
    indexed = {number(record, "case"): record for record in records}
    normalized = []
    for case, (offset, width) in enumerate(ACCESSES):
        record = indexed[case]
        admit = case in (0, 3)
        require(number(record, "offset") == offset and
                number(record, "width") == width, "admission access")
        require(record["expected"] == ("admit" if admit else "reject") and
                record["observed"] == record["expected"] and
                record["result"] == "PASS" and
                number(record, "executed") == 0, "admission outcome")
        if not admit:
            require("invalid access to map value" in sections[case] and
                    f"value_size=7 off={offset} size={width}" in sections[case],
                    "verifier bounds diagnostic " + str(case))
        normalized.append({"case": case, "offset": offset, "width": width,
                           "expected": record["expected"],
                           "observed": record["observed"],
                           "errno": number(record, "errno"), "executed": False})
    summary = one(lines, "CBPF_SPATIAL_ADMISSION_SUMMARY ")
    require(summary["result"] == "PASS" and number(summary, "cases") == 5 and
            number(summary, "admitted") == 2 and number(summary, "rejected") == 3 and
            number(summary, "map_create_count") == 1 and
            number(summary, "prog_load_count") == 5 and
            number(summary, "executions") == 0 and
            number(summary, "failures") == 0, "admission summary")
    return {"cases": normalized, "admitted": 2, "rejected": 3,
            "executions": 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("calibration", "matrix"), required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--disassembly", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    text = args.log.read_text(errors="strict")
    lines = text.splitlines()
    forbidden = ("Kernel panic", "Oops:", "Unable to handle kernel", "result=FAIL")
    require(not any(token in text for token in forbidden), "fatal/failing log marker")
    disassembly = disassembly_words(args.disassembly.read_text())
    native = validate_native(lines, args.mode, disassembly)
    admission = validate_admission(lines, text)
    require("CBPF_SPATIAL_ADMISSION poweroff=begin result=PASS" in text,
            "clean guest completion")
    result = {
        "schema": "cbpf-spatial-selectivity-v1",
        "result": "PASS",
        "mode": args.mode,
        "native": native,
        "verifier_admission": admission,
        "scope": {
            "native_fixture": "fixed trusted synthetic validation through production provider",
            "invalid_bpf_execution": False,
            "original_cve_execution": False,
            "complete_mediation_claim": False,
        },
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"CBPF spatial selectivity {args.mode}: PASS "
          f"native={native['observations']} admission=5 executions=0")


if __name__ == "__main__":
    main()
