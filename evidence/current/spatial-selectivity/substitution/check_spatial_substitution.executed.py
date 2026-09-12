#!/usr/bin/env python3
"""Check one fixed trusted wrong-value counterexample; never admit or execute BPF."""
import argparse
import json
from pathlib import Path
import re
import shlex

import check_spatial_selectivity as extent
from native_receipt_common import by_suffix, checksums, digest, require, validate_completion


PROTECTED = {
    "array-authority.patch": "ac74717a7dbd2c61760115c1b8b719e52d27d60d02957a2b73c3ff155206c4ac",
    "native-observation.patch": "2f7889c53d0b4de2e47a94b8acb0d6c1ab73bca6effaccee5b4733984f449b07",
}
EXTENT_CHECKER = "1ee14daac0e0c2b96214391b17e259636f99c210eb26b9e349cc14a97f202d07"
CASES = (("correct_a", 0, 0, 0x29, True),
         ("legitimate_b", 1, 1, 0x87, True),
         ("substituted_b", 0, 1, 0x87, False))


def validate_native(lines, decoded):
    number = extent.number
    begin = extent.one(lines, "CBPF_SPATIAL_SUBSTITUTION_BEGIN ")
    for key, value in {"map_id": 0, "key_size": 4, "value_size": 7,
                       "stride": 8, "max_entries": 2}.items():
        require(number(begin, key) == value, "fixture " + key)
    require(begin["fixture"] == extent.INITIAL.hex(), "distinct initial fixture")
    map_address = number(begin, "map")
    require(map_address > 0, "fixture map identity")
    require(not extent.selected(lines, "CBPF_SPATIAL_SELECTIVITY_CASE ") and
            not extent.selected(lines, "CBPF_SPATIAL_SELECTIVITY_BEGIN "),
            "Substitution is separate from the extent matrix")
    providers = extent.selected(lines, "CBPF_SPATIAL_NATIVE_VALUE ")
    require(len(providers) == 2 and
            [number(p, "index") for p in providers] == [0, 1],
            "Two independent production selections, A then B")
    values = number(providers[0], "values")
    require(values > map_address, "array value storage follows fixture map")
    for key, provider in enumerate(providers):
        require(provider["branch"] == "reduced", "production provider branch")
        expected = {"map_id": 0, "index": key, "value_size": 7, "stride": 8,
                    "values": values, "selected": values + 8 * key,
                    "base": values + 8 * key, "cursor": values + 8 * key,
                    "tag": 1, "sealed": 0, "length": 7, "perms": extent.DATA_PERMS}
        for field, value in expected.items():
            require(number(provider, field) == value, "provider " + field)
    records = extent.selected(lines, "CBPF_SPATIAL_SUBSTITUTION_CASE ")
    require(len(records) == 3 and [number(r, "case") for r in records] == [0, 1, 2],
            "Three ordered fixed substitution cases")
    markers = [line for line in lines if any(marker in line for marker in
        ("CBPF_SPATIAL_SUBSTITUTION_", "CBPF_SPATIAL_NATIVE_VALUE "))]
    expected_markers = ["SUBSTITUTION_BEGIN ", "NATIVE_VALUE ", "NATIVE_VALUE ",
                        "SUBSTITUTION_CASE ", "SUBSTITUTION_CASE ",
                        "SUBSTITUTION_CASE ", "SUBSTITUTION_SUMMARY "]
    require(len(markers) == len(expected_markers) and
            all(marker in line for marker, line in zip(expected_markers, markers)),
            "Ordered fixture, independent provider calls, cases and summary")
    normalized, instructions = [], set()
    for case, (record, expected) in enumerate(zip(records, CASES)):
        name, intended_key, actual_key, value, binding = expected
        require(record["name"] == name and record["op"] == "load" and
                record["result"] == "PASS", "case identity/outcome")
        expected_fields = {
            "intended_map": map_address, "intended_key": intended_key,
            "intended_base": values + intended_key * 8,
            "actual_map": map_address, "actual_provider_key": actual_key,
            "offset": 6, "width": 1, "root_reg": 2, "operand_match": 1,
            "cap_tag": 1, "cap_sealed": 0, "cap_base": values + actual_key * 8,
            "cap_address": values + actual_key * 8 + 6,
            "cap_length": 7, "cap_perms": extent.DATA_PERMS,
            "err": 0, "fault_count": 0, "fault_overflow": 0,
            "value": value, "binding_match": int(binding),
        }
        for field, expected_value in expected_fields.items():
            require(number(record, field) == expected_value,
                    f"case {case} {field}")
        actual_binding = (number(record, "actual_map") == number(record, "intended_map") and
                          number(record, "cap_base") == number(record, "intended_base") and
                          number(record, "cap_address") == number(record, "intended_base") + 6)
        require(actual_binding == binding, "Independently recomputed binding")
        require(record["before"] == record["after"] == extent.INITIAL.hex(),
                "Fixture reset and unchanged full storage")
        pc, word = number(record, "pc"), number(record, "insn")
        require(pc > 0 and pc in decoded and pc - 4 in decoded,
                "Access and capture in complete linked helper")
        require(word == extent.ACCESS_WORDS["load", 1] == decoded[pc][0] and
                decoded[pc][1] == "ldurb" and
                re.fullmatch(r"w8,\s*\[c2,\s*#(?:0x0|0)\]", decoded[pc][2]),
                "Same byte-load instruction and capability register")
        require(decoded[pc - 4][0] == 0xC2C1D041 and decoded[pc - 4][1] == "mov" and
                re.fullmatch(r"c1,\s*c2", decoded[pc - 4][2]),
                "Full operand capture immediately precedes load")
        instructions.add((pc, word))
        normalized.append({
            "case": name,
            "intended": {"map": record["intended_map"], "key": intended_key,
                         "base": record["intended_base"]},
            "actual": {"map": record["actual_map"], "provider_key": actual_key,
                       **{key: record[key] for key in ("cap_base", "cap_address", "cap_perms")},
                       "cap_length": 7, "cap_tag": 1, "cap_sealed": 0,
                       "operand_match": True},
            "offset": 6, "width": 1, "pc": record["pc"], "instruction": record["insn"],
            "root_reg": 2, "returned_byte": value, "binding_match": binding,
            "hardware_permitted": True, "fault_count": 0,
            "before": record["before"], "after": record["after"],
        })
    require(len(instructions) == 1, "Same instruction location in all three cases")
    summary = extent.one(lines, "CBPF_SPATIAL_SUBSTITUTION_SUMMARY ")
    require(summary["result"] == "PASS" and summary["provider"] == "production" and
            summary["substitution"] == "trusted", "Trusted counterexample summary")
    for field, value in {"cases": 3, "permits": 3, "failures": 0, "verifier_execution": 0}.items():
        require(number(summary, field) == value, "summary " + field)
    return {"observations": 3, "permits": 3, "binding_matches": 2,
            "binding_mismatches": 1, "cases": normalized,
            "pass_means": "Expected wrong-value counterexample observed, not correct assignment"}


def validate_run(run):
    metadata = json.loads((run / "validation.json").read_text())
    require(metadata == {"schema": "cbpf-spatial-substitution-inputs-v1", "mode": "substitution",
                         "admission_profile": "loads-stores-v2", "origin": "new-run"},
            "Fixed substitution mode and admission profile")
    identity = extent.build_identity(run / "build-receipt")
    require(all(identity[name] == value for name, value in PROTECTED.items()),
            "Unchanged production provider and observation overlay")
    require(digest(Path(extent.__file__)) == EXTENT_CHECKER, "Unchanged strict extent checker")
    recorded = checksums(run / "inputs.sha256")
    for suffix, expected in (("/arch/arm64/boot/Image", identity["Image"]),
                             ("/vmlinux", identity["vmlinux"]), ("/.config", identity["config"]),
                             ("/guest.c", extent.GUEST_HASHES["loads-stores-v2"])):
        require(by_suffix(recorded, suffix) == expected, "Run/build binding " + suffix)
    require(digest(run / "kernel.config") == identity["config"] and
            digest(run / "guest.c") == extent.GUEST_HASHES["loads-stores-v2"],
            "Unchanged configuration and load-only guest")
    # Launch paths may be role-redacted in publication copies. Bind the command's
    # kernel, initrd and mode below; its original digest remains in inputs.sha256.
    for name in ("init", "initramfs.cpio.gz", "validation.json",
                 "check_spatial_selectivity.py", "check_spatial_selectivity.executed.py",
                 "check_spatial_substitution.executed.py", "native_receipt_common.py",
                 "run-script.executed.sh", "prepare_spatial_selectivity.executed.py",
                 "package_native_extension.executed.py"):
        require(digest(run / name) == by_suffix(recorded, "/" + name), "Run input " + name)
    require(digest(run / "check_spatial_selectivity.py") == EXTENT_CHECKER and
            digest(run / "check_spatial_selectivity.executed.py") == EXTENT_CHECKER,
            "Captured strict extent checker")
    text = (run / "boot.log").read_text(errors="strict")
    completion = validate_completion(text, (run / "qemu-exit.txt").read_text())
    require(text.count("CBPF_SPATIAL_ADMISSION poweroff=begin result=PASS") == 1 and
            text.rfind("reboot: Power down") > text.rfind("poweroff=begin"), "Ordered guest completion")
    command = (run / "qemu-command.sh").read_text()
    placement, kernel = extent.relocation(text, command, "new-run", "substitution")
    argv = shlex.split(command)
    append = shlex.split(argv[argv.index("-append") + 1])
    logged = re.findall(r"Kernel command line: ([^\n]+)", text)[0].split()
    for options in (append, logged):
        require([s for s in options if s.startswith("cbpf.selectivity_")] ==
                ["cbpf.selectivity_substitution=1"], "Exclusive fixed substitution boot mode")
    require(recorded.get(kernel) == identity["Image"], "Launched kernel/input binding")
    require(argv.count("-initrd") == 1 and
            recorded.get(argv[argv.index("-initrd") + 1]) == digest(run / "initramfs.cpio.gz"),
            "Launched guest/input binding")
    decoded = extent.linked_helper(run / "linked", identity["vmlinux"])
    native = validate_native(text.splitlines(), decoded)
    admission = extent.validate_admission(text.splitlines(), text, "loads-stores-v2")
    calibration = extent.validate_run(run / "calibration", expected_mode="calibration")
    extent.validate_calibration_receipt(calibration,
        json.loads((run / "calibration/results.json").read_text()), recorded)
    require(calibration["build_identity"] == identity, "Calibration kernel/configuration/overlay mismatch")
    paths = ["validation.json", "boot.log", "inputs.sha256", "guest.c", "kernel.config",
             "qemu-command.sh", "qemu-exit.txt", "init", "initramfs.cpio.gz",
             "check_spatial_selectivity.py", "check_spatial_substitution.executed.py"]
    paths += ["build-receipt/" + name for name in extent.BUILD_FILES]
    paths += ["linked/" + name for name in extent.LINKED_FILES]
    return {"schema": "cbpf-spatial-substitution-v1", "result": "PASS",
            "checker_sha256": digest(Path(__file__)), "extent_checker_sha256": EXTENT_CHECKER,
            "shared_checks_sha256": digest(Path(__file__).with_name("native_receipt_common.py")),
            "input_sha256": {name: digest(run / name) for name in paths},
            "build_identity": identity, "relocation": placement, "completion": completion,
            "native": native, "verifier_admission": admission, "calibration": calibration,
            "prelaunch_calibration_sha256": digest(run / "calibration/results.json"),
            "scope": {"observed": "Fixed trusted wrong-value capability substitution",
                      "invalid_bpf_execution": False, "semantic_authentication_claim": False,
                      "complete_mediation_claim": False, "production_changes": False}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = validate_run(args.run)
    require(args.output.resolve() not in {(args.run / name).resolve() for name in result["input_sha256"]},
            "Output must not overwrite an input")
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("CBPF spatial substitution: PASS native=3 permits=3 binding_mismatches=1 executions=0")


if __name__ == "__main__":
    main()
