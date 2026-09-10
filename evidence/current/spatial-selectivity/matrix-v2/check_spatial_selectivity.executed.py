#!/usr/bin/env python3
"""Validate the fixed native selectivity matrix and load-only verifier controls."""
import argparse
import json
import re
import shlex
import struct
from pathlib import Path

from native_receipt_common import by_suffix, checksums, digest, require, validate_completion


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
ACCESS_WORDS = {("load", 1): 0xE2000448, ("load", 2): 0xE2400448,
                ("store", 1): 0xE2000048, ("store", 2): 0xE2400048}
GUEST_HASHES = {
    "loads-v1": "4b394e3a46874e20719acfa55ab7cb63e9ad2e6f535c53905a24f9a0a697826a",
    "loads-stores-v2": "07fb1f6618cb09b5ffd8194e11d1685aacfafe28fdb7d611ac2a737742862762",
}
VERIFIER_SHA256 = "e1b3401c312176633922671d52b1bd0ccd75f9ab1fcc266a0acb764f784d4239"


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
        match = re.match(r"\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(\S+)\s*(.*)", line)
        if match:
            pc = int(match[1], 16)
            require(pc not in result, "Duplicate linked instruction address")
            result[pc] = (int(match[2], 16), match[3], match[4].strip())
    return result


def linked_helper(directory, vmlinux_sha256):
    receipt = json.loads((directory / "linked-ranges.json").read_text())
    require(receipt["vmlinux_sha256"] == vmlinux_sha256, "Linked image identity")
    require(len(receipt["ranges"]) == 1, "Exactly one complete helper range")
    entry = receipt["ranges"][0]
    require(entry["symbol"] == "cbpf_selectivity_native_access" and
            entry["extent_basis"] == "ELF symbol st_size", "ELF helper extent basis")
    require(entry["file"] == "cbpf_selectivity_native_access.bin", "Helper file identity")
    data = (directory / entry["file"]).read_bytes()
    listing = directory / "complete-linked-disassembly.txt"
    require(digest(directory / entry["file"]) == entry["sha256"] and
            len(data) == entry["bytes"], "Helper bytes identity")
    require(digest(listing) == receipt["disassembly"]["sha256"] and
            listing.stat().st_size == receipt["disassembly"]["bytes"], "Linked listing identity")
    start, end = int(entry["start"], 0), int(entry["end_exclusive"], 0)
    require(start > 0 and start % 4 == 0 and end - start == len(data) and
            len(data) > 0 and len(data) % 4 == 0, "Nonzero aligned complete helper extent")
    symbol = entry["elf_symbol"].split()
    require(len(symbol) == 8 and int(symbol[1], 16) == start and
            int(symbol[2]) == len(data) and symbol[3] == "FUNC" and
            symbol[7] == entry["symbol"], "ELF symbol/range agreement")
    decoded = disassembly_words(listing.read_text())
    require(list(decoded) == list(range(start, end, 4)), "Truncated or extra helper instructions")
    for pc, (word, mnemonic, _) in decoded.items():
        require(word == struct.unpack_from("<I", data, pc - start)[0] and
                mnemonic != "<unknown>", "Linked byte/decode correspondence")
    for form, word in ACCESS_WORDS.items():
        locations = [pc for pc, row in decoded.items() if row[0] == word]
        require(len(locations) == 1, "One fixed access per operation/width")
        pc = locations[0]
        require(decoded[pc][1] == MNEMONICS[form] and
                re.fullmatch(r"w8,\s*\[c2,\s*#(?:0x0|0)\]", decoded[pc][2]),
                "Fixed capability access operands")
        require(pc - 4 in decoded and decoded[pc - 4][0] == 0xC2C1D041 and
                decoded[pc - 4][1] == "mov" and
                re.fullmatch(r"c1,\s*c2", decoded[pc - 4][2]),
                "Logged operand capture immediately precedes access")
    return decoded


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
        selected_address = number(provider, "selected", 0)
        require(selected_address > 0 and base == selected_address and
                number(record, "cap_address", 0) == selected_address + offset and
                number(record, "cap_length") == length and
                number(record, "cap_perms", 0) == DATA_PERMS,
                "capability metadata " + str(case))

        instruction = number(record, "insn", 0)
        pc = number(record, "pc", 0)
        require(pc > 0 and pc in disassembly, "access PC outside complete linked helper")
        decoded_word, mnemonic, operands = disassembly[pc]
        require(instruction == decoded_word == ACCESS_WORDS[(operation, width)] and
                mnemonic == MNEMONICS[(operation, width)] and
                re.fullmatch(r"w8,\s*\[c2,\s*#(?:0x0|0)\]", operands) and
                number(record, "root_reg") == ((instruction >> 5) & 31) == 2,
                "instruction kind " + str(case))
        instruction_sets.setdefault((operation, width), set()).add((pc, instruction))

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
            "pc": record["pc"], "root_reg": number(record, "root_reg"),
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


def admission_shapes(profile):
    require(profile in GUEST_HASHES, "Explicit supported admission profile required")
    operations = ("load",) if profile == "loads-v1" else ("load", "store")
    return [(op, offset, width) for op in operations for offset, width in ACCESSES]


def validate_bpf_programs(lines, profile):
    shapes = admission_shapes(profile)
    rows = selected(lines, "CBPF_SPATIAL_ADMISSION_BPF ")
    require(len(rows) == 10 * len(shapes), "BPF instruction receipt count")
    by_case = {case: [] for case in range(len(shapes))}
    for row in rows:
        require(number(row, "case") in by_case, "Unexpected BPF case")
        by_case[number(row, "case")].append(row)
    map_fds = set()
    for case, (operation, offset, width) in enumerate(shapes):
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
        if operation == "store":
            expected[7] = (0x72 if width == 1 else 0x6A, 0, 0, offset,
                           0xD1 if width == 1 else 0xD2D1)
            expected[8] = (0xB7, 0, 0, 0, 0)
        require(observed == expected, "fixed BPF fixture " + str(case))
    require(len(map_fds) == 1 and next(iter(map_fds)) >= 0, "BPF map reference")


def verifier_sections(text):
    pattern = re.compile(
        r"CBPF_SPATIAL_ADMISSION_VERIFIER_BEGIN case=(\d+)\n(.*?)"
        r"CBPF_SPATIAL_ADMISSION_VERIFIER_END case=\1", re.S)
    matches = list(pattern.finditer(text))
    result = {int(match[1]): match[2] for match in matches}
    require(len(result) == len(matches), "Duplicate verifier section")
    return result


def validate_admission(lines, text, profile):
    shapes = admission_shapes(profile)
    count = len(shapes)
    begin = one(lines, "CBPF_SPATIAL_ADMISSION_BEGIN ")
    require(begin.get("profile", "loads-v1") == profile, "Admission profile marker")
    for key, expected in {"cases": count, "key": 0, "key_size": 4,
                          "value_size": 7, "max_entries": 2,
                          "execution": 0}.items():
        require(number(begin, key) == expected, "admission begin " + key)
    validate_bpf_programs(lines, profile)
    sections = verifier_sections(text)
    require(set(sections) == set(range(count)), "verifier log sections")
    records = selected(lines, "CBPF_SPATIAL_ADMISSION_CASE ")
    require(len(records) == count, "admission case count")
    indexed = {number(record, "case"): record for record in records}
    require(set(indexed) == set(range(count)), "Duplicate or missing admission case")
    normalized = []
    for case, (operation, offset, width) in enumerate(shapes):
        record = indexed[case]
        admit = offset + width <= 7
        require(record.get("op", "load") == operation, "Admission operation")
        require(number(record, "offset") == offset and
                number(record, "width") == width, "admission access")
        require(record["expected"] == ("admit" if admit else "reject") and
                record["observed"] == record["expected"] and
                record["result"] == "PASS" and
                number(record, "executed") == 0, "admission outcome")
        require((number(record, "errno") == 0) == admit, "Admission errno")
        if not admit:
            require("invalid access to map value" in sections[case] and
                    f"value_size=7 off={offset} size={width}" in sections[case],
                    "verifier bounds diagnostic " + str(case))
        normalized.append({"case": case, "operation": operation, "offset": offset, "width": width,
                           "expected": record["expected"],
                           "observed": record["observed"],
                           "errno": number(record, "errno"), "executed": False})
    summary = one(lines, "CBPF_SPATIAL_ADMISSION_SUMMARY ")
    admitted, rejected = (2, 3) if profile == "loads-v1" else (4, 6)
    require(summary["result"] == "PASS" and number(summary, "cases") == count and
            number(summary, "admitted") == admitted and number(summary, "rejected") == rejected and
            number(summary, "map_create_count") == 1 and
            number(summary, "prog_load_count") == count and
            number(summary, "executions") == 0 and
            number(summary, "failures") == 0, "admission summary")
    return {"profile": profile, "cases": normalized, "admitted": admitted, "rejected": rejected,
            "executions": 0}


BUILD_FILES = ("outputs.sha256", "inputs.sha256", "source-pins.json", "kernel.config",
               "array-authority.patch", "native-observation.patch", "selectivity-test.patch",
               "verifier-before.sha256", "patched-sources.sha256")
LINKED_FILES = ("linked-ranges.json", "complete-linked-disassembly.txt",
                "cbpf_selectivity_native_access.bin")


def build_identity(build):
    outputs, inputs = checksums(build / "outputs.sha256"), checksums(build / "inputs.sha256")
    identity = {"Image": by_suffix(outputs, "/arch/arm64/boot/Image"),
                "vmlinux": by_suffix(outputs, "/vmlinux"),
                "config": by_suffix(outputs, "/.config")}
    require(digest(build / "kernel.config") == identity["config"], "Build configuration identity")
    for name in ("array-authority.patch", "native-observation.patch", "selectivity-test.patch"):
        identity[name] = digest(build / name)
        require(identity[name] == by_suffix(inputs, "/" + name), "Build overlay identity " + name)
    pins = json.loads((build / "source-pins.json").read_text())
    require(pins["verified_tree"] == "e6c69574c16bc2b9bce06329f9ac3f4b3269e79a", "Inherited source tree")
    require((build / "verifier-before.sha256").read_text().strip() == VERIFIER_SHA256 and
            by_suffix(checksums(build / "patched-sources.sha256"), "/kernel/bpf/verifier.c") == VERIFIER_SHA256,
            "Unchanged inherited verifier")
    identity["source_tree"] = pins["verified_tree"]
    identity["verifier"] = VERIFIER_SHA256
    settings = dict(line.split("=", 1) for line in (build / "kernel.config").read_text().splitlines()
                    if line.startswith("CONFIG_") and "=" in line)
    for option in ("CBPF_ARRAY_AUTHORITY", "CBPF_SPATIAL_SELECTIVITY_TEST", "BPF_SYSCALL",
                   "BPF_JIT", "BPF_UNPRIV_DEFAULT_OFF", "ARM64_MORELLO", "CHERI_PURECAP_UABI",
                   "STRICT_KERNEL_RWX", "STRICT_MODULE_RWX", "SECURITY", "RANDOMIZE_BASE"):
        require(settings.get("CONFIG_" + option) == "y", "Required configuration " + option)
    require(settings.get("CONFIG_CAPEBPF_SPATIAL_OFFLOAD", "n") == "n" and
            settings.get("CONFIG_CPU_BIG_ENDIAN", "n") == "n" and
            all(value in ("n", "0") for key, value in settings.items()
                if key.startswith("CONFIG_CAPEBPF_TEST_")), "Excluded test modes")
    return identity


def relocation(text, command, origin, mode):
    argv = shlex.split(command)
    require(argv.count("-append") == 1 and argv.count("-kernel") == 1, "QEMU command shape")
    append = shlex.split(argv[argv.index("-append") + 1])
    logged = re.findall(r"Kernel command line: ([^\n]+)", text)
    require(len(logged) == 1, "Recorded kernel command line")
    boot_options = logged[0].split()
    require(("cbpf.selectivity_calibration=1" in append) == (mode == "calibration") and
            ("cbpf.selectivity_calibration=1" in boot_options) == (mode == "calibration"),
            "Calibration boot mode")
    kaslr = [line for line in text.splitlines() if "KASLR" in line]
    require(len(kaslr) == 1, "Missing/contradictory KASLR basis")
    if origin == "new-run":
        require("nokaslr" in append and "nokaslr" in boot_options and
                "KASLR disabled on command line" in kaslr[0], "Explicit zero relocation")
        basis = "explicit nokaslr command and boot observation"
    else:
        require("KASLR disabled due to lack of seed" in kaslr[0] and
                "nokaslr" not in append and "nokaslr" not in boot_options,
                "Retained zero relocation basis")
        basis = "retained boot explicitly reports KASLR disabled due to lack of seed"
    return {"offset": 0, "basis": basis}, argv[argv.index("-kernel") + 1]


def validate_run(run, expected_mode=None):
    metadata = json.loads((run / "validation.json").read_text())
    require(metadata["schema"] == "cbpf-spatial-validation-inputs-v2", "Validation input schema")
    mode, profile, origin = metadata["mode"], metadata["admission_profile"], metadata["origin"]
    require(mode in ("matrix", "calibration") and origin in ("retained-run", "new-run"), "Run edition")
    require(expected_mode is None or mode == expected_mode, "Required calibration mode")
    require(profile in GUEST_HASHES and digest(run / "guest.c") == GUEST_HASHES[profile],
            "Explicit admission profile/guest identity")
    require((origin == "retained-run") == (profile == "loads-v1"), "Run/profile edition")
    identity = build_identity(run / "build-receipt")
    recorded = checksums(run / "inputs.sha256")
    for suffix, expected in (("/arch/arm64/boot/Image", identity["Image"]),
                             ("/vmlinux", identity["vmlinux"]), ("/.config", identity["config"]),
                             ("/guest.c", GUEST_HASHES[profile])):
        require(by_suffix(recorded, suffix) == expected, "Run/build binding " + suffix)
    require(digest(run / "kernel.config") == identity["config"], "Run configuration")
    for name in ("init", "initramfs.cpio.gz"):
        require(digest(run / name) == by_suffix(recorded, "/" + name), "Guest binary binding " + name)
    text = (run / "boot.log").read_text(errors="strict")
    completion = validate_completion(text, (run / "qemu-exit.txt").read_text())
    require(text.count("CBPF_SPATIAL_ADMISSION poweroff=begin result=PASS") == 1 and
            text.rfind("reboot: Power down") > text.rfind("poweroff=begin"), "Ordered guest completion")
    placement, kernel_path = relocation(text, (run / "qemu-command.sh").read_text(), origin, mode)
    require(recorded.get(kernel_path) == identity["Image"], "Launched kernel/input binding")
    argv = shlex.split((run / "qemu-command.sh").read_text())
    require(argv.count("-initrd") == 1 and
            recorded.get(argv[argv.index("-initrd") + 1]) == digest(run / "initramfs.cpio.gz"),
            "Launched guest/input binding")
    decoded = linked_helper(run / "linked", identity["vmlinux"])
    native = validate_native(text.splitlines(), mode, decoded)
    admission = validate_admission(text.splitlines(), text, profile)
    calibration = None
    if origin == "new-run" and mode == "matrix":
        calibration = validate_run(run / "calibration", expected_mode="calibration")
        require(calibration == json.loads((run / "calibration/results.json").read_text()),
                "Missing/stale passing calibration receipt")
        require(calibration["build_identity"] == identity, "Calibration kernel/configuration/overlay mismatch")
    else:
        require(not (run / "calibration").exists(), "Unexpected nested calibration")
    paths = ["validation.json", "boot.log", "inputs.sha256", "guest.c", "kernel.config",
             "qemu-command.sh", "qemu-exit.txt", "init", "initramfs.cpio.gz"]
    paths += ["build-receipt/" + name for name in BUILD_FILES]
    paths += ["linked/" + name for name in LINKED_FILES]
    return {
        "schema": "cbpf-spatial-selectivity-v2",
        "result": "PASS",
        "mode": mode, "origin": origin,
        "checker_sha256": digest(Path(__file__)),
        "shared_checks_sha256": digest(Path(__file__).with_name("native_receipt_common.py")),
        "input_sha256": {name: digest(run / name) for name in paths},
        "build_identity": identity, "relocation": placement, "completion": completion,
        "native": native,
        "verifier_admission": admission,
        "calibration": calibration,
        "scope": {
            "native_fixture": "fixed trusted synthetic validation through production provider",
            "invalid_bpf_execution": False,
            "original_cve_execution": False,
            "complete_mediation_claim": False,
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Offline check of one self-contained v2 spatial receipt")
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = validate_run(args.run)
    require(args.output.resolve() not in {(args.run / name).resolve() for name in result["input_sha256"]},
            "Output must not overwrite an input")
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"CBPF spatial selectivity {result['mode']}: PASS "
          f"native={result['native']['observations']} "
          f"admission={len(result['verifier_admission']['cases'])} executions=0")


if __name__ == "__main__":
    main()
