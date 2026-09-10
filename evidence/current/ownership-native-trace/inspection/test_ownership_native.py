"""Constructed host mutations test receipt logic, not runtime execution."""
import copy
import json
from pathlib import Path
import re
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import check_ownership_trace as trace
import ownership_native_checks as check
from native_receipt_common import digest

PACKAGE = ROOT / "evidence/current/ownership-native-trace"


class OwnershipNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (PACKAGE / "run/boot.log").read_text()
        cls.sections = trace.native_sections(trace.normalize(cls.raw))
        cls.ranges, cls.linked = check.linked_receipt(PACKAGE / "derivation",
            PACKAGE / "run/inputs.sha256", PACKAGE / "run/kernel.config", cls.raw)

    def workspace(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        return Path(temp.name)

    def arguments(self, name="stale_read"):
        lines = self.sections[name]
        accepted, = [re.fullmatch(r"CBPF_NATIVE accepted insns=\d+ words=\d+ entry=([0-9a-f]+) restricted_exit=(\d+) executive_exit=(\d+) template_check=pass", line)
                     for line in lines if line.startswith("CBPF_NATIVE accepted ")]
        entered, = [re.fullmatch(r"CBPF_ENTER restricted_base=(0x[0-9a-f]+) restricted_size=(\d+) executive_base=(0x[0-9a-f]+) executive_size=(\d+) .+", line)
                    for line in lines if line.startswith("CBPF_ENTER ")]
        values = [int(line.rsplit("=", 1)[1], 16) for line in lines if line.startswith("CBPF_NATIVE word ")]
        maps = [(int(m[1]), int(m[2])) for line in lines
                if (m := re.fullmatch(r"CBPF_NATIVE map pc=\d+ begin=(\d+) end=(\d+) code=\w+ op=\d+", line))]
        listing = self.workspace() / "listing.txt"
        shutil.copy2(PACKAGE / f"derivation/native-{name}-disassembly.txt", listing)
        return dict(case=name, values=values, maps=maps, bpf=trace.expected_native_bpf(name),
            entry=int(accepted[1], 16), restricted=int(accepted[2]), executive=int(accepted[3]),
            enter=tuple(int(value, 0) for value in entered.groups()), listing=listing,
            ranges=copy.deepcopy(self.ranges))

    def rewrite_word(self, args, index, word, assembly):
        """Keep the forged listing and encoding bytes internally consistent."""
        args["values"][index] = word
        lines = args["listing"].read_text().splitlines()
        encoding = ",".join(f"0x{x:02x}" for x in struct.pack("<I", word))
        lines[index] = f"{index:04d}  {args['entry'] + index * 4:#018x}  {word:08x}  {assembly} // encoding: [{encoding}]"
        args["listing"].write_text("\n".join(lines) + "\n")

    def test_all_three_retained_images(self):
        for name, count in (("positive", 153), ("stale_read", 163), ("repeated_release", 163)):
            args = self.arguments(name)
            with self.subTest(case=name):
                self.assertEqual(check.fixed_image(**args)["checked_words"], count)
                trace.validate_native(name, self.sections[name], self.workspace(),
                                      PACKAGE / "derivation", self.ranges)
        check.linked_terminal_checks(self.ranges, self.linked)

    def test_every_non_nop_word_rejects_nop(self):
        for name in trace.NAMES:
            baseline = self.arguments(name)
            original = baseline["listing"].read_bytes()
            for index, word in enumerate(baseline["values"].copy()):
                if word == 0xD503201F:
                    continue
                self.rewrite_word(baseline, index, 0xD503201F, "nop")
                with self.subTest(case=name, word=index), self.assertRaises(ValueError):
                    check.fixed_image(**baseline)
                baseline["values"][index] = word
                baseline["listing"].write_bytes(original)

    def test_review_mostly_nop_counterexample(self):
        for name in trace.NAMES:
            args = self.arguments(name)
            preserved = {args["maps"][4][0], args["maps"][9][0]}
            if name != "positive":
                preserved.add(args["maps"][15][0])
            preserved |= {begin + 3 for (begin, _), insn in zip(args["maps"], args["bpf"]) if insn[0] == "85"}
            for index in range(len(args["values"])):
                if index not in preserved:
                    self.rewrite_word(args, index, 0xD503201F, "nop")
            with self.subTest(case=name), self.assertRaises(ValueError):
                check.fixed_image(**args)

    def test_critical_targets_with_matching_forged_decode(self):
        # Entry failure, both null exits, both BPF exits, caller fallback.
        for index in (27, 65, 77, 110, 115, 160):
            args = self.arguments()
            word = args["values"][index]
            kind = "cbz" if index in (65, 77, 160) else "b"
            changed = word + (32 if kind == "cbz" else 1)
            target = check.branch_target(changed, args["entry"] + 4 * index, kind)
            operand = f"x{changed & 31}, " if kind == "cbz" else ""
            self.rewrite_word(args, index, changed, f"{kind} {operand}#{target - args['entry'] - 4 * index}")
            with self.subTest(index=index), self.assertRaises(ValueError):
                check.fixed_image(**args)

    def test_wrong_operand_call_and_enter_target(self):
        for index, word, asm in ((94, 0xC2C1D280, "mov c0, c20"),
                (95, 0xD2800064, "mov x4, #3"),
                (96, 0xD2800265, "mov x5, #19"),
                (98, 0xC2C23202, "blrs c16"),
                (20, 0xD29DEF8A, "mov x10, #61308")):
            args = self.arguments()
            self.rewrite_word(args, index, word, asm)
            with self.subTest(index=index), self.assertRaises(ValueError):
                check.fixed_image(**args)

    def test_map_holes_and_entry_envelope(self):
        for mutation in ("first", "last", "empty", "entry", "bounds", "epilogue"):
            args = self.arguments()
            if mutation == "first":
                args["maps"][0] = (55, 60)
            elif mutation == "last":
                args["maps"][-1] = (115, 115)
            elif mutation == "empty":
                args["maps"][17] = (95, 95)
            elif mutation == "entry":
                args["entry"] = 0
            elif mutation == "bounds":
                args["enter"] = (args["enter"][0] - 4, args["enter"][1] + 4, *args["enter"][2:])
            else:
                args["executive"] += 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                check.fixed_image(**args)

    def test_missing_or_falsely_decoded_listing(self):
        for change in ("truncate", "address", "operand", "encoding"):
            args = self.arguments()
            text = args["listing"].read_text()
            if change == "truncate":
                text = "\n".join(text.splitlines()[:-1])
            elif change == "address":
                text = text.replace(hex(args["entry"]), "0x0000000000000000", 1)
            elif change == "operand":
                text = text.replace("retr\tc16", "retr\tc17")
            else:
                text = text.replace("encoding: [0xc9", "encoding: [0xc8", 1)
            args["listing"].write_text(text)
            with self.subTest(change=change), self.assertRaises(ValueError):
                check.fixed_image(**args)

    def test_every_gateway_word_is_checked(self):
        start, end = self.ranges["cbpf_gateway"]
        for adjustment in (-4, 4):
            ranges = self.ranges.copy()
            ranges["cbpf_gateway"] = (start, end + adjustment)
            with self.subTest(extent=adjustment), self.assertRaises(ValueError):
                check.linked_terminal_checks(ranges, self.linked)
        for pc in range(start, end, 4):
            mutated = self.linked.copy()
            mutated[pc] = 0xD503201F, "nop"
            with self.subTest(pc=hex(pc)), self.assertRaises(ValueError):
                check.linked_terminal_checks(self.ranges, mutated)

    def test_linked_failure_entry_and_cleanup_sequences(self):
        for name, offset in (("cbpf_gate_impl", 0x208), ("cbpf_gate_impl", 0x2F8),
                            ("cbpf_gate_impl", 0x34C), ("cbpf_enter", 0x204),
                            ("cbpf_enter", 0x29C), ("cbpf_test_invoke", 0x340),
                            ("cbpf_test_invoke", 0x354), ("cbpf_test_invoke", 0x284),
                            ("cbpf_consume", 0x40), ("cbpf_consume", 0xD4),
                            ("cbpf_consume", 0x180)):
            mutated = self.linked.copy()
            mutated[self.ranges[name][0] + offset] = 0xD503201F, "nop"
            with self.subTest(symbol=name, offset=offset), self.assertRaises(ValueError):
                check.linked_terminal_checks(self.ranges, mutated)

    def test_linked_image_and_relocation_bindings(self):
        for change in ("kernel", "truncated", "placement"):
            path = self.workspace() / "derivation"
            shutil.copytree(PACKAGE / "derivation", path)
            receipt_path = path / "linked-ranges.json"
            receipt = json.loads(receipt_path.read_text())
            raw = self.raw
            if change == "kernel":
                receipt["vmlinux_sha256"] = "0" * 64
            elif change == "truncated":
                listing = path / "complete-linked-disassembly.txt"
                listing.write_text(listing.read_text().replace("ffff80008003e370: d503245f", "not-an-instruction: d503245f", 1))
                receipt["disassembly"] = {"bytes": listing.stat().st_size, "sha256": digest(listing)}
            else:
                raw = raw.replace("KASLR disabled due to lack of seed", "KASLR enabled")
            receipt_path.write_text(json.dumps(receipt))
            with self.subTest(change=change), self.assertRaises(ValueError):
                check.linked_receipt(path, PACKAGE / "run/inputs.sha256", PACKAGE / "run/kernel.config", raw)

    def test_signed_branch_decoding(self):
        self.assertEqual(check.branch_target(0x17FFFFFF, 0x1000, "b"), 0xFFC)
        self.assertEqual(check.branch_target(0xB4FFFFE0, 0x1000, "cbz"), 0xFFC)
        self.assertEqual(check.branch_target(0x94000002, 0x1000, "bl"), 0x1008)


if __name__ == "__main__":
    unittest.main()
