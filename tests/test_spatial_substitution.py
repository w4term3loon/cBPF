"""Adversarial host checks of the fixed receipt; mutations are not native runs."""
import copy
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import check_spatial_selectivity as extent
import check_spatial_substitution as check


class SpatialSubstitution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = ROOT / "evidence/current/spatial-selectivity/substitution"
        cls.lines = (cls.receipt / "boot.log").read_text().splitlines()
        identity = extent.build_identity(cls.receipt / "build-receipt")
        cls.decoded = extent.linked_helper(cls.receipt / "linked", identity["vmlinux"])

    def mutated(self, target_case, **changes):
        lines = self.lines.copy()
        index, = [i for i, line in enumerate(lines)
                  if f"CBPF_SPATIAL_SUBSTITUTION_CASE case={target_case} " in line]
        for key, value in changes.items():
            lines[index], count = re.subn(r"(?<!\w)" + key + r"=[^\s]+",
                                         f"{key}={value}", lines[index])
            self.assertEqual(count, 1)
        return lines

    def clone(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        run = Path(temp.name) / "substitution"
        shutil.copytree(self.receipt, run)
        return run

    def test_observed_counterexample_passes(self):
        result = check.validate_run(self.receipt)
        self.assertEqual(result, json.loads((self.receipt / "results.json").read_text()))
        self.assertEqual([r["binding_match"] for r in result["native"]["cases"]], [True, True, False])
        self.assertEqual([r["returned_byte"] for r in result["native"]["cases"]], [0x29, 0x87, 0x87])
        self.assertEqual(result["verifier_admission"]["executions"], 0)

    def test_binding_mismatch_is_required(self):
        for case, fields in ((2, {"binding_match": 1}), (1, {"binding_match": 0}),
                             (2, {"intended_key": 1}), (2, {"actual_provider_key": 0}),
                             (2, {"intended_map": "0x0"}), (2, {"actual_map": "0x0"}),
                             (2, {"intended_base": "0x0"})):
            with self.subTest(case=case, fields=fields), self.assertRaises(ValueError):
                check.validate_native(self.mutated(case, **fields), self.decoded)

    def test_extent_checker_keeps_its_original_profile(self):
        with self.assertRaisesRegex(ValueError, "Validation input schema"):
            extent.validate_run(self.receipt)

    def test_wrong_operand_metadata_rejected(self):
        for field, value in (("cap_base", "0x0"), ("cap_address", "0x0"),
                             ("cap_length", 8), ("cap_tag", 0), ("cap_sealed", 1),
                             ("cap_perms", "0x10001"), ("operand_match", 0),
                             ("width", 2), ("offset", 7)):
            for case in range(3):
                with self.subTest(case=case, field=field), self.assertRaises(ValueError):
                    check.validate_native(self.mutated(case, **{field: value}), self.decoded)

    def test_wrong_byte_or_storage_rejected(self):
        for case, field, value in ((2, "value", "0x29"), (0, "value", "0x87"),
                                   (0, "before", "00" * 16), (1, "after", "00" * 16),
                                   (2, "before", "11223344556629a711223344556629a7")):
            with self.subTest(case=case, field=field), self.assertRaises(ValueError):
                check.validate_native(self.mutated(case, **{field: value}), self.decoded)

    def test_faults_and_failed_case_rejected(self):
        for field, value in (("fault_count", 1), ("fault_overflow", 1),
                             ("err", -14), ("result", "FAIL")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                check.validate_native(self.mutated(2, **{field: value}), self.decoded)

    def test_missing_repeated_or_reordered_cases_rejected(self):
        index, = [i for i, line in enumerate(self.lines) if "CASE case=1 name=legitimate_b " in line]
        for lines in (self.lines[:index] + self.lines[index + 1:],
                      self.lines[:index] + [self.lines[index]] + self.lines[index:],
                      self.mutated(1, case=2)):
            with self.subTest(), self.assertRaises(ValueError):
                check.validate_native(lines, self.decoded)

    def test_independent_b_provider_required(self):
        lines = [line for line in self.lines if not
                 ("CBPF_SPATIAL_NATIVE_VALUE " in line and " index=1 " in line)]
        with self.assertRaises(ValueError):
            check.validate_native(lines, self.decoded)
        lines = [line.replace(" index=1 ", " index=0 ") if "CBPF_SPATIAL_NATIVE_VALUE " in line
                 else line for line in self.lines]
        with self.assertRaises(ValueError):
            check.validate_native(lines, self.decoded)

    def test_instruction_and_capture_checked(self):
        for fields in ({"pc": "0x0"}, {"root_reg": 3}, {"insn": "0xe2000048"}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                check.validate_native(self.mutated(2, **fields), self.decoded)
        pc, = [pc for pc, row in self.decoded.items() if row[0] == extent.ACCESS_WORDS["load", 1]]
        for address, row in ((pc, (0xE2000448, "ldurb", "w8, [x2, #0]")),
                             (pc - 4, (0xC2C1D041, "mov", "c1, c3"))):
            decoded = copy.deepcopy(self.decoded)
            decoded[address] = row
            with self.subTest(address=address), self.assertRaises(ValueError):
                check.validate_native(self.lines, decoded)

    def test_full_receipt_rejects_timeout_or_incomplete_shutdown(self):
        run = self.clone()
        (run / "qemu-exit.txt").write_text("124\n")
        with self.assertRaisesRegex(ValueError, "exit zero"):
            check.validate_run(run)
        (run / "qemu-exit.txt").write_text("0\n")
        log = run / "boot.log"
        log.write_text(log.read_text().replace("reboot: Power down", "shutdown requested"))
        with self.assertRaisesRegex(ValueError, "shutdown completion"):
            check.validate_run(run)

    def test_substitution_mode_and_calibration_required(self):
        run = self.clone()
        command = run / "qemu-command.sh"
        original = command.read_text()
        command.write_text(original.replace("cbpf.selectivity_substitution=1", "cbpf.selectivity_substitution=0"))
        with self.assertRaisesRegex(ValueError, "substitution boot mode"):
            check.validate_run(run)
        command.write_text(original)
        shutil.rmtree(run / "calibration")
        with self.assertRaises((FileNotFoundError, ValueError)):
            check.validate_run(run)


if __name__ == "__main__":
    unittest.main()
