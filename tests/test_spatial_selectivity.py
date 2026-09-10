"""Host-only adversarial receipt tests; constructed records are not native runs."""
import copy
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import check_spatial_selectivity as check
from native_receipt_common import digest, validate_completion
from prepare_spatial_selectivity import retained, calibration_check


def replace_field(line, key, value):
    changed, count = re.subn(r"(?<!\w)" + re.escape(key) + r"=[^\s]+", f"{key}={value}", line)
    assert count == 1, (key, line)
    return changed


class SpatialReceipts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory()
        cls.base = Path(cls.workspace.name) / "retained"
        retained(ROOT / "evidence/current/spatial-selectivity", cls.base)
        cls.matrix_path = cls.base / "matrix"
        cls.text = (cls.matrix_path / "boot.log").read_text()
        cls.lines = cls.text.splitlines()
        cls.identity = check.build_identity(cls.matrix_path / "build-receipt")
        cls.decoded = check.linked_helper(cls.matrix_path / "linked", cls.identity["vmlinux"])

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def mutated(self, case, **changes):
        lines = self.lines.copy()
        index, = [i for i, line in enumerate(lines)
                  if f"CBPF_SPATIAL_SELECTIVITY_CASE mode=matrix case={case} " in line]
        for key, value in changes.items():
            lines[index] = replace_field(lines[index], key, value)
        return lines

    def clone(self, mode="matrix"):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        run = Path(temp.name) / mode
        shutil.copytree(self.base / mode, run)
        return run

    def test_retained_controls_pass(self):
        matrix = check.validate_run(self.matrix_path)
        self.assertEqual((matrix["native"]["observations"], matrix["native"]["permits"],
                          matrix["native"]["rejects"]), (30, 22, 8))
        calibration = check.validate_run(self.base / "calibration")
        self.assertEqual((calibration["native"]["permits"], calibration["native"]["rejects"]), (1, 1))
        self.assertEqual(matrix["verifier_admission"]["profile"], "loads-v1")

    def test_every_base_must_equal_provider(self):
        records = check.selected(self.lines, "CBPF_SPATIAL_SELECTIVITY_CASE ")
        for case, record in enumerate(records):
            with self.subTest(case=case), self.assertRaises(ValueError):
                check.validate_native(self.mutated(case,
                    cap_base=hex(int(record["cap_base"], 0) + 64),
                    cap_address=hex(int(record["cap_address"], 0) + 64)), "matrix", self.decoded)

    def test_native_rejections(self):
        probes = [(0, {"pc": "0x0"}), (3, {"pc": "0x0", "fault_pc": "0x0"}),
                  (3, {"pc": "0x1234", "fault_pc": "0x1234"}),
                  (0, {"root_reg": 3}), (3, {"root_reg": 3}),
                  (3, {"fsc": "0x11"}), (3, {"wnr": 1}),
                  (3, {"fault_count": 2}), (3, {"fault_overflow": 1}),
                  (3, {"value": "0x0"}), (0, {"cap_address": "0x0"}),
                  (0, {"observed": "reject"}),
                  (18, {"after": "00223344556629a781828384858687bf"})]
        for case, fields in probes:
            with self.subTest(case=case, fields=fields), self.assertRaises(ValueError):
                check.validate_native(self.mutated(case, **fields), "matrix", self.decoded)

    def test_wrong_in_helper_pc(self):
        pc, = [pc for pc, row in self.decoded.items() if row[0] == check.ACCESS_WORDS["store", 1]]
        with self.assertRaises(ValueError):
            check.validate_native(self.mutated(3, pc=hex(pc), fault_pc=hex(pc),
                insn="0xe2000048", fault_insn="0xe2000048"), "matrix", self.decoded)

    def test_contradictory_decoded_operands(self):
        for operands in ("w8, [c3, #0x0]", "w8, [c2, #0x1]", "w8, [x2, #0x0]", "w9, [c2, #0x0]"):
            decoded = copy.deepcopy(self.decoded)
            pc, = [pc for pc, row in decoded.items() if row[0] == check.ACCESS_WORDS["load", 1]]
            word, mnemonic, _ = decoded[pc]
            decoded[pc] = word, mnemonic, operands
            with self.subTest(operands=operands), self.assertRaises(ValueError):
                check.validate_native(self.lines, "matrix", decoded)

    def test_complete_linked_range_required(self):
        run = self.clone()
        listing = run / "linked/complete-linked-disassembly.txt"
        lines = listing.read_text().splitlines(keepends=True)
        listing.write_text("".join(line for line in lines if not re.match(r"ffff8000801c47cc:", line)))
        receipt = run / "linked/linked-ranges.json"
        data = json.loads(receipt.read_text())
        data["disassembly"] = {"bytes": listing.stat().st_size, "sha256": digest(listing)}
        receipt.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "Truncated"):
            check.validate_run(run)

    def test_relocation_basis_required(self):
        command = (self.matrix_path / "qemu-command.sh").read_text()
        for text in (self.text.replace("KASLR", "ASLR"),
                     self.text + "KASLR enabled\n",
                     self.text.replace("KASLR disabled due to lack of seed", "KASLR enabled")):
            with self.subTest(), self.assertRaises(ValueError):
                check.relocation(text, command, "retained-run", "matrix")
        with self.assertRaises(ValueError):
            check.relocation(self.text, command, "new-run", "matrix")

    def test_matching_efi_and_kernel_nokaslr_messages(self):
        argv = shlex.split((self.matrix_path / "qemu-command.sh").read_text())
        argv[argv.index("-append") + 1] += " nokaslr"
        text = self.text.replace("KASLR disabled due to lack of seed", "KASLR disabled on command line")
        text = text.replace("bpf_jit_enable=1", "bpf_jit_enable=1 nokaslr")
        efi = "EFI stub: KASLR disabled on kernel command line\n"
        result, _ = check.relocation(efi + text, shlex.join(argv), "new-run", "matrix")
        self.assertEqual(result["offset"], 0)
        for extra in (efi, "KASLR enabled\n"):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                check.relocation(extra + efi + text, shlex.join(argv), "new-run", "matrix")

    def test_prelaunch_receipt_keeps_its_checker_identity(self):
        saved = check.validate_run(self.base / "calibration")
        actual = copy.deepcopy(saved)
        actual["checker_sha256"] = "1" * 64
        inputs = {"/run/check_spatial_selectivity.executed.py": saved["checker_sha256"],
                  "/run/native_receipt_common.py": saved["shared_checks_sha256"]}
        check.validate_calibration_receipt(actual, saved, inputs)
        saved["checker_sha256"] = "2" * 64
        with self.assertRaisesRegex(ValueError, "checker identity"):
            check.validate_calibration_receipt(actual, saved, inputs)

    def test_new_matrix_requires_calibration(self):
        # Before there is a new native receipt, exercise the shared gate itself.
        with self.assertRaises((FileNotFoundError, ValueError)):
            calibration_check(self.base, self.base / "missing")

    def test_completion(self):
        validate_completion(self.text, "0\n")
        for status in ("1", "124", "-15", "0\n0"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                validate_completion(self.text, status)
        for marker in ("Kernel panic", "Oops:", "BUG:", "WARNING:", "refcount_t:",
                       "timeout", "Unable to handle kernel", "poweroff=FAIL"):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                validate_completion(self.text + "\n" + marker, "0")
        with self.assertRaises(ValueError):
            validate_completion(self.text.replace("reboot: Power down", "shutdown requested"), "0")

    def test_explicit_guest_profile(self):
        run = self.clone()
        path = run / "validation.json"
        data = json.loads(path.read_text())
        data["admission_profile"] = "loads-stores-v2"
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "profile/guest"):
            check.validate_run(run)

    def test_ten_case_admission_shape(self):
        # Constructed host records exercise parser logic, not verifier behavior.
        sections = check.verifier_sections(self.text)
        generated = ["CBPF_SPATIAL_ADMISSION_BEGIN profile=loads-stores-v2 cases=10 key=0 key_size=4 value_size=7 max_entries=2 execution=0"]
        for case, (operation, offset, width) in enumerate(check.admission_shapes("loads-stores-v2")):
            original = case % 5
            rows = [line for line in self.lines if f"CBPF_SPATIAL_ADMISSION_BPF case={original} " in line]
            for pc, row in enumerate(rows):
                row = replace_field(row, "case", case)
                if operation == "store" and pc == 7:
                    for key, value in {"code": "72" if width == 1 else "6a", "dst": 0,
                                       "imm": 0xD1 if width == 1 else 0xD2D1}.items():
                        row = replace_field(row, key, value)
                if operation == "store" and pc == 8:
                    for key, value in {"code": "b7", "src": 0}.items():
                        row = replace_field(row, key, value)
                generated.append(row)
            generated += [f"CBPF_SPATIAL_ADMISSION_VERIFIER_BEGIN case={case}", sections[original],
                          f"CBPF_SPATIAL_ADMISSION_VERIFIER_END case={case}"]
            outcome = "admit" if offset + width <= 7 else "reject"
            generated.append(f"CBPF_SPATIAL_ADMISSION_CASE case={case} op={operation} offset={offset} width={width} expected={outcome} observed={outcome} errno={0 if outcome == 'admit' else 13} executed=0 result=PASS")
        generated.append("CBPF_SPATIAL_ADMISSION_SUMMARY result=PASS cases=10 admitted=4 rejected=6 map_create_count=1 prog_load_count=10 executions=0 failures=0")
        text = "\n".join(generated)
        result = check.validate_admission(text.splitlines(), text, "loads-stores-v2")
        self.assertEqual((result["admitted"], result["rejected"], result["executions"]), (4, 6, 0))
        with self.assertRaises(ValueError):
            check.validate_admission(self.lines, self.text, "loads-stores-v2")
        malformed = text.replace("code=72 dst=0", "code=62 dst=0", 1)
        with self.assertRaises(ValueError):
            check.validate_admission(malformed.splitlines(), malformed, "loads-stores-v2")

    def test_calibration_gate(self):
        calibration = self.clone("calibration")
        build = calibration.parent / "build"
        shutil.copytree(calibration / "build-receipt", build / "receipt")
        calibration_check(build, calibration)
        receipt = calibration / "results.json"
        data = json.loads(receipt.read_text())
        data["result"] = "FAIL"
        receipt.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "modified or stale"):
            calibration_check(build, calibration)
        receipt.unlink()
        with self.assertRaises(FileNotFoundError):
            calibration_check(build, calibration)

    def test_mismatched_calibration_image_and_overlay(self):
        for field in ("Image", "array-authority.patch"):
            calibration = self.clone("calibration")
            build = calibration.parent / "build"
            shutil.copytree(calibration / "build-receipt", build / "receipt")
            if field == "Image":
                manifest = build / "receipt/outputs.sha256"
                manifest.write_text(manifest.read_text().replace(self.identity["Image"], "1" * 64))
            else:
                patch = build / "receipt" / field
                patch.write_bytes(patch.read_bytes() + b"\n")
                manifest = build / "receipt/inputs.sha256"
                manifest.write_text(manifest.read_text().replace(self.identity[field], digest(patch)))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "mismatch"):
                calibration_check(build, calibration)

    def test_launcher_requires_calibration_before_build_or_boot(self):
        env = os.environ.copy()
        env.pop("CBPF_SPATIAL_SELECTIVITY_CALIBRATION", None)
        result = subprocess.run(["bash", str(ROOT / "tools/run_spatial_selectivity.sh"),
                                 "/not-a-real-kernel-build"], env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CBPF_SPATIAL_SELECTIVITY_CALIBRATION", result.stderr)
        self.assertNotIn("QEMU", result.stdout)


if __name__ == "__main__":
    unittest.main()
