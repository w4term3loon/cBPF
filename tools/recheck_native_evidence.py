#!/usr/bin/env python3
"""Recheck committed native receipts on the host; never build or boot kernels."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from check_spatial_selectivity import validate_run
from native_receipt_common import require


def main():
    root = Path(__file__).resolve().parents[1]
    spatial = root / "evidence/current/spatial-selectivity"
    for name in ("revalidation/calibration", "revalidation/matrix", "matrix-v2"):
        run = spatial / name
        actual = validate_run(run)
        expected = json.loads((run / "results.json").read_text())
        require(actual == expected, "Spatial recheck differs from published receipt: " + name)
        print(f"Spatial {name}: PASS, native={actual['native']['observations']}, "
              f"admission={len(actual['verifier_admission']['cases'])}, executed=0")
    ownership = root / "evidence/current/ownership-native-trace"
    (root / "build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ownership-receipt-recheck.", dir=root / "build") as temp:
        output = Path(temp) / "results.json"
        process = subprocess.run([sys.executable, str(root / "tools/check_ownership_trace.py"),
            "--log", str(ownership / "run/boot.log"), "--inspection-directory",
            str(ownership / "derivation"), "--run-inputs", str(ownership / "run/inputs.sha256"),
            "--kernel-config", str(ownership / "run/kernel.config"),
            "--qemu-exit", str(ownership / "run/qemu-exit.txt"),
            "--output", str(output), "--native-directory", temp],
            check=True, capture_output=True, text=True)
        actual = json.loads(output.read_text())
        original = json.loads((ownership / "run/results.json").read_text())
        require(all(actual[key] == value for key, value in original.items()),
                "Ownership original observations changed")
        completion = json.loads((ownership / "revalidation/completion.json").read_text())
        require(all(actual[key] == value for key, value in completion.items()),
                "Ownership completion observations changed")
        require(actual == json.loads((ownership / "inspection/results.json").read_text()),
                "Ownership native recheck differs from published receipt")
        for case in actual["cases"]:
            filename = "native-" + case["case"] + ".bin"
            require((Path(temp) / filename).read_bytes() == (ownership / "run" / filename).read_bytes(),
                    "Ownership retained native binary differs from logged words")
        print(process.stdout.strip())
    print("Offline spatial and fixed ownership byte/operand/target rechecks; no native execution or external reproduction.")


if __name__ == "__main__":
    main()
