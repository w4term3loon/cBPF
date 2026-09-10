#!/usr/bin/env python3
"""Prepare fixed spatial receipt inputs or check calibration; never boot a guest."""
import argparse
import json
from pathlib import Path
import shutil

from check_spatial_selectivity import BUILD_FILES, LINKED_FILES, build_identity, validate_run
from native_receipt_common import require
from package_native_extension import extract_linked


def metadata(run, mode, profile, origin):
    (run / "validation.json").write_text(json.dumps({
        "schema": "cbpf-spatial-validation-inputs-v2", "mode": mode,
        "admission_profile": profile, "origin": origin}, indent=2) + "\n")


def copy_files(source, destination, names):
    destination.mkdir()
    for name in names:
        shutil.copy2(source / name, destination / name)


def calibration_check(build, calibration):
    actual = validate_run(calibration, expected_mode="calibration")
    require(actual == json.loads((calibration / "results.json").read_text()),
            "Calibration receipt is absent, modified or stale; recheck its artifacts first")
    require(actual["build_identity"] == build_identity(build / "receipt"),
            "Calibration kernel/configuration/overlay mismatch")
    return actual


def retained(package, output):
    require(not output.exists(), "Refusing to overwrite retained revalidation")
    output.mkdir(parents=True)
    for mode, source in (("calibration", "calibration"), ("matrix", "run")):
        run = output / mode
        shutil.copytree(package / source, run)
        (run / "results.json").rename(run / "original-results.json")
        copy_files(package / "build", run / "build-receipt", BUILD_FILES)
        copy_files(package / "derivation", run / "linked", LINKED_FILES)
        metadata(run, mode, "loads-v1", "retained-run")
        result = validate_run(run)
        (run / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Retained matrix/calibration revalidated; no native execution: " + str(output))


def prepare(build, run, mode, calibration):
    if mode == "matrix":
        require(calibration is not None, "A passing calibration receipt is required")
        calibration_check(build, calibration)
        shutil.copytree(calibration, run / "calibration")
    copy_files(build / "receipt", run / "build-receipt", BUILD_FILES)
    linked = run / "linked"
    linked.mkdir()
    commands = []
    extract_linked(build / "objects/vmlinux", ["cbpf_selectivity_native_access"], linked, commands)
    (linked / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    metadata(run, mode, "loads-stores-v2", "new-run")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    old = sub.add_parser("retained")
    old.add_argument("package", type=Path)
    old.add_argument("output", type=Path)
    new = sub.add_parser("prepare")
    new.add_argument("build", type=Path)
    new.add_argument("run", type=Path)
    new.add_argument("--mode", choices=("matrix", "calibration"), required=True)
    new.add_argument("--calibration", type=Path)
    gate = sub.add_parser("calibration-check")
    gate.add_argument("build", type=Path)
    gate.add_argument("calibration", type=Path)
    args = parser.parse_args()
    if args.action == "retained":
        retained(args.package, args.output)
    elif args.action == "prepare":
        prepare(args.build, args.run, args.mode, args.calibration)
    else:
        calibration_check(args.build, args.calibration)
        print("Passing calibration rechecked and bound to this kernel/configuration/overlay")


if __name__ == "__main__":
    main()
