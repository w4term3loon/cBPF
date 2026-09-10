#!/usr/bin/env python3
"""Extract complete ownership listings from retained bytes; never boot a guest."""
import argparse
import datetime
import json
from pathlib import Path
import re
import struct

from native_receipt_common import by_suffix, checksums, digest, require
from ownership_native_checks import SYMBOLS
from package_native_extension import extract_jit, extract_linked


def prepare(image, run, output):
    require(not output.exists(), "Refusing to overwrite an inspection extraction")
    require(digest(image) == by_suffix(checksums(run / "inputs.sha256"), "/vmlinux"),
            "Extraction kernel/run identity")
    raw = (run / "boot.log").read_text()
    for case in ("positive", "stale_read", "repeated_release"):
        sections = re.findall(rf"CBPF_OWNERSHIP_TRACE case={case} phase=begin\b(.*?)"
                              rf"CBPF_OWNERSHIP_TRACE case={case} phase=end\b", raw, re.S)
        require(len(sections) == 1, "One logged image for " + case)
        rows = re.findall(r"CBPF_NATIVE word index=(\d+) value=([0-9a-f]{8})", sections[0])
        require(rows and [int(index) for index, _ in rows] == list(range(len(rows))), "Logged image indices")
        data = b"".join(struct.pack("<I", int(word, 16)) for _, word in rows)
        path = run / ("native-" + case + ".bin")
        if path.exists():
            require(path.read_bytes() == data, "Preserved native image differs from log")
        else:
            path.write_bytes(data)
    output.mkdir()
    commands = []
    extract_linked(image, SYMBOLS, output, commands)
    extract_jit(run, image, output, commands)
    (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    (output / "extraction.json").write_text(json.dumps({
        "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "vmlinux_sha256": digest(image), "boot_sha256": digest(run / "boot.log"),
        "preparer_sha256": digest(Path(__file__)),
        "extractor_sha256": digest(Path(__file__).with_name("package_native_extension.py")),
        "native_boots": 0,
        "scope": "Complete post-run extraction and LLVM decoding, not semantic inspection or native execution",
    }, indent=2) + "\n")
    print("Complete native/linked disassembly retained; no guest executed: " + str(output))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.image.resolve(), args.run.resolve(), args.output.resolve())
