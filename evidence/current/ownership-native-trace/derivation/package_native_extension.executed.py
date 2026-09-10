#!/usr/bin/env python3
"""Publish the two retained native-extension experiments; never boot a guest.

Copies originals to a fresh private directory before publication. Disassembly
is newly derived evidence, not a rerun, semantic validation or native review.
Requires the already-installed pinned decoder image; never pulls/downloads.
Existing publication packages are never overwritten.
"""
import argparse
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile


PROJECT = Path(__file__).resolve().parents[1]
BUILDER = "sha256:76c8ca062c30aa59b8eb072f30620a2a7e9604515aefe84d64161bf9eb644038"
SDK = "/opt/cheri/output/morello-sdk/bin/"
PACKAGES = ("spatial-selectivity", "ownership-native-trace")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def identity(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def verify_hashes(path, checked):
    rows = path.read_text().splitlines()
    for row in rows:
        digest, name = row.split("  ", 1)
        target = Path(name)
        require(re.fullmatch(r"[0-9a-f]{64}", digest), "Invalid checksum: " + str(path))
        if target not in checked:
            checked[target] = file_digest(target)
        require(checked[target] == digest, "Retained input changed: " + name)
    return {"manifest": str(path), "verified_files": len(rows),
            "sha256": file_digest(path)}


def command(argv, commands, stdin=None):
    result = subprocess.run(argv, input=stdin, capture_output=True, check=True)
    require(not result.stderr, "Unexpected diagnostic: " + result.stderr.decode(errors="replace"))
    commands.append({"argv": argv, "exit_status": result.returncode,
                     "stdin_sha256": identity(stdin)["sha256"] if stdin is not None else None})
    return result.stdout


def docker_tool(name, arguments, image, commands, stdin=None):
    argv = ["docker", "run", "--rm", "--pull=never", "--network", "none",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    if stdin is not None:
        argv.append("-i")
    argv.extend(["-v", str(image) + ":/kernel/vmlinux:ro", BUILDER,
                 SDK + name, *arguments])
    return command(argv, commands, stdin)


def elf_bytes(path, address, size):
    """Read a bounded executable ELF64 section range without a new dependency."""
    with path.open("rb") as stream:
        header = struct.unpack("<16sHHIQQQIHHHHHH", stream.read(64))
        require(header[0][:6] == b"\x7fELF\x02\x01" and header[2] == 183,
                "Expected little-endian AArch64 ELF64")
        section_offset, section_size, section_count = header[6], header[11], header[12]
        require(section_size == 64 and section_count > 0, "Unsupported ELF sections")
        for index in range(section_count):
            stream.seek(section_offset + index * section_size)
            _, kind, flags, base, offset, length, *_ = struct.unpack("<IIQQQQIIQQ", stream.read(64))
            if kind == 1 and flags & 4 and base <= address and address + size <= base + length:
                position = offset + address - base
                stream.seek(position)
                data = stream.read(size)
                require(len(data) == size, "Truncated ELF range")
                return data, {"section_index": index, "elf_file_offset": position}
    raise ValueError("Symbol range is outside executable file-backed sections")


def extract_linked(image, names, output, commands):
    table = command(["readelf", "-sW", str(image)], commands).decode()
    symbols = {}
    for row in table.splitlines():
        fields = row.split()
        if len(fields) == 8 and fields[7] in names:
            require(fields[7] not in symbols, "Ambiguous ELF symbol " + fields[7])
            symbols[fields[7]] = (int(fields[1], 16), int(fields[2]), row.strip())
    require(set(symbols) == set(names), "Missing ELF symbols")
    receipts, listing = [], []
    for name in names:
        address, size, symbol_row = symbols[name]
        basis = "ELF symbol st_size"
        if name == "cbpf_gateway" and size == 0:
            # This assembly label has no .size directive. The next named
            # function is its exclusive boundary, including any alignment.
            size = symbols["cbpf_gate_impl"][0] - address
            basis = "Zero-sized assembly label; exclusive boundary cbpf_gate_impl"
        require(size > 0 and size % 4 == 0, "Invalid linked extent " + name)
        data, location = elf_bytes(image, address, size)
        disassembly = docker_tool("llvm-objdump", ["-d", "--mattr=+morello,+lse",
            f"--start-address={address:#x}", f"--stop-address={address + size:#x}",
            "/kernel/vmlinux"], image, commands)
        decoded = re.findall(rb"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.+)$", disassembly, re.M)
        require(len(decoded) == size // 4, "Incomplete linked disassembly " + name)
        require(b"<unknown>" not in disassembly, "Unknown linked instruction " + name)
        for index, (pc, word, _) in enumerate(decoded):
            require(int(pc, 16) == address + index * 4 and
                    int(word, 16) == struct.unpack_from("<I", data, index * 4)[0],
                    "ELF/disassembly mismatch " + name)
        filename = name + ".bin"
        (output / filename).write_bytes(data)
        listing.append(disassembly)
        receipts.append({"symbol": name, "elf_symbol": symbol_row,
            "start": hex(address), "end_exclusive": hex(address + size),
            "extent_basis": basis, **location, "file": filename, **identity(data)})
    combined = b"\n".join(listing)
    (output / "complete-linked-disassembly.txt").write_bytes(combined)
    write_json(output / "linked-ranges.json", {
        "vmlinux_sha256": file_digest(image), "ranges": receipts,
        "disassembly": identity(combined),
        "scope": "Complete extraction and byte/decoder correspondence only; semantic inspection pending."})


def extract_jit(run, image, output, commands):
    log = (run / "boot.log").read_bytes().decode()
    results = []
    for case in ("positive", "stale_read", "repeated_release"):
        match = re.search(rf"CBPF_OWNERSHIP_TRACE case={case} phase=begin\b(.*?)"
                          rf"CBPF_OWNERSHIP_TRACE case={case} phase=end\b", log, re.S)
        require(match, "Missing native section " + case)
        rows = re.findall(r"CBPF_NATIVE word index=(\d+) value=([0-9a-f]{8})", match[1])
        require([int(index) for index, _ in rows] == list(range(len(rows))), "Native indices")
        data = b"".join(struct.pack("<I", int(word, 16)) for _, word in rows)
        require(data == (run / ("native-" + case + ".bin")).read_bytes(), "Logged native bytes " + case)
        entry_match = re.search(r"CBPF_NATIVE accepted insns=\d+ words=(\d+) entry=([0-9a-f]+)", match[1])
        require(entry_match and int(entry_match[1]) == len(rows), "Native image envelope")
        entry = int(entry_match[2], 16)
        mc_input = "".join(" ".join(f"0x{byte:02x}" for byte in data[i:i + 4]) + "\n"
                           for i in range(0, len(data), 4)).encode()
        decoded = docker_tool("llvm-mc", ["--disassemble", "--triple=aarch64",
            "--mattr=+morello", "--show-encoding"], image, commands, mc_input).decode()
        lines = [line.strip() for line in decoded.splitlines() if "// encoding:" in line]
        require(len(lines) == len(rows) and "<unknown>" not in decoded, "Incomplete native decode")
        for index, line in enumerate(lines):
            encoding = line.split("// encoding:", 1)[1]
            actual = bytes(int(byte, 16) for byte in re.findall(r"0x([0-9a-f]{2})", encoding))
            require(actual == data[index * 4:index * 4 + 4], "Native decoder encoding mismatch")
        filename = "native-" + case + "-disassembly.txt"
        (output / filename).write_text("\n".join(
            f"{index:04d}  {entry + 4 * index:#018x}  {rows[index][1]}  {line}"
            for index, line in enumerate(lines)) + "\n")
        results.append({"case": case, "entry_from_log": hex(entry), "words": len(rows),
                        "native": identity(data), "disassembly_file": filename})
    write_json(output / "native-decode.json", {"images": results,
        "scope": "Complete decoder listings bound to logged bytes and retained binaries; not a control-flow review.",
        "address_note": "Address columns use logged image entries. LLVM MC branch operands are relative displacements."})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("spatial-build", "spatial-run", "spatial-calibration", "ownership-build", "ownership-run"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    inputs = {name: path.resolve() for name, path in vars(args).items()}
    manifest_path = PROJECT / "evidence/publication-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for name in PACKAGES:
        destination = PROJECT / "evidence/current" / name
        require(not destination.exists(), "Refusing to overwrite " + str(destination))
        require(not any(entry["file"].startswith(str(destination.relative_to(PROJECT)) + "/")
                        for entry in manifest["files"]), "Package already inventoried")
    checked, checks = {}, {}
    for kind in ("spatial", "ownership"):
        build = inputs[kind + "_build"]
        checks[kind] = [verify_hashes(build / "receipt" / name, checked)
                        for name in ("inputs.sha256", "patched-sources.sha256", "outputs.sha256")]
        for role in (["run", "calibration"] if kind == "spatial" else ["run"]):
            run = inputs[kind + "_" + role]
            require(Path((run / "build-directory.txt").read_text().strip()).resolve() == build,
                    "Run/build mismatch " + role)
            require((run / "qemu-exit.txt").read_text().strip() == "0", "Recorded QEMU exit")
            checks[kind].append(verify_hashes(run / "inputs.sha256", checked))
    private = Path(tempfile.mkdtemp(prefix="cbpf-native-evidence-originals.", dir=PROJECT.parent))
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    mappings = {str(path): "${" + name.upper() + "}" for name, path in inputs.items()}
    mappings.update({str(private): "${PRIVATE_ORIGINALS}",
        str(PROJECT.parent / "cbpf-m4-dependencies-20260906"): "${SOURCE_DEPENDENCIES}",
        str(Path(os.environ.get("CBPF_NATIVE_ROOT", Path.home() / ".cache/cbpf/morello"))): "${TOOLCHAIN_CACHE}",
        str(PROJECT): "${REPOSITORY}", str(Path.home()): "${USER_HOME}"})
    replacements = sorted(mappings.items(), key=lambda pair: -len(pair[0]))
    for kind, package in zip(("spatial", "ownership"), PACKAGES):
        original = private / package
        original.mkdir()
        build, run = inputs[kind + "_build"], inputs[kind + "_run"]
        shutil.copytree(build / "receipt", original / "build")
        shutil.copy2(build / "summary.txt", original / "build/summary.txt")
        shutil.copytree(run, original / "run")
        if kind == "spatial":
            shutil.copytree(inputs["spatial_calibration"], original / "calibration")
        derived = original / "derivation"
        derived.mkdir()
        shutil.copy2(__file__, derived / "package_native_extension.executed.py")
        image, commands = build / "objects/vmlinux", []
        names = (["cbpf_selectivity_native_access"] if kind == "spatial" else
                 ["cbpf_ownership_trace_program", "cbpf_gateway", "cbpf_gate_impl",
                  "cbpf_fail", "cbpf_trace", "cbpf_consume", "cbpf_test_invoke", "cbpf_enter"])
        extract_linked(image, names, derived, commands)
        if kind == "ownership":
            extract_jit(run, image, derived, commands)
        toolchain = docker_tool("llvm-objdump", ["--version"], image, commands)
        toolchain += docker_tool("llvm-mc", ["--version"], image, commands)
        toolchain += command(["docker", "run", "--rm", "--pull=never", "--network", "none",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", BUILDER,
            "sha256sum", SDK + "llvm-objdump", SDK + "llvm-mc"], commands)
        (derived / "toolchain.txt").write_bytes(toolchain)
        write_json(derived / "commands.json", commands)
        write_json(derived / "receipt.json", {
            "schema": "cbpf-native-extension-publication-v1", "derived_utc": stamp,
            "source_repository_commit": subprocess.check_output(
                ["git", "-C", str(PROJECT), "rev-parse", "HEAD"], text=True).strip(),
            "derivation_script_sha256": file_digest(Path(__file__)),
            "builder_image": BUILDER, "retained_checksum_verification": checks[kind],
            "kernel_image_sha256": file_digest(build / "objects/arch/arm64/boot/Image"),
            "vmlinux_sha256": file_digest(image),
            "new_native_execution": False, "semantic_revalidation": False,
            "native_inspection": "Pending the later correspondence batch; extraction only.",
            "scope": "Original run files are unchanged privately; publication applies path redaction and lossless source-manifest compression.",
            "omitted_dependencies": "Full Image/vmlinux, source Git objects and compiler/QEMU/firmware distributions remain external; identities and original commands are retained."})
    # All extraction succeeds before any publication files are installed.
    additions = []
    for package in PACKAGES:
        original = private / package
        destination = PROJECT / "evidence/current" / package
        staging = private / "publication" / package
        for source in sorted(original.rglob("*")):
            require(not source.is_symlink(), "Symlink in retained artifacts")
            if not source.is_file():
                continue
            relative = source.relative_to(original)
            data = source.read_bytes()
            published, changes = data, []
            if source.name == "source-tree.manifest":
                require(not any(value.encode() in data for value in mappings), "Private path in source inventory")
                published = gzip.compress(data, mtime=0)
                require(gzip.decompress(published) == data, "Source inventory compression")
                relative = relative.with_name(relative.name + ".gz")
                changes.append("Lossless gzip (mtime=0) of the original NUL-delimited Git tree inventory; original identity applies after decompression.")
            elif source.suffix == ".gz" or source.suffix == ".bin" or source.name == "init":
                visible = gzip.decompress(data) if source.suffix == ".gz" else data
                require(not any(value.encode() in visible for value in mappings), "Private path in binary " + str(source))
            else:
                text = data.decode("utf-8", errors="strict")
                for value, role in replacements:
                    text = text.replace(value, role)
                published = text.encode()
                require(published.count(b"\n") == data.count(b"\n"), "Line-count-changing publication edit")
                if published != data:
                    changes.append("Personal source/cache/run paths replaced with role markers; observations and embedded historical digests unchanged.")
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(published)
            require(target.read_bytes() == published, "Publication copy verification")
            scope = ("Post-run derivation; not an original execution record."
                     if relative.parts[0] == "derivation" else "Original retained experiment/build record.")
            additions.append({"file": str((destination / relative).relative_to(PROJECT)),
                "original": {"file": "${PRIVATE_ORIGINALS}/" + package + "/" + str(source.relative_to(original)), **identity(data)},
                "original_identity_scope": scope, "availability": "publication_copy",
                "publication": identity(published), "changes": changes})
    for package in PACKAGES:
        shutil.copytree(private / "publication" / package,
                        PROJECT / "evidence/current" / package)
    manifest["files"].extend(additions)
    manifest["date"] = stamp[:10]
    write_json(manifest_path, manifest)
    print(f"Published {len(additions)} artifacts; {len(checked)} distinct retained checksum inputs verified.")
    print("Private originals: " + str(private))
    print("Post-run extraction only: no guest boot, semantic revalidation or native inspection claimed.")


if __name__ == "__main__":
    main()
