"""Focused byte/operand/target checks for the three fixed ownership images.

This is not a general native validator. It does not import or invoke the
production encoder. Layouts below deliberately reject other emitter profiles.
LLVM listings, build identities and trusted logging remain explicit premises.
"""
import json
import re
import struct

from native_receipt_common import by_suffix, checksums, digest, require


SYMBOLS = ("cbpf_ownership_trace_program", "cbpf_gateway", "cbpf_gate_impl",
           "cbpf_fail", "cbpf_trace", "cbpf_consume", "cbpf_test_invoke", "cbpf_enter")


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def branch_target(word, pc, kind):
    if kind in ("b", "bl"):
        require(word & 0xFC000000 == (0x14000000 if kind == "b" else 0x94000000),
                "Expected immediate " + kind)
        return pc + 4 * signed(word & 0x3FFFFFF, 26)
    if kind == "cbz":
        require(word & 0xFF000000 == 0xB4000000, "Expected 64-bit cbz")
    else:
        require(kind == "b.ne" and word & 0xFF00001F == 0x54000001, "Expected b.ne")
    return pc + 4 * signed((word >> 5) & 0x7FFFF, 19)


def adr_target(word, pc, register):
    require(word & 0x9F00001F == 0x10000000 | register, "Expected ADR register")
    return pc + signed(((word >> 5) & 0x7FFFF) * 4 + ((word >> 29) & 3), 21)


def canonical(assembly):
    text = assembly.split("//", 1)[0].split(" <", 1)[0].strip().lower()
    text = re.sub(r"#(-?)0x([0-9a-f]+)", lambda m: "#" + m[1] + str(int(m[2], 16)), text)
    return re.sub(r"\s+", " ", text)


def native_listing(path, entry, values):
    result = []
    pattern = re.compile(r"(\d{4})\s+(0x[0-9a-f]+)\s+([0-9a-f]{8})\s+(.+?)\s+// encoding: \[(.+)\]")
    lines = path.read_text().splitlines()
    require(len(lines) == len(values), "Complete native listing required")
    for index, (line, word) in enumerate(zip(lines, values)):
        match = pattern.fullmatch(line)
        require(match and int(match[1]) == index and int(match[2], 16) == entry + 4 * index and
                int(match[3], 16) == word, "Native listing index/address/word")
        encoding = bytes(int(x.strip(), 16) for x in match[5].split(","))
        require(encoding == struct.pack("<I", word), "Native decoder encoding bytes")
        require("unknown" not in match[4], "Unknown native instruction")
        result.append(canonical(match[4]))
    return result


def linked_receipt(directory, inputs, config, log):
    receipt = json.loads((directory / "linked-ranges.json").read_text())
    require(receipt["vmlinux_sha256"] == by_suffix(checksums(inputs), "/vmlinux"),
            "Linked kernel/run identity")
    require(digest(config) == by_suffix(checksums(inputs), "/.config"), "Kernel configuration identity")
    settings = dict(line.split("=", 1) for line in config.read_text().splitlines()
                    if line.startswith("CONFIG_") and "=" in line)
    for option in ("CBPF_KFUNC_GATE", "CBPF_OWNERSHIP_NATIVE_TRACE_TEST", "ARM64_MORELLO"):
        require(settings.get("CONFIG_" + option) == "y", "Required fixed profile " + option)
    for option in ("ARM64_BTI_KERNEL", "ARM64_PTR_AUTH_KERNEL", "CPU_BIG_ENDIAN"):
        require(settings.get("CONFIG_" + option, "n") == "n", "Unsupported image profile " + option)
    kaslr = [re.sub(r"^\[\s*\d+\.\d+\]\s*", "", line).strip()
             for line in log.splitlines() if "KASLR" in line]
    require(kaslr == ["KASLR disabled due to lack of seed"],
            "Ownership linked placement requires recorded zero relocation")
    listing = directory / "complete-linked-disassembly.txt"
    require(digest(listing) == receipt["disassembly"]["sha256"] and
            listing.stat().st_size == receipt["disassembly"]["bytes"], "Complete linked listing identity")
    decoded = {}
    for line in listing.read_text().splitlines():
        match = re.fullmatch(r"\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.+)", line)
        if match:
            address = int(match[1], 16)
            require(address not in decoded and "<unknown>" not in match[3], "Linked decode uniqueness")
            decoded[address] = int(match[2], 16), canonical(match[3])
    ranges = {}
    addresses = set()
    for item in receipt["ranges"]:
        name = item["symbol"]
        require(name in SYMBOLS and name not in ranges and item["file"] == name + ".bin", "Linked symbol/file")
        start, end = int(item["start"], 0), int(item["end_exclusive"], 0)
        data = (directory / item["file"]).read_bytes()
        require(start > 0 and start % 4 == 0 and end - start == len(data) == item["bytes"] and
                len(data) > 0 and len(data) % 4 == 0 and digest(directory / item["file"]) == item["sha256"],
                "Linked range/bytes " + name)
        symbol = item["elf_symbol"].split()
        require(len(symbol) == 8 and symbol[7] == name and int(symbol[1], 16) == start,
                "Linked ELF symbol " + name)
        if name == "cbpf_gateway":
            require(int(symbol[2]) == 0 and symbol[3] == "NOTYPE" and
                    item["extent_basis"] == "Zero-sized assembly label; exclusive boundary cbpf_gate_impl",
                    "Assembly gateway boundary")
        else:
            require(int(symbol[2]) == len(data) and symbol[3] == "FUNC" and
                    item["extent_basis"] == "ELF symbol st_size", "Complete ELF function extent")
        for index, (word,) in enumerate(struct.iter_unpack("<I", data)):
            address = start + 4 * index
            require(address not in addresses and address in decoded and decoded[address][0] == word,
                    "Complete linked bytes/decode " + name)
            addresses.add(address)
        ranges[name] = (start, end)
    require(set(ranges) == set(SYMBOLS) and set(decoded) == addresses and
            ranges["cbpf_gateway"][1] == ranges["cbpf_gate_impl"][0], "Linked coverage")
    return ranges, decoded


PREFIX = """
910003c9 add x9, x30, #0
d503201f nop
a9bf7bfd stp x29, x30, [sp, #-16]!
910003fd mov x29, sp
a9bf53f3 stp x19, x20, [sp, #-16]!
a9bf5bf5 stp x21, x22, [sp, #-16]!
a9bf63f7 stp x23, x24, [sp, #-16]!
a9bf6bf9 stp x25, x26, [sp, #-16]!
a9bf73fb stp x27, x28, [sp, #-16]!
a9bf7fff stp xzr, xzr, [sp, #-16]!
d10043ff sub sp, sp, #16
910003e0 mov x0, sp
d2800201 mov x1, #16
"""
RESTORE = """
910043ff add sp, sp, #16
c24003f0 ldr c16, [sp, #0]
910043ff add sp, sp, #16
a8c173fb ldp x27, x28, [sp], #16
a8c16bf9 ldp x25, x26, [sp], #16
a8c163f7 ldp x23, x24, [sp], #16
a8c15bf5 ldp x21, x22, [sp], #16
a8c153f3 ldp x19, x20, [sp], #16
a8c17bfd ldp x29, x30, [sp], #16
910000e0 add x0, x7, #0
c2c0920a gctag x10, c16
b400004a cbz x10, #8
c2c25203 retr c16
d65f03c0 ret
"""


def fixed_image(case, values, maps, bpf, entry, restricted, executive, enter, listing, ranges):
    """Check all words of this small fixed fixture, including every map interval.

    Decode immediate/register/branch fields; literal frame encodings are paired
    with independently retained LLVM operand text. No image is regenerated.
    """
    decoded = native_listing(listing, entry, values)
    touched = set()
    branches = []

    def expect(index, word, assembly):
        require(index not in touched and values[index] == word and decoded[index] == canonical(assembly),
                f"{case}: native instruction/operand mismatch at word {index}: expected {assembly}")
        touched.add(index)

    def block(index, text):
        for line in text.strip().splitlines():
            word, asm = line.strip().split(" ", 1)
            expect(index, int(word, 16), asm)
            index += 1

    def movwide(index, register, value=None, wide=False):
        result = 0
        for part in range(4 if wide else 1):
            word = values[index + part]
            require(word & 0xFF80001F == (0xD2800000 if part == 0 else 0xF2800000) | register and
                    (word >> 21) & 3 == part, f"{case}: MOVZ/MOVK register/shift at {index + part}")
            immediate = (word >> 5) & 0xFFFF
            result |= immediate << (16 * part)
            asm = f"mov x{register}, #{immediate}" if part == 0 else f"movk x{register}, #{immediate}, lsl #{16 * part}"
            expect(index + part, word, asm)
        require(value is None or result == value, f"{case}: immediate value at {index}")
        return result

    def branch(index, target, kind="b", register=None):
        word = values[index]
        require(branch_target(word, entry + index * 4, kind) == entry + target * 4 and
                (register is None or word & 31 == register), f"{case}: branch target/register at {index}")
        operands = (f"x{register}, " if register is not None else "") + f"#{4 * (target - index)}"
        expect(index, word, kind + " " + operands)
        branches.append({"word": index, "kind": kind, "target_word": target})

    def capmove(index, dest, source):
        word = values[index]
        require(word & 0xFFFFFC00 == 0xC2C1D000 and word & 31 == dest and
                (word >> 5) & 31 == source, f"{case}: capability move at {index}")
        expect(index, word, f"mov c{dest}, c{source}")

    require(entry > 0 and entry % 4 == 0 and len(values) == (153 if case == "positive" else 163) and
            restricted == len(values) - 47 and executive == restricted + 1, "Fixed native envelope")
    require(enter[0] == entry + 25 * 4 and enter[1] == (executive - 25) * 4 and
            enter[2] == entry + executive * 4 and enter[3] == 184, "Exact restricted/epilogue entry bounds")
    block(0, PREFIX)
    require(adr_target(values[13], entry + 52, 2) == enter[2], "Prologue ADR must address common epilogue")
    expect(13, values[13], f"adr x2, #{4 * (executive - 13)}")
    movwide(14, 3, 184)
    expect(15, 0x91000124, "add x4, x9, #0")
    cookie = movwide(16, 5, wide=True)
    require(cookie > 0 and cookie % 8 == 0, "Nonzero aligned program cookie; private entry checks its identity")
    movwide(20, 10, ranges["cbpf_enter"][0], wide=True)
    expect(24, 0xD63F0140, "blr x10")
    branch(25, 28, "cbz", 0)
    movwide(26, 7, 0)
    branch(27, executive)
    for index, reg in enumerate(reg for reg in range(30) if reg not in (15, 17)):
        movwide(28 + index, reg, 0)
    native_regs = (7, 0, 1, 2, 3, 4, 19, 20, 21, 22)
    cursor = 56
    mapping = []
    for pc, instruction in enumerate(bpf):
        code, dst, src, offset, imm = instruction
        begin, end = maps[pc]
        length = 4 if code == "b7" else 5 if code == "85" else 1
        require(begin == cursor and end == begin + length, f"{case}: exact map interval PC {pc}")
        if code == "b7":
            movwide(begin, native_regs[dst], imm & ((1 << 64) - 1), wide=True)
        elif code == "bf":
            capmove(begin, native_regs[dst], native_regs[src])
        elif code == "7b":
            expect(begin, 0x824003F3, "str c19, [csp, #0]")
        elif code == "79":
            expect(begin, 0x826003F5, "ldr c21, [csp, #0]")
        elif code == "15":
            branch(begin, maps[pc + 1 + offset][0], "cbz", native_regs[dst])
        elif code == "85":
            movwide(begin, 4, imm)
            movwide(begin + 1, 5, pc)
            capmove(begin + 2, 13, 30)
            expect(begin + 3, 0xC2C23222, "blrs c17")
            capmove(begin + 4, 7, 0)
        elif code == "95":
            branch(begin, restricted)
        else:
            raise ValueError("Unsupported fixed native BPF form")
        cursor = end
        mapping.append({"pc": pc, "begin_word": begin, "end_word_exclusive": end})
    require(cursor == restricted, "Body must end exactly at restricted return")
    expect(restricted, 0xC2C253C0, "ret c30")
    expect(executive, 0xF90003FF, "str xzr, [sp]")
    expect(executive + 1, 0xF90007FF, "str xzr, [sp, #8]")
    expect(executive + 2, 0x910000E7, "add x7, x7, #0")
    for index, reg in enumerate(reg for reg in range(30) if reg != 7):
        movwide(executive + 3 + index, reg, 0)
    block(executive + 32, RESTORE)
    require(branch_target(values[-3], entry + 4 * (len(values) - 3), "cbz") ==
            entry + 4 * (len(values) - 1), "Untagged caller fallback target")
    require(touched == set(range(len(values))), "Every fixed image word must be checked")
    return {"case": case, "checked_words": len(touched), "entry": hex(entry),
            "program_cookie": hex(cookie), "cbpf_enter": hex(ranges["cbpf_enter"][0]),
            "restricted_return": hex(entry + 4 * restricted), "common_epilogue": hex(enter[2]),
            "epilogue_bytes": 184, "branches": branches, "source_map": mapping,
            "scope": "Fixed-profile byte/operand/target checks, not a compiler correctness proof"}


def linked_terminal_checks(ranges, decoded):
    """Fixed compiled-profile checks around rejection, return and cleanup.

    Full linked functions are retained for inspection, not generally validated.
    Offsets intentionally fail closed for an unreviewed rebuilt layout.
    """
    require(ranges["cbpf_gateway"][1] - ranges["cbpf_gateway"][0] == 56 * 4,
            "Complete fixed gateway must contain exactly 56 words")
    checked = []

    def exact(name, offset, words):
        start, end = ranges[name]
        values = [int(word, 16) for word in words.split()]
        require(start + offset + 4 * len(values) <= end, "Terminal sequence extent")
        require([decoded[start + offset + 4 * i][0] for i in range(len(values))] == values,
                f"Linked terminal sequence {name}+{offset:#x}")
        checked.append({"symbol": name, "offset": hex(offset), "words": len(values)})

    def target(name, offset, destination, dest_offset=0, kind="b"):
        pc = ranges[name][0] + offset
        expected = ranges[destination][0] + dest_offset
        require(branch_target(decoded[pc][0], pc, kind) == expected and
                decoded[pc][1] == f"{kind} {expected:#x}", "Linked branch target and operand")
        checked.append({"symbol": name, "offset": hex(offset), "target": hex(expected), "kind": kind})

    # Complete assembly gateway: saves/restores, argument transport, sentinel
    # selection and register scrub. Only the BL displacement is symbolic.
    exact("cbpf_gateway", 0, "d503245f 910003ec 910001ff d10203ff f90003ef f90007ec "
          "c20007ed c2000bf1 c2000ff3 c20013f4 c20017f5 c2001bf6 c2001ffe aa0403e1 aa0503e2")
    target("cbpf_gateway", 0x3C, "cbpf_gate_impl", kind="bl")
    exact("cbpf_gateway", 0x40, "f94003ef f94007ec c24007ed c2400bf1 c2400ff3 c24013f4 "
          "c24017f5 c2401bf6 c2401fee 910203ff 9100019f b100041f")
    target("cbpf_gateway", 0x70, "cbpf_gateway", 0x80, "b.ne")
    exact("cbpf_gateway", 0x74, "c2c1d1ae aa1f03e0 aa1f03e7 c2c1d1be "
          "aa1f03e1 aa1f03e2 aa1f03e3 aa1f03e4 aa1f03e5 aa1f03e6 aa1f03e7 "
          "aa1f03e8 aa1f03e9 aa1f03ea aa1f03eb aa1f03ec aa1f03ed aa1f03f0 "
          "aa1f03f2 aa1f03f7 aa1f03f8 aa1f03f9 aa1f03fa aa1f03fb aa1f03fc aa1f03fd c2c251c3")
    # Actual compiled stale gate: private tag branch precedes object read and
    # consume, inlined failure sets state and returns scalar -1 in c0.
    exact("cbpf_gate_impl", 0x1FC, "8b215289 a2401d22 c2c0904a b400032a")
    pc = ranges["cbpf_gate_impl"][0] + 0x208
    require(branch_target(decoded[pc][0], pc, "cbz") == ranges["cbpf_gate_impl"][0] + 0x26C,
            "Private-invalid gate branch must reach rejection")
    exact("cbpf_gate_impl", 0x2F8, "39019689")
    exact("cbpf_gate_impl", 0x348, "aa1f03e0 02800400 a9464ff4 a94557f6 a9447bfd 9101c3ff d65f03c0")
    # Entry installs sidecar/zero RDDC, sealed gateway c17, fixed executive
    # return c30 and restricted code c1. Its ADR selects the linked gateway.
    pc = ranges["cbpf_enter"][0] + 0x204
    require(adr_target(decoded[pc][0], pc, 8) == ranges["cbpf_gateway"][0], "Entry gateway ADR target")
    exact("cbpf_enter", 0x27C, "c24007e0 c28f4160 c28b433f a25f03a1 c2400be2 c24003e3 "
          "aa1503ef 910002bf c2c1d071 aa1f03e0 c2c1d05e c2c21023")
    # Bounded cleanup walks each acquired cell and skips already-invalid A.
    exact("cbpf_test_invoke", 0x31C, "aa1f03f4 910143f7 14000004 91000694 eb25429f "
          "54ffefc2 8b1412e8 c2400500 c2c09008 b4ffff48 910143e0 2a1403e1 92800002 52800023")
    target("cbpf_test_invoke", 0x354, "cbpf_consume", kind="bl")
    exact("cbpf_test_invoke", 0x358, "b940a3e5 17fffff3")
    exact("cbpf_test_invoke", 0x244, "c2001bff c20023ff c2001fff c20027ff")
    exact("cbpf_test_invoke", 0x280, "c24013e0 c28b4320 c2400fe0 c28f4160 3942d7e8 7100011f 1a9f0260")
    # Consume invalidates the private capability before either compiled atomic
    # decrement alternative; cleanup accounting is conditional on its flag.
    exact("cbpf_consume", 0x40, "c2c19000 a2286920")
    exact("cbpf_consume", 0xB8, "b8680128 7100051f 5400068d")
    exact("cbpf_consume", 0xC4, "b9405688 11000506 b9405e88 b9005686 360000d6 11000508")
    exact("cbpf_consume", 0x178, "885f7d48 4b09010b 880cfd4b 35ffffac")
    return {"result": "PASS", "sequences": checked,
            "scope": "Complete gateway and selected compiled gate/entry/cleanup sequences; other linked code inspected, not generally validated"}
