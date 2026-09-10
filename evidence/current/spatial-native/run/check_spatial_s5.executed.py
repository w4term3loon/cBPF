#!/usr/bin/env python3
"""Review only the fixed, benign cbpf_s5 fixture; never load or execute BPF.

pre: bind the stopped guest's FD dump to its accepted certificate, decode actual
Morello bytes, and write expectations plus linked code for independent review.
post: reconcile the single invocation with those saved expectations. A pre PASS
is not execution authorization: the linked transport and boot identity still
require the root agent's independent review described in docs/s5-feasibility.md.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


BUILDER = "sha256:b4de3680a00e3ac68ccc56bd87131b97c1fffcd5e016c2d1a54d7e3386d9fc6e"
PROJECT = Path(__file__).resolve().parents[1]
SYMBOLS = ("bpf_enter_sandbox", "bpf_cheri_helper_gateway",
           "bpf_cheri_map_lookup_impl", "cbpf_array_value_cap",
           "cbpf_map_area_alloc", "array_map_alloc", "ex_handler_bpf",
           "array_map_lookup_elem", "__bpf_call_base")
DATA_PERMS = 0x30001  # Morello LOAD | STORE | GLOBAL; compiler macro receipt.
EXECUTE, EXECUTIVE, SYSREG, WRITE = 0x8000, 2, 0x200, 0x13000


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fields(row):
    pairs = re.findall(r"([A-Za-z_][A-Za-z_0-9]*)=([^\s]+)", row)
    require(len(pairs) == len(dict(pairs)), "duplicate field: " + row)
    return dict(pairs)


def number(record, key, base=0):
    return int(record[key], base)


def select(rows, prefix):
    return [fields(r) for r in rows if r.startswith(prefix)]


def one(rows, prefix):
    found = select(rows, prefix)
    require(len(found) == 1, "expected exactly one " + prefix)
    return found[0]


def indexed(records, key, count):
    result = {number(r, key): r for r in records}
    require(len(result) == len(records) and set(result) == set(range(count)),
            "missing/duplicate/out-of-range " + key)
    return [result[i] for i in range(count)]


def bpf(record):
    return (number(record, "code", 16), *(number(record, k) for k in ("dst", "src", "off", "imm")))


def docker_tool(tool, arguments, mounts=(), input_text=None):
    cmd = ["docker", "run", "--rm", "--interactive", "--pull=never", "--network", "none",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    for host, guest in mounts:
        cmd += ["-v", str(host.resolve()) + ":" + guest + ":ro"]
    cmd += [BUILDER, "/opt/cheri/output/morello-sdk/bin/" + tool, *arguments]
    result = subprocess.run(cmd, input=input_text, text=True, capture_output=True, check=True)
    require(not result.stderr.strip(), tool + " diagnostics: " + result.stderr)
    return result.stdout


def fixed_fixture(map_reference, call_reference):
    return [(0x62,10,0,-4,1), (0xbf,2,10,0,0), (0x07,2,0,0,-4),
            (0x18,1,1,0,map_reference), (0,0,0,0,0), (0x85,0,0,0,call_reference),
            (0x15,0,0,5,0), (0x79,1,0,0,0), (0x07,1,0,0,1),
            (0x7b,0,1,0,0), (0xbf,0,1,0,0), (0x95,0,0,0,0),
            (0xb7,0,0,0,0), (0x95,0,0,0,0)]


def pre(rows, raw_log, args):
    out = args.output
    begin = one(rows, "CBPF_S5 begin ")
    require(begin["program"] == "cbpf_s5", "unexpected program")
    for k, expected in dict(prog_flags=0, map_flags=0, key=1, key_size=4,
                            value_size=8, max_entries=2).items():
        require(number(begin, k) == expected, "fixture " + k)
    ready = one(rows, "CBPF_S5_READY ")
    require(number(ready, "executed") == 0, "already executed")
    require(not select(rows, "CBPF_S5 result=") and not select(rows, "CBPF_S5_VALUE ") and
            not select(rows, "CBPF_S5_GATE ") and not select(rows, "CBPF_S5 authorization="),
            "result/provider observation exists before review")
    image = one(rows, "CBPF_S5 image ")
    initial = one(rows, "CBPF_S5 map ")
    for k in ("map_id", "prog_id"):
        require(number(image, k) == number(ready, k) > 0, "held identity " + k)
    require(number(initial, "map_id") == number(ready, "map_id") and
            number(initial, "map_fd") == number(ready, "held_map_fd") and
            number(initial, "key") == 1 and number(initial, "initial") == 41 and
            number(initial, "map_readback") == 41, "initial map identity/value")
    count = number(image, "jited_len") // 4
    require(count > 0 and number(image, "jited_len") == 4 * count and
            number(image, "func_len") == 4 * count and
            number(image, "nr_jited_ksyms") == number(image, "nr_jited_func_lens") == 1,
            "native length/function count")
    require(number(image, "original_count") == number(image, "translated_count") == 14,
            "unexpected verifier rewrite: requires explicit new review")
    original = indexed(select(rows, "CBPF_S5 bpf kind=original "), "pc", 14)
    require([bpf(r) for r in original] == fixed_fixture(number(ready, "held_map_fd"), 1),
            "original BPF is not the fixed benign fixture")
    raw_words = indexed(select(rows, "CBPF_S5 word "), "index", count)
    words = [number(r, "value", 16) for r in raw_words]
    native = b"".join(struct.pack("<I", w) for w in words)
    (out / "jit.bin").write_bytes(native)

    cert = one(rows, "CERT_BEGIN ")
    require(cert["program"] == "cbpf_s5" and number(cert, "bpf_len") == 14 and
            number(cert, "native_len") == count and
            number(cert, "image") == number(image, "native_entry") != 0,
            "certificate/live-FD image identity")
    decision = one(rows, "CERT_DECISION ")
    require(decision["program"] == "cbpf_s5" and number(decision, "accepted") == 1 and
            decision["stage"] == "complete" and number(decision, "covered_words") == count,
            "missing complete accepted certificate")
    cert_end = one(rows, "CERT_END ")
    require(cert_end["program"] == "cbpf_s5" and number(cert_end, "covered_words") == count, "certificate end")
    stream = select(rows, "CERT_WORD ") + select(rows, "CERT_IMAGE_WORD ")
    stream = indexed(stream, "native", count)
    require(all(r["program"] == "cbpf_s5" for r in stream) and
            [number(r, "value", 16) for r in stream] == words, "certificate/live bytes differ")
    fnv = 14695981039346656037
    for byte in native:
        fnv = ((fnv ^ byte) * 1099511628211) & ((1 << 64) - 1)
    require(number(decision, "image_fnv1a64", 16) == fnv, "certificate image digest")
    ranges = indexed(select(rows, "CERT_RANGE "), "bpf", 14)
    sources = indexed(select(rows, "CERT_SOURCE "), "bpf", 14)
    states = indexed(select(rows, "CERT_STATE "), "bpf", 14)
    require(all(r["program"] == "cbpf_s5" for r in ranges+sources+states), "certificate program labels")
    csource = [dict(s, off=r["off"], imm=r["imm"]) for s, r in zip(sources, ranges)]
    bs, be, ep, plt = [number(cert, k) for k in ("body_start", "body_end", "epilogue_start", "plt_start")]
    require(0 < bs <= be == ep < plt < count and
            number(cert, "executive_return_size") == 4 * (plt - ep - 1), "certificate ranges")
    cursor = bs
    body = []
    for r in ranges:
        start, end = number(r, "start"), number(r, "end")
        require(start == cursor and start <= end <= be, "noncontiguous BPF native ranges")
        body.append(words[start:end]); cursor = end
    require(cursor == be, "incomplete BPF native ranges")
    envelope = select(rows, "CERT_ENVELOPE ")
    require([(r["region"], number(r,"start"), number(r,"end")) for r in envelope] ==
            [("prologue",0,bs),("software_stub",be,ep),("epilogue",ep,plt),("plt",plt,count)],
            "unexpected envelope")
    for r in select(rows, "CERT_WORD "):
        owner = number(r, "bpf")
        require(0 <= owner < 14 and number(ranges[owner],"start") <= number(r,"native") < number(ranges[owner],"end"),
                "body word outside its declared BPF range")
    for r in select(rows, "CERT_IMAGE_WORD "):
        owner = [e for e in envelope if e["region"] == r["region"]]
        require(len(owner) == 1 and number(owner[0],"start") <= number(r,"native") < number(owner[0],"end"),
                "envelope word outside its declared region")

    # Linked addresses and actual Morello decoding; no compiler/emulator here.
    nm = docker_tool("llvm-nm", ["--defined-only", "--numeric-sort", "/kernel/vmlinux"],
                     [(args.vmlinux.parent, "/kernel")])
    symbols = {}
    for line in nm.splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]+)\s+\S\s+(\S+)", line)
        if match and match[2] in SYMBOLS:
            require(match[2] not in symbols, "duplicate linked symbol " + match[2])
            symbols[match[2]] = int(match[1], 16)
    require(set(symbols) == set(SYMBOLS), "missing linked symbols: " + str(set(SYMBOLS)-set(symbols)))
    call = symbols["array_map_lookup_elem"] - symbols["__bpf_call_base"]
    require(-(1 << 31) <= call < (1 << 31), "helper relative call range")
    translated = indexed(select(rows, "CBPF_S5 bpf kind=translated "), "pc", 14)
    require([bpf(r) for r in translated] == fixed_fixture(number(ready,"map_id"), call),
            "translated BPF differs from fixture plus ordinary map/call fixups")
    expected = fixed_fixture(number(ready,"map_id"), call)
    for i, r in enumerate(csource):
        if i == 3:
            require(bpf(r)[:4] == (0x18,1,0,0), "certificate map-object load")
        elif i == 4:
            require(bpf(r)[:4] == (0,0,0,0), "certificate map-object continuation")
        else:
            require(bpf(r) == expected[i], "certificate BPF differs at " + str(i))
    require(number(states[5], "helper") == 0 and number(states[7], "src_kind") == 16 and
            number(states[9], "dst_kind") == 16, "certificate map/helper authority")
    dis = docker_tool("llvm-mc", ["--disassemble", "--triple=aarch64", "--mattr=+morello", "--show-encoding"],
                      input_text="".join(" ".join(f"0x{b:02x}" for b in struct.pack("<I", w))+"\n" for w in words))
    decoded = [r.strip() for r in dis.splitlines() if "// encoding:" in r]
    require(len(decoded) == count and "<unknown>" not in dis, "incomplete Morello disassembly")
    (out / "jit-disassembly.txt").write_text("\n".join(
        f"{i:04d}  {number(image,'native_entry')+4*i:#018x}  {w:08x}  {d}"
        for i,(w,d) in enumerate(zip(words,decoded)))+"\n")
    linked = docker_tool("llvm-objdump", ["-d", "--mattr=+morello",
                         "--disassemble-symbols="+",".join(SYMBOLS), "/kernel/vmlinux"],
                         [(args.vmlinux.parent, "/kernel")])
    require(all(re.search(r"^[0-9a-f]+ <"+re.escape(name)+r">:", linked, re.M) for name in SYMBOLS),
            "incomplete linked-symbol disassembly")
    (out / "linked-disassembly.txt").write_text(linked)
    nominal_symbols = dict(symbols)

    # Fixed constants/operands, not a general decoder or second JIT.
    checks = {0:[0xd280002a,0xe29fc32a], 1:[0xc2c1d321], 2:[0x02801021],
              3:[0x52800000], 4:[], 5:[0xd2800004,0xc2c1d3cd,0xc2c23222,0xc2c1d007],
              7:[0xe2c004e0], 8:[0x91000400], 9:[0xe2c000e0], 10:[0xc2c1d007],
              12:[0xd2800007], 13:[]}
    for i, expected_words in checks.items():
        require(body[i] == expected_words, f"unexpected fixed native encoding at BPF {i}: {body[i]}")
    n6, n11 = number(ranges[6],"start"), number(ranges[11],"start")
    require(body[6] == [0xf10000ff, 0x54000000 | ((number(ranges[12],"start")-n6-1) << 5)],
            "NULL branch does not skip all selected accesses")
    require(body[11] == [0x14000000 | (ep-n11)], "computed-return branch does not reach epilogue")
    prologue = words[:bs]
    calls = [i for i,w in enumerate(prologue) if w == 0xd63f0140]  # BLR x10
    require(len(calls) == 1 and calls[0] >= 3, "sandbox entry call")
    ci = calls[0]
    address_words = prologue[ci-3:ci]
    require([w & 0xffe0001f for w in address_words] == [0x9280000a,0xf2a0000a,0xf2c0000a],
            "sandbox entry address materialization")
    target = ((~((address_words[0] >> 5) & 0xffff)) & ((1 << 64)-1))
    for shift,w in zip((16,32),address_words[1:]):
        target = (target & ~(0xffff << shift)) | (((w >> 5) & 0xffff) << shift)
    relocation = target - symbols["bpf_enter_sandbox"]
    require(relocation % 4096 == 0, "unaligned inferred kernel relocation")
    require(args.relocation is None or relocation == args.relocation, "kernel relocation differs from requested check")
    symbols = {name:address+relocation for name,address in symbols.items()}
    (out / "linked-symbols.json").write_text(json.dumps(
        dict(nominal=nominal_symbols, runtime=symbols, inferred_relocation=relocation), indent=2)+"\n")
    require(prologue[ci+1:ci+3] == [0xb4000060,0xd2800007] and
            prologue[ci+3] == 0x14000000 | (ep+1-ci-3), "entry errors must return zero")
    poke = 2 if prologue[0] == 0xd50324df else 1  # optional BTI jc
    require(prologue[poke-1] == 0xaa1e03e9 and prologue[poke] == 0xd503201f,
            "return-cursor capture/POKE is not the expected MOV/NOP")
    require(words[ep] == 0xc2c253c0 and words[plt-2:plt] == [0xc2c25203,0xd65f03c0],
            "restricted/executive returns")
    require(re.search(r"blrs\s+c17\s", decoded[number(ranges[5],"start")+2]), "decoded helper")
    base = number(image,"native_entry")
    restricted = base + 4 * (ci+1)
    executive = base + 4 * (ep+1)
    return dict(result="PASS_PRE_EXECUTION_CHECKS", program="cbpf_s5", image=image, ready=ready,
                log_prefix_bytes=len(raw_log), log_prefix_sha256=sha(raw_log),
                jit_sha256=sha(native), vmlinux_sha256=sha(args.vmlinux.read_bytes()),
                checker_sha256=sha(Path(__file__).read_bytes()), linked_disassembly_sha256=sha(linked.encode()),
                builder=BUILDER, symbols=symbols, relocation=relocation,
                restricted=dict(base=restricted, length=executive-restricted),
                executive=dict(base=executive, length=4*(plt-ep-1)),
                selected=dict(load_native=number(ranges[7],"start"), store_native=number(ranges[9],"start"),
                              capability="c7", data_register="x0", bytes=8),
                independent_review_required=["Exact boot Image/vmlinux/source/config binding",
                    "Complete emitted prologue/epilogue; linked entry C17/CLR/FNP transport, current provider branch, c0 return transport",
                    "Linked bounded exception handler clears r0 and exits; no reachable PLT/attachment"],
                limitations="One fixed program; constructed operand logs, not independent hardware attestation. JIT span excludes PLT target/exception table.")


def post(rows, raw_log, args):
    saved = json.loads(args.preflight.read_text())
    require(saved["result"] == "PASS_PRE_EXECUTION_CHECKS", "preflight did not pass")
    require(saved["checker_sha256"] == sha(Path(__file__).read_bytes()), "checker changed after preflight")
    require(sha(raw_log[:saved["log_prefix_bytes"]]) == saved["log_prefix_sha256"], "preflight log prefix changed")
    result = one(rows, "CBPF_S5 result=")
    require(result["result"] == "PASS" and result["stage"] == "complete" and
            number(result,"retval") == number(result,"readback") == 42, "single computed result/readback")
    for key,value in dict(loaded=1,map_create_count=1,map_update_count=1,map_lookup_count=2,
                          prog_load_count=1,test_run_count=1,info_count=3,errno=0,attached=0).items():
        require(number(result,key) == value, "unexpected guest count/status: " + key)
    authorization = one(rows, "CBPF_S5 authorization=")
    require(authorization["authorization"] == "accepted" and number(authorization,"test_run_count") == 0,
            "one pre-execution authorization")
    for k in ("map_id","prog_id"):
        require(result[k] == saved["ready"][k], "post identity " + k)
    roots = select(rows, "ROOT_ATTEST ")
    for kind,key,executive in (("restricted_code","restricted",False),("executive_return","executive",True)):
        found = [r for r in roots if r["kind"] == kind]
        require(len(found) == 1, "expected exactly one " + kind)
        r, expected = found[0], saved[key]
        require(number(r,"tag") == number(r,"sealed") == 1 and
                number(r,"base") == number(r,"address") == number(r,"object_id") == expected["base"] and
                number(r,"length") == number(r,"expected_size") == expected["length"], kind + " exact bounds")
        perms = number(r,"perms")
        require(perms & EXECUTE and bool(perms & EXECUTIVE) == executive and
                (executive or not perms & SYSREG), kind + " transition permissions")
    # Observation schema is deliberately restricted to the two S5 logging sites.
    provider = one(rows, "CBPF_S5_VALUE ")
    gateway = one(rows, "CBPF_S5_GATE ")
    order = [next(i for i,r in enumerate(rows) if r.startswith(prefix)) for prefix in
             ("CBPF_S5 authorization=", "CBPF_S5_GATE ", "ROOT_ATTEST kind=restricted_code ",
              "ROOT_ATTEST kind=executive_return ", "CBPF_S5_VALUE ", "CBPF_S5 result=")]
    require(order == sorted(order), "invocation observations out of order")
    require(provider["branch"] == "reduced" and number(provider,"map_id") == int(saved["ready"]["map_id"]) and
            number(provider,"index") == 1 and number(provider,"value_size") == number(provider,"stride") == 8,
            "selected provider identity/profile")
    selected = number(provider,"values") + 8
    require(number(provider,"selected") == number(provider,"base") == number(provider,"cursor") == selected and
            number(provider,"length") == 8 and number(provider,"tag") == 1 and
            number(provider,"sealed") == 0 and number(provider,"perms") == DATA_PERMS,
            "selected retained capability")
    require(number(gateway,"target") == number(gateway,"cursor") == saved["symbols"]["bpf_cheri_helper_gateway"] and
            number(gateway,"tag") == number(gateway,"sealed") == 1 and
            number(gateway,"perms") & EXECUTE and number(gateway,"perms") & EXECUTIVE and
            not number(gateway,"perms") & WRITE, "helper gateway target/capability")
    require(number(gateway,"base") <= number(gateway,"cursor") < number(gateway,"base")+number(gateway,"length"),
            "helper gateway cursor bounds")
    require(not any(re.search(r"contained BPF|recovered BPF|authority .* rejected|CBPF_S5.*result=FAIL|Kernel panic|Oops:",r) for r in rows),
            "failure/fault reported")
    return dict(result="PASS_SINGLE_S5_OBSERVATION", preflight_sha256=sha(args.preflight.read_bytes()),
                log_sha256=sha(raw_log), provider=provider, gateway=gateway, roots=roots, guest=result,
                limitations=saved["limitations"], gateway_bounds="Inherited DDC bounds; not narrowed to gateway")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("pre","post"))
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--vmlinux", type=Path)
    parser.add_argument("--relocation", type=lambda x:int(x,0), help="optional check of inferred kernel relocation")
    parser.add_argument("--preflight", type=Path)
    args = parser.parse_args()
    review_root = (PROJECT / "build/spatial-s5-review").resolve()
    require(args.output.resolve().is_relative_to(review_root), "output must be inside new build/spatial-s5-review")
    args.output.mkdir(parents=True, exist_ok=True)
    require((args.phase == "pre" and args.vmlinux) or (args.phase == "post" and args.preflight), "missing phase input")
    raw_log = args.log.read_bytes()
    rows = [re.sub(r"^\[\s*\d+\.\d+\]\s*", "", r).removeprefix("bpf_jit: ")
            for r in raw_log.decode(errors="replace").replace("\r", "").splitlines()]
    try:
        report = pre(rows, raw_log, args) if args.phase == "pre" else post(rows, raw_log, args)
    except (ValueError, KeyError, subprocess.CalledProcessError) as error:
        report = dict(result="FAIL", phase=args.phase, reason=str(error), log_sha256=sha(raw_log))
    (args.output / (args.phase+".json")).write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps(report, indent=2))
    return 0 if report["result"].startswith("PASS_") else 1


if __name__ == "__main__":
    raise SystemExit(main())
