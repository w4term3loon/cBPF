#!/bin/bash
# Read-only inspection of the retained M3 run; no kernel or native wrapper execution.
set -euo pipefail
project=${REPOSITORY}
review=$project/build/m3-review
run=$project/build/ownership-m3-run.l2BxDW
mkdir -p "$review/wrappers"
python3 - "$run" "$review/wrappers" <<'PY'
import pathlib, struct, sys
run, wrappers = map(pathlib.Path, sys.argv[1:])
for case in ('ab_spill', 'ab_alternate', 'null_second', 'fail_second'):
    data = (run / ('native-' + case + '.bin')).read_bytes()
    assert data and len(data) % 4 == 0
    words = struct.unpack('<' + 'I' * (len(data) // 4), data)
    (wrappers / (case + '.s')).write_text('.text\n.global cbpf_retained_image\ncbpf_retained_image:\n' +
        ''.join('.inst 0x%08x\n' % word for word in words))
PY
docker run --rm --interactive --pull=never --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    -v "$project/build/ownership-m3-kernel:/kernel:ro" \
    -v "$run:/run:ro" -v "$review:/audit" \
    sha256:b4de3680a00e3ac68ccc56bd87131b97c1fffcd5e016c2d1a54d7e3386d9fc6e \
    /bin/bash -s <<'INSPECT'
set -euo pipefail
runtime=/opt/cheri/output/morello-sdk/bin
"$runtime/llvm-nm" -S /kernel/vmlinux | awk '$4 ~ /^cbpf_/ { print }' > /audit/kernel-symbols.txt
"$runtime/llvm-objdump" --mattr=+morello,+lse -d \
    --start-address=0xffff80008003e180 --stop-address=0xffff80008003ef28 \
    /kernel/vmlinux > /audit/runtime-linked-range.txt
"$runtime/llvm-objdump" --mattr=+morello,+lse -d \
    --start-address=0xffff800080e4a248 --stop-address=0xffff800080e4a6f4 \
    /kernel/vmlinux > /audit/guard-linked-range.txt
for case in ab_spill ab_alternate null_second fail_second; do
    "$runtime/clang" --target=aarch64-linux-gnu -march=morello -c \
        "/audit/wrappers/$case.s" -o "/audit/wrappers/$case.o"
    "$runtime/llvm-objcopy" --only-section=.text -O binary \
        "/audit/wrappers/$case.o" "/audit/wrappers/$case.text"
    cmp "/audit/wrappers/$case.text" "/run/native-$case.bin"
    "$runtime/llvm-objdump" --mattr=+morello,+lse -d \
        "/audit/wrappers/$case.o" > "/audit/native-disassembly-$case.txt"
done
"$runtime/clang" --version > /audit/inspection-toolchain.txt
"$runtime/llvm-objdump" --version >> /audit/inspection-toolchain.txt
INSPECT
python3 - "$run" "$review" <<'PY'
import hashlib, json, pathlib, sys
run, review = map(pathlib.Path, sys.argv[1:])
rows = []
for case in ('ab_spill', 'ab_alternate', 'null_second', 'fail_second'):
    observed = (run / ('native-' + case + '.bin')).read_bytes()
    extracted = (review / 'wrappers' / (case + '.text')).read_bytes()
    assert observed == extracted
    rows.append({'case': case, 'bytes': len(observed), 'sha256': hashlib.sha256(observed).hexdigest(),
                 'wrapper_text_byte_equal': True, 'wrapper_executed': False})
(review / 'wrapper-equality.json').write_text(json.dumps(rows, indent=2) + '\n')
PY
