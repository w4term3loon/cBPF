#!/bin/sh
# CBPF optional architecture probe/gate runner. Uses local assets; no kernel rebuild.
set -eu
test "$#" -le 1 || { echo "Usage: $0 [probe|gate]" >&2; exit 2; }
probe_mode=${1:-probe}
case "$probe_mode" in
    probe|gate) ;;
    *) echo "Usage: $0 [probe|gate]" >&2; exit 2 ;;
esac
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
native=${CBPF_NATIVE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/cbpf/morello}
kernel=${CBPF_KERNEL:?Set CBPF_KERNEL to the pinned probe kernel Image}
compiler=$native/opt/cheri/output/morello-sdk/bin/clang
linker=$native/opt/cheri/output/morello-sdk/bin/ld.lld
qemu=$native/opt/cheri/output/sdk/bin/qemu-system-morello
firmware=$native/opt/cheri/output/sdk/share/qemu/edk2-aarch64-code.fd
sysroot=$native/musl-sysroot
builtins=$native/libclang_rt.builtins-aarch64.a
for input in "$compiler" "$linker" "$qemu" "$firmware" "$kernel" "$builtins" "$sysroot/lib/libc.a"; do
    test -r "$input" || { echo "CBPF missing local dependency: $input" >&2; exit 1; }
done
mkdir -p "$project/build"
run=$(mktemp -d "$project/build/cheri-$probe_mode.XXXXXX")
if [ "$probe_mode" = gate ]; then
    set -- "$project/src/cbpf.c" "$project/src/gate.c" "$project/src/gate_demo.c"
else
    set -- "$project/src/cheri_demo.c"
fi
"$compiler" --target=aarch64-linux-musl_purecap -march=morello -mabi=purecap \
    --sysroot="$sysroot" --ld-path="$linker" -static -O2 -Wall -Wextra -Werror \
    -DCBPF_GATE_GUEST \
    -nostdlib "$sysroot/lib/crt1.o" "$sysroot/lib/crti.o" \
    "$@" "$sysroot/lib/libc.a" "$builtins" \
    "$sysroot/lib/crtn.o" -o "$run/init" >"$run/compile.log" 2>&1
if [ "$probe_mode" = gate ]; then
    "$compiler" --target=aarch64-linux-musl_purecap -march=morello -mabi=purecap \
        --sysroot="$sysroot" -O2 -Wall -Wextra -Werror -DCBPF_GATE_GUEST \
        -S "$project/src/gate.c" -o "$run/gate.s" >>"$run/compile.log" 2>&1
fi
# A tiny deterministic newc archive avoids root privileges for /dev/console.
python3 - "$run" <<'PY'
import gzip, pathlib, stat, sys
root = pathlib.Path(sys.argv[1]); archive = bytearray(); inode = 0
def emit(name, mode, data=b'', major=0, minor=0):
    global inode
    inode += 1
    encoded = name.encode() + b'\0'
    fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(encoded), 0]
    archive.extend(b'070701' + ''.join(f'{v:08x}' for v in fields).encode() + encoded)
    archive.extend(b'\0' * (-len(archive) % 4)); archive.extend(data)
    archive.extend(b'\0' * (-len(archive) % 4))
emit('init', stat.S_IFREG | 0o755, (root/'init').read_bytes())
emit('dev', stat.S_IFDIR | 0o755)
emit('dev/console', stat.S_IFCHR | 0o600, major=5, minor=1)
emit('TRAILER!!!', 0)
(root/'initramfs.cpio.gz').write_bytes(gzip.compress(archive, mtime=0))
PY
sha256sum "$@" "$0" "$compiler" "$linker" "$qemu" \
    "$firmware" "$kernel" "$sysroot/lib/crt1.o" "$sysroot/lib/crti.o" \
    "$sysroot/lib/crtn.o" "$sysroot/lib/libc.a" "$builtins" "$run/init" \
    "$run/initramfs.cpio.gz" >"$run/inputs.sha256"
if [ "$probe_mode" = gate ]; then
    sha256sum "$project/src/cbpf.h" "$project/src/gate.h" \
        "$native/opt/cheri/output/morello-sdk/lib/clang/17/include/cheriintrin.h" \
        "$run/gate.s" \
        >>"$run/inputs.sha256"
fi
"$compiler" --version >"$run/toolchain.txt"
"$qemu" --version >>"$run/toolchain.txt"
status=0
timeout --signal=TERM --kill-after=5 60 "$qemu" \
    -M virt,gic-version=3 -cpu morello -m 2G -smp 1 \
    -bios "$firmware" -kernel "$kernel" -initrd "$run/initramfs.cpio.gz" \
    -append 'console=ttyAMA0 loglevel=4 rdinit=/init panic=-1' \
    -nic none -display none -monitor none -serial stdio -no-reboot \
    >"$run/boot.log" 2>&1 || status=$?
python3 - "$run" "$status" "$probe_mode" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1]); log = (root/'boot.log').read_text(errors='replace').replace('\r', '')
if sys.argv[3] == 'gate':
    required = ['CBPF_GATE scope=validated_IR isolation=0 kfunc=0 jit=0',
                'CBPF_GATE backend=cheri', 'CBPF_GATE result=PASS']
    counts = re.findall(r'^CBPF_GATE cases=(\d+) matched=(\d+)$', log, re.M)
    controls_ok = len(counts) == 1 and int(counts[0][0]) > 0 and counts[0][0] == counts[0][1]
    failure = 'CBPF_GATE result=FAIL'
else:
    required = ['CBPF distinct_cells=1 same_object=1 valid_A=42 valid_B=42',
     'CBPF consumed_A=1 duplicate_effect=0 references=2 stale_tag=0 cursor_preserved=1',
     'CBPF surviving_B=42 direct_object=42', 'CBPF stale_copy signal=11 code=10 terminal=1',
     'CBPF stale_spill signal=11 code=10 terminal=1',
     'CBPF final_references=1 effects=2 cells_allocated=2 cells_reused=0', 'CBPF CHERI PROBE PASS']
    controls_ok = True
    failure = 'CBPF CHERI PROBE FAIL'
passed = (sys.argv[2] == '0' and all(log.splitlines().count(row) == 1 for row in required)
          and controls_ok and 'Power down' in log and 'Kernel panic' not in log and failure not in log)
summary = '\n'.join(line for line in log.splitlines() if line.startswith(('CBPF ', 'CBPF_GATE ')))
summary += f'\nCBPF runner={"PASS" if passed else "FAIL"} mode={sys.argv[3]} qemu_exit={sys.argv[2]}\n'
(root/'summary.txt').write_text(summary)
print(summary, end=''); print(f'CBPF retained evidence: {root}')
raise SystemExit(0 if passed else 1)
PY
