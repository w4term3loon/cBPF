#!/bin/bash
# Boot one synthetic native ownership trace build; invalid BPF is load-only.
set -euo pipefail
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[[ $# == 1 ]] || { echo 'Usage: run_ownership_trace.sh BUILD_DIRECTORY' >&2; exit 2; }
build=$(realpath "$1")
receipt=$build/receipt
builder=sha256:76c8ca062c30aa59b8eb072f30620a2a7e9604515aefe84d64161bf9eb644038
native=${CBPF_NATIVE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/cbpf/morello}
compiler=$native/opt/cheri/output/morello-sdk/bin/clang
linker=$native/opt/cheri/output/morello-sdk/bin/ld.lld
qemu=$native/opt/cheri/output/sdk/bin/qemu-system-morello
firmware=$native/opt/cheri/output/sdk/share/qemu/edk2-aarch64-code.fd
sysroot=$native/musl-sysroot
builtins=$native/libclang_rt.builtins-aarch64.a
kernel=$build/objects/arch/arm64/boot/Image

python3 - "$build" "$project" <<'PY'
import hashlib, pathlib, sys
build, project = map(pathlib.Path, sys.argv[1:]); receipt = build/'receipt'
def require(condition, message):
    if not condition:
        raise SystemExit('CBPF ownership trace artifact validation failed: '+str(message))
require('CBPF_OWNERSHIP_TRACE_BUILD result=PASS' in (build/'summary.txt').read_text(), 'build result')
require((receipt/'source-commit.txt').read_text().strip() ==
        'b96da308ef1a054c3c04c9445e5ed70259b7c397', 'source commit')
require((receipt/'kernel-release.txt').read_text().strip() ==
        '6.7.0-cbpf-ownership-native-trace', 'kernel release')
for name in ('platform.patch', 'integration.patch', 'cbpf.h', 'cbpf_runtime.c',
             'cbpf_jit.c', 'native-trace.patch'):
    require((receipt/name).read_bytes() == (project/'linux/ownership'/name).read_bytes(),
            'current input: '+name)
require((receipt/'build_ownership_trace.executed.sh').read_bytes() ==
        (project/'tools/build_ownership_trace.sh').read_bytes(), 'current build recipe')
expected = {
    'patched-sources.sha256': {build/'source'/name for name in (
        'arch/arm64/include/asm/morello.h', 'arch/arm64/include/asm/ptrace.h',
        'arch/arm64/include/asm/suspend.h', 'arch/arm64/kernel/asm-offsets.c',
        'arch/arm64/kernel/entry-common.c', 'arch/arm64/kernel/entry.S',
        'arch/arm64/kernel/head.S', 'arch/arm64/kernel/morello.c',
        'arch/arm64/kernel/ptrace.c', 'arch/arm64/mm/proc.S',
        'arch/arm64/net/Makefile', 'arch/arm64/net/bpf_jit_comp.c',
        'arch/arm64/net/cbpf_jit.c', 'arch/arm64/net/cbpf_runtime.c',
        'include/linux/bpf.h', 'include/linux/cbpf.h', 'kernel/bpf/Kconfig',
        'kernel/bpf/core.c', 'kernel/bpf/syscall.c', 'kernel/bpf/verifier.c',
        'net/bpf/test_run.c')},
    'outputs.sha256': {build/name for name in (
        'objects/arch/arm64/boot/Image', 'objects/vmlinux', 'objects/Module.symvers',
        'objects/.config', 'headers/include/linux/bpf.h')},
}
for manifest, names in expected.items():
    rows = (receipt/manifest).read_text().splitlines()
    require(len(rows) == len(names), manifest)
    for row in rows:
        digest, name = row.split('  ', 1); path = pathlib.Path(name)
        require(path in names, (manifest, name)); names.remove(path)
        require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, name)
    require(not names, manifest)
config = (build/'objects/.config').read_bytes()
require(config == (receipt/'kernel.config').read_bytes(), 'configuration receipt')
settings = dict(row.split('=', 1) for row in config.decode().splitlines()
                if row.startswith('CONFIG_') and '=' in row)
for option in ('CBPF_KFUNC_GATE', 'CBPF_OWNERSHIP_NATIVE_TRACE_TEST', 'BPF_SYSCALL',
               'BPF_JIT', 'BPF_UNPRIV_DEFAULT_OFF', 'ARM64_MORELLO',
               'CHERI_PURECAP_UABI', 'DEBUG_INFO_BTF', 'STRICT_KERNEL_RWX'):
    require(settings.get('CONFIG_'+option) == 'y', option)
require(settings.get('CONFIG_MODULE_ALLOW_BTF_MISMATCH', 'n') == 'n', 'BTF mismatch allowance')
require(not any(key.startswith('CONFIG_CAPEBPF_') for key in settings), 'research config')
require(hashlib.sha256((build/'source/kernel/bpf/verifier.c').read_bytes()).hexdigest() ==
        (receipt/'verifier-before.sha256').read_text().strip(), 'unchanged verifier')
print('ownership trace source, kernel, configuration and verifier identities verified')
PY
for input in "$compiler" "$linker" "$qemu" "$firmware" "$builtins" "$sysroot/lib/libc.a"; do
	test -r "$input" || { echo "CBPF missing local dependency: $input" >&2; exit 1; }
done
run=$(mktemp -d "$project/build/ownership-native-trace-run.XXXXXX")
printf '%s\n' "$build" >"$run/build-directory.txt"
cp "$project/linux/ownership/native-trace-guest.c" "$run/guest.c"
cp "$project/tools/check_ownership_trace.py" "$run/check_ownership_trace.executed.py"
cp "$0" "$run/run_ownership_trace.executed.sh"
cp "$receipt"/{kernel-release.txt,kernel.config,native-trace-symbols.txt,native-trace-linked-disassembly.txt} "$run/"
echo "CBPF ownership native trace run artifacts: $run"
python3 - "$run" "$build/objects/vmlinux" <<'PY'
import json, pathlib, re, subprocess, sys
root = pathlib.Path(sys.argv[1]); ids = {}; selected = []
btf = subprocess.check_output(['bpftool', 'btf', 'dump', 'file', sys.argv[2], 'format', 'raw'], text=True)
for name, macro in [('cbpf_cap_acquire', 'ACQUIRE'), ('cbpf_cap_read', 'READ'),
                    ('cbpf_cap_release', 'RELEASE')]:
    matches = re.findall(r"^\[(\d+)\] FUNC '"+name+r"' type_id=\d+ linkage=(?:global|static)$", btf, re.M)
    if len(matches) != 1:
        raise SystemExit('Expected one built-in FUNC BTF ID for '+name)
    ids[macro] = int(matches[0])
    selected.extend(row for row in btf.splitlines() if row.startswith('['+matches[0]+'] FUNC '))
(root/'btf-selection.txt').write_text('\n'.join(selected)+'\n')
(root/'ownership_ids.h').write_text('/* Generated from the matching built-in vmlinux BTF. */\n'+
    ''.join(f'#define CBPF_{name}_BTF_ID {value}U\n' for name, value in ids.items())+
    '#define CBPF_EXPECTED_RELEASE '+json.dumps((root/'kernel-release.txt').read_text().strip())+'\n')
PY
"$compiler" --target=aarch64-linux-musl_purecap -march=morello -mabi=purecap \
	--sysroot="$sysroot" --ld-path="$linker" -static -O2 -Wall -Wextra -Werror \
	-isystem "$build/headers/include" -I "$run" -nostdlib \
	"$sysroot/lib/crt1.o" "$sysroot/lib/crti.o" "$run/guest.c" \
	"$sysroot/lib/libc.a" "$builtins" "$sysroot/lib/crtn.o" -o "$run/init" \
	>"$run/compile.log" 2>&1
python3 - "$run" <<'PY'
import gzip, pathlib, stat, sys
root = pathlib.Path(sys.argv[1]); archive = bytearray(); inode = 0
def emit(name, mode, data=b'', major=0, minor=0):
    global inode
    inode += 1; encoded = name.encode()+b'\0'
    fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(encoded), 0]
    archive.extend(b'070701'+''.join(f'{value:08x}' for value in fields).encode()+encoded)
    archive.extend(b'\0'*(-len(archive)%4)); archive.extend(data)
    archive.extend(b'\0'*(-len(archive)%4))
emit('init', stat.S_IFREG | 0o755, (root/'init').read_bytes())
emit('dev', stat.S_IFDIR | 0o755)
emit('dev/console', stat.S_IFCHR | 0o600, major=5, minor=1)
emit('TRAILER!!!', 0)
(root/'initramfs.cpio.gz').write_bytes(gzip.compress(archive, mtime=0))
PY
sha256sum "$run/guest.c" "$run/check_ownership_trace.executed.py" \
	"$run/run_ownership_trace.executed.sh" "$run/native-trace-symbols.txt" \
	"$run/native-trace-linked-disassembly.txt" "$run/ownership_ids.h" \
	"$run/btf-selection.txt" "$compiler" "$linker" "$qemu" "$firmware" \
	"$kernel" "$build/objects/vmlinux" "$build/objects/.config" \
	"$build/headers/include/linux/bpf.h" "$(command -v bpftool)" \
	"$sysroot/lib/crt1.o" "$sysroot/lib/crti.o" "$sysroot/lib/crtn.o" \
	"$sysroot/lib/libc.a" "$builtins" "$run/init" "$run/initramfs.cpio.gz" \
	>"$run/inputs.sha256"
"$compiler" --version >"$run/toolchain.txt"
"$qemu" --version >>"$run/toolchain.txt"
bpftool version >>"$run/toolchain.txt"
args=(-M virt,gic-version=3 -cpu morello -m 2G -smp 1 -bios "$firmware"
	-kernel "$kernel" -initrd "$run/initramfs.cpio.gz"
	-append 'console=ttyAMA0 loglevel=7 rdinit=/init panic=-1 sysctl.net.core.bpf_jit_enable=1'
	-nic none -display none -monitor none -serial stdio -no-reboot)
printf '%q ' "$qemu" "${args[@]}" >"$run/qemu-command.sh"
printf '\n' >>"$run/qemu-command.sh"
set +e
timeout --foreground --signal=TERM --kill-after=5 300 "$qemu" "${args[@]}" 2>&1 | tee "$run/boot.log"
status=${PIPESTATUS[0]}
set -e
printf '%s\n' "$status" >"$run/qemu-exit.txt"
sha256sum -c "$run/inputs.sha256" >"$run/inputs-verified.txt"
if ((status)); then
	echo "CBPF ownership native trace QEMU failed: exit=$status artifacts=$run" >&2
	exit "$status"
fi
python3 "$run/check_ownership_trace.executed.py" --log "$run/boot.log" \
	--linked-disassembly "$run/native-trace-linked-disassembly.txt" \
	--output "$run/results.json" --native-directory "$run"
printf 'CBPF_OWNERSHIP_TRACE_RUN result=PASS qemu_exit=%s results=%s\n' \
	"$status" "$run/results.json" >"$run/summary.txt"
cat "$run/summary.txt"
echo "CBPF retained ownership native trace validation: $run"
