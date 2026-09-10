#!/bin/bash
# Optional normal-verifier Linux binding checks inside a fresh, offline guest.
set -euo pipefail
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
native=${CBPF_NATIVE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/cbpf/morello}
builder=${CBPF_KFUNC_BUILDER:-sha256:76c8ca062c30aa59b8eb072f30620a2a7e9604515aefe84d64161bf9eb644038}
pahole_runtime=${CBPF_KFUNC_PAHOLE_RUNTIME:?Set CBPF_KFUNC_PAHOLE_RUNTIME to the pahole dependency directory}
# The pinned wrapper requires this container mount: /opt/gate4-pahole.
source_dir=$project/build/kfunc-kernel-source
kernel_build=$project/build/kfunc-kernel
headers=$project/build/kfunc-headers
receipt=$project/build/kfunc-build
kernel=$kernel_build/arch/arm64/boot/Image
compiler=$native/opt/cheri/output/morello-sdk/bin/clang
linker=$native/opt/cheri/output/morello-sdk/bin/ld.lld
qemu=$native/opt/cheri/output/sdk/bin/qemu-system-morello
firmware=$native/opt/cheri/output/sdk/share/qemu/edk2-aarch64-code.fd
sysroot=$native/musl-sysroot
builtins=$native/libclang_rt.builtins-aarch64.a

# Accept only the artifacts recorded by the pinned clean-kernel recipe.
python3 - "$project" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1]); receipt = root/'build/kfunc-build'
def require(condition, message):
    if not condition:
        raise SystemExit('CBPF kernel validation failed: '+str(message))
require((receipt/'source-commit.txt').read_text().strip() == 'b96da308ef1a054c3c04c9445e5ed70259b7c397', 'source commit')
require((receipt/'kernel-release.txt').read_text().strip() == '6.7.0-cbpf-kfunc-stock', 'kernel release')
seen = set()
for row in (receipt/'outputs.container.sha256').read_text().splitlines():
    digest, name = row.split('  ', 1)
    require(name not in seen, 'duplicate artifact')
    seen.add(name)
    if name.startswith('/build/'):
        path = root/'build/kfunc-kernel'/name.removeprefix('/build/')
    elif name.startswith('/headers/'):
        path = root/'build/kfunc-headers'/name.removeprefix('/headers/')
    else:
        raise SystemExit('Unexpected kernel artifact path: '+name)
    require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, path)
require(seen == {'/build/arch/arm64/boot/Image', '/build/vmlinux', '/build/Module.symvers',
                 '/build/.config', '/headers/include/linux/bpf.h'}, 'artifact set')
config = (root/'build/kfunc-kernel/.config').read_text().splitlines()
for option in ('BPF_SYSCALL', 'BPF_JIT', 'BPF_UNPRIV_DEFAULT_OFF', 'MODULES',
               'DEBUG_INFO_BTF', 'DEBUG_INFO_BTF_MODULES', 'CHERI_PURECAP_UABI'):
    require(f'CONFIG_{option}=y' in config, option)
require(not any(row.startswith('CONFIG_CAPEBPF_') for row in config), 'research config')
require('CONFIG_MODULE_ALLOW_BTF_MISMATCH=y' not in config, 'BTF mismatch config')
verifier = root/'build/kfunc-kernel-source/kernel/bpf/verifier.c'
require(hashlib.sha256(verifier.read_bytes()).hexdigest() == '48268a29931754296882a9ff6847eb556ba8e8564959be1c62754afdb2fb4851', 'verifier source')
print('CBPF kfunc clean kernel artifacts verified')
PY
for input in "$compiler" "$linker" "$qemu" "$firmware" "$builtins" \
    "$sysroot/lib/libc.a" "$pahole_runtime/pahole.bin"; do
    test -r "$input" || { echo "CBPF missing local dependency: $input" >&2; exit 1; }
done
run=$(mktemp -d "$project/build/kfunc-run.XXXXXX")
mkdir "$run/module"
cp "$project/linux/kfunc/Makefile" "$project/linux/kfunc/cbpf_kfunc.c" "$run/module/"
cp "$project/linux/kfunc/guest.c" "$run/guest.c"
cp "$0" "$run/run-script.executed.sh"
cp "$receipt/kernel.config" "$receipt/source-commit.txt" "$receipt/source-tree.txt" \
    "$receipt/builder-image.txt" "$receipt/kernel-release.txt" "$run/"
echo "CBPF kfunc build/run artifacts: $run"
docker image inspect --format '{{.Id}} {{json .RepoDigests}}' "$builder" >"$run/module-builder-image.txt"
docker run --rm --pull=never --network none --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" --memory 4g \
    -v "$source_dir:/src:ro" -v "$kernel_build:/build" -v "$run/module:/module" \
    -v "$pahole_runtime:/opt/gate4-pahole:ro" -w /src "$builder" \
    make O=/build M=/module ARCH=arm64 LLVM=/opt/cheri/output/morello-sdk/bin/ \
    LLVM_IAS=1 PAHOLE=/opt/gate4-pahole/pahole \
    'PAHOLE_FLAGS=--btf_gen_floats --skip_encoding_btf_inconsistent_proto --btf_gen_optimized' \
    -j4 modules >"$run/module-build.log" 2>&1
bpftool -B "$kernel_build/vmlinux" btf dump file "$run/module/cbpf_kfunc.ko" \
    format raw >"$run/module-btf.txt"
python3 - "$run" <<'PY'
import json, pathlib, re, sys
root = pathlib.Path(sys.argv[1]); btf = (root/'module-btf.txt').read_text()
ids = {}
for name, macro in [('cbpf_ref_acquire', 'ACQUIRE'), ('cbpf_ref_read', 'READ'),
                    ('cbpf_ref_release', 'RELEASE')]:
    matches = re.findall(r"^\[(\d+)\] FUNC '"+name+r"' type_id=\d+ linkage=(?:global|static)$", btf, re.M)
    if len(matches) != 1:
        raise SystemExit('Expected one module FUNC BTF ID for '+name)
    ids[macro] = int(matches[0])
release = (root/'kernel-release.txt').read_text().strip()
(root/'kfunc_ids.h').write_text('/* Generated from this module and its matching vmlinux. */\n'+
    ''.join(f'#define CBPF_{name}_BTF_ID {value}U\n' for name, value in ids.items())+
    '#define CBPF_EXPECTED_RELEASE '+json.dumps(release)+'\n')
PY
"$compiler" --target=aarch64-linux-musl_purecap -march=morello -mabi=purecap \
    --sysroot="$sysroot" --ld-path="$linker" -static -O2 -Wall -Wextra -Werror \
    -isystem "$headers/include" -I "$run" \
    -nostdlib "$sysroot/lib/crt1.o" "$sysroot/lib/crti.o" \
    "$run/guest.c" "$sysroot/lib/libc.a" "$builtins" \
    "$sysroot/lib/crtn.o" -o "$run/init" >"$run/compile.log" 2>&1
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
emit('cbpf_kfunc.ko', stat.S_IFREG | 0o444, (root/'module/cbpf_kfunc.ko').read_bytes())
for name in ('dev', 'proc', 'sys'):
    emit(name, stat.S_IFDIR | 0o755)
emit('dev/console', stat.S_IFCHR | 0o600, major=5, minor=1)
emit('TRAILER!!!', 0)
(root/'initramfs.cpio.gz').write_bytes(gzip.compress(archive, mtime=0))
PY
sha256sum "$run/module/cbpf_kfunc.c" "$run/module/Makefile" \
    "$run/guest.c" "$run/run-script.executed.sh" "$compiler" "$linker" "$qemu" \
    "$firmware" "$kernel" "$kernel_build/vmlinux" "$kernel_build/Module.symvers" \
    "$kernel_build/.config" "$headers/include/linux/bpf.h" \
    "$sysroot/lib/crt1.o" "$sysroot/lib/crti.o" "$sysroot/lib/crtn.o" \
    "$sysroot/lib/libc.a" "$builtins" "$run/init" "$run/module/cbpf_kfunc.ko" \
    "$run/kfunc_ids.h" "$run/module-btf.txt" "$run/initramfs.cpio.gz" \
    "$run/module-builder-image.txt" "$pahole_runtime/pahole" \
    "$pahole_runtime/pahole.bin" "$pahole_runtime/ld.so" \
    "$pahole_runtime"/lib/* >"$run/inputs.sha256"
"$compiler" --version >"$run/toolchain.txt"
"$qemu" --version >>"$run/toolchain.txt"
bpftool version >>"$run/toolchain.txt"
status=0
timeout --signal=TERM --kill-after=5 60 "$qemu" \
    -M virt,gic-version=3 -cpu morello -m 2G -smp 1 \
    -bios "$firmware" -kernel "$kernel" -initrd "$run/initramfs.cpio.gz" \
    -append 'console=ttyAMA0 loglevel=4 rdinit=/init panic=-1' \
    -nic none -display none -monitor none -serial stdio -no-reboot \
    >"$run/boot.log" 2>&1 || status=$?
python3 - "$run" "$status" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1]); log = (root/'boot.log').read_text(errors='replace').replace('\r', '')
required = ['CBPF_KFUNC scope=linux_kfunc_binding runtime_cheri=0 normal_verifier=1',
    'CBPF_KFUNC kernel_release=6.7.0-cbpf-kfunc-stock',
    'CBPF_KFUNC positive_cases=13 rejected_cases=5 repeated_runs=32 executed_total=45 acquisitions=82 releases=82 reads=38 live=0 object_refs=1',
    'CBPF_KFUNC result=PASS']
rejects = re.findall(r'^CBPF_KFUNC case=(\w+) kind=reject executed=0 errno=\d+ result=PASS$', log, re.M)
valid = re.findall(r'^CBPF_KFUNC case=(\w+) kind=valid executed=(\d+) .* result=PASS$', log, re.M)
passed = (sys.argv[2] == '0' and all(log.splitlines().count(row) == 1 for row in required)
    and len(valid) == 14 and sum(int(n) for _, n in valid) == 45
    and sorted(rejects) == sorted(['stale_copy', 'stale_spill', 'double_release', 'missing_null', 'leaked_ref'])
    and 'Power down' in log
    and not re.search(r'result=FAIL|Kernel panic|Oops:|BUG:|WARNING:|refcount_t:', log))
summary = '\n'.join(row for row in log.splitlines() if row.startswith('CBPF_KFUNC '))
summary += f'\nCBPF kfunc_runner={"PASS" if passed else "FAIL"} qemu_exit={sys.argv[2]}\n'
(root/'summary.txt').write_text(summary)
print(summary, end=''); print(f'CBPF retained evidence: {root}')
raise SystemExit(0 if passed else 1)
PY
