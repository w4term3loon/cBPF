#!/bin/bash
# Prepare and boot the sole benign S5 control. It waits before TEST_RUN.
# Review READY with check_spatial_s5.py before sending CBPF_S5_EXECUTE on stdin.
set -euo pipefail
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[[ $# == 1 ]] || { echo 'Usage: run_spatial_s5.sh /absolute/S5-build-directory' >&2; exit 2; }
build=$(realpath "$1")
receipt=$build/receipt
native=${CBPF_NATIVE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/cbpf/morello}
compiler=$native/opt/cheri/output/morello-sdk/bin/clang
linker=$native/opt/cheri/output/morello-sdk/bin/ld.lld
qemu=$native/opt/cheri/output/sdk/bin/qemu-system-morello
firmware=$native/opt/cheri/output/sdk/share/qemu/edk2-aarch64-code.fd
sysroot=$native/musl-sysroot
builtins=$native/libclang_rt.builtins-aarch64.a
kernel=$build/objects/arch/arm64/boot/Image
python3 - "$build" "$project" <<'PY'
import hashlib,pathlib,sys
build,project=map(pathlib.Path,sys.argv[1:]); receipt=build/'receipt'
assert 'CBPF_S5_BUILD result=PASS' in (build/'summary.txt').read_text()
assert (receipt/'kernel-release.txt').read_text().strip()=='6.7.0-cbpf-spatial-s5'
assert (receipt/'array-authority.patch').read_bytes()==(project/'linux/spatial/array-authority.patch').read_bytes()
assert (receipt/'s5-observe.patch').read_bytes()==(project/'linux/spatial/s5-observe.patch').read_bytes()
assert (receipt/'build_spatial_s5.executed.sh').read_bytes()==(project/'tools/build_spatial_s5.sh').read_bytes()
expected={
 'inputs.sha256':{receipt/name for name in ('array-authority.patch','s5-observe.patch',
     'build_spatial_s5.executed.sh','source-tree.manifest','builder-image.txt')},
 'patched-sources.sha256':{build/'source'/name for name in ('arch/arm64/net/bpf_jit_comp.c',
     'include/linux/bpf.h','kernel/bpf/Kconfig','kernel/bpf/arraymap.c',
     'kernel/bpf/syscall.c','kernel/bpf/verifier.c')},
 'outputs.sha256':{build/name for name in ('objects/arch/arm64/net/bpf_jit_comp.o',
     'objects/kernel/bpf/arraymap.o','objects/kernel/bpf/syscall.o','objects/.config',
     'objects/arch/arm64/boot/Image','objects/vmlinux','headers/include/linux/bpf.h')}}
for manifest,names in expected.items():
 rows=(receipt/manifest).read_text().splitlines()
 assert len(rows)==len(names),manifest
 for line in rows:
  digest,name=line.split('  ',1)
  path=pathlib.Path(name)
  assert path in names,(manifest,name)
  names.remove(path)
  assert hashlib.sha256(path.read_bytes()).hexdigest()==digest,name
 assert not names,manifest
config=(build/'objects/.config').read_bytes()
assert config==(receipt/'kernel.config').read_bytes()
settings=dict(s.split('=',1) for s in config.decode().splitlines() if s.startswith('CONFIG_') and '=' in s)
for option in ('CBPF_ARRAY_AUTHORITY','BPF_SYSCALL','BPF_JIT','BPF_UNPRIV_DEFAULT_OFF',
               'ARM64_MORELLO','CHERI_PURECAP_UABI','STRICT_KERNEL_RWX','STRICT_MODULE_RWX',
               'SECURITY','RANDOMIZE_BASE'):
 assert settings.get('CONFIG_'+option)=='y',option
assert settings.get('CONFIG_CAPEBPF_SPATIAL_OFFLOAD','n')=='n'
assert all(v in ('n','0') for k,v in settings.items() if k.startswith('CONFIG_CAPEBPF_TEST_'))
assert hashlib.sha256((build/'source/kernel/bpf/verifier.c').read_bytes()).hexdigest()=='e1b3401c312176633922671d52b1bd0ccd75f9ab1fcc266a0acb764f784d4239'
print('S5 source, kernel, configuration and inherited verifier identities verified')
PY
run=$(mktemp -d "$project/build/spatial-s5-run.XXXXXX")
printf '%s\n' "$build" > "$run/build-directory.txt"
cp "$project/linux/spatial/s5-guest.c" "$run/guest.c"
cp "$0" "$run/run-script.executed.sh"
cp "$project/tools/check_spatial_s5.py" "$run/check_spatial_s5.executed.py"
cp "$receipt"/{kernel-release.txt,kernel.config,compile.h} "$run/"
echo "CBPF S5 run artifacts: $run"
"$compiler" --target=aarch64-linux-musl_purecap -march=morello -mabi=purecap \
    --sysroot="$sysroot" --ld-path="$linker" -static -O2 -Wall -Wextra -Werror \
    -isystem "$build/headers/include" -nostdlib \
    "$sysroot/lib/crt1.o" "$sysroot/lib/crti.o" "$run/guest.c" \
    "$sysroot/lib/libc.a" "$builtins" "$sysroot/lib/crtn.o" -o "$run/init" \
    >"$run/compile.log" 2>&1
python3 - "$run" <<'PY'
import gzip,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); archive=bytearray(); inode=0
def emit(name,mode,data=b'',major=0,minor=0):
 global inode
 inode+=1; encoded=name.encode()+b'\0'
 fields=[inode,mode,0,0,1,0,len(data),0,0,major,minor,len(encoded),0]
 archive.extend(b'070701'+''.join(f'{n:08x}' for n in fields).encode()+encoded)
 archive.extend(b'\0'*(-len(archive)%4)); archive.extend(data); archive.extend(b'\0'*(-len(archive)%4))
emit('init',stat.S_IFREG|0o755,(root/'init').read_bytes())
emit('dev',stat.S_IFDIR|0o755); emit('dev/console',stat.S_IFCHR|0o600,major=5,minor=1)
emit('TRAILER!!!',0)
(root/'initramfs.cpio.gz').write_bytes(gzip.compress(archive,mtime=0))
PY
sha256sum "$run/guest.c" "$run/run-script.executed.sh" "$run/check_spatial_s5.executed.py" \
    "$compiler" "$linker" "$qemu" "$firmware" "$kernel" "$build/objects/vmlinux" \
    "$build/objects/.config" "$build/headers/include/linux/bpf.h" \
    "$sysroot/lib/crt1.o" "$sysroot/lib/crti.o" "$sysroot/lib/crtn.o" \
    "$sysroot/lib/libc.a" "$builtins" "$run/init" "$run/initramfs.cpio.gz" > "$run/inputs.sha256"
"$compiler" --version > "$run/toolchain.txt"
"$qemu" --version >> "$run/toolchain.txt"
args=(-M virt,gic-version=3 -cpu morello -m 2G -smp 1 -bios "$firmware"
      -kernel "$kernel" -initrd "$run/initramfs.cpio.gz"
      -append 'console=ttyAMA0 loglevel=7 rdinit=/init panic=-1 capebpf.jit_certificate_transcript=1'
      -nic none -display none -monitor none -serial stdio -no-reboot)
printf '%q ' "$qemu" "${args[@]}" > "$run/qemu-command.sh"
printf '\n' >> "$run/qemu-command.sh"
echo 'Guest will wait at CBPF_S5_READY; review native admission before sending its execution token.'
set +e
timeout --foreground --signal=TERM --kill-after=5 900 "$qemu" "${args[@]}" 2>&1 | tee "$run/boot.log"
status=${PIPESTATUS[0]}
set -e
printf '%s\n' "$status" > "$run/qemu-exit.txt"
sha256sum -c "$run/inputs.sha256" > "$run/inputs-verified.txt"
echo "CBPF S5 QEMU exit: $status; retain final validation in $run"
exit "$status"
