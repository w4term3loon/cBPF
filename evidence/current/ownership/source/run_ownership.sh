#!/bin/bash
# One benign, synchronous M2 control in a fresh offline Morello guest.
set -euo pipefail
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
native=${CBPF_NATIVE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/cbpf/morello}
kernel_build=$project/build/ownership-kernel
headers=$project/build/ownership-headers
receipt=$project/build/ownership-build
kernel=$kernel_build/arch/arm64/boot/Image
compiler=$native/opt/cheri/output/morello-sdk/bin/clang
linker=$native/opt/cheri/output/morello-sdk/bin/ld.lld
qemu=$native/opt/cheri/output/sdk/bin/qemu-system-morello
firmware=$native/opt/cheri/output/sdk/share/qemu/edk2-aarch64-code.fd
sysroot=$native/musl-sysroot
builtins=$native/libclang_rt.builtins-aarch64.a

python3 - "$project" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1]); receipt = root/'build/ownership-build'
def require(condition, message):
    if not condition:
        raise SystemExit('CBPF ownership artifact validation failed: '+str(message))
require((receipt/'source-commit.txt').read_text().strip() == 'b96da308ef1a054c3c04c9445e5ed70259b7c397', 'source commit')
require((receipt/'kernel-release.txt').read_text().strip() == '6.7.0-cbpf-ownership', 'kernel release')
require('CBPF_OWNERSHIP_BUILD result=PASS ' in (receipt/'summary.txt').read_text(), 'build result')
expected = {'/build/arch/arm64/boot/Image', '/build/vmlinux', '/build/Module.symvers',
            '/build/.config', '/headers/include/linux/bpf.h'}
actual = {}
for row in (receipt/'outputs.container.sha256').read_text().splitlines():
    digest, name = row.split('  ', 1)
    require(name in expected, 'unexpected or duplicate artifact: '+name); expected.remove(name)
    path = root / ('build/ownership-kernel/'+name[7:] if name.startswith('/build/')
                   else 'build/ownership-headers/'+name[9:])
    require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, path)
    actual[str(path)] = digest
require(not expected, 'missing artifact')
host_rows = (receipt/'outputs.sha256').read_text().splitlines()
host = dict((name, digest) for digest, name in (row.split('  ', 1) for row in host_rows))
require(len(host_rows) == len(actual) and host == actual, 'host/container output manifests disagree')
config = (receipt/'kernel.config').read_bytes()
require(config == (root/'build/ownership-kernel/.config').read_bytes(), 'configuration receipt')
for option in ('CBPF_KFUNC_GATE', 'BPF_SYSCALL', 'BPF_JIT', 'BPF_UNPRIV_DEFAULT_OFF',
               'ARM64_MORELLO', 'CHERI_PURECAP_UABI', 'DEBUG_INFO_BTF', 'STRICT_KERNEL_RWX'):
    require(f'CONFIG_{option}=y'.encode() in config.splitlines(), option)
require(b'CONFIG_CAPEBPF_' not in config, 'inherited research configuration')
require(b'CONFIG_MODULE_ALLOW_BTF_MISMATCH=y' not in config, 'BTF mismatch allowance')
verifier = root/'build/ownership-kernel-source/kernel/bpf/verifier.c'
require(hashlib.sha256(verifier.read_bytes()).hexdigest() ==
        '48268a29931754296882a9ff6847eb556ba8e8564959be1c62754afdb2fb4851', 'unchanged stock verifier')
print('CBPF ownership kernel artifacts verified')
PY
for input in "$compiler" "$linker" "$qemu" "$firmware" "$builtins" "$sysroot/lib/libc.a"; do
    test -r "$input" || { echo "CBPF missing local dependency: $input" >&2; exit 1; }
done
run=$(mktemp -d "$project/build/ownership-run.XXXXXX")
cp "$project/linux/ownership/guest.c" "$run/guest.c"
cp "$0" "$run/run-script.executed.sh"
cp "$receipt"/{kernel.config,source-commit.txt,source-tree.txt,builder-image.txt,kernel-release.txt} "$run/"
echo "CBPF ownership run artifacts: $run"
python3 - "$run" "$kernel_build/vmlinux" <<'PY'
import json, pathlib, re, subprocess, sys
root = pathlib.Path(sys.argv[1]); ids = {}; selected = []
btf = subprocess.check_output(['bpftool', 'btf', 'dump', 'file', sys.argv[2], 'format', 'raw'], text=True)
for name, macro in [('cbpf_cap_acquire', 'ACQUIRE'), ('cbpf_cap_read', 'READ'), ('cbpf_cap_release', 'RELEASE')]:
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
    -isystem "$headers/include" -I "$run" -nostdlib \
    "$sysroot/lib/crt1.o" "$sysroot/lib/crti.o" "$run/guest.c" \
    "$sysroot/lib/libc.a" "$builtins" "$sysroot/lib/crtn.o" \
    -o "$run/init" >"$run/compile.log" 2>&1
python3 - "$run" <<'PY'
import gzip, pathlib, stat, sys
root = pathlib.Path(sys.argv[1]); archive = bytearray(); inode = 0
def emit(name, mode, data=b'', major=0, minor=0):
    global inode
    inode += 1; encoded = name.encode()+b'\0'
    fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(encoded), 0]
    archive.extend(b'070701'+''.join(f'{v:08x}' for v in fields).encode()+encoded)
    archive.extend(b'\0'*(-len(archive)%4)); archive.extend(data)
    archive.extend(b'\0'*(-len(archive)%4))
emit('init', stat.S_IFREG | 0o755, (root/'init').read_bytes())
emit('dev', stat.S_IFDIR | 0o755)
emit('dev/console', stat.S_IFCHR | 0o600, major=5, minor=1)
emit('TRAILER!!!', 0)
(root/'initramfs.cpio.gz').write_bytes(gzip.compress(archive, mtime=0))
PY
sha256sum "$run/guest.c" "$run/run-script.executed.sh" "$compiler" "$linker" "$qemu" \
    "$firmware" "$kernel" "$kernel_build/vmlinux" "$kernel_build/Module.symvers" \
    "$kernel_build/.config" "$headers/include/linux/bpf.h" "$(command -v bpftool)" \
    "$sysroot/lib/crt1.o" "$sysroot/lib/crti.o" "$sysroot/lib/crtn.o" \
    "$sysroot/lib/libc.a" "$builtins" "$run/init" "$run/ownership_ids.h" \
    "$run/btf-selection.txt" "$run/initramfs.cpio.gz" >"$run/inputs.sha256"
"$compiler" --version >"$run/toolchain.txt"
"$qemu" --version >>"$run/toolchain.txt"
bpftool version >>"$run/toolchain.txt"
status=0
timeout --signal=TERM --kill-after=5 60 "$qemu" \
    -M virt,gic-version=3 -cpu morello -m 2G -smp 1 \
    -bios "$firmware" -kernel "$kernel" -initrd "$run/initramfs.cpio.gz" \
    -append 'console=ttyAMA0 loglevel=7 rdinit=/init panic=-1' \
    -nic none -display none -monitor none -serial stdio -no-reboot \
    >"$run/boot.log" 2>&1 || status=$?
sha256sum -c "$run/inputs.sha256" >"$run/inputs-verified.txt"
python3 - "$run" "$status" <<'PY'
import hashlib, pathlib, re, struct, sys
root = pathlib.Path(sys.argv[1]); log = (root/'boot.log').read_text(errors='replace').replace('\r', '')
rows = [re.sub(r'^\[\s*\d+\.\d+\]\s*', '', row) for row in log.splitlines()]
required = ['CBPF_M2 kernel=6.7.0-cbpf-ownership normal_verifier=1 attached=0', 'CBPF_M2 result=PASS',
            'CBPF_RESULT value=42 entered=1 failed=0 balanced=1']
cases = re.findall(r'^CBPF_M2 case=ab_spill executed=1 retval=42 jited_len=(\d+)$', log, re.M)
words = re.findall(r'^CBPF_M2 word index=(\d+) value=([0-9a-f]{8})$', log, re.M)
native = b''.join(struct.pack('<I', int(value, 16)) for _, value in words)
(root/'native.bin').write_bytes(native)
(root/'native.sha256').write_text(hashlib.sha256(native).hexdigest()+'  '+str(root/'native.bin')+'\n')
native_ok = (len(cases) == 1 and 0 < len(native) == int(cases[0]) <= 8192
             and [int(index) for index, _ in words] == list(range(len(words))))
kernel_words = [re.fullmatch(r'CBPF_NATIVE word index=(\d+) value=([0-9a-f]{8})', row)
                for row in rows if row.startswith('CBPF_NATIVE word ')]
native_ok = (native_ok and all(kernel_words) and [match.groups() for match in kernel_words] == words
             and sum(row.startswith('CBPF_M2 word ') for row in rows) == len(words))
pattern = (r'^CBPF_GATE seq=(\d+) event=(\w+) pc=(\d+) id=(\d+) acquired=(\d+) released=(\d+) '
           r'reads=(\d+) cleanup=(\d+) refs=(\d+) tagA=(\d+) tagB=(\d+)$')
gates = [re.fullmatch(pattern, row).groups() for row in rows if re.fullmatch(pattern, row)]
gates = [(int(g[0]), g[1], *(int(v) for v in g[2:])) for g in gates]
expected = [(1, 'acquire', 1, 1, 1, 0, 0, 0, 2, 1, 0),
            (2, 'acquire', 6, 2, 2, 0, 0, 0, 3, 1, 1),
            (3, 'clear', 11, 1, 2, 0, 0, 0, 3, 0, 1),
            (4, 'release', 11, 1, 2, 1, 0, 0, 2, 0, 1),
            (5, 'read', 13, 2, 2, 1, 1, 0, 2, 0, 1),
            (6, 'clear', 16, 2, 2, 1, 1, 0, 2, 0, 0),
            (7, 'release', 16, 2, 2, 2, 1, 0, 1, 0, 0),
            (8, 'exit', 2**64-1, 0, 2, 2, 1, 0, 1, 0, 0)]
binds = [re.fullmatch(r'CBPF_BIND pc=(\d+) id=(\d+) cell=([0-9a-f]+) object=([0-9a-f]+) '
    r'public_tag=1 public_base=0x([0-9a-f]+) public_length=16 public_perms=0x20001', row)
    for row in rows if row.startswith('CBPF_BIND ')]
binding_ok = len(binds) == 2 and all(binds)
if binding_ok:
    a, b = [match.groups() for match in binds]
    binding_ok = (a[:2] == ('1', '1') and b[:2] == ('6', '2') and a[3] == b[3]
                  and abs(int(a[2], 16)-int(b[2], 16)) >= 16
                  and all(int(m[2], 16) == int(m[4], 16) for m in (a, b)))
enters = [re.fullmatch(r'CBPF_ENTER restricted_base=0x([0-9a-f]+) restricted_size=(\d+) '
    r'executive_base=0x([0-9a-f]+) executive_size=(\d+) stack_base=0x([0-9a-f]+) '
    r'stack_size=16 rddc_tag=0 gate_sealed=1', row) for row in rows if row.startswith('CBPF_ENTER ')]
entry_ok = len(enters) == 1 and all(enters)
if entry_ok:
    base, size, exit_base, exit_size, stack = enters[0].groups()
    entry_ok = (int(size) > 0 and int(exit_size) > 0 and int(stack, 16) % 16 == 0
                and int(base, 16)+int(size) == int(exit_base, 16))
ids = dict(re.findall(r'#define CBPF_(\w+)_BTF_ID (\d+)U', (root/'ownership_ids.h').read_text()))
calls = re.findall(r'^CBPF_M2 bpf pc=(\d+) code=85 dst=0 src=2 off=0 imm=(\d+)$', log, re.M)
calls_ok = calls == [(str(pc), ids[op]) for pc, op in
                    [(1, 'ACQUIRE'), (6, 'ACQUIRE'), (11, 'RELEASE'), (13, 'READ'), (16, 'RELEASE'), (21, 'RELEASE')]]
accepted = [re.fullmatch(r'CBPF_NATIVE accepted insns=(\d+) words=(\d+) entry=([0-9a-f]+) '
    r'restricted_exit=(\d+) executive_exit=(\d+) template_check=pass', row)
    for row in rows if row.startswith('CBPF_NATIVE accepted ')]
maps = [re.fullmatch(r'CBPF_NATIVE map pc=(\d+) begin=(\d+) end=(\d+) code=([0-9a-f]{2}) op=(\d+)', row)
        for row in rows if row.startswith('CBPF_NATIVE map ')]
bpf = re.findall(r'^CBPF_M2 bpf pc=(\d+) code=([0-9a-f]{2}) dst=(\d+) src=(\d+) off=(-?\d+) imm=(-?\d+)$', log, re.M)
mapping_ok = len(accepted) == 1 and all(accepted) and bool(bpf) and len(maps) == len(bpf) and all(maps)
if mapping_ok:
    count, word_count, image, restricted, executive = accepted[0].groups()
    count, word_count, restricted, executive = map(int, (count, word_count, restricted, executive))
    op_ids = {ids[name]: str(op) for name, op in [('ACQUIRE', 1), ('READ', 2), ('RELEASE', 3)]}
    mapping = [match.groups() for match in maps]
    mapping_ok = (count == len(bpf) and word_count == len(words) and 0 < restricted < executive < word_count
        and executive == restricted+1 and [row[0] for row in mapping] == [str(i) for i in range(count)]
        and [row[0] for row in bpf] == [str(i) for i in range(count)]
        and all(m[3] == instruction[1] and m[4] == (op_ids.get(instruction[5]) if m[3] == '85' else '0')
                and 0 <= int(m[1]) < int(m[2]) <= restricted for m, instruction in zip(mapping, bpf))
        and all(a[2] == b[1] for a, b in zip(mapping, mapping[1:]))
        and int(mapping[-1][2]) == restricted)
    if entry_ok:
        mapping_ok = (mapping_ok and int(exit_base, 16) == int(image, 16)+4*executive
                      and int(exit_size) == 4*(word_count-executive))
gate_ok = (gates == expected and sum(row.startswith('CBPF_GATE ') for row in rows) == len(expected)
           and binding_ok and entry_ok and calls_ok and mapping_ok
           and sum(row.startswith('CBPF_RESULT ') for row in rows) == 1)
passed = (sys.argv[2] == '0' and all(rows.count(row) == 1 for row in required)
          and native_ok and gate_ok and 'Power down' in log
          and not re.search(r'result=FAIL|Kernel panic|Oops:|BUG:|WARNING:|refcount_t:', log))
summary = '\n'.join(row for row in rows if 'CBPF_' in row and not row.startswith(('CBPF_M2 word ', 'CBPF_M2 bpf ', 'CBPF_NATIVE word ')))
summary += f'\nCBPF ownership_runner={"PASS" if passed else "FAIL"} qemu_exit={sys.argv[2]} native_bytes={len(native)}\n'
(root/'summary.txt').write_text(summary)
print(summary, end=''); print(f'CBPF retained evidence: {root}')
raise SystemExit(0 if passed else 1)
PY
