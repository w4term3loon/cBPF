#!/bin/bash
# Bounded M3 controls in a fresh offline Morello guest; invalid BPF is load-only.
set -euo pipefail
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
native=${CBPF_NATIVE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/cbpf/morello}
kernel_build=$project/build/ownership-m3-kernel
headers=$project/build/ownership-m3-headers
receipt=$project/build/ownership-m3-build
kernel=$kernel_build/arch/arm64/boot/Image
compiler=$native/opt/cheri/output/morello-sdk/bin/clang
linker=$native/opt/cheri/output/morello-sdk/bin/ld.lld
qemu=$native/opt/cheri/output/sdk/bin/qemu-system-morello
firmware=$native/opt/cheri/output/sdk/share/qemu/edk2-aarch64-code.fd
sysroot=$native/musl-sysroot
builtins=$native/libclang_rt.builtins-aarch64.a

python3 - "$project" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1]); receipt = root/'build/ownership-m3-build'
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
    path = root / ('build/ownership-m3-kernel/'+name[7:] if name.startswith('/build/')
                   else 'build/ownership-m3-headers/'+name[9:])
    require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, path)
    actual[str(path)] = digest
require(not expected, 'missing artifact')
host_rows = (receipt/'outputs.sha256').read_text().splitlines()
host = dict((name, digest) for digest, name in (row.split('  ', 1) for row in host_rows))
require(len(host_rows) == len(actual) and host == actual, 'host/container output manifests disagree')
config = (receipt/'kernel.config').read_bytes()
require(config == (root/'build/ownership-m3-kernel/.config').read_bytes(), 'configuration receipt')
for option in ('CBPF_KFUNC_GATE', 'BPF_SYSCALL', 'BPF_JIT', 'BPF_UNPRIV_DEFAULT_OFF',
               'ARM64_MORELLO', 'CHERI_PURECAP_UABI', 'DEBUG_INFO_BTF', 'STRICT_KERNEL_RWX'):
    require(f'CONFIG_{option}=y'.encode() in config.splitlines(), option)
require(b'CONFIG_CAPEBPF_' not in config, 'inherited research configuration')
require(b'CONFIG_MODULE_ALLOW_BTF_MISMATCH=y' not in config, 'BTF mismatch allowance')
verifier = root/'build/ownership-m3-source/kernel/bpf/verifier.c'
require(hashlib.sha256(verifier.read_bytes()).hexdigest() ==
        '48268a29931754296882a9ff6847eb556ba8e8564959be1c62754afdb2fb4851', 'unchanged stock verifier')
for name in ('platform.patch', 'integration.patch', 'cbpf.h', 'cbpf_runtime.c', 'cbpf_jit.c'):
    require((receipt/name).read_bytes() == (root/'linux/ownership'/name).read_bytes(), 'current mechanism: '+name)
require((receipt/'build-script.executed.sh').read_bytes() == (root/'tools/build_ownership_kernel.sh').read_bytes(), 'current build recipe')
print('CBPF ownership kernel artifacts verified')
PY
for input in "$compiler" "$linker" "$qemu" "$firmware" "$builtins" "$sysroot/lib/libc.a"; do
    test -r "$input" || { echo "CBPF missing local dependency: $input" >&2; exit 1; }
done
run=$(mktemp -d "$project/build/ownership-m3-run.XXXXXX")
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
import hashlib, json, pathlib, re, struct, sys
root = pathlib.Path(sys.argv[1])
log = (root/'boot.log').read_text(errors='replace').replace('\r', '')
rows = [re.sub(r'^\[\s*\d+\.\d+\]\s*', '', row) for row in log.splitlines()]
end_pc = 2**64-1
def require(condition, message):
    if not condition:
        raise SystemExit('CBPF M3 validation failed: '+message)
def sections(prefix, names, begin):
    result = {}; active = None
    require(sum(r.startswith(prefix+' case=') for r in rows) == 2*len(names), 'unexpected '+prefix+' case marker')
    for row in rows:
        match = re.fullmatch(begin, row)
        if match:
            require(active is None and match[1] not in result, 'duplicate/nested '+prefix)
            active = match[1]; result[active] = []
        if active is not None:
            result[active].append(row)
            if row.startswith(prefix+' case='+active+' ') and (' phase=end ' in row or ' result=' in row):
                active = None
    require(active is None and list(result) == names, 'missing/unordered '+prefix)
    return result
def gates(lines):
    pattern = (r'CBPF_GATE seq=(\d+) event=(\w+) pc=(\d+) id=(\d+) acquired=(\d+) '
               r'released=(\d+) reads=(\d+) cleanup=(\d+) refs=(\d+) tagA=(\d+) tagB=(\d+)')
    matches = [re.fullmatch(pattern, row) for row in lines if row.startswith('CBPF_GATE ')]
    require(all(matches), 'malformed gate event')
    return [(int(m[1]), m[2], *(int(v) for v in m.groups()[2:])) for m in matches]
def bindings(lines, pcs):
    matches = [re.fullmatch(r'CBPF_BIND pc=(\d+) id=(\d+) cell=([0-9a-f]+) object=([0-9a-f]+) '
               r'public_tag=1 public_base=0x([0-9a-f]+) public_length=16 public_perms=0x20001', row)
               for row in lines if row.startswith('CBPF_BIND ')]
    require(len(matches) == len(pcs) and all(matches), 'public binding receipt')
    require(all(int(m[1]) == pc and int(m[2]) == i+1 and int(m[3],16) == int(m[5],16)
                for i,(m,pc) in enumerate(zip(matches,pcs))), 'binding identity/bounds')
    require(len({m[4] for m in matches}) == 1, 'same provider object')
    if len(matches) == 2:
        require(abs(int(matches[0][3],16)-int(matches[1][3],16)) >= 16, 'distinct cells')

guard_names = ['stale_copy', 'stale_spill', 'duplicate_release']
guards = sections('CBPF_GUARD', guard_names,
    r'CBPF_GUARD case=(\w+) phase=begin native_bpf=0 scope=trusted_resolver')
guard_events = [(1,'acquire',0,1,1,0,0,0,2,1,0), (2,'clear',1,1,1,0,0,0,2,0,0),
                (3,'release',1,1,1,1,0,0,1,0,0), (4,'reject',2,0,1,1,0,0,1,0,0)]
for name, lines in guards.items():
    require(gates(lines) == guard_events, name+' trusted guard effects')
    bindings(lines, [0])
    require(lines[-1] == f'CBPF_GUARD case={name} result=PASS acquired=1 released=1 reads=0 cleanup=0 '
            'refs=1 public_tag=1 canonical=1 tagA=0 failed=1 failure_return=1 native_bpf=0 scope=trusted_resolver',
            name+' trusted guard result')

names = ['ab_spill','ab_alternate','null_second','fail_second','stale_copy','stale_spill','duplicate_release']
cases = sections('CBPF_M3', names, r'CBPF_M3 case=(\w+) phase=begin expected=(?:execute|reject)')
ab = [(1,'acquire',1,1,1,0,0,0,2,1,0), (2,'acquire',6,2,2,0,0,0,3,1,1),
      (3,'clear',11,1,2,0,0,0,3,0,1), (4,'release',11,1,2,1,0,0,2,0,1),
      (5,'read',13,2,2,1,1,0,2,0,1), (6,'clear',16,2,2,1,1,0,2,0,0),
      (7,'release',16,2,2,2,1,0,1,0,0), (8,'exit',end_pc,0,2,2,1,0,1,0,0)]
null = [(1,'acquire',1,1,1,0,0,0,2,1,0), (2,'null',6,0,1,0,0,0,2,1,0),
        (3,'clear',21,1,1,0,0,0,2,0,0), (4,'release',21,1,1,1,0,0,1,0,0),
        (5,'exit',end_pc,0,1,1,0,0,1,0,0)]
failure = [(1,'acquire',1,1,1,0,0,0,2,1,0), (2,'reject',6,0,1,0,0,0,2,1,0),
           (3,'clear',end_pc,1,1,0,0,0,2,0,0), (4,'cleanup',end_pc,1,1,1,0,1,1,0,0),
           (5,'failed',end_pc,0,1,1,0,1,1,0,0)]
ids = dict(re.findall(r'#define CBPF_(\w+)_BTF_ID (\d+)U', (root/'ownership_ids.h').read_text()))
op_ids = {ids[n]: str(op) for n,op in [('ACQUIRE',1),('READ',2),('RELEASE',3)]}
results = []; bytecodes = {}; native_hashes = []
for index,(name,lines) in enumerate(cases.items()):
    end = re.fullmatch(r'CBPF_M3 case='+name+r' phase=end loaded=(\d+) executed=(\d+) retval=(\d+) '
                       r'jited_len=(\d+) load_errno=(\d+) stage=(\w+) result=PASS', lines[-1])
    require(end is not None, name+' case result')
    loaded,executed,value,length,error = map(int,end.groups()[:5])
    bpf = [re.fullmatch(r'CBPF_M3 bpf pc=(\d+) code=([0-9a-f]{2}) dst=(\d+) src=(\d+) off=(-?\d+) imm=(-?\d+)',r)
           for r in lines if r.startswith('CBPF_M3 bpf ')]
    require(bpf and all(bpf) and [int(m[1]) for m in bpf] == list(range(len(bpf))), name+' BPF receipt')
    bytecodes[name] = [m.groups()[1:] for m in bpf]
    if index >= 4:
        require((loaded,executed,value,length) == (0,0,0,0) and error in (13,22) and end[6] == 'load', name+' load-only')
        require(any(re.search(r'R1 (?:type=scalar|!read_ok|must be referenced)|arg#0 pointer type STRUCT cbpf_cap_ref must point to scalar',r)
                    for r in lines) and any(re.search(r'^13: \(85\) call cbpf_cap_(?:read|release)#',r) for r in lines),
                name+' verifier diagnostic/call PC')
        require(not any(r.startswith(('CBPF_GATE ','CBPF_BIND ','CBPF_ENTER ','CBPF_RESULT ', 'CBPF_NATIVE ')) for r in lines), name+' never executed')
        results.append({'case':name, 'result':'PASS', 'loaded':False, 'executed':False, 'load_errno':error})
        continue
    expected_value = [42,42,7,0][index]
    require((loaded,executed,value,error) == (1,1,expected_value,0) and end[6] == 'execute', name+' execution result')
    expected_gates = [ab,ab,null,failure][index]
    require(gates(lines) == expected_gates, name+' exact ordered effects/terminal containment')
    bindings(lines, [1,6] if index < 2 else [1])
    require([r for r in lines if r.startswith('CBPF_RESULT ')] ==
            [f'CBPF_RESULT value={value} entered=1 failed={int(index == 3)} balanced=1'], name+' final accounting')
    words = [re.fullmatch(r'CBPF_M3 word index=(\d+) value=([0-9a-f]{8})',r)
             for r in lines if r.startswith('CBPF_M3 word ')]
    require(words and all(words) and [int(m[1]) for m in words] == list(range(len(words))), name+' native word indices')
    kernel_words = [re.fullmatch(r'CBPF_NATIVE word index=(\d+) value=([0-9a-f]{8})',r)
                    for r in lines if r.startswith('CBPF_NATIVE word ')]
    require(all(kernel_words) and [m.groups() for m in kernel_words] == [m.groups() for m in words], name+' kernel/native equality')
    native = b''.join(struct.pack('<I',int(m[2],16)) for m in words)
    require(0 < len(native) == length <= 8192, name+' native size')
    native_file = root/('native-'+name+'.bin'); native_file.write_bytes(native)
    digest = hashlib.sha256(native).hexdigest(); native_hashes.append(digest+'  '+str(native_file))
    accepted = [re.fullmatch(r'CBPF_NATIVE accepted insns=(\d+) words=(\d+) entry=([0-9a-f]+) '
                 r'restricted_exit=(\d+) executive_exit=(\d+) template_check=pass',r)
                 for r in lines if r.startswith('CBPF_NATIVE accepted ')]
    maps = [re.fullmatch(r'CBPF_NATIVE map pc=(\d+) begin=(\d+) end=(\d+) code=([0-9a-f]{2}) op=(\d+)',r)
            for r in lines if r.startswith('CBPF_NATIVE map ')]
    require(len(accepted) == 1 and all(accepted) and len(maps) == len(bpf) and all(maps), name+' native map')
    count,word_count,image,restricted,executive = accepted[0].groups()
    require(int(count) == len(bpf) and int(word_count) == len(words) and
            0 < int(restricted) < int(executive) < len(words) and int(executive) == int(restricted)+1, name+' native envelope')
    require([int(m[1]) for m in maps] == list(range(len(bpf))) and
            all(m[4] == b[2] and m[5] == (op_ids.get(b[6]) if b[2] == '85' else '0') and
                0 <= int(m[2]) < int(m[3]) <= int(restricted) for m,b in zip(maps,bpf)) and
            all(a[3] == b[2] for a,b in zip(maps,maps[1:])) and int(maps[-1][3]) == int(restricted), name+' source/native map')
    entries = [re.fullmatch(r'CBPF_ENTER restricted_base=0x([0-9a-f]+) restricted_size=(\d+) '
                r'executive_base=0x([0-9a-f]+) executive_size=(\d+) stack_base=0x([0-9a-f]+) '
                r'stack_size=16 rddc_tag=0 gate_sealed=1',r) for r in lines if r.startswith('CBPF_ENTER ')]
    require(len(entries) == 1 and all(entries), name+' restricted entry')
    base,size,exit_base,exit_size,stack = entries[0].groups()
    require(int(size) > 0 and int(base,16)+int(size) == int(exit_base,16) and
            int(exit_base,16) == int(image,16)+4*int(executive) and
            int(exit_size) == 4*(len(words)-int(executive)) and int(stack,16)%16 == 0, name+' restricted bounds')
    results.append({'case':name, 'result':'PASS', 'loaded':True, 'executed':True, 'retval':value,
                    'bpf_instructions':len(bpf), 'native_bytes':length, 'native_sha256':digest,
                    'acquired':expected_gates[-1][4], 'released':expected_gates[-1][5],
                    'reads':expected_gates[-1][6], 'cleanup':expected_gates[-1][7], 'refs':1})
require(len(bytecodes['ab_spill']) == 26 and len(bytecodes['ab_alternate']) == 27 and
        bytecodes['ab_spill'] != bytecodes['ab_alternate'], 'alternate structural arrangement')
for name, argument in [('null_second','1'),('fail_second','2')]:
    expected = list(bytecodes['ab_spill']); expected[5] = (*expected[5][:-1], argument)
    require(bytecodes[name] == expected, name+' controlled acquisition argument')
require(sum(r.startswith('CBPF_GATE ') for r in rows) == 38 and
        sum(r.startswith('CBPF_ENTER ') for r in rows) == 4 and
        sum(r.startswith('CBPF_RESULT ') for r in rows) == 4, 'no extra execution events')
require(sys.argv[2] == '0' and rows.count('CBPF_M3 result=PASS') == 1 and
        rows.count('CBPF_M3 kernel=6.7.0-cbpf-ownership normal_verifier=1 attached=0') == 1 and
        'Power down' in log and not re.search(r'result=FAIL|Kernel panic|Oops:|BUG:|WARNING:|refcount_t:',log), 'clean guest result')
(root/'native.sha256').write_text('\n'.join(native_hashes)+'\n')
(root/'results.json').write_text(json.dumps({'milestone':'M3', 'trusted_resolver_checks':guard_names,
    'cases':results, 'qemu_exit':0, 'invalid_bpf_executions':0,
    'limits':['Trusted stale controls do not execute invalid restricted BPF.',
              'Scalar 2 tests pre-provider argument rejection, not exact-bounds construction failure.',
              'Nonzero normal-return cleanup is inspected/modelled; the verifier rejects leaked ownership.']},indent=2)+'\n')
summary = '\n'.join(r for r in rows if 'CBPF_' in r and not r.startswith(('CBPF_M3 word ','CBPF_M3 bpf ','CBPF_NATIVE word ')))
summary += '\nCBPF ownership_runner=PASS milestone=M3 qemu_exit=0 executed=4 rejected=3 trusted_checks=3\n'
(root/'summary.txt').write_text(summary)
print(summary, end=''); print(f'CBPF retained evidence: {root}')
PY
