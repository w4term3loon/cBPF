#!/bin/bash
# Build the default-off synthetic native ownership containment trace.
set -euo pipefail
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
revision=b96da308ef1a054c3c04c9445e5ed70259b7c397
source_git=${CBPF_OWNERSHIP_SOURCE_GIT:?Set CBPF_OWNERSHIP_SOURCE_GIT to the pinned kernel Git directory}
pahole_runtime=${CBPF_OWNERSHIP_PAHOLE_RUNTIME:?Set CBPF_OWNERSHIP_PAHOLE_RUNTIME to the pahole dependency directory}
builder=sha256:76c8ca062c30aa59b8eb072f30620a2a7e9604515aefe84d64161bf9eb644038
jobs=${CBPF_OWNERSHIP_TRACE_BUILD_JOBS:-4}
[[ "$jobs" =~ ^[1-4]$ ]] || { echo 'CBPF ownership trace jobs must be 1..4' >&2; exit 2; }
baseline=$project/evidence/current/kfunc/kernel.config
inputs=$project/linux/ownership
for file in platform.patch integration.patch cbpf.h cbpf_runtime.c cbpf_jit.c native-trace.patch; do
	test -r "$inputs/$file"
done
test -r "$baseline"
test -r "$source_git/HEAD"
test -r "$pahole_runtime/pahole.bin"
test "$(sha256sum "$baseline" | cut -d' ' -f1)" = ca41988a4a902f161874cfcad58221a440180f0573d2bcccff7fdeed4ed4389a
export GIT_NO_LAZY_FETCH=1 GIT_ALLOW_PROTOCOL= GIT_OPTIONAL_LOCKS=0
export GIT_CEILING_DIRECTORIES="$project/build"
git --git-dir="$source_git" cat-file -e "$revision^{commit}"
mkdir -p "$project/build"
run=$(mktemp -d "$project/build/ownership-native-trace-build.XXXXXX")
mkdir "$run/source" "$run/objects" "$run/headers" "$run/receipt"
trap 'status=$?; if ((status)); then printf "CBPF_OWNERSHIP_TRACE_BUILD result=FAIL exit=%s\n" "$status" >"$run/summary.txt"; fi' EXIT
echo "CBPF ownership native trace build artifacts: $run"
cp "$0" "$run/receipt/build_ownership_trace.executed.sh"
cp "$baseline" "$run/receipt/baseline.config"
cp "$inputs"/{platform.patch,integration.patch,cbpf.h,cbpf_runtime.c,cbpf_jit.c,native-trace.patch} "$run/receipt/"
docker image inspect --format '{{.Id}} {{json .RepoDigests}}' "$builder" >"$run/receipt/builder-image.txt"
git --git-dir="$source_git" archive "$revision" | tar -x -C "$run/source"

python3 - "$source_git" "$revision" "$run" <<'PY'
import hashlib, os, pathlib, stat, subprocess, sys
git, revision, directory = sys.argv[1:]
run = pathlib.Path(directory); root = run/'source'
manifest = subprocess.check_output(['git', '--git-dir='+git, 'ls-tree', '-rz', revision])
(run/'receipt/source-tree.manifest').write_bytes(manifest)
expected = set(); directories = set()
for entry in manifest.split(b'\0'):
    if not entry:
        continue
    metadata, name = entry.split(b'\t', 1); mode, kind, digest = metadata.split()
    if kind != b'blob':
        raise SystemExit('Unexpected non-blob source entry')
    relative = pathlib.Path(os.fsdecode(name)); path = root/relative
    expected.add(relative); directories.update(p for p in relative.parents if p != pathlib.Path('.'))
    actual_mode = path.lstat().st_mode
    if mode == b'120000':
        if not stat.S_ISLNK(actual_mode):
            raise SystemExit('Source type mismatch: '+str(path))
        data = os.fsencode(os.readlink(path))
    else:
        if (mode not in (b'100644', b'100755') or not stat.S_ISREG(actual_mode)
                or bool(actual_mode & 0o111) != (mode == b'100755')):
            raise SystemExit('Source mode mismatch: '+str(path))
        data = path.read_bytes()
    actual = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest().encode()
    if actual != digest:
        raise SystemExit('Source content mismatch: '+str(path))
for relative in directories:
    if not stat.S_ISDIR((root/relative).lstat().st_mode):
        raise SystemExit('Source directory mismatch: '+str(relative))
observed = {(pathlib.Path(base)/name).relative_to(root)
            for base, dirs, files in os.walk(root, followlinks=False) for name in dirs+files}
if observed != expected | directories:
    raise SystemExit('Unexpected source entries')
(run/'receipt/source-commit.txt').write_text(revision+'\n')
(run/'receipt/source-tree.txt').write_text(subprocess.check_output(
    ['git', '--git-dir='+git, 'rev-parse', revision+'^{tree}'], text=True))
verifier = root/'kernel/bpf/verifier.c'
(run/'receipt/verifier-before.sha256').write_text(hashlib.sha256(verifier.read_bytes()).hexdigest()+'\n')
print('CBPF pristine ownership trace source verified: '+revision)
PY

for patch in platform integration; do
	git -C "$run/source" apply --check --whitespace=error-all "$run/receipt/$patch.patch"
	git -C "$run/source" apply --numstat "$run/receipt/$patch.patch" >"$run/receipt/$patch.numstat"
	git -C "$run/source" apply --whitespace=error-all "$run/receipt/$patch.patch"
done
cp "$run/receipt/cbpf.h" "$run/source/include/linux/cbpf.h"
cp "$run/receipt/cbpf_runtime.c" "$run/receipt/cbpf_jit.c" "$run/source/arch/arm64/net/"
git -C "$run/source" apply --check --whitespace=error-all "$run/receipt/native-trace.patch"
git -C "$run/source" apply --numstat "$run/receipt/native-trace.patch" >"$run/receipt/native-trace.numstat"
python3 - "$run" <<'PY'
import pathlib, sys
run = pathlib.Path(sys.argv[1])
expected = {'kernel/bpf/Kconfig', 'include/linux/cbpf.h',
            'arch/arm64/net/cbpf_jit.c', 'arch/arm64/net/cbpf_runtime.c'}
paths = [row.split('\t')[2] for row in (run/'receipt/native-trace.numstat').read_text().splitlines()]
if set(paths) != expected or len(paths) != len(expected):
    raise SystemExit('Native trace overlay changes unexpected source paths')
PY
git -C "$run/source" apply --whitespace=error-all "$run/receipt/native-trace.patch"
python3 - "$run" <<'PY'
import hashlib, pathlib, sys
run = pathlib.Path(sys.argv[1]); root = run/'source'
verifier = hashlib.sha256((root/'kernel/bpf/verifier.c').read_bytes()).hexdigest()
if verifier != (run/'receipt/verifier-before.sha256').read_text().strip():
    raise SystemExit('Ownership native trace changes the verifier source')
paths = {'include/linux/cbpf.h', 'arch/arm64/net/cbpf_runtime.c',
         'arch/arm64/net/cbpf_jit.c', 'kernel/bpf/verifier.c'}
for name in ('platform', 'integration', 'native-trace'):
    paths.update(row.split('\t')[2] for row in
                 (run/'receipt'/(name+'.numstat')).read_text().splitlines())
(run/'receipt/patched-sources.sha256').write_text(''.join(
    hashlib.sha256((root/path).read_bytes()).hexdigest()+'  '+str(root/path)+'\n'
    for path in sorted(paths)))
PY
sha256sum "$0" "$baseline" "$inputs"/{platform.patch,integration.patch,cbpf.h,cbpf_runtime.c,cbpf_jit.c,native-trace.patch} \
	"$run/receipt"/{build_ownership_trace.executed.sh,baseline.config,platform.patch,integration.patch,cbpf.h,cbpf_runtime.c,cbpf_jit.c,native-trace.patch,source-tree.manifest,builder-image.txt} \
	"$pahole_runtime/pahole" "$pahole_runtime/pahole.bin" "$pahole_runtime/ld.so" \
	"$pahole_runtime"/lib/* >"$run/receipt/inputs.sha256"

docker run --rm --interactive --pull=never --network none --cap-drop ALL --security-opt no-new-privileges \
	--user "$(id -u):$(id -g)" --memory 12g -e CBPF_BUILD_JOBS="$jobs" \
	-v "$run/source:/src:ro" -v "$run/objects:/build" -v "$run/headers:/headers" \
	-v "$run/receipt:/receipt" -v "$pahole_runtime:/opt/gate4-pahole:ro" \
	-w /src "$builder" /bin/bash -s >"$run/compile.log" 2>&1 <<'BUILD'
set -euo pipefail
export KBUILD_BUILD_TIMESTAMP='2026-09-10 00:00:00 UTC'
export KBUILD_BUILD_USER=cbpf KBUILD_BUILD_HOST=ownership-native-trace
args=(O=/build ARCH=arm64 LLVM=/opt/cheri/output/morello-sdk/bin/ LLVM_IAS=1
    PAHOLE=/opt/gate4-pahole/pahole
    'PAHOLE_FLAGS=--btf_gen_floats --skip_encoding_btf_inconsistent_proto --btf_gen_optimized')
/opt/cheri/output/morello-sdk/bin/clang --version > /receipt/toolchain.txt
/opt/gate4-pahole/pahole --version >> /receipt/toolchain.txt
make --version | head -1 >> /receipt/toolchain.txt
sha256sum /opt/cheri/output/morello-sdk/bin/{clang,ld.lld,llvm-objdump,llvm-nm} > /receipt/compiler.sha256
cp /receipt/baseline.config /build/.config
scripts/config --file /build/.config --enable CBPF_KFUNC_GATE \
    --enable CBPF_OWNERSHIP_NATIVE_TRACE_TEST --disable LOCALVERSION_AUTO \
    --set-str LOCALVERSION '-cbpf-ownership-native-trace'
make "${args[@]}" olddefconfig
python3 - <<'PY_CONFIG'
import pathlib, re
def read(path):
    result = {}
    for line in pathlib.Path(path).read_text().splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1); result[key] = value
        elif match := re.fullmatch(r'# (CONFIG_\w+) is not set', line):
            result[match[1]] = 'n'
    return result
baseline, config = read('/receipt/baseline.config'), read('/build/.config')
allowed = {'CONFIG_CBPF_KFUNC_GATE', 'CONFIG_CBPF_OWNERSHIP_NATIVE_TRACE_TEST',
           'CONFIG_LOCALVERSION', 'CONFIG_LOCALVERSION_AUTO'}
changes = {k: (baseline.get(k), config.get(k)) for k in baseline.keys() | config.keys()
           if k not in allowed and baseline.get(k) != config.get(k)}
if changes:
    raise SystemExit('Unexpected baseline configuration changes: '+repr(changes))
for option in ('CBPF_KFUNC_GATE', 'CBPF_OWNERSHIP_NATIVE_TRACE_TEST', 'BPF_SYSCALL',
               'BPF_JIT', 'BPF_UNPRIV_DEFAULT_OFF', 'MODULES', 'DEBUG_INFO_BTF',
               'DEBUG_INFO_BTF_MODULES', 'ARM64_MORELLO', 'CHERI_PURECAP_UABI',
               'STRICT_KERNEL_RWX', 'STRICT_MODULE_RWX', 'SECURITY'):
    if config.get('CONFIG_'+option) != 'y':
        raise SystemExit('Missing required config: '+option)
if any(k.startswith('CONFIG_CAPEBPF_') for k in config):
    raise SystemExit('Unexpected inherited research configuration')
if config.get('CONFIG_MODULE_ALLOW_BTF_MISMATCH', 'n') != 'n':
    raise SystemExit('BTF mismatch allowance is forbidden')
if config['CONFIG_LOCALVERSION'] != '"-cbpf-ownership-native-trace"':
    raise SystemExit('Unexpected kernel local version')
PY_CONFIG
cp /build/.config /receipt/kernel.config
make "${args[@]}" KCFLAGS=-Werror -j"$CBPF_BUILD_JOBS" \
    arch/arm64/net/cbpf_jit.o arch/arm64/net/cbpf_runtime.o
make "${args[@]}" -j"$CBPF_BUILD_JOBS" Image modules
make "${args[@]}" -j"$CBPF_BUILD_JOBS" INSTALL_HDR_PATH=/headers headers_install
cat /build/include/config/kernel.release > /receipt/kernel-release.txt
test "$(cat /receipt/kernel-release.txt)" = '6.7.0-cbpf-ownership-native-trace'
/opt/cheri/output/morello-sdk/bin/llvm-nm -n /build/vmlinux | \
    grep -E ' cbpf_(gateway|gate_impl|test_invoke|enter|ownership_trace_program)$' \
    > /receipt/native-trace-symbols.txt
for symbol in cbpf_gateway cbpf_gate_impl cbpf_test_invoke cbpf_enter cbpf_ownership_trace_program; do
    /opt/cheri/output/morello-sdk/bin/llvm-objdump -d --disassemble-symbols="$symbol" /build/vmlinux
done > /receipt/native-trace-linked-disassembly.txt
sha256sum /build/arch/arm64/boot/Image /build/vmlinux /build/Module.symvers \
    /build/.config /headers/include/linux/bpf.h > /receipt/outputs.container.sha256
BUILD

sha256sum -c "$run/receipt/inputs.sha256" >"$run/receipt/inputs-verified.txt"
sha256sum -c "$run/receipt/patched-sources.sha256" >"$run/receipt/sources-verified.txt"
sha256sum "$run/objects/arch/arm64/boot/Image" "$run/objects/vmlinux" \
	"$run/objects/Module.symvers" "$run/objects/.config" \
	"$run/headers/include/linux/bpf.h" >"$run/receipt/outputs.sha256"
printf '%s\n' \
	"CBPF_OWNERSHIP_TRACE_BUILD result=PASS source_commit=$revision image=1" \
	'CBPF_OWNERSHIP_TRACE_BUILD verifier_unchanged=1 production_provider_overlay=unchanged native_trace_test=1 boot=0' \
	>"$run/summary.txt"
cat "$run/summary.txt"
echo "CBPF retained ownership native trace build artifacts: $run"
