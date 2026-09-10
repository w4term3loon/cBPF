#!/bin/bash
# Build the bounded CBPF ownership kernel from a verified pristine export.
# This recipe builds local artifacts only; it never starts a guest.
set -euo pipefail
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
revision=b96da308ef1a054c3c04c9445e5ed70259b7c397
source_git=${CBPF_OWNERSHIP_SOURCE_GIT:-${TEMP_SOURCE}/cheri-ebpf-closure-linux-base/.git}
builder=sha256:b4de3680a00e3ac68ccc56bd87131b97c1fffcd5e016c2d1a54d7e3386d9fc6e
pahole_runtime=${CBPF_OWNERSHIP_PAHOLE_RUNTIME:-${PRIOR_OWNERSHIP_EVIDENCE}/tools/pahole-runtime}
jobs=${CBPF_OWNERSHIP_BUILD_JOBS:-4}
[[ "$jobs" =~ ^[1-4]$ ]] || { echo 'CBPF ownership jobs must be 1..4' >&2; exit 2; }
source_dir=$project/build/ownership-c1-source
output=$project/build/ownership-c1-kernel
headers=$project/build/ownership-c1-headers
receipt=$project/build/ownership-c1-build
baseline=$project/evidence/current/kfunc/kernel.config
inputs=$project/linux/ownership
test ! -e "$source_dir" || { echo "Preserve/move the prior generated source before a fresh build: $source_dir" >&2; exit 2; }
test ! -e "$receipt" || { echo "Preserve/move the prior build receipt before a fresh build: $receipt" >&2; exit 2; }
for file in platform.patch integration.patch cbpf.h cbpf_runtime.c cbpf_jit.c; do
    test -r "$inputs/$file"
done
test -r "$source_git/HEAD"
test -r "$pahole_runtime/pahole.bin"
test "$(sha256sum "$baseline" | cut -d' ' -f1)" = ca41988a4a902f161874cfcad58221a440180f0573d2bcccff7fdeed4ed4389a
export GIT_NO_LAZY_FETCH=1 GIT_ALLOW_PROTOCOL= GIT_OPTIONAL_LOCKS=0
export GIT_CEILING_DIRECTORIES="$project/build"
git --git-dir="$source_git" cat-file -e "$revision^{commit}"
mkdir -p "$source_dir" "$output" "$headers" "$receipt"
trap 'status=$?; if ((status)); then printf "CBPF_OWNERSHIP_BUILD result=FAIL exit=%s\n" "$status" >"$receipt/summary.txt"; fi' EXIT
cp "$0" "$receipt/build-script.executed.sh"
cp "$baseline" "$receipt/baseline.config"
cp "$inputs"/{platform.patch,integration.patch,cbpf.h,cbpf_runtime.c,cbpf_jit.c} "$receipt/"
git --git-dir="$source_git" archive "$revision" | tar -x -C "$source_dir"
# Check contents, symlinks, executable modes, directories, and absence of extras.
python3 - "$source_git" "$revision" "$source_dir" "$receipt" <<'PY'
import hashlib, os, pathlib, stat, subprocess, sys
git, revision, directory, receipt = sys.argv[1:]
root = pathlib.Path(directory)
manifest = subprocess.check_output(['git', '--git-dir='+git, 'ls-tree', '-rz', revision])
pathlib.Path(receipt, 'source-tree.manifest').write_bytes(manifest)
entries = set(); directories = set()
for entry in manifest.split(b'\0'):
    if not entry:
        continue
    metadata, name = entry.split(b'\t', 1); mode, kind, expected = metadata.split()
    if kind != b'blob':
        raise SystemExit('Unexpected non-blob source entry')
    relative = pathlib.Path(os.fsdecode(name)); path = root / relative
    entries.add(relative)
    directories.update(p for p in relative.parents if p != pathlib.Path('.'))
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
    if hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest().encode() != expected:
        raise SystemExit('Source content mismatch: '+str(path))
for relative in directories:
    if not stat.S_ISDIR((root / relative).lstat().st_mode):
        raise SystemExit('Source directory mismatch: '+str(relative))
observed = {(pathlib.Path(base)/name).relative_to(root)
            for base, dirs, files in os.walk(root, followlinks=False) for name in dirs+files}
if observed != entries | directories:
    raise SystemExit('Unexpected source entries')
print('CBPF pristine ownership source verified: '+revision)
PY
printf '%s\n' "$revision" >"$receipt/source-commit.txt"
git --git-dir="$source_git" rev-parse "$revision^{tree}" >"$receipt/source-tree.txt"
sha256sum "$source_dir/kernel/bpf/verifier.c" >"$receipt/verifier-before.sha256"
for patch in platform integration; do
    git -C "$source_dir" apply --numstat "$receipt/$patch.patch" >"$receipt/$patch.numstat"
    git -C "$source_dir" apply --check --whitespace=error-all "$receipt/$patch.patch"
    git -C "$source_dir" apply --whitespace=error-all "$receipt/$patch.patch"
done
cp "$receipt/cbpf.h" "$source_dir/include/linux/cbpf.h"
cp "$receipt/cbpf_runtime.c" "$receipt/cbpf_jit.c" "$source_dir/arch/arm64/net/"
sha256sum -c "$receipt/verifier-before.sha256" >"$receipt/verifier-unchanged.txt"
python3 - "$source_dir" "$receipt" <<'PY'
import hashlib, pathlib, sys
root, receipt = map(pathlib.Path, sys.argv[1:])
paths = {'include/linux/cbpf.h', 'arch/arm64/net/cbpf_runtime.c', 'arch/arm64/net/cbpf_jit.c',
         'kernel/bpf/verifier.c'}
for name in ('platform', 'integration'):
    paths.update(row.split('\t')[2] for row in (receipt/(name+'.numstat')).read_text().splitlines())
(receipt/'patched-sources.sha256').write_text(''.join(
    hashlib.sha256((root/path).read_bytes()).hexdigest()+'  '+str(root/path)+'\n' for path in sorted(paths)))
PY
docker image inspect --format '{{.Id}} {{json .RepoDigests}}' "$builder" >"$receipt/builder-image.txt"
sha256sum "$0" "$baseline" "$inputs"/{platform.patch,integration.patch,cbpf.h,cbpf_runtime.c,cbpf_jit.c} \
    "$receipt"/{build-script.executed.sh,baseline.config,platform.patch,integration.patch,cbpf.h,cbpf_runtime.c,cbpf_jit.c,source-tree.manifest} \
    "$pahole_runtime/pahole" "$pahole_runtime/pahole.bin" "$pahole_runtime/ld.so" \
    "$pahole_runtime"/lib/* >"$receipt/inputs.sha256"

docker run --rm --interactive --pull=never --network none --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" --memory 12g -e CBPF_BUILD_JOBS="$jobs" \
    -v "$source_dir:/src:ro" -v "$output:/build" -v "$headers:/headers" \
    -v "$receipt:/receipt" -v "$pahole_runtime:/opt/gate4-pahole:ro" \
    -w /src "$builder" /bin/bash -s >"$receipt/compile.log" 2>&1 <<'BUILD'
set -euo pipefail
export KBUILD_BUILD_TIMESTAMP='2026-09-07 00:00:00 UTC'
export KBUILD_BUILD_USER=cbpf KBUILD_BUILD_HOST=ownership
args=(O=/build ARCH=arm64 LLVM=/opt/cheri/output/morello-sdk/bin/ LLVM_IAS=1
    PAHOLE=/opt/gate4-pahole/pahole
    'PAHOLE_FLAGS=--btf_gen_floats --skip_encoding_btf_inconsistent_proto --btf_gen_optimized')
/opt/cheri/output/morello-sdk/bin/clang --version > /receipt/toolchain.txt
/opt/gate4-pahole/pahole --version >> /receipt/toolchain.txt
make --version | head -1 >> /receipt/toolchain.txt
sha256sum /opt/cheri/output/morello-sdk/bin/{clang,ld.lld} > /receipt/compiler.sha256
cp /receipt/baseline.config /build/.config
scripts/config --file /build/.config --enable CBPF_KFUNC_GATE \
    --set-str LOCALVERSION '-cbpf-ownership'
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
allowed = {'CONFIG_CBPF_KFUNC_GATE', 'CONFIG_LOCALVERSION'}
changes = {k: (baseline.get(k), config.get(k)) for k in baseline.keys() | config.keys()
           if k not in allowed and baseline.get(k) != config.get(k)}
if changes:
    raise SystemExit('Unexpected baseline configuration changes: '+repr(changes))
for option in ('CBPF_KFUNC_GATE', 'BPF_SYSCALL', 'BPF_JIT', 'BPF_UNPRIV_DEFAULT_OFF',
               'MODULES', 'DEBUG_INFO_BTF', 'DEBUG_INFO_BTF_MODULES', 'ARM64_MORELLO',
               'CHERI_PURECAP_UABI', 'STRICT_KERNEL_RWX', 'STRICT_MODULE_RWX', 'SECURITY'):
    if config.get('CONFIG_'+option) != 'y':
        raise SystemExit('Missing required config: '+option)
if any(k.startswith('CONFIG_CAPEBPF_') for k in config):
    raise SystemExit('Unexpected inherited research configuration')
if config.get('CONFIG_MODULE_ALLOW_BTF_MISMATCH', 'n') != 'n':
    raise SystemExit('BTF mismatch allowance is forbidden')
if config['CONFIG_LOCALVERSION'] != '"-cbpf-ownership"':
    raise SystemExit('Unexpected kernel local version')
PY_CONFIG
cp /build/.config /receipt/kernel.config
make "${args[@]}" -j"$CBPF_BUILD_JOBS" arch/arm64/net/cbpf_jit.o arch/arm64/net/cbpf_runtime.o
make "${args[@]}" -j"$CBPF_BUILD_JOBS" Image modules
make "${args[@]}" -j"$CBPF_BUILD_JOBS" INSTALL_HDR_PATH=/headers headers_install
cat /build/include/config/kernel.release > /receipt/kernel-release.txt
test "$(cat /receipt/kernel-release.txt)" = '6.7.0-cbpf-ownership'
sha256sum /build/arch/arm64/boot/Image /build/vmlinux /build/Module.symvers \
    /build/.config /headers/include/linux/bpf.h > /receipt/outputs.container.sha256
BUILD

sha256sum -c "$receipt/inputs.sha256" >"$receipt/inputs-verified.txt"
sha256sum -c "$receipt/patched-sources.sha256" >"$receipt/sources-verified.txt"
sha256sum "$output/arch/arm64/boot/Image" "$output/vmlinux" "$output/Module.symvers" \
    "$output/.config" "$headers/include/linux/bpf.h" >"$receipt/outputs.sha256"
printf '%s\n' "CBPF_OWNERSHIP_BUILD result=PASS source_commit=$revision" \
    'CBPF_OWNERSHIP_BUILD verifier_unchanged=1 config_baseline_preserved=1 image=1 boot=0' \
    >"$receipt/summary.txt"
cat "$receipt/summary.txt"
echo "CBPF ownership build artifacts: $receipt"
