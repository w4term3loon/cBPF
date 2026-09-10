#!/bin/bash
# Compile the reduced CBPF spatial patch against its pinned inherited tree.
# This check never links a kernel Image, builds modules, or boots a guest.
set -euo pipefail
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tree=e6c69574c16bc2b9bce06329f9ac3f4b3269e79a
source_git=${CBPF_SPATIAL_SOURCE_GIT:?Set CBPF_SPATIAL_SOURCE_GIT to the pinned kernel Git directory}
builder=sha256:76c8ca062c30aa59b8eb072f30620a2a7e9604515aefe84d64161bf9eb644038
jobs=${CBPF_SPATIAL_BUILD_JOBS:-4}
[[ "$jobs" =~ ^[1-4]$ ]] || { echo 'CBPF spatial jobs must be 1..4' >&2; exit 2; }
patch=$project/linux/spatial/array-authority.patch
test -r "$patch"
export GIT_NO_LAZY_FETCH=1 GIT_ALLOW_PROTOCOL= GIT_OPTIONAL_LOCKS=0
# Apply inside the exported tree, without discovering the enclosing CBPF repo.
export GIT_CEILING_DIRECTORIES="$project/build"
mkdir -p "$project/build"
run=$(mktemp -d "$project/build/spatial-check.XXXXXX")
mkdir "$run/source" "$run/objects" "$run/receipt"
trap 'status=$?; if ((status)); then printf "CBPF_SPATIAL_CHECK result=FAIL exit=%s\n" "$status" >"$run/summary.txt"; fi' EXIT
echo "CBPF spatial compile artifacts: $run"
cp "$patch" "$run/receipt/array-authority.patch"
cp "$0" "$run/receipt/check_spatial.executed.sh"
docker image inspect --format '{{.Id}} {{json .RepoDigests}}' "$builder" \
    >"$run/receipt/builder-image.txt"
git --git-dir="$source_git" archive --format=tar "$tree" | tar -xf - -C "$run/source"

# The tree, not the unavailable historical replay commit, is the verified pin.
python3 - "$source_git" "$tree" "$run" <<'PY'
import hashlib, json, os, pathlib, re, stat, subprocess, sys
git, tree, directory = sys.argv[1:]; run = pathlib.Path(directory); root = run/'source'
manifest = subprocess.check_output(['git', '--git-dir='+git, 'ls-tree', '-rz', tree])
(run/'receipt/source-tree.manifest').write_bytes(manifest)
expected = set(); directories = set(); count = 0
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
    count += 1
for relative in directories:
    if not stat.S_ISDIR((root/relative).lstat().st_mode):
        raise SystemExit('Source directory mismatch: '+str(relative))
observed = {(pathlib.Path(base)/name).relative_to(root)
            for base, dirs, files in os.walk(root, followlinks=False) for name in dirs+files}
if observed != expected | directories:
    raise SystemExit('Unexpected source entries')
pins = {'source_git': git, 'verified_tree': tree, 'verified_blobs': count,
        'historically_recorded_commit': '4e4604875fbf4144f9ce456bc6d60f3ef55da4d0',
        'pin_kind': 'tree; historical commit is not required or claimed verified',
        'source_manifest_sha256': hashlib.sha256(manifest).hexdigest()}
(run/'receipt/source-pins.json').write_text(json.dumps(pins, indent=2)+'\n')
verifier = root/'kernel/bpf/verifier.c'
(run/'receipt/verifier-before.sha256').write_text(hashlib.sha256(verifier.read_bytes()).hexdigest()+'\n')
config = (root/'kernel/bpf/Kconfig').read_text()
tests = re.findall(r'^config (CAPEBPF_TEST_[A-Z0-9_]+)$', config, re.M)
(run/'receipt/test-options.txt').write_text('\n'.join(tests)+'\n')
print('CBPF spatial pristine tree verified: '+tree)
PY

git -C "$run/source" apply --check --whitespace=error-all "$run/receipt/array-authority.patch" \
    >"$run/receipt/patch-check.log" 2>&1
git -C "$run/source" apply --numstat "$run/receipt/array-authority.patch" \
    >"$run/receipt/patch-numstat.txt"
python3 - "$run" <<'PY'
import pathlib, sys
run = pathlib.Path(sys.argv[1])
allowed = {'arch/arm64/net/bpf_jit_comp.c', 'include/linux/bpf.h',
           'kernel/bpf/Kconfig', 'kernel/bpf/arraymap.c', 'kernel/bpf/syscall.c'}
paths = [row.split('\t')[2] for row in (run/'receipt/patch-numstat.txt').read_text().splitlines()]
if not paths or len(paths) != len(set(paths)) or not set(paths) <= allowed:
    raise SystemExit('Patch changes an unexpected source path')
PY
git -C "$run/source" apply --whitespace=error-all "$run/receipt/array-authority.patch"
python3 - "$run" <<'PY'
import hashlib, pathlib, sys
run = pathlib.Path(sys.argv[1]); root = run/'source'
verifier = hashlib.sha256((root/'kernel/bpf/verifier.c').read_bytes()).hexdigest()
if verifier != (run/'receipt/verifier-before.sha256').read_text().strip():
    raise SystemExit('Reduced patch changes the inherited verifier source')
paths = [row.split('\t')[2] for row in (run/'receipt/patch-numstat.txt').read_text().splitlines()]
paths.append('kernel/bpf/verifier.c')
(run/'receipt/patched-sources.sha256').write_text(''.join(
    hashlib.sha256((root/path).read_bytes()).hexdigest()+'  '+str(root/path)+'\n' for path in paths))
PY
sha256sum "$run/receipt/array-authority.patch" "$run/receipt/check_spatial.executed.sh" \
    "$run/receipt/source-tree.manifest" "$run/receipt/builder-image.txt" \
    >"$run/receipt/inputs.sha256"

docker run --rm --interactive --pull=never --network none --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" --memory 4g \
    -v "$run/source:/src:ro" -v "$run/objects:/build" -v "$run/receipt:/receipt" \
    -w /src "$builder" /bin/bash -s -- "$jobs" >"$run/compile.log" 2>&1 <<'BUILD'
set -euo pipefail
export KBUILD_BUILD_TIMESTAMP='2026-09-06 00:00:00 UTC'
export KBUILD_BUILD_USER=cbpf KBUILD_BUILD_HOST=spatial-check
args=(O=/build ARCH=arm64 LLVM=/opt/cheri/output/morello-sdk/bin/ LLVM_IAS=1)
/opt/cheri/output/morello-sdk/bin/clang --version > /receipt/compiler.txt
sha256sum /opt/cheri/output/morello-sdk/bin/clang > /receipt/compiler.sha256
make "${args[@]}" morello_pcuabi_defconfig
cp /build/.config /receipt/inherited-defconfig.config
while IFS= read -r option; do
    scripts/config --file /build/.config --disable "$option"
done < /receipt/test-options.txt
scripts/config --file /build/.config --set-val CAPEBPF_TEST_JIT_CERTIFICATE_MUTATION 0 \
    --enable BPF_SYSCALL --enable BPF_JIT --enable MODULES \
    --enable BPF_UNPRIV_DEFAULT_OFF --enable CBPF_ARRAY_AUTHORITY \
    --disable CAPEBPF_SPATIAL_OFFLOAD --disable DEBUG_INFO_BTF
make "${args[@]}" olddefconfig
python3 - <<'PY_CONFIG'
import pathlib
config = dict(row.split('=', 1) for row in pathlib.Path('/build/.config').read_text().splitlines()
              if row.startswith('CONFIG_') and '=' in row)
for option in ('BPF_SYSCALL', 'BPF_JIT', 'MODULES', 'ARM64_MORELLO',
               'CHERI_PURECAP_UABI', 'BPF_UNPRIV_DEFAULT_OFF', 'CBPF_ARRAY_AUTHORITY'):
    if config.get('CONFIG_'+option) != 'y':
        raise SystemExit('Required config missing: '+option)
if config.get('CONFIG_CAPEBPF_SPATIAL_OFFLOAD', 'n') != 'n':
    raise SystemExit('Spatial verifier delegation must be disabled')
for key, value in config.items():
    if key.startswith('CONFIG_CAPEBPF_TEST_') and value not in ('n', '0'):
        raise SystemExit('Unsafe test config: '+key+'='+value)
PY_CONFIG
cp /build/.config /receipt/kernel.config
make "${args[@]}" -j"$1" arch/arm64/net/bpf_jit_comp.o kernel/bpf/arraymap.o kernel/bpf/syscall.o
test ! -e /build/arch/arm64/boot/Image
test ! -e /build/vmlinux
BUILD

sha256sum -c "$run/receipt/inputs.sha256" >"$run/receipt/inputs-verified.txt"
sha256sum -c "$run/receipt/patched-sources.sha256" >"$run/receipt/sources-verified.txt"
sha256sum "$run/objects/arch/arm64/net/bpf_jit_comp.o" \
    "$run/objects/kernel/bpf/arraymap.o" "$run/objects/kernel/bpf/syscall.o" \
    "$run/objects/.config" >"$run/receipt/outputs.sha256"
printf '%s\n' \
    "CBPF_SPATIAL_CHECK result=PASS source_tree=$tree requested_objects=3" \
    'CBPF_SPATIAL_CHECK verifier_unchanged_from_substrate=1 offload=0 test_modes=0 image=0 boot=0' \
    >"$run/summary.txt"
cat "$run/summary.txt"
echo "CBPF retained spatial compile evidence: $run"
