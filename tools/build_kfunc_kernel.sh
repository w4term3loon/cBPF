#!/bin/bash
# Build an isolated stock Morello kernel for the CBPF kfunc binding.
# No research kernel patches, guest execution, or network access are used.
set -euo pipefail
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
revision=b96da308ef1a054c3c04c9445e5ed70259b7c397
source_git=${CBPF_KFUNC_SOURCE_GIT:?Set CBPF_KFUNC_SOURCE_GIT to the pinned kernel Git directory}
builder=${CBPF_KFUNC_BUILDER:-sha256:76c8ca062c30aa59b8eb072f30620a2a7e9604515aefe84d64161bf9eb644038}
pahole_runtime=${CBPF_KFUNC_PAHOLE_RUNTIME:?Set CBPF_KFUNC_PAHOLE_RUNTIME to the pahole dependency directory}
# The pinned wrapper requires this container mount: /opt/gate4-pahole.
jobs=${CBPF_KFUNC_BUILD_JOBS:-4}
[[ "$jobs" =~ ^[1-4]$ ]] || { echo 'CBPF kernel jobs must be 1..4' >&2; exit 2; }
source_dir=$project/build/kfunc-kernel-source
output=$project/build/kfunc-kernel
headers=$project/build/kfunc-headers
receipt=$project/build/kfunc-build
mkdir -p "$output" "$headers" "$receipt"
test -r "$source_git/HEAD"
test -r "$pahole_runtime/pahole.bin"
export GIT_NO_LAZY_FETCH=1
git --git-dir="$source_git" cat-file -e "$revision^{commit}"
if test ! -d "$source_dir"; then
    mkdir "$source_dir"
    git --git-dir="$source_git" archive "$revision" | tar -x -C "$source_dir"
fi
# Compare every source file to the pinned tree before exposing it to Kbuild.
python3 - "$source_git" "$revision" "$source_dir" <<'PY'
import hashlib, os, pathlib, stat, subprocess, sys
git, revision, root = sys.argv[1:]
root = pathlib.Path(root)
if not stat.S_ISDIR(root.lstat().st_mode):
    raise SystemExit('Source root is not a directory')
manifest = subprocess.check_output(['git', '--git-dir='+git, 'ls-tree', '-rz', revision])
expected_entries = set()
expected_directories = set()
for entry in manifest.split(b'\0'):
    if not entry:
        continue
    metadata, name = entry.split(b'\t', 1)
    mode, kind, expected = metadata.split()
    if kind != b'blob':
        raise SystemExit('Unexpected non-blob source entry')
    relative = pathlib.Path(os.fsdecode(name))
    expected_entries.add(relative)
    expected_directories.update(p for p in relative.parents if p != pathlib.Path('.'))
    path = root / relative
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
    if actual != expected:
        raise SystemExit('Source mismatch: '+str(path))
for relative in expected_directories:
    if not stat.S_ISDIR((root / relative).lstat().st_mode):
        raise SystemExit('Source directory mismatch: '+str(relative))
actual_entries = set()
for directory, dirs, files in os.walk(root, followlinks=False):
    for name in dirs + files:
        actual_entries.add((pathlib.Path(directory) / name).relative_to(root))
if actual_entries != expected_entries | expected_directories:
    unexpected = sorted(str(p) for p in actual_entries - expected_entries - expected_directories)
    raise SystemExit('Unexpected source entries: '+', '.join(unexpected[:10]))
print('CBPF pristine source verified: '+revision)
PY
git --git-dir="$source_git" ls-tree -rz "$revision" >"$receipt/source-tree.manifest"
printf '%s\n' "$revision" >"$receipt/source-commit.txt"
git --git-dir="$source_git" rev-parse "$revision^{tree}" >"$receipt/source-tree.txt"
docker image inspect --format '{{.Id}} {{json .RepoDigests}}' "$builder" >"$receipt/builder-image.txt"
cp "$0" "$receipt/build-script.executed.sh"
sha256sum "$source_dir/kernel/bpf/verifier.c" "$receipt/build-script.executed.sh" \
    "$receipt/source-tree.manifest" "$pahole_runtime/pahole" \
    "$pahole_runtime/pahole.bin" "$pahole_runtime/ld.so" \
    "$pahole_runtime"/lib/* >"$receipt/inputs.sha256"
docker run --rm --pull=never --network none --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" --memory 12g \
    -e CBPF_BUILD_JOBS="$jobs" \
    -v "$source_dir:/src:ro" -v "$output:/build" \
    -v "$headers:/headers" -v "$receipt:/receipt" \
    -v "$pahole_runtime:/opt/gate4-pahole:ro" \
    -w /src "$builder" /bin/bash -euo pipefail -c '
    export KBUILD_BUILD_TIMESTAMP="2026-09-06 00:00:00 UTC"
    export KBUILD_BUILD_USER=cbpf KBUILD_BUILD_HOST=kfunc
    make_args=(O=/build ARCH=arm64 LLVM=/opt/cheri/output/morello-sdk/bin/
        LLVM_IAS=1 PAHOLE=/opt/gate4-pahole/pahole
        "PAHOLE_FLAGS=--btf_gen_floats --skip_encoding_btf_inconsistent_proto --btf_gen_optimized")
    /opt/cheri/output/morello-sdk/bin/clang --version > /receipt/toolchain.txt
    /opt/gate4-pahole/pahole --version >> /receipt/toolchain.txt
    make --version | head -1 >> /receipt/toolchain.txt
    if test ! -f /build/.config; then
        make "${make_args[@]}" morello_pcuabi_defconfig
        cp /build/.config /receipt/upstream-defconfig.config
        # Serial initramfs guest: these physical-device and disk/network-filesystem
        # families are unnecessary. Preserve the stock security/verifier options.
        for option in DRM FB USB_SUPPORT MMC SCSI ATA MD NETDEVICES I2C \
            SOUND MEDIA_SUPPORT INPUT HID CORESIGHT EXT4_FS NFS_FS ROOT_NFS \
            9P_FS NET_9P VFAT_FS QUOTA AUTOFS_FS ANDROID_BINDER_IPC; do
            scripts/config --file /build/.config --disable "$option"
        done
        scripts/config --file /build/.config \
            --enable BPF_SYSCALL --enable BPF_JIT --enable BPF_UNPRIV_DEFAULT_OFF \
            --enable MODULES --enable MODULE_UNLOAD \
            --enable DEBUG_INFO --disable DEBUG_INFO_NONE \
            --disable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT --enable DEBUG_INFO_DWARF4 \
            --enable DEBUG_INFO_BTF --enable DEBUG_INFO_BTF_MODULES \
            --disable MODULE_ALLOW_BTF_MISMATCH \
            --enable NET --enable INET --enable NET_SCHED --enable NET_CLS_ACT \
            --enable NET_CLS_BPF --enable BPF_EVENTS \
            --enable PROC_FS --enable SYSFS --enable TMPFS \
            --enable BLK_DEV_INITRD --enable RD_GZIP \
            --set-str LOCALVERSION "-cbpf-kfunc-stock"
        make "${make_args[@]}" olddefconfig
    fi
    for option in BPF_SYSCALL BPF_JIT BPF_UNPRIV_DEFAULT_OFF MODULES \
        DEBUG_INFO_BTF DEBUG_INFO_BTF_MODULES ARM64_MORELLO CHERI_PURECAP_UABI \
        PROC_FS SYSFS SERIAL_AMBA_PL011_CONSOLE; do
        grep -qx "CONFIG_${option}=y" /build/.config || { echo "Missing $option" >&2; exit 1; }
    done
    if grep -Eq "^CONFIG_CAPEBPF_|^CONFIG_MODULE_ALLOW_BTF_MISMATCH=y" /build/.config; then
        echo "Unexpected research or BTF-bypass config" >&2; exit 1
    fi
    cp /build/.config /receipt/kernel.config
    make "${make_args[@]}" -j"$CBPF_BUILD_JOBS" Image modules
    make "${make_args[@]}" -j"$CBPF_BUILD_JOBS" INSTALL_HDR_PATH=/headers headers_install
    sha256sum /build/arch/arm64/boot/Image /build/vmlinux /build/Module.symvers \
        /build/.config /headers/include/linux/bpf.h > /receipt/outputs.container.sha256
    cat /build/include/config/kernel.release > /receipt/kernel-release.txt
    '
sha256sum "$output/arch/arm64/boot/Image" "$output/vmlinux" "$output/Module.symvers" \
    "$output/.config" "$headers/include/linux/bpf.h" >"$receipt/outputs.sha256"
printf 'CBPF kernel build complete: %s\n' "$output"
