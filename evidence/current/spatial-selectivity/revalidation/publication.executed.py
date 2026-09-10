"""Fixed Batch 2 export. Preserve originals and append, never replace a package."""
import argparse
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / 'tools'))
from prepare_spatial_selectivity import retained
from check_spatial_selectivity import validate_run


def identity(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


parser = argparse.ArgumentParser()
parser.add_argument('--run', type=Path, required=True)
args = parser.parse_args()
run = args.run.resolve()
spatial = ROOT / 'evidence/current/spatial-selectivity'
ownership = ROOT / 'evidence/current/ownership-native-trace'
for path in (spatial / 'revalidation', spatial / 'matrix-v2', ownership / 'revalidation'):
    assert not path.exists(), path
private = Path(tempfile.mkdtemp(prefix='cbpf-spatial-batch2-originals.', dir=ROOT.parent))
stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
raw = private / 'matrix-v2'
shutil.copytree(run, raw)
retained(spatial, private / 'revalidation')
revalidation = private / 'revalidation'
for name in ('check_spatial_selectivity.py', 'native_receipt_common.py', 'prepare_spatial_selectivity.py'):
    shutil.copy2(ROOT / 'tools' / name, revalidation / name)
shutil.copy2(__file__, revalidation / 'publication.executed.py')

# Replay the original post-boot checker failure, not the native experiment.
failure = private / 'initial-checker-replay'
failure.mkdir()
command = [sys.executable, str(run / 'check_spatial_selectivity.executed.py'),
           '--run', str(run), '--output', str(failure / 'unexpected-result.json')]
replay = subprocess.run(command, capture_output=True)
assert replay.returncode == 1 and b'Missing/contradictory KASLR basis' in replay.stderr
assert not (failure / 'unexpected-result.json').exists()
(failure / 'stdout.txt').write_bytes(replay.stdout)
(failure / 'stderr.txt').write_bytes(replay.stderr)
write_json(failure / 'receipt.json', {'recorded_utc': stamp, 'command': command,
    'exit_status': replay.returncode, 'scope': 'Post-run replay of the archived checker failure; no guest execution.'})
shutil.copytree(failure, revalidation / 'initial-checker-replay')

owner = private / 'ownership-completion'
owner.mkdir()
native_outputs = private / 'ownership-extracted'
native_outputs.mkdir()
subprocess.run([sys.executable, str(ROOT / 'tools/check_ownership_trace.py'),
    '--log', str(ownership / 'run/boot.log'), '--linked-disassembly',
    str(ownership / 'derivation/complete-linked-disassembly.txt'), '--qemu-exit',
    str(ownership / 'run/qemu-exit.txt'), '--output', str(owner / 'completion.json'),
    '--native-directory', str(native_outputs)], check=True)
shutil.copy2(ROOT / 'tools/check_ownership_trace.py', owner / 'check_ownership_trace.py')
shutil.copy2(ROOT / 'tools/native_receipt_common.py', owner / 'native_receipt_common.py')
write_json(owner / 'receipt.json', {'recorded_utc': stamp, 'new_native_execution': False,
    'scope': 'Original ownership events/bytes rechecked with explicit QEMU status and kernel shutdown; full native inspection remains pending.'})

write_json(revalidation / 'receipt.json', {
    'recorded_utc': stamp, 'repository_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    'working_tree_sources': 'Exact checker/preparer snapshots are retained; this does not assert they belonged to repository HEAD.',
    'kernel_rebuilds': 0, 'new_native_boots': 1, 'ownership_native_boots': 0,
    'new_run_original_boot': identity((run / 'boot.log').read_bytes()),
    'new_run_qemu_exit': int((run / 'qemu-exit.txt').read_text()),
    'initial_launcher_result': 'Post-boot checker failed on two compatible EFI/kernel nokaslr messages. No original PASS summary was produced.',
    'resolution': 'Corrected parser; saved run revalidated without another native boot. Original checker failure is separately replayed and retained.',
    'result_policy': 'matrix-v2/rechecked-results.json preserves the pre-publication recheck. results.json is computed over publication bytes. Older original-results.json files retain v1 outcomes.',
    'scope': 'Selected spatial accesses and admission-only BPF controls; no original CVE execution or complete-mediation claim.'})

prefixes = {
    str(run): '${SPATIAL_V2_RUN}', str(private): '${PRIVATE_ORIGINALS}',
    str(ROOT / 'build/spatial-selectivity-build.7OKOhx'): '${SPATIAL_BUILD}',
    str(ROOT.parent / 'cbpf-m4-dependencies-20260906'): '${SOURCE_DEPENDENCIES}',
    str(Path(os.environ.get('CBPF_NATIVE_ROOT', Path.home() / '.cache/cbpf/morello'))): '${TOOLCHAIN_CACHE}',
    str(ROOT): '${REPOSITORY}', str(Path.home()): '${USER_HOME}',
}
entries = []
staging = private / 'publication'
groups = [(private / 'revalidation', spatial / 'revalidation'),
          (raw, spatial / 'matrix-v2'), (owner, ownership / 'revalidation')]
for source_root, destination in groups:
    for source in sorted(source_root.rglob('*')):
        assert not source.is_symlink()
        if not source.is_file():
            continue
        relative = source.relative_to(source_root)
        if '__pycache__' in relative.parts or source.suffix == '.pyc':
            continue  # Interpreter caches are not experimental artifacts.
        data = source.read_bytes()
        publication = data
        if source.name == 'init' or source.suffix in ('.gz', '.bin'):
            visible = gzip.decompress(data) if source.suffix == '.gz' else data
            assert not any(prefix.encode() in visible for prefix in prefixes)
        else:
            text = data.decode()
            for prefix, role in sorted(prefixes.items(), key=lambda pair: -len(pair[0])):
                text = text.replace(prefix, role)
            publication = text.encode()
            assert publication.count(b'\n') == data.count(b'\n')
        target = staging / destination.relative_to(ROOT) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(publication)
        entries.append({'file': str(target.relative_to(staging)),
            'original': {'file': '${PRIVATE_ORIGINALS}/' + str(source.relative_to(private)), **identity(data)},
            'original_identity_scope': 'Preserved Batch 2 source artifact; post-run checker outputs and failure replay are explicitly identified by the batch receipt.',
            'availability': 'publication_copy', 'publication': identity(publication),
            'changes': [] if publication == data else ['Path-only publication redaction; original embedded identities unchanged.']})

# Revalidation is distinct from preservation of the original native artifacts.
published_spatial = staging / spatial.relative_to(ROOT)
for path in (published_spatial / 'revalidation/calibration', published_spatial / 'revalidation/matrix', published_spatial / 'matrix-v2'):
    result = validate_run(path)
    target = path / 'results.json'
    prior = next((entry for entry in entries if entry['file'] == str(target.relative_to(staging))), None)
    write_json(target, result)
    if prior:
        prior['publication'] = identity(target.read_bytes())
        prior['changes'].append('Recomputed post-run validation over publication bytes; no native execution.')
    else:
        entries.append({'file': str(target.relative_to(staging)), 'availability': 'publication_copy',
            'publication': identity(target.read_bytes()),
            'changes': ['New post-run validation over publication bytes; no native execution.']})
for _, destination in groups:
    shutil.copytree(staging / destination.relative_to(ROOT), destination)
manifest_path = ROOT / 'evidence/publication-manifest.json'
manifest = json.loads(manifest_path.read_text())
manifest['files'].extend(entries)
manifest['date'] = stamp[:10]
write_json(manifest_path, manifest)
print(f'Published {len(entries)} Batch 2 files. Private originals: {private}')
