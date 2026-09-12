"""One bounded local evidence export; preserves originals and never pushes."""
import argparse
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sys

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / 'tools'))
import check_spatial_selectivity as extent
import check_spatial_substitution as substitution


def identity(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--run', required=True, type=Path)
parser.add_argument('--workspace', required=True, type=Path)
args = parser.parse_args()
run, workspace = args.run.resolve(), args.workspace.resolve()
build = Path((run / 'build-directory.txt').read_text().strip())
destination = ROOT / 'evidence/current/spatial-selectivity/substitution'
assert not destination.exists(), 'Do not overwrite evidence'
actual = substitution.validate_run(run)
assert actual == json.loads((run / 'results.json').read_text())
baseline = json.loads((workspace / 'baseline.json').read_text())
for name, value in baseline['protected_sha256'].items():
    assert identity((ROOT / name).read_bytes())['sha256'] == value, name
old_overlay = (workspace / 'before/linux/spatial/selectivity-test.patch').read_text()
new_overlay = (ROOT / 'linux/spatial/selectivity-test.patch').read_text()
unchanged_parts = {}
for name, start, old_end, new_end in (
    ('exception_handler_overlay', 'diff --git a/arch/arm64/mm/extable.c',
     'diff --git a/kernel/bpf/Kconfig', 'diff --git a/kernel/bpf/Kconfig'),
    ('fault_recorder_and_native_access_helper', '+void cbpf_spatial_selectivity_record_fault(struct pt_regs *regs)\n+{',
     '+static bool cbpf_selectivity_cap_valid', '+static bool cbpf_selectivity_cap_valid'),
    ('strict_extent_case', '+static bool\n+cbpf_selectivity_run_case',
     '+static int __init cbpf_spatial_selectivity_init', '+/* Fixed trusted counterexample:')):
    old_part = old_overlay[old_overlay.index(start):old_overlay.index(old_end)]
    new_part = new_overlay[new_overlay.index(start):new_overlay.index(new_end)]
    assert old_part == new_part, name
    unchanged_parts[name] = identity(old_part.encode())

originals = workspace / 'originals'
originals.mkdir()
raw = originals / 'substitution'
shutil.copytree(run, raw)
for source in run.rglob('*'):
    if source.is_file():
        assert source.read_bytes() == (raw / source.relative_to(run)).read_bytes()
extra = originals / 'build'
extra.mkdir()
for name in ('build_spatial_selectivity.executed.sh', 'builder-image.txt',
             'source-tree.manifest', 'compiler.txt', 'compiler.sha256',
             'selectivity-test.numstat', 'patch-numstat.txt'):
    shutil.copy2(build / 'receipt' / name, extra / name)
shutil.copy2(build / 'compile.log', extra / 'compile.log')
shutil.copy2(build / 'summary.txt', extra / 'summary.txt')

stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
write_json(originals / 'refinement-receipt.json', {
    'recorded_utc': stamp, 'reviewed_tag': 'presi',
    'repository_head': baseline['revision'], 'presi_commit': baseline['presi_commit'],
    'working_tree_had_uncommitted_presentation_changes': baseline['dirty_files'],
    'working_tree_sources': 'Executed overlay and tool snapshots identify the changes; HEAD alone does not.',
    'feasibility_inspection_utc': ['2026-09-12T20:24:08Z', '2026-09-12T20:34:03Z'],
    'feasibility_limit_hours': 2, 'direct_existing_fixture': True,
    'kernel_builds': 1, 'calibration_boots': 1, 'substitution_boots': 1,
    'extent_matrix_boots': 0, 'normally_verified_witness_reruns': 0,
    'production_changes': 0, 'new_exception_handling': 0,
    'protected_original_sha256': baseline['protected_sha256'],
    'unchanged_fixture_parts': unchanged_parts,
    'original_boot': identity((run / 'boot.log').read_bytes()),
    'original_result': identity((run / 'results.json').read_bytes()),
    'result': 'PASS: three permitted loads, one expected intended/actual binding mismatch',
    'scope': 'Fixed trusted native counterexample, separate from verified BPF. No semantic authentication, complete mediation or reachable-exploit claim.',
    'publication_policy': 'Private originals remain local. Host paths are role-redacted; embedded original hashes remain unchanged. results.json is rechecked over publication bytes; original-results.json preserves the earlier output.',
})
shutil.copy2(__file__, originals / 'publication.executed.py')

calibration_command = shlex.split((run / 'calibration/qemu-command.sh').read_text())
calibration_path = Path(calibration_command[calibration_command.index('-initrd') + 1]).parent
prefixes = {
    str(run / 'calibration'): '${CALIBRATION_COPY}',
    str(run): '${SUBSTITUTION_RUN}',
    # The nested receipt was originally launched at its own path.
    str(calibration_path): '${CALIBRATION_RUN}',
    str(build): '${SPATIAL_BUILD}', str(workspace): '${REFINEMENT_WORKSPACE}',
    str(ROOT.parent / 'cbpf-m4-dependencies-20260906'): '${SOURCE_DEPENDENCIES}',
    str(Path(os.environ.get('CBPF_NATIVE_ROOT', Path.home() / '.cache/cbpf/morello'))): '${TOOLCHAIN_CACHE}',
    str(ROOT): '${REPOSITORY}', str(Path.home()): '${USER_HOME}',
}
stage = workspace / 'publication-staging'
stage.mkdir()
entries = []


def publish(source, relative, compress=False):
    data = source.read_bytes()
    if compress:
        publication = gzip.compress(data, mtime=0)
        changes = ['Lossless gzip compression; original manifest identity retained.']
    elif source.name == 'init' or source.suffix in ('.gz', '.bin'):
        publication = data
        visible = gzip.decompress(data) if source.suffix == '.gz' else data
        assert not any(prefix.encode() in visible for prefix in prefixes)
        changes = []
    else:
        text = data.decode()
        for prefix, replacement in sorted(prefixes.items(), key=lambda pair: -len(pair[0])):
            text = text.replace(prefix, replacement)
        publication = text.encode()
        assert publication.count(b'\n') == data.count(b'\n')
        changes = [] if data == publication else ['Path-only redaction; embedded original identities unchanged.']
    path = stage / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(publication)
    entries.append({'file': str((destination / relative).relative_to(ROOT)),
        'original': {'file': '${PRIVATE_ORIGINALS}/' + str(source.relative_to(originals)), **identity(data)},
        'original_identity_scope': 'Preserved local source artifact; post-run exports and validations are identified by refinement-receipt.json.',
        'availability': 'publication_copy', 'publication': identity(publication), 'changes': changes})


for source in sorted(raw.rglob('*')):
    assert not source.is_symlink()
    if source.is_file() and '__pycache__' not in source.parts and source.suffix != '.pyc':
        relative = source.relative_to(raw)
        if source.name == 'results.json':
            publish(source, relative.with_name('original-results.json'))
        else:
            publish(source, relative)
for source in sorted(extra.iterdir()):
    relative = Path('build-receipt') / source.name
    compressed = source.name == 'source-tree.manifest'
    publish(source, relative.with_suffix('.manifest.gz') if compressed else relative, compressed)
for name in ('refinement-receipt.json', 'publication.executed.py'):
    publish(originals / name, Path(name))

for directory, checker in ((stage / 'calibration', extent.validate_run), (stage, substitution.validate_run)):
    result = checker(directory)
    target = directory / 'results.json'
    write_json(target, result)
    relative = target.relative_to(stage)
    entries.append({'file': str((destination / relative).relative_to(ROOT)),
        'availability': 'publication_copy', 'publication': identity(target.read_bytes()),
        'changes': ['New post-run validation over publication bytes; no additional native execution.']})

manifest_path = ROOT / 'evidence/publication-manifest.json'
manifest = json.loads(manifest_path.read_text())
assert not any(entry['file'].startswith(str(destination.relative_to(ROOT)) + '/') for entry in manifest['files'])
shutil.copytree(stage, destination)
manifest['files'].extend(entries)
manifest['date'] = stamp[:10]
write_json(manifest_path, manifest)
print(f'Exported {len(entries)} substitution evidence files locally; original bytes retained at {originals}')
