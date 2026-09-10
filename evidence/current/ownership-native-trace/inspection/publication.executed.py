"""Publish bounded post-run ownership inspection artifacts, preserving originals."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from native_receipt_common import digest, require

package = ROOT / "evidence/current/ownership-native-trace"
output = package / "inspection"
require(set(p.name for p in output.iterdir()) == {"README.md", "native-review.md"},
        "Refusing to overwrite an inspection publication")
private = Path(tempfile.mkdtemp(prefix="cbpf-ownership-inspection-originals.", dir=ROOT.parent))
stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")

for name in ("check_ownership_trace.py", "ownership_native_checks.py", "native_receipt_common.py",
             "prepare_ownership_inspection.py", "run_ownership_trace.sh"):
    shutil.copy2(ROOT / "tools" / name, private / name)
shutil.copy2(ROOT / "tests/test_ownership_native.py", private / "test_ownership_native.py")
shutil.copy2(__file__, private / "publication.executed.py")

# Run against published inputs: result hashes intentionally identify publication
# bytes, not private original paths. Native outputs are temporary, never executed.
with tempfile.TemporaryDirectory(prefix="native-output.", dir=ROOT / "build") as temporary:
    result = subprocess.run([sys.executable, str(ROOT / "tools/check_ownership_trace.py"),
        "--log", str(package / "run/boot.log"), "--inspection-directory", str(package / "derivation"),
        "--run-inputs", str(package / "run/inputs.sha256"),
        "--kernel-config", str(package / "run/kernel.config"),
        "--qemu-exit", str(package / "run/qemu-exit.txt"),
        "--native-directory", temporary, "--output", str(private / "results.json")],
        check=True, capture_output=True, text=True)
    require(not result.stderr, "Unexpected checker diagnostics")
    for name in ("positive", "stale_read", "repeated_release"):
        filename = "native-" + name + ".bin"
        require((Path(temporary) / filename).read_bytes() == (package / "run" / filename).read_bytes(),
                "Original native binary differs from checked logged words")
    (private / "checker-stdout.txt").write_text(result.stdout)

decode = ROOT / "build/ownership-inspection-batch3/decoder-recheck"
replay = private / "decoder-replay"
replay.mkdir()
for name in ("extraction.json", "commands.json"):
    shutil.copy2(decode / name, replay / name)
comparisons = []
for path in sorted(decode.iterdir()):
    if path.suffix == ".bin" or path.name in ("complete-linked-disassembly.txt", "linked-ranges.json", "native-decode.json") or path.name.startswith("native-"):
        require(path.read_bytes() == (package / "derivation" / path.name).read_bytes(),
                "Offline decode differs: " + path.name)
        comparisons.append({"file": path.name, "sha256": digest(path), "matches_retained": True})
write_json(replay / "comparison.json", {"recorded_utc": stamp, "files": comparisons,
    "native_boots": 0, "scope": "Offline extraction/decoder replay equality only"})
write_json(private / "receipt.json", {
    "schema": "cbpf-fixed-ownership-inspection-v1", "recorded_utc": stamp,
    "repository_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, cwd=ROOT).strip(),
    "working_tree_sources": "Exact current checker/test/runner snapshots retained; not asserted to belong to HEAD.",
    "new_native_boots": 0, "kernel_rebuilds": 0, "original_artifacts_changed": False,
    "original_results_sha256": digest(package / "run/results.json"),
    "prior_completion_sha256": digest(package / "revalidation/completion.json"),
    "authored_review_sha256": digest(output / "native-review.md"),
    "checker_exit_status": result.returncode,
    "reviewer_scope": "AI-assisted internal source/native inspection; no independent external reviewer or reproduction.",
    "assurance": ["production encoder self-check", "external fixed-profile receipt checks", "authored native inspection"],
    "limits": "No general validator, compiler proof, normally verified stale BPF or callback-policy implementation.",
})

manifest_path = ROOT / "evidence/publication-manifest.json"
manifest = json.loads(manifest_path.read_text())
known = {entry["file"] for entry in manifest["files"]}
replacements = {
    str(ROOT / "build/ownership-native-trace-build.tyc1VG"): "${OWNERSHIP_BUILD}",
    str(ROOT): "${REPOSITORY}", str(Path.home()): "${USER_HOME}",
}
copies = []
for source in sorted(private.rglob("*")):
    if not source.is_file():
        continue
    relative = source.relative_to(private)
    target = output / relative
    require(not target.exists(), "Refusing to overwrite " + str(relative))
    data = source.read_bytes()
    text = data.decode()
    for before, after in sorted(replacements.items(), key=lambda item: -len(item[0])):
        text = text.replace(before, after)
    published = text.encode()
    require(not re.search(rb"/home/[A-Za-z0-9_-]+", published), "Unredacted private path")
    copies.append((target, published))
    name = str(target.relative_to(ROOT))
    require(name not in known, "Duplicate manifest entry")
    manifest["files"].append({"file": name, "availability": "publication_copy",
        "original": {"file": "ownership-inspection/" + str(relative), "bytes": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()},
        "original_identity_scope": "Post-run host inspection/revalidation artifact, not original native execution.",
        "publication": {"bytes": len(published), "sha256": hashlib.sha256(published).hexdigest()},
        "changes": ["Personal paths replaced by role markers."] if data != published else [],
    })
for target, published in copies:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(published)
for name in ("README.md", "native-review.md"):
    path = output / name
    manifest["files"].append({"file": str(path.relative_to(ROOT)), "availability": "publication_only",
        "publication": {"bytes": path.stat().st_size, "sha256": digest(path)},
        "changes": ["New authored post-run internal inspection and assurance distinction."]})
editorial = {"evidence/README.md", "evidence/current/README.md", "evidence/current/ownership-native-trace/README.md"}
for entry in manifest["files"]:
    if entry["file"] in editorial:
        path = ROOT / entry["file"]
        entry["publication"] = {"bytes": path.stat().st_size, "sha256": digest(path)}
        entry["changes"].append("Batch 3: indexed fixed ownership instruction/target checks and authored internal inspection; original records preserved.")
        editorial.remove(entry["file"])
require(not editorial, "Missing editorial manifest entry")
write_json(manifest_path, manifest)
print("Published new ownership inspection; originals retained in " + str(private))
