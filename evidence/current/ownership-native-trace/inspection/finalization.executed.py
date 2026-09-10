"""Record final draft hardening without relabeling earlier artifact identities."""
import datetime
import hashlib
import json
from pathlib import Path
import shutil

root = Path(__file__).resolve().parents[1]
directory = root / "evidence/current/ownership-native-trace/inspection"
manifest_path = root / "evidence/publication-manifest.json"
manifest = json.loads(manifest_path.read_text())
names = {"ownership_native_checks.py", "test_ownership_native.py", "results.json", "receipt.json"}

def identity(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

receipt_path = directory / "receipt.json"
receipt = json.loads(receipt_path.read_text())
assert "finalized_utc" not in receipt
receipt.update({
    "finalized_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "finalization": "Required exactly 56 gateway words, added extent regressions, and rechecked the same retained run. Original manifest identities for revised files denote earlier post-run drafts; their publication identities denote final files.",
    "finalization_recipe": "finalization.executed.py",
    "finalized_artifacts": {name: identity(directory / name) for name in sorted(names - {"receipt.json"})},
})
receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
for entry in manifest["files"]:
    path = root / entry["file"]
    if path.parent == directory and path.name in names:
        entry["publication"] = identity(path)
        entry["changes"].append("Finalized before commit: exact gateway extent and matching regressions/recheck; original identity denotes earlier post-run draft, not original native execution.")
        names.remove(path.name)
assert not names
target = directory / "finalization.executed.py"
assert not target.exists()
shutil.copy2(__file__, target)
manifest["files"].append({"file": str(target.relative_to(root)), "availability": "publication_only",
    "publication": identity(target), "changes": ["Exact finalization recipe for the uncommitted post-run inspection package."]})
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
print("Finalized inspection publication identities; historical run and draft identities preserved.")
