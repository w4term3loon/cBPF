#!/usr/bin/env python3
"""Verify publication bytes, keeping original identities separate from redaction."""
import hashlib
import json
import re
from pathlib import Path


def verify_identity(data, identity, label):
    if len(data) != identity["bytes"] or hashlib.sha256(data).hexdigest() != identity["sha256"]:
        raise SystemExit(f"Publication evidence mismatch: {label}")


def main():
    root = Path(__file__).resolve().parents[1]
    evidence = root / "evidence"
    manifest_path = evidence / "publication-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema") != "cbpf-publication-evidence-v1":
        raise SystemExit("Unsupported publication manifest schema")
    seen = set()
    published = set()
    unchanged = redacted = private_only = 0
    for entry in manifest["files"]:
        name = entry["file"]
        relative = Path(name)
        candidate = root / relative
        path = candidate.resolve()
        if relative.is_absolute() or ".." in relative.parts or not path.is_relative_to(evidence):
            raise SystemExit(f"Invalid publication evidence path: {name}")
        if name in seen:
            raise SystemExit(f"Duplicate publication evidence path: {name}")
        seen.add(name)
        original = entry.get("original")
        if original is not None:
            if not isinstance(original.get("bytes"), int) or original["bytes"] < 0:
                raise SystemExit(f"Invalid original size metadata: {name}")
            if not re.fullmatch(r"[0-9a-f]{64}", original.get("sha256", "")):
                raise SystemExit(f"Invalid original hash metadata: {name}")
        current = entry.get("publication")
        if current is None:
            if entry.get("availability") != "private_only" or original is None or path.exists():
                raise SystemExit(f"Invalid private-only evidence record: {name}")
            private_only += 1
            continue
        if not path.is_file() or path != candidate:
            raise SystemExit(f"Missing publication evidence file: {name}")
        verify_identity(path.read_bytes(), current, name)
        published.add(path)
        if original is not None and current == {key: original[key] for key in ("bytes", "sha256")}:
            unchanged += 1
        else:
            redacted += 1
    actual = {path.resolve() for path in evidence.rglob("*") if path.is_file()}
    actual.discard(manifest_path.resolve())
    if actual != published:
        unexpected = sorted(str(path.relative_to(root)) for path in actual - published)
        missing = sorted(str(path.relative_to(root)) for path in published - actual)
        raise SystemExit(f"Publication inventory mismatch: unexpected={unexpected}, missing={missing}")
    print(f"CBPF publication evidence: {len(published)} files match publication hashes")
    print(f"Original-byte copies: {unchanged}; redacted/editorial copies: {redacted}; private-only archives: {private_only}")
    print("Original digests are historical metadata; private originals are not checked here.")
    print("Integrity only; no experiment, native execution or semantic revalidation performed.")


if __name__ == "__main__":
    main()
