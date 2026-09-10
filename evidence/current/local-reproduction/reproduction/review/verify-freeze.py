import datetime, hashlib, json, os, pathlib, stat, sys, tarfile
manifest_path = pathlib.Path(sys.argv[1]).resolve()
snapshot = pathlib.Path(sys.argv[2]).resolve()
output = pathlib.Path(sys.argv[3]).resolve()
main_root = manifest_path.parents[3]
manifest = json.loads(manifest_path.read_text())
expected = {row["file"]: row for row in manifest["files"]}
assert len(expected) == len(manifest["files"]) == 234
archive = main_root / manifest["archive"]["file"]
def sha(data): return hashlib.sha256(data).hexdigest()
assert archive.stat().st_size == manifest["archive"]["bytes"]
assert sha(archive.read_bytes()) == manifest["archive"]["sha256"]
checks = []
with tarfile.open(archive, "r:gz") as tar:
    members = tar.getmembers()
    assert len(members) == len(expected)
    assert len({m.name for m in members}) == len(expected)
    assert {m.name for m in members} == set(expected)
    for member in members:
        row = expected[member.name]
        assert member.isfile(), member.name
        assert not pathlib.PurePosixPath(member.name).is_absolute()
        assert ".." not in pathlib.PurePosixPath(member.name).parts
        data = tar.extractfile(member).read()
        assert len(data) == member.size == row["bytes"], member.name
        assert sha(data) == row["sha256"], member.name
        assert oct(member.mode) == row["mode"], member.name
        path = snapshot / member.name
        assert stat.S_ISREG(path.lstat().st_mode), member.name
        assert oct(stat.S_IMODE(path.stat().st_mode)) == row["mode"], member.name
        assert path.read_bytes() == data, member.name
        checks.append({"file": member.name, "bytes": len(data), "sha256": sha(data), "mode": row["mode"], "archive_and_snapshot_equal_freeze": True})
observed = {str(p.relative_to(snapshot)) for p in snapshot.rglob("*") if not p.is_dir() and "build" != p.relative_to(snapshot).parts[0]}
assert observed == set(expected), sorted(observed.symmetric_difference(expected))
report = {"result":"PASS", "checked_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(), "reviewer":"Separate AI reviewer ${PRIVATE_REPRO_ROOT}; same host, shared session, same cached toolchain; not external or human reproduction", "freeze_manifest":str(manifest_path), "freeze_manifest_sha256":sha(manifest_path.read_bytes()), "source_git_head_recorded_by_freeze":manifest["source_git_head"], "snapshot":str(snapshot), "archive":{"path":str(archive), "bytes":archive.stat().st_size, "sha256":sha(archive.read_bytes()), "entries":len(members)}, "verified_files":len(checks), "content_size_mode_and_archive_membership_verified":True, "snapshot_nonbuild_entries_exact":True, "build_directory_excluded_from_inventory":True, "files":sorted(checks,key=lambda row:row["file"])}
output.write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps({k:v for k,v in report.items() if k != "files"},indent=2))
