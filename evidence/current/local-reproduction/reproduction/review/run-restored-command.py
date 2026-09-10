import datetime, json, os, pathlib, subprocess, sys, time
review = pathlib.Path(__file__).resolve().parent
snapshot = review.parent / "snapshot"
label = sys.argv[1]
command = sys.argv[2:]
log = review / (label + ".log")
receipt_path = review / (label + ".json")
assert not log.exists() and not receipt_path.exists(), "Prior run must not be overwritten"
overrides = {"ownership-run":{"CBPF_NATIVE_ROOT":"${REPRO_DEPENDENCIES}/runtime/morello"}, "spatial-check":{"CBPF_SPATIAL_SOURCE_GIT":"${REPRO_DEPENDENCIES}/linux-source.git"}}[label]
assert command == ["make", label]
record = {"command":command, "cwd":str(snapshot), "started_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(), "log":str(log), "environment_overrides":overrides, "recipe_environment":{k:v for k,v in os.environ.items() if k.startswith(("CBPF_", "XDG_CACHE_HOME"))}}
assert not record["recipe_environment"], "Unexpected inherited overrides"
start = time.monotonic()
receipt_path.write_text(json.dumps(record,indent=2)+"\n")
with log.open("x") as handle:
    process = subprocess.run(command,cwd=snapshot,env={**os.environ, **overrides},stdout=handle,stderr=subprocess.STDOUT)
record.update({"finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(), "elapsed_seconds":round(time.monotonic()-start,3), "exit_code":process.returncode})
receipt_path.write_text(json.dumps(record,indent=2)+"\n")
print(json.dumps(record,indent=2),flush=True)
sys.exit(process.returncode)
