import datetime, hashlib, json, pathlib, re, sys
review = pathlib.Path(__file__).resolve().parent
snapshot = review.parent / "snapshot"
prior = snapshot / "evidence/current/ownership-closure"
runs = list((snapshot / "build").glob("ownership-m3-run.*"))
assert len(runs) == 1
run = runs[0]
def sha(path):
    with path.open("rb") as handle: return hashlib.file_digest(handle, "sha256").hexdigest()
def comparison(old, new, expected=None):
    old_hash, new_hash = sha(old), sha(new)
    if expected is not None: assert old_hash == expected, old
    item = {"original":str(old), "reproduced":str(new), "original_bytes":old.stat().st_size, "reproduced_bytes":new.stat().st_size, "original_sha256":old_hash, "reproduced_sha256":new_hash, "byte_equal":old_hash==new_hash}
    if old_hash != new_hash:
        different = 0; first = []; offset = 0
        with old.open("rb") as a, new.open("rb") as b:
            while True:
                ab,bb=a.read(1024*1024),b.read(1024*1024)
                if not ab and not bb: break
                if ab != bb:
                    different += abs(len(ab)-len(bb))
                    for i,(av,bv) in enumerate(zip(ab,bb)):
                        if av != bv:
                            different += 1
                            if len(first)<32: first.append({"offset_zero_based":offset+i,"original_hex":f"{av:02x}","reproduced_hex":f"{bv:02x}"})
                offset += max(len(ab),len(bb))
        item.update({"different_byte_positions_including_length_difference":different,"first_up_to_32_differences":first})
    return item
kernel = []
for row in (prior/"kernel/outputs.sha256").read_text().splitlines():
    digest, oldname = row.split("  ",1)
    old = pathlib.Path(oldname)
    new = snapshot / "build" / oldname.split("/cbpf/build/",1)[1]
    kernel.append(comparison(old,new,digest))
native = [comparison(old,run/old.name) for old in sorted(prior.glob("native-*.bin"))]
original_result=json.loads((prior/"results.json").read_text())
new_result=json.loads((run/"results.json").read_text())
assert new_result["invalid_bpf_executions"]==0 and new_result["qemu_exit"]==0
assert len([c for c in new_result["cases"] if c["executed"]])==4
assert len([c for c in new_result["cases"] if not c["loaded"] and not c["executed"]])==3
def decisive(path):
    return [re.sub(r"^\[\s*\d+\.\d+\]\s*", "",row) for row in path.read_text(errors="replace").replace("\r", "").splitlines() if re.search(r"CBPF_(?:GATE |GUARD |RESULT |M3 case=|M3 result=|M3 kernel=)",row)]
old_decisive,new_decisive=decisive(prior/"boot.log"),decisive(run/"boot.log")
report={"result":"PASS" if new_result==original_result and old_decisive==new_decisive else "REVIEW_DIFFERENCES", "compared_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(), "scope":"Independent hash/byte and outcome comparison with retained original M3 on the same host/toolchain; not an independent architecture or external human reproduction.", "kernel_outputs":kernel,"four_native_binaries":native,"all_five_kernel_outputs_byte_equal":all(r["byte_equal"] for r in kernel),"all_four_native_binaries_byte_equal":all(r["byte_equal"] for r in native),"structured_results_equal_original":new_result==original_result,"decisive_ordered_log_rows_equal_original":old_decisive==new_decisive,"decisive_rows":len(new_decisive),"raw_boot_log":{"original_sha256":sha(prior/"boot.log"),"reproduced_sha256":sha(run/"boot.log"),"byte_equal":sha(prior/"boot.log")==sha(run/"boot.log"),"note":"Raw boot logs include elapsed timestamps and runtime address/layout observations. Only the explicitly listed decisive rows are compared after removing timestamps; raw logs remain separately retained."},"reproduced_results":new_result}
(review/"comparison.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps({k:v for k,v in report.items() if k not in ("kernel_outputs","four_native_binaries","reproduced_results")},indent=2))
