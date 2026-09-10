# Native dependency replay

## Purpose

The experiment repeats the existing controls using the reduced builder image
and restored source/runtime. Its receipts identify two separately built kernel
profiles. It tests local repeatability of the bounded mechanisms, with the
[CVE evidence](../results/causal-review.md#the-two-cve-mappings-side-by-side)
retaining its separate historical and projected scope.

## Fixed scope and acceptance criteria

Two fresh kernel builds use the recorded Linux trees, current mechanism
sources and the delivered compiler. Containers have no network and guests
have no network or disk. The normal verifier remains intact; historical
test modes and spatial verifier delegation remain disabled.

| Control | Decisive observation required |
|---|---|
| Protected ownership | Four admitted native controls return 42, 42, 7 and 0 with final references at the permanent baseline. The failure control performs terminal cleanup. |
| Trusted ownership resolver | Copied/spilled stale identities and duplicate release reject without another object effect. |
| Trusted C callbacks | One persistent A permits one decrement across repeated callback entries; rejection stops dispatch. Independent B remains readable as 42 and is released normally. |
| Invalid ownership programs | Three normal-verifier rejections; zero executions, including on unexpected acceptance. |
| Spatial native witness | Review the complete held-FD native image and linked transport before one valid invocation; exact eight-byte authority, initial 41, return/readback 42. |
| Ownership CVE projection | The existing two projected event sequences agree with both host implementations: four matches. |

## Source and delivery identities

The starting source selection is `cbpf-examiner-source-20260907-native`.
The replay found two remaining old image references, in the spatial
disassembly checker and the ordinary kfunc runner. Their correction changes
only the tool image reference. No kernel mechanism, fixture, verifier or
checking rule changes. The corrected tools and their before/after hashes
accompany the [replay receipt](../../evidence/current/native-replay/README.md); the earlier export remains an earlier
identity.

## Status and interpretation

**Passed on 7 September 2026:** both fresh builds, four protected ownership
runs, three trusted resolver checks, two trusted callback controls, three
load-only rejections and the single spatial invocation. Both guests exited
cleanly. The four model/host projection comparisons also passed.

The repeated-release callback caused one decrement, then rejected without a
third callback entry. Independent B remained readable as 42. The spatial
provider returned length 8 and permissions `0x30001`; both return and readback
were 42. The [fresh result identities](../../evidence/current/native-replay/results.json)
and linked-code reviews keep these observations separate from older receipts.

All four ownership native images and the spatial 392-byte image match their
prior retained bytes. Nine complete ownership linked ranges also match;
spatial data/string relocations were reviewed against their current referents.
This is local identity and path evidence, not an independent native validator.

This experiment cannot establish complete spatial mediation, dynamic padding
exclusion, original ownership-CVE mitigation, protected BPF callbacks, the
acquisition-leak arm, heap reclamation or composition. The spatial negative
CVE-stage comparison remains historical. Morello instruction execution here
uses QEMU, not a physical Morello board. Local replay does not establish
independent reproduction.

The later [logical extent discriminator](../results/logical-extent.md) reuses this
verified spatial kernel with a new seven-byte fixture. Its result has a
separate receipt and does not change the eight-byte replay recorded here.
