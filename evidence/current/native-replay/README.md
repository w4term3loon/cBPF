# Examiner dependency native replay

**PASS, 7 September 2026.** Two fresh kernels were built with the clean
examiner image and ran in offline Morello QEMU guests on the existing host.
The [result receipt](results.json) identifies the executed inputs and scope;
the [research account](../../../docs/native-replay.md) explains their relevance.

| Observation | Retained evidence |
|---|---|
| Four protected ownership runs return 42, 42, 7 and 0; three invalid programs remain unexecuted | [Ownership results](ownership/run/results.json), [console](ownership/run/boot.log) |
| Three trusted resolver checks and two trusted C callback controls pass; one A decrement and independent B=42 | Same ownership results and console; [linked review](ownership/review/manual-review.json) |
| One spatial invocation changes 41 to 42 using exact eight-byte authority; return/readback 42 | [Preflight](spatial/review/pre.json), [recorded manual review](spatial/review/manual-review.json), [postflight](spatial/review/post.json), [console](spatial/run/boot.log) |
| Two projected ownership controls agree with both host paths | [Four comparisons](ownership-projection.json); no original CVE trigger |
| Normal verifier inputs are unchanged | [Verifier identities](verifier-source-check.json); build configurations and output hashes in the two build directories |

The starting source edition is `cbpf-examiner-source-20260907-native`, with
[two tool image references corrected](tool-pin-correction.json). Kernel,
fixture and checking rules are unchanged. All four ownership native binaries
match their prior retained bytes. The spatial native image also matches its
prior 392 bytes; linked spatial data/string relocations were separately
reviewed. Fresh kernels have their own output identities and observations.

The ownership instruction review preceded launch, but its JSON receipt was
written afterward following a wrong-directory write failure. The receipt
states that sequence explicitly. The spatial manual review was successfully
recorded while the guest remained paused at execution count zero.

These are selected, privacy-redacted copies. Raw logs and receipts are retained
privately; full generated kernels remain in the local build directories.
The repository publication manifest records both original and distributed
hashes. Paths use role markers. Hashes embedded inside copied receipts still
identify their original inputs; they must not be mistaken for hashes of
editorially redacted files. `make evidence` checks the distributed copies.

This replay adds no original CVE execution, spatial negative-access experiment,
padding discriminator, protected BPF callback support, heap reclamation,
combined-kernel guarantee or independent reproduction. Native instruction
execution was emulated, not measured on a physical Morello board.
