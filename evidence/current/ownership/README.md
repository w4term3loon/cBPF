# Protected ownership execution

This is a [publication copy](../../README.md). Personal paths are redacted;
the original source/build identities remain historical metadata.

On 6 September 2026, `build/ownership-run.AsvItO` passed one unattached,
normal-verifier-accepted `SCHED_CLS` execution under Morello QEMU. Its 26 BPF
instructions compiled to 165 native words (660 bytes). The kernel's emitted
word log exactly matches the bytes returned by `BPF_OBJ_GET_INFO_BY_FD`.

The decisive observation is the ordered gate trace:

| Event | A tag | B tag | Provider references |
|---|---|---|---|
| Acquire A | 1 | 0 | 2 |
| Acquire B | 1 | 1 | 3 |
| Clear A's stored authority | 0 | 1 | 3 |
| Release A's reference | 0 | 1 | 2 |
| Read B, returning 42 | 0 | 1 | 2 |
| Clear B's stored authority | 0 | 0 | 2 |
| Release B and exit | 0 | 0 | 1 |

The two exact 16-byte public views have different cell addresses, the same
provider object, and only `LOAD | GLOBAL` permissions. The entry receipt has
an untagged RDDC, a 16-byte restricted stack, 376 bytes of restricted code,
and a 184-byte executive epilogue. There were two acquisitions, two explicit
releases, one read, no cleanup release, and no remaining live cell. The guest
returned 42 and powered off with QEMU status zero and no kernel warning/Oops.

`boot.log` is the raw observation; `summary.txt` is the runner's checked
selection. `native.bin` contains the observed bytes, and
`native-disassembly.txt` decodes them using the pinned Morello toolchain.
For inspection, those bytes were wrapped as assembler `.inst` words in an
ELF object; its extracted `.text` was checked byte-identical to `native.bin`.
The wrapper object was never executed.

`source/` contains publication source/recipe snapshots. `kernel/`
binds the stock source commit, unchanged verifier, platform/integration
patches, configuration, compiler, and linked artifacts. Large source trees,
Images and toolchains remain external build dependencies; their hashes are
retained. Checksum lists retain original digests with host paths redacted.

`audit/` contains source and compiled-code review receipts. The early boundary
review records an older runner hash: its subsequent BTF lookup fix permits
the matching kernel's `static` FUNC records as well as `global` records.
The kernel mechanism did not change after the recorded native reviews.
`audit/native-review.json` maps the retained native image and linked runtime
to the mediation obligations; `audit/runtime-linked-range.txt` includes blocks
omitted by the earlier symbol-filtered disassembly. The compiler's author
performed that final review, so it is not an independent reproduction.
`manifest.json` retains original sizes and SHA-256 identities; the publication
manifest and `make check` verify shareable bytes without repeating the guest.

Two failed compilation attempts and one BTF-ID preparation failure remain
under ignored `build/`; none booted a guest. The first protected ownership guest
execution is this successful run. Build warnings concern inherited Morello
PCC padding and capability-pointer formatting in unchanged kernel sources.

This evidence establishes the bounded A/B path. It does not execute stale
aliases, invalid BPF, an exploit, or a CVE. NULL/failure/cleanup controls and
an alternate admitted arrangement belong to the later boundary controls. Native inspection is not a
compiler proof; provider assignment, executive root construction, trusted
kernel/compiler behavior, and synchronous invocation containment remain
explicit assumptions. Composition with the spatial provider is not established.
