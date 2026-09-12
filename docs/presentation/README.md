# Presentation

[Open the cBPF presentation](index.html#title).

The 27-slide deck introduces two CVE motivations, explains Morello hardware,
and follows spatial authority and acquisition validity to their native effects.
Recorded code, byte comparisons and ownership state transitions carry the
explanation. The manuscript and speaker script remain separate local materials;
this public presentation needs neither to run.

The existing spatial comparison slide joins extent, intended-value binding and
actual operand use in one panel. Offset eight distinguishes one value from
both value slots; the offset-six width pair retains full-access checking.
The separate trusted substitution control has an explicit evidence-status
label and does not change the normally verified key-one walkthrough. Broad
capability controls remain distinct from the unbuilt non-capability baseline.

## Browse locally

Run `make docs-serve` from the repository root, then open
[the presentation](http://127.0.0.1:8767/docs/presentation/index.html#title).
It is also linked from the documentation home and sidebar. For offline
playback, open `index.html` with the scripts, stylesheet and `assets/` alongside
it. Playback downloads no fonts or images; external sources open only when clicked.

| Action | Control |
|---|---|
| Next / previous slide | Arrow buttons, arrow keys, Space / Shift+Space, Page Up/Down |
| First / last slide | Home / End |
| Return to cover | cBPF wordmark |
| Fullscreen | `F` or the fullscreen button |
| Replay transition | `R` or the replay button, when available |
| Memory-access example | **Walk through one load** on slide 7; use its own arrows |
| Reset that example | **Return to overview** or Escape |

No slide advances automatically. Reduced-motion preferences select still views.
Allow roughly 30 minutes, including pauses. Keep the topology and core
discussion brief; their detailed explanation and the hardware walkthrough are optional.

## Research scope and records

The normally verified key-one spatial witness, synthetic key-zero matrix,
trusted native ownership trace and historical CVE records retain separate
identities. Playing the slides adds no experimental result. The two runtime
profiles remain separate implementations. The [claim map](../research/claim-evidence.md)
distinguishes observations, source/native inspection and conditional arguments.

The spatial introduction explains **CVE-2021-3490** and distinguishes the
archived metadata-read contrast from the current seven-byte controls. The
ownership introduction explains **CVE-2022-50650** and the projected
repeated-release effect. The later release-policy comparison explains why
consume-once validity does not implement the complete callback repair.
The [causal mapping](../results/causal-review.md#the-two-cve-mappings-side-by-side)
is the canonical account of both relationships.

Recorded excerpts link to the [spatial walkthrough](../results/logical-extent.md#recorded-code-to-native-walkthrough),
[selective result](../results/spatial-selectivity.md),
[ownership trace](../results/ownership-native-trace.md) and
[implementation inventory](../research/implementation-scope.md).
Extracted instructions are distinguished from source-derived or illustrative
comparisons; no conventional baseline kernel was built. Ownership failure
returns directly to the executive epilogue in the negative images, as detailed
in the linked inspection. The hardware views are explanatory diagrams, not
physical floorplans, clock-cycle traces or measured hardware costs.

## Source map

PDF pages count from one. External facts are paraphrased; the editable
functional drawings use the sources below. Slide footers link to the relevant
source or public research record.

| View | Primary source and location | Use |
|---|---|---|
| Physical overview | [Watson et al., Figure 2, p6](https://api.repository.cam.ac.uk/server/api/core/bitstreams/f95cc789-b818-49ec-ae35-b1f5fb677d84/content#page=6) | Morello die photograph |
| System map | [Arm Morello SDP TRM, §3.1, Figure 3-2, p34](https://documentation-service.arm.com/static/62a735d731ea212bb6623405#page=34), [Appendix B.1, p265](https://documentation-service.arm.com/static/62a735d731ea212bb6623405#page=265) | Two clusters, private L1/L2, per-cluster shared L3 and system connections |
| Core mechanisms | [The Arm Morello Evaluation Platform, pp5–7](https://www.cl.cam.ac.uk/research/security/ctsrd/pdfs/202305ieeemicro-morello-platform.pdf#page=5) | Register state, checks alongside TLB/MMU, cache/tag support and retained datapath widths |
| Register overlap | [Arm DWARF Morello supplement, §4.1](https://github.com/ARM-software/abi-aa/blob/main/aadwarf64-morello/aadwarf64-morello.rst#41-dwarf-register-names) | X/C, SP/CSP and PC/PCC views |
| Derivation and bounds | [Arm Hot Chips 2022, slides 5 and 10–14](https://hc34.hotchips.org/assets/program/conference/day1/Academia/HC2022.Arm.RichardGrisenthwaite.v1_0.pdf#page=12) | Guarded operations, compressed bounds and GetBounds reconstruction |
| PCC and ambient data authority | [Capability Essential IP, §§4.1.1.4 and 4.2.3](https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-953.pdf#page=20) | DDC and implemented PCC dependency handling |
| Tag transport and storage | [Arm Hot Chips 2022, slides 10 and 16](https://hc34.hotchips.org/assets/program/conference/day1/Academia/HC2022.Arm.RichardGrisenthwaite.v1_0.pdf#page=16), [Arm TRM, §2.1, p19](https://documentation-service.arm.com/static/62a735d731ea212bb6623405#page=19) | Tag granularity, tag-clearing stores and physical storage alternatives |
| Linux/eBPF lifecycle | [Linux libbpf overview](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html) | Load, verify, prepare and attach phases |
| Verifier | [Linux 6.7 verifier documentation, pruning](https://www.kernel.org/doc/html/v6.7/bpf/verifier.html#pruning) | Abstract register/stack state and coverage-based pruning |
| BPF machine and maps | [BPF register model](https://docs.kernel.org/bpf/classic_vs_extended.html), [BPF maps](https://docs.kernel.org/bpf/maps.html) | Logical registers and kernel-managed state; obsolete loop/call claims elsewhere in the former page are not adopted |
| Kernel functions | [Linux 6.7 kfunc documentation](https://www.kernel.org/doc/html/v6.7/bpf/kfuncs.html) | BTF, registration, acquire/release contracts and interface stability |
| Existing runtime enforcement | [AEE, USENIX Security 2025, §§7.3–8](https://www.usenix.org/system/files/usenixsecurity25-sun-hao.pdf) | Object-level approximation enforcement with trusted static safety checks; no cBPF security or cost ranking |
| Morello eBPF predecessor | [Leaf's RFC, 3 May 2024, Current State & Future Work](https://op-lists.linaro.org/archives/list/linux-morello@op-lists.linaro.org/message/LBV3YQWCTQRERLGNRU5ML7VA3JVQSDNQ/) | Native compartment foundation and helper/kfunc interface challenges |
| Spatial CVE motivation | [CVE-2021-3490 disclosure](https://www.openwall.com/lists/oss-security/2021/05/11/11), [upstream repair 049c4e1](https://github.com/torvalds/linux/commit/049c4e13714ecbca567b4d5f6d563f05d431c80e) | Incorrect ALU32 bitwise bounds tracking and the distinction between repairing analysis and bounding a selected native effect |
| Ownership CVE motivation | [Linux CVE-2022-50650 announcement](https://lists.openwall.net/linux-cve-announce/2025/12/09/30), [upstream repair 9d9d00a](https://github.com/torvalds/linux/commit/9d9d00ac29d0ef7ce426964de46fa6b380357d0a) | Repeated synchronous callbacks, caller-owned release restrictions and callback-local reference obligations |
| cBPF bindings | [Spatial argument](../../theory/spatial.md), [ownership argument](../../theory/ownership.md), [native correspondence](../../theory/kernel-ownership.md) | Exact grant, acquisition identity, capability transport and retained trust |

The Morello die photograph is reproduced from **Watson et al., “CHERI:
Hardware-Enabled C/C++ Memory Protection at Scale,” Figure 2**. Rights remain
with the original rights holders. The photograph is cropped and shown on an
illustrative rendered mount; no ownership or Creative Commons licence for that
image is asserted. The functional diagrams and annotations are original
explanatory work. Literature documents remain at their source links.

The supplied University of Twente mark is retained unaltered in
`assets/university-of-twente.png`, including its proportions, colours and
transparency. The opening artwork and anchor data are also retained unchanged.
