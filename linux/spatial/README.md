# Selected-value array-map authority

A successful array lookup authorizes one logical value. The surrounding
allocation can also contain metadata, padding and other values, so an
allocation-wide capability is insufficient to express that authority. cBPF
narrows a retained allocation root to the selected value and connects the
result to native accesses. The [research overview](../../docs/overview.md)
explains the argument and its CVE evidence.

The [contribution assessment](../../docs/research/related-work.md#defensible-positioning-and-present-evidence) distinguishes
logical extent, storage stride and actual native authority. A
[protected software alternative](../../docs/research/capability-comparison.md) can
enforce the same interval policy; CHERI supplies architectural bounds and
permissions when the access uses the correctly assigned capability.

Spatial provider reduction extracts the defensive array-map mechanism into cBPF. The patch adds
193 lines and removes one across five kernel files. It retains allocation-time
root construction, checked value narrowing, cleanup/accounting, and the existing
Morello lookup handoff. It imports no exploit fixture or runtime test matrix.

On 6 September 2026, patch application and compilation of all three changed
kernel objects passed in `build/spatial-check.hA1pbw`. The
[retained receipt](../../evidence/current/spatial/manifest.json) binds the
source, configuration, tools, and objects. Spatial provider reduction linked no Image and ran no guest.
The later [spatial native witness](../../docs/results/spatial-native-result.md), also on 6 September 2026,
used a fresh linked kernel and one benign native execution. These are separate
studies and receipts.

## Mechanism and argument

`cbpf_map_area_alloc()` creates a companion capability immediately after the
ordinary map allocation. Construction must produce exact bounds and exactly
`LOAD | STORE | GLOBAL` permissions; otherwise the allocation is freed. This
permits scalar data access, without capability load/store or execution.
The initial executive-DDC derivation and correct object assignment remain
trusted; this is not an allocator-minted capability ABI.

`cbpf_array_value_cap()` accepts only a live plain `BPF_MAP_TYPE_ARRAY` with
the expected operations, zero map flags, no special BTF value record, and its
attached authority descriptor. It validates the retained root and checked key,
then narrows that root to the logical `value_size`, excluding neighbouring
values and padding. Tag, sealing, base, address, length, and permissions must
match exactly. Unrepresentable bounds return no capability, never a wider one.
Lookup does not derive a replacement from DDC.

The new branch of `bpf_cheri_map_lookup_impl()` validates key access and returns
that capability through the inherited gateway. It does not select the historical
broad/software-bound paths. Descriptor allocation is charged to kernel memory
accounting; failure and map destruction release the owned resources.

[The spatial lemma](../../theory/spatial.md) explains the conditional containment
property. Spatial native witness supplies actual-use correspondence for two inspected native
accesses; complete mediation for every admitted program remains unproved.
The mechanism establishes no ownership composition or verifier-failure result.

## Spatial native witness

The observation overlay adds 16 logging lines at two sites and changes no
enforcement rule. A normal-verifier-accepted socket filter contains 14 BPF
instructions and 392 native bytes. It selects key 1 in a plain two-entry
array with seven-byte values and eight-byte stride, reads byte six, adds one, and stores through the same
returned capability. One execution changes 41 to 42; computed return and
ordinary readback both equal 42.

The provider record identifies map 1/key 1 and a tagged, unsealed capability
whose base/cursor equal the selected value, length is 7, and permissions are
`LOAD | STORE | GLOBAL` (`0x30001`). Native inspection connects the gateway's
return in `c0` to `c7`, then the load and store through unchanged `c7`.
The held program's complete native bytes match the accepted certificate.
The [logical extent package](../../evidence/current/logical-extent/README.md) retains source
identities, linked review, construction records, effects, and clean exit.

This is a source/native correspondence witness under trusted provider,
compiler/kernel/image and architecture premises. RDDC remains vmalloc-wide,
and the gateway retains broader authority. Construction logs are not
independent hardware attestation. The length-seven observation distinguishes
logical size from stride. Padding accesses and bounds faults are not executed.
The earlier eight-byte witness retains its separate receipt. The result
establishes neither general JIT mediation nor a fresh CVE mitigation result.

## Selective spatial validation profile

The separate, default-off selectivity profile applies
`selectivity-test.patch` after the unchanged provider and observation overlay.
It creates two disposable seven-byte values at stride eight and compares the
production exact-value capability with trusted eight- and sixteen-byte
controls. Fixed byte and halfword loads and stores cover the last logical byte,
padding, the neighbouring value, an in-bounds halfword, and a halfword crossing
the logical boundary. Existing kernel-access exception-table recovery records
only faults from the active boot fixture; it does not add a new exception type.

Build once, run the two-case recovery calibration, then run the 30-case matrix:

```sh
make spatial-selectivity-kernel
export CBPF_SPATIAL_SELECTIVITY_BUILD=/absolute/path/printed/by/the/build
make spatial-selectivity-calibration
make spatial-selectivity
```

The accompanying purecap guest submits five load-only programs to the normal
verifier: two valid accesses and three explicit out-of-value accesses. It never
uses `BPF_PROG_TEST_RUN`; an unexpectedly admitted negative is closed without
execution. The checker requires 22 permitted native operations, eight Morello
bounds faults, complete fixture preservation on rejected stores, unchanged
load sentinels, and zero BPF executions. This is synthetic native validation
through the production provider, not execution of verifier-admitted invalid
eBPF and not reproduction of an original vulnerable path.

## Spatial provider reduction prerequisites and reproduction

```sh
make spatial-check
```

This exports and verifies pinned source, checks/applies the patch, and compiles
`kernel/bpf/arraymap.o`, `kernel/bpf/syscall.o`, and
`arch/arm64/net/bpf_jit_comp.o`, including their Kbuild prerequisites. It does
not link a kernel Image, build modules, or boot a guest. The normal host
`make check` remains separate.

The verified substrate is tree
`e6c69574c16bc2b9bce06329f9ac3f4b3269e79a`, the earlier cBPF prototype replay over
Morello Linux base `b96da308ef1a054c3c04c9445e5ed70259b7c397`. The historical
replay commit is `4e4604875fbf4144f9ce456bc6d60f3ef55da4d0`; that commit object
is absent locally, so only the tree and its contents are claimed verified.
This patch is not directly applicable to pristine upstream Linux.

Set `CBPF_SPATIAL_SOURCE_GIT` to a restored Git store containing this tree.
The checker requires the cached immutable Docker image
`sha256:b4de3680a00e3ac68ccc56bd87131b97c1fffcd5e016c2d1a54d7e3386d9fc6e`
with Morello Clang 17. It permits no image pull or network access, mounts source
read-only, uses the host UID, and limits memory to 4 GiB. Jobs default to four;
`CBPF_SPATIAL_BUILD_JOBS` accepts 1–4. Local reproduction separately supplies the
[dependency package and frozen-source reproduction](../../docs/reproduction/README.md).
External provisioning and reproduction remain open.

Each fresh `build/spatial-check.*` directory retains the executed patch/script,
source/tree identities, configuration, compiler/image identity, logs, and object
hashes. The verifier source must remain byte-identical to the inherited tree;
this is not a claim that the inherited verifier equals pristine Linux.

## Excluded historical controls

The checker enables `CBPF_ARRAY_AUTHORITY`, disables spatial verifier
delegation and every inherited test option, and restores
`BPF_UNPRIV_DEFAULT_OFF=y`. The patch refuses conflicting configurations.
With this feature enabled, the inherited boot mutation selector, mutator, and
its dedicated decoders are excluded; its diagnostic value is immutable zero.

The external substrate still contains historical research code. No bootable
kernel is produced or certified safe for execution by this compile check.
Spatial native witness uses its separate build recipe, observation overlay and native-path
review; no old launcher is used by either current target.

## Ancestry, reduction, and evidence

Derived from the retained provider patch of the earlier cBPF prototype,
identified in [historical provenance](../../evidence/provenance.json).
Its original SHA-256 is
`c558e7082c987380ef29dc070e00484390f2b3936d9347a661880e658d284b39`.
The unredacted original is retained privately. The changed kernel files are GPL-2.0-only;
their existing license and copyright headers are preserved. This reduction
credits the earlier provider mechanism and the inherited Arm/Linaro and earlier cBPF prototype
gateway/JIT infrastructure; neither is newly attributed to spatial provider reduction.

The historical provider delta was 285 additions and ten deletions, alongside
roughly 1,200 fixture/validator lines. Spatial provider reduction removes provider IDs, verbose runtime
reports, broad/wide selectors, and redundant bookkeeping; it additionally
restricts capability transfer permissions, charges descriptor memory, and guards
against inherited test activation. Therefore historical runtime results are
not measurements of this reduced source.

The inherited substrate remains substantial: 3,628 additions and 166 deletions
across 21 files relative to the pinned Morello base. Keeping it as a dependency
reduces the material imported into cBPF, not the trusted implementation size.
The new 155-line compile checker is build/provenance support, separate from
the 194-line kernel change; generated patch formatting is not counted twice.

[Selected historical evidence](../../evidence/prior/spatial/README.md) supports
the original adjacent-value and CVE-2021-3490 metadata-read-stage findings.
The CVE's [root cause](https://www.openwall.com/lists/oss-security/2021/05/11/11)
was verifier ALU32 bounds tracking; the archived comparison
measures containment of an out-of-value read inside the allocation, not repair
of that verifier defect. It includes no runnable exploit inputs.
Spatial provider reduction source/object evidence remains under `evidence/current/spatial/`; spatial native witness is
separate under `evidence/current/spatial-native/`. Neither is a fresh CVE execution.
