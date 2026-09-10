/* One persistent explanatory scene; camera paths preserve spatial relationships. */
(() => {
'use strict';
const $=id=>document.getElementById(id), D=window.CBPF_DIAGRAMS;
const sources={die:'https://api.repository.cam.ac.uk/server/api/core/bitstreams/f95cc789-b818-49ec-ae35-b1f5fb677d84/content#page=6',micro:'https://www.cl.cam.ac.uk/research/security/ctsrd/pdfs/202305ieeemicro-morello-platform.pdf#page=5',hot:'https://hc34.hotchips.org/assets/program/conference/day1/Academia/HC2022.Arm.RichardGrisenthwaite.v1_0.pdf',trm:'https://documentation-service.arm.com/static/62a735d731ea212bb6623405',linux:'https://docs.kernel.org/bpf/libbpf/libbpf_overview.html',verifier:'https://docs.kernel.org/bpf/verifier.html',kfuncs:'https://www.kernel.org/doc/html/v6.7/bpf/kfuncs.html'};
const section=(title,text)=>`<section><h2>${D.inline(title)}</h2><p>${D.inline(text)}</p></section>`;
const slides=[
{id:'title',chapter:'MASTER’S THESIS',title:'Hardware capabilities for eBPF',subtitle:'Selected-value bounds and per-acquisition ownership',source:'',url:'',description:'cBPF. Hardware capabilities for eBPF: selected-value bounds and per-acquisition ownership. Barna Ifkovics. Supervisor dr.ir. A. Continella. Daily supervisor Mattia Napoli.'},
{id:'question',chapter:'RESEARCH QUESTION',title:'Preserving the exact interface right',subtitle:'Can the runtime preserve the exact right granted by an eBPF interface: one logical map value, or one independently consumable acquisition?',caption:'Two bounded case studies; ordinary verifier protections remain enabled',source:'Research question and claim–evidence map',url:'../research/claim-evidence.md',
body:section('Spatial case','Selecting one value must not grant its padding or its neighbour.')+section('Ownership case','Consuming A must invalidate A’s aliases without consuming the independent right B.'),takeaway:'<strong>Two separate runtime profiles:</strong> selected-value bounds and consume-once ownership.',description:'Can the runtime preserve the exact right granted by an eBPF interface: one logical map value, or one independently consumable acquisition? A seven-byte logical value has an eight-byte storage stride. A and B independently acquire rights to one object; consuming A must reject A’s aliases while B remains usable before termination. Morello hardware supports the two separate runtime profiles.'},
{id:'system',chapter:'MORELLO',title:'The Morello chip',subtitle:'Software permissions at native execution',source:'Die photograph · Watson et al., Fig. 2 · illustrative mount',url:sources.die,description:'Actual Morello die photograph on an illustrative mount. It provides a physical reference before the presentation switches to documented functional diagrams.'},
{id:'topology',chapter:'HARDWARE / SYSTEM',title:'A top-down map of Morello',subtitle:'Two dual-core clusters connect to a coherent memory system.',diagram:'soc',caption:'Functional subset · top-down diagram, not physical circuit placement · I/O omitted',source:'Arm Morello TRM · Fig. 3-2; Appendix B.1',url:sources.trm+'#page=265',move:'photo',
body:section('A pointer with protected authority','A capability carries an address with bounds, permissions and a validity tag. The core represents and checks this authority.')+section('Support across the system','Private L1/L2 and shared cluster L3 caches connect to the interconnect and memory controllers. Stored capability tags must survive that route.'),takeaway:'<strong>Follow one permission:</strong> the core represents it, the access path checks it, and storage preserves it.',description:'An orthographic functional Morello topology: two Rainier clusters, each with two CPU cores, private L1 and L2, and shared DSU L3. Both connect to CMN-Skeena, two DMC-Bing controllers and external DDR4.'},
{id:'core',chapter:'HARDWARE / ONE CORE',title:'The capability changes inside a core',subtitle:'Familiar execution machinery gains authority state and checks.',diagram:'soc',focus:'core',caption:'Teal: capability support · grey: existing machinery · selected request/dependency paths',source:'Arm IEEE Micro · CPU microarchitecture; Arm Hot Chips · slide 15',url:sources.micro,move:'core',
body:section('Data access','Capability registers carry authority. Load/store checks use it alongside existing translation and page protection.')+section('Instruction execution','The program counter capability (`PCC`) bounds execution. Fetch and branch handling check that authority.'),takeaway:'<strong>Inside the core:</strong> registers hold authority; data and instruction paths check its use.',description:'Zoom into the first core of the preceding system map. Capability registers feed load/store checks. PCC supports fetch and branch checks. Address generation feeds the MMU and capability-check paths; cache roles remain; highlighted blocks indicate capability-related functions, not measured hardware area.'},
{id:'registers',chapter:'HARDWARE / POINTER STATE',title:'A pointer carries an access contract',subtitle:'Morello combines an address, encoded authority and a protected validity tag.',diagram:'registers',caption:'Architectural representation · logical widths · simplified metadata fields',source:'Arm IEEE Micro · pp. 5–6; Arm Hot Chips · slides 10–14',url:sources.hot+'#page=12',
body:section('State that ordinary bits cannot forge','`Xn` overlaps the low 64 bits of `Cn`. The tag identifies a valid capability; it is separate from the 128-bit representation.')+section('Authority can be narrowed','Derivation cannot grant extra rights. Compressed bounds are reconstructed using the address; exact bounds need a representability check.'),takeaway:'<strong>Software chooses the grant.</strong> A valid capability can still cover more bytes than an interface intended.',description:'Comparison of Xn with Morello Cn: 64-bit address, 64-bit metadata, plus a separate protected tag. Encoded bounds and the address feed GetBounds to reconstruct base and limit.'},
{id:'checks',chapter:'HARDWARE / DATA ACCESS',title:'Object authority and page protection',subtitle:'A valid page mapping does not identify which object an interface intended.',diagram:'checks',caption:'Logical conditions · most address-based checks run in parallel with the TLB/MMU',source:'Arm IEEE Micro · p. 6; cBPF spatial argument',url:sources.micro,
body:section('Capability check','Validate the tag, operation permissions and the whole access interval against the capability’s bounds.')+section('Existing MMU check','Translate the virtual address and enforce page permissions. Both sets of checks must allow the access.'),takeaway:'<strong>Different units of protection:</strong> a mapped page can contain several objects; a capability can bound one.',description:'Metadata and tag feed capability checks. Address and access width feed the bounds condition; the address also feeds TLB/MMU translation and page permissions. The two conditions jointly authorize access. Full-width bounds are base less than or equal to a and a+w less than or equal to limit, with non-wrapping arithmetic.'},
{id:'memory',chapter:'HARDWARE / STORED AUTHORITY',title:'Saving a capability preserves its permissions',subtitle:'Follow one pointer from a register into memory and back.',diagram:'memory',caption:'16-byte representation + protected tag per aligned slot · other copies are unchanged',source:'Arm Hot Chips · slides 10 & 16; Arm IEEE Micro · pp. 6–7',url:sources.hot+'#page=16',
body:section('Save the whole capability','A capability store saves the address, bounds and permissions with their protected tag. A capability load restores that state.')+section('If ordinary bytes overwrite the slot','The write clears that slot’s tag. The bits may still contain an address, but they can no longer authorize an access as a valid capability.'),takeaway:'<strong>Saving the address alone is insufficient.</strong> The restrictions and protected tag must survive too.',description:'Top: a valid capability moves from a register to an aligned memory slot with a capability store, then back to a register with a capability load. The full 128-bit representation and separate validity tag are preserved. Below, a separate case shows an ordinary overlapping byte write clearing the saved slot’s tag. Loading those bits does not restore valid capability authority; other copies are unchanged. Tagged caches and the supported memory path preserve this information.'},
{id:'software',chapter:'HARDWARE → LINUX',title:'The same chip now executes Linux',subtitle:'Kernel permissions are software policy; the core checks concrete machine state.',caption:'Software hierarchy over the same hardware · boxes are not silicon regions',source:'Linux libbpf overview',url:sources.linux,
body:section('The kernel manages shared resources','Userspace enters through system calls. Linux manages memory, devices and networking; eBPF adds behavior at selected kernel hooks.')+section('Connect policy to the operand','The processor sees the capability used by an instruction. It cannot infer which map value was promised or which acquired right was consumed.'),takeaway:'<strong>Inside privileged execution,</strong> object and reference rules still matter alongside the user/kernel boundary.',description:'The camera returns through the system view and follows the execution-platform connection to userspace, system calls, Linux services and eBPF hooks. The same Morello cores execute these software roles; they are not separate silicon regions.'},
{id:'ebpf',chapter:'BACKGROUND / PROGRAM LIFECYCLE',title:'How eBPF reaches execution',subtitle:'Program lifecycle: userspace preparation, then kernel execution.',diagram:'pipeline',caption:'Context around the program · typical load / attach lifecycle',source:'Linux libbpf overview; verifier documentation · abstract-state pruning',url:sources.linux,
body:section('Before execution','The verifier reasons about abstract states, object bounds and reference obligations. A JIT translates accepted BPF instructions into native code.')+section('At execution','An attached hook invokes the prepared program. The CPU executes its actual operands; preserving the checked meaning depends on correct translation and interfaces.'),takeaway:'<strong>Static acceptance and native enforcement must agree.</strong> cBPF retains the normal verifier.',description:'Userspace C source is compiled by LLVM into eBPF bytecode, then submitted by a loader through bpf(). At load time the kernel verifier either rejects the program or permits subsequent preparation. A JIT produces native code, or an interpreter is used where configured. Once attached, a hook invokes the program. Static preparation does not occur at every event.'},
{id:'prior-work',chapter:'CONTEXT / EXISTING RESPONSES',title:'Runtime enforcement and Morello eBPF',subtitle:'Existing work establishes the mechanisms; interface binding gives this study its focus.',diagram:'prior',caption:'Related designs · different enforcement premises · no security or cost ranking',source:'AEE · USENIX Security 2025; Leaf · Morello RFC 2024',url:'../research/related-work.md',
body:section('AEE: enforce the analysis at runtime','Object-level spatial enforcement constrains execution to verifier approximations. Static safety rules and the enforcement mechanism remain trusted.')+section('Leaf: compartmentalise native eBPF','The Morello RFC establishes a compartment foundation. Helper/kfunc transitions and capability transport across the interface remain explicit challenges.'),takeaway:'<strong>The next design question:</strong> exactly which right should an interface convey to native execution?',description:'Two related approaches. AEE enforces verifier approximations at object granularity. Leaf’s Morello RFC explores native eBPF compartments with helper and kfunc boundary work remaining. cBPF studies limited interface bindings built on established mechanisms.'},
{id:"spatial-question",chapter:"SPATIAL / THE QUESTION",title:"Which bytes did the lookup grant?",subtitle:"Storage layout locates a value; it does not define the returned authority.",caption:"Conditional design counterexample; Linux already checks logical value size",source:"Logical extent and exact-value argument",url:"../results/logical-extent.md",
body:section("Two values, two sizes","A seven-byte logical value occupies an eight-byte stride. Offset seven is padding; offset eight starts the next value.")+section("The question","A stride-wide capability would honestly authorize padding. The provider must supply the interface’s logical extent."),takeaway:"<strong>Grant the selected value, not its storage slot.</strong> The capability tag is separate integrity metadata.",description:"Seven logical bytes and one padding byte. A hypothetical stride-based constructor loses the interface boundary; this is not a new Linux vulnerability."},
{id:"spatial-input",chapter:"SPATIAL / A · INTERFACE AND INPUT",title:"A seven-byte value, a small valid program",subtitle:"Key 1 selects the second value. Byte six is the last logical byte.",caption:"Recorded BPF excerpt; inherited interface and layout",source:"Logical-extent guest and verifier transcript",url:"../results/logical-extent.md#recorded-code-to-native-walkthrough",
body:'',takeaway:"<strong>Ordinary valid BPF:</strong> lookup → NULL check → byte-six load, increment and store.",description:"The displayed instructions are BPF PCs 5–11 from the retained key-one guest. Two values have logical size seven, stride eight and four-byte keys; no forbidden access is attempted.",layout:'wide'},
{id:"spatial-analysis",chapter:"SPATIAL / B · ORDINARY ANALYSIS",title:"The verifier already knows the logical size",subtitle:"The non-NULL branch refines the lookup result before the byte access.",caption:"Observed verifier state; ordinary checks retained",source:"Retained logical-extent boot.log; pinned verifier source",url:"../results/logical-extent.md#recorded-code-to-native-walkthrough",
body:'',takeaway:"<strong>Unchanged in this provider patch:</strong> map-size, access-width and NULL checks remain enabled.",description:"Before the branch R0 is map_value_or_null with vs seven; after refinement R0 is map_value with vs seven. These observed abstract states are not the runtime capability representation.",layout:'wide'},
{id:"spatial-handoff",chapter:"SPATIAL / C · THE ACTUAL HANDOFF",title:"A root summary is not a serialized bound",subtitle:"Verifier metadata and the separate JIT authority analysis have different jobs.",caption:"Pinned-source inspection; not a new execution or analysis-correctness proof",source:"Verifier/JIT producer–field–consumer map",url:"../results/logical-extent.md#c-what-actually-crosses-the-compilation-boundary",
body:'',takeaway:"<strong>The verifier summary constrains the profile;</strong> JIT analysis selects capability instructions; runtime map metadata supplies the bound.",description:"Verifier ptr_type becomes prog aux jit_memory_roots with version and valid fields. Separate bpf_cheri_build_authority reconstructs register kinds in ctx authority; build_insn consumes these kinds. Runtime extent comes from map value_size.",layout:'wide'},
{id:"spatial-binding",chapter:"SPATIAL / D · RUNTIME CONSTRUCTION",title:"Selection by stride, authority by logical size",subtitle:"Stride-based address selection is inherited. cBPF adds exact logical-size authority from a retained root.",caption:"Offsets within cbpf_array_value_cap at 0xffff8000801c1e78; actual C and retained linked instructions",source:"array-authority.patch; linked provider inspection",url:"../results/logical-extent.md#d-runtime-extent-and-selected-address",
body:'',takeaway:"<strong>New production binding:</strong> exact selected-value authority, or no usable grant.",description:"Actual provider C is aligned with extracted linked instructions. scvalue c1,c7,x6 sets the selected address; scbndse c1,c1,x3 requests exact logical bounds. Provider-local c7 is the retained allocation capability, x6 is the stride-selected address, x3 is the logical extent from map value_size, and c1 is the resulting selected-value capability. This c7 is distinct from the later JIT program’s c7. Descriptor checks require length seven, tag one, unsealed state and permissions 0x30001; unsupported construction fails.",layout:'wide'},
{id:"spatial-transport",chapter:"SPATIAL / E · TRANSPORT",title:"Full-capability lookup transport",subtitle:"The inherited hybrid gateway returns c0; BPF R0 maps to c7.",caption:"Source and retained native inspection; existing ABI transport",source:"Lookup handoff and native word 72",url:"../results/logical-extent.md#ef-transport-and-actual-instructions",
body:'',takeaway:"<strong>Full-capability move:</strong> address, encoded authority and tag reach the operand together.",description:"The JIT source emits emit_cheri_cap_mov from A64_R zero to the BPF result register. Native word 72 is mov c7,c0. Address-only transport would not establish this capability correspondence.",layout:'wide'},
{id:"spatial-native",chapter:"SPATIAL / F · MACHINE CODE",title:"Capability operands in the retained native image",subtitle:"The retained image uses c7 for both one-byte accesses at displacement six.",caption:"Right: actual extracted instructions. Left: illustrative AArch64 forms, no built baseline",source:"392-byte key-one image; complete native review",url:"../results/logical-extent.md#ef-transport-and-actual-instructions",
body:'',takeaway:"<strong>Inspected scope:</strong> these two operands use the returned capability; this is not an all-program proof.",description:"Illustrative address-based ldrb and strb through x7 are compared with actual ldurb and sturb through c7 at native words 75 and 77. On Morello address-based forms use ambient DDC authority; they are not necessarily unchecked.",layout:'wide'},
{id:"spatial-evidence",chapter:"SPATIAL / G · VALID EFFECT",title:"One normal execution: 41 becomes 42",subtitle:"Key 1 · normally verified BPF · one TEST_RUN in Morello QEMU.",caption:"Recorded effect, joined to the inspected key-one image",source:"Logical-extent run and review artifacts",url:"../results/logical-extent.md",
body:'',takeaway:"<strong>Observed:</strong> exact construction and valid native use. This execution attempts no padding access.",description:"Initial bytes 11 22 33 44 55 66 29 become 11 22 33 44 55 66 2a; return and readback are 42. The six-byte prefix is unchanged. This key-one execution is distinct from the key-zero rejection matrix.",layout:'wide'},
{id:"spatial-rejection",chapter:"SPATIAL / G · SEPARATE SYNTHETIC REJECTION",title:"Exact authority selectively excludes padding",subtitle:"Key 0 · same backing address and permissions · fixed trusted native access forms.",caption:"30 operations: 22 permits, 8 bounds faults · test-only recovery · not verifier-admitted invalid BPF",source:"Spatial selectivity matrix-v2 and linked helper",url:"../results/spatial-selectivity.md",
body:'',takeaway:"<strong>At offset six:</strong> width one is permitted; width two is rejected by exact-seven authority and permitted by both wider controls.",description:"The highlighted offset-six pair distinguishes checking the full access from only its starting address: width one is permitted by all three roots; width two is rejected by exact-seven authority and permitted by stride-eight and both-slot-sixteen controls. All roots share the selected base and permissions. The other three matrix rows are retained. Separate case three loads padding through c2 with length seven and reports FSC 0x2a, unchanged sentinel and fixture. Test-only recovery is outside the production solution.",layout:'wide'},
{id:"ownership-question",chapter:"OWNERSHIP / THE QUESTION",title:"Same object. Which acquired right?",subtitle:"Copying A creates an alias of A, not another acquisition.",caption:"Conditional representation question; ordinary verifier ownership rules remain",source:"Acquisition-distinguishability argument",url:"../../theory/acquisition-distinguishability.md",
body:section("Acquire A and independent B","Both rights refer to the same live object. Its address, bounds and aggregate count cannot identify which right a request presents.")+section("Consume A once","B must remain usable before termination, while a later use through any alias of A must reject."),takeaway:"<strong>Object identity is not acquisition identity.</strong> The experiment holds object lifetime constant.",description:"Two independent acquisitions share one permanent object. Copies retain A’s identity. Consuming A should invalidate A’s aliases without consuming B."},
{id:"ownership-binding",chapter:"OWNERSHIP / CONSTRUCTION AND TRANSPORT",title:"An alias keeps A’s identity, not its validity",subtitle:"Private cells distinguish acquisitions; the public capability identifies a cell.",caption:"Actual fixed-image excerpts plus ordered gate observations",source:"Integrated native trace and complete inspection",url:"../results/ownership-native-trace.md",
body:'',takeaway:"<strong>Hardware preserves identity; software checks current validity.</strong> A’s public tag need not clear.",description:"Native words 67 and 79 store and load complete capability A through a sixteen-byte sidecar. Release clears A’s private authority before decrementing. B then reads 42 at BPF-shaped PC 13; A’s public alias remains tagged and canonical.",layout:'wide'},
{id:"ownership-evidence",chapter:"OWNERSHIP / REJECTION → TERMINATION → CLEANUP",title:"Stale A rejects; cleanup consumes B once",subtitle:"The native negatives reach the production gate at PC 17 after B has read 42.",caption:"Fixed trusted native fixtures, verified_bpf=0 · software ownership rejection, not an architectural bounds fault",source:"Ordered trace; linked gateway, epilogue and wrapper inspection",url:"../results/ownership-native-trace.md",
body:'',takeaway:"<strong>Reject consumed A → skip continuation → clean live B exactly once.</strong>",description:"The gateway restores saved state before cmn x0,#1 tests the failure sentinel. Failure selects the executive epilogue with mov c14,c13, zeroes x0/x7, restores c30 and clears scratch registers. retr c14 enters word 117 directly. Normal BPF exit uses the restricted-return stub at word 116. The epilogue scrubs the sidecar and registers; wrapper cleanup consumes B once. PC 19 release and PC 20 marker do not execute. This is software ownership rejection, not a spatial bounds fault.",layout:'wide'},
{id:"release-eligibility",chapter:"ANALYSIS / A DIFFERENT QUESTION",title:"Live does not mean entitled to release",subtitle:"An owning caller and a borrowing callback can present the same live A.",caption:"Conditional counterexample; no callback-policy implementation",source:"Validity versus contextual release eligibility",url:"../../theory/acquisition-distinguishability.md#3-live-validity-does-not-determine-release-eligibility",
body:'',takeaway:"<strong>CVE-2022-50650 relevance:</strong> projected repeated-consumption containment, not equivalence to the repair.",description:"The same identity and live state permit an owning caller’s release but do not authorize a borrowing callback’s first release. Current and owning context, plus callback-exit obligations, are separate information not implemented by cBPF.",layout:'wide'},
{id:"implementation-scope",chapter:"ENGINEERING / CORE AND SUPPORT",title:"Policy-specific engineering scope",subtitle:"Inherited platform and transport are credited separately from the policy-specific additions.",caption:"Physical-line estimate; mixed-file exclusions; no simplicity or security inference",source:"Reproducible implementation inventory at 89c0ece",url:"../research/implementation-scope.md",
body:'',takeaway:"<strong>Core first, evaluation second:</strong> fixtures, recovery, checkers and evidence copies are not the runtime policy.",description:"Spatial provider integration adds 193 and deletes one line over the inherited tree. Ownership core is about 841 physical lines relative to Morello base, excluding separately attributed platform extraction and support. Counts retain the pinned snapshot, mixed-span exclusions and inherited-versus-new distinction.",layout:'wide'},
{id:"findings",chapter:"SYNTHESIS / WHAT WAS ESTABLISHED",title:"Four decisions a runtime designer can reuse",subtitle:"Preserve the distinction the interface needs, then follow it to the actual effect.",caption:"Two separate profiles; evidence categories remain distinct",source:"Contribution and claim–evidence map",url:"../research/claim-evidence.md",
body:section("Representation","Use logical extent rather than stride. Use acquisition identity rather than object address. Associate identity with current validity.")+section("Execution boundary","Join rejection to stopped continuation and discharged obligations. These links are observed only in the selected controls."),takeaway:"<strong>Assurance is layered:</strong> model reasoning, execution, encoder self-check and internal native inspection are different support.",description:"Four decisions: extent differs from layout, object differs from acquisition, identity requires validity, and rejection needs terminal handling. Published receipts can be rechecked; no independently provisioned external reproduction or compiler proof is claimed."},
{id:"conclusion",chapter:"CONCLUSION / THE ANSWER",title:"Interface grants at native enforcement points",subtitle:"Construction → full transport → enforcement → terminal handling.",caption:"Bounded study complete; no performance or whole-runtime correctness claim",source:"Finalized findings and scope",url:"../research/claim-evidence.md",
body:section("Spatial answer","A normally verified valid witness and a separate same-storage matrix connect exact logical extent to selected native permit/reject outcomes.")+section("Ownership answer","A fixed trusted native trace preserves B, rejects consumed A, stops continuation and cleans B once through the production path."),takeaway:"<strong>The contribution:</strong> concrete bindings and discriminating evidence, with explicit software and architectural premises.",description:"The two implemented profiles demonstrate bounded feasibility of selected-value and acquisition-sensitive authority. They are not composed, do not reproduce complete original CVEs, and do not prove general reclamation, compiler correctness or performance superiority."}
];
const names=slides.map(s=>s.id), reduced=matchMedia('(prefers-reduced-motion: reduce)');
const photoIndex=names.indexOf('system'), topologyIndex=names.indexOf('topology');
const aliases={linux:'software',interfaces:'spatial-question',mismatch:'spatial-question',contract:'findings',conventional:'system',capability:'registers',bounds:'registers',spatial:'checks',ownership:'ownership-binding',control:'core'};
const map=Object.fromEntries(names.map(id=>[id,['system','topology'].includes(id)?'hardware':id]));
const scene=D.scene(), nodes=scene.nodes;
$('diagram').innerHTML=`<title id="diagram-title"></title><desc id="diagram-description"></desc>${D.defs}<defs><clipPath id="viewport-clip"><rect id="viewport-rect"/></clipPath></defs><g id="world" clip-path="url(#viewport-clip)">${scene.markup}</g>`;
const layers=Object.fromEntries(Object.values(nodes).filter(n=>n.portal).map(n=>{const cover=document.querySelector(`[data-cover="${n.id}"]`);return [n.id,{cover,labels:cover.querySelectorAll('text'),detail:document.querySelector(`[data-detail="${n.id}"]`)}];}));
let current=-1, contentIndex=-1, headingIndex=-1, logicalNode='hardware', token=0, raf=0, cancelTween=null, lastFrom=0;
let camera=[...nodes.hardware.frame], weights={}, photo=0, copyAlpha=1, viewAlpha=1;
// The running program is the shared landmark between two different software contexts.
const programAnchors={software:[2060,410,350,80],ebpf:[3200,468,350,80]};
const programContexts=[...document.querySelectorAll('[data-program-context]')];
let programBridge=false, programContextAlpha=1, headingAlpha=1;
// Empty presentation surfaces join conceptual diagrams. They encode no object
// identity, execution path or composition between the two research profiles.
const conceptBoundaries={
 'ebpf|prior-work':'panel','prior-work|spatial-question':'split',
 'spatial-question|spatial-binding':'panel','spatial-binding|spatial-evidence':'rows',
 'spatial-evidence|ownership-question':'split','ownership-question|ownership-binding':'panel',
 'ownership-binding|ownership-evidence':'rows','ownership-evidence|findings':'split',
 'findings|conclusion':'rows'
};
const conceptSheets=[...document.querySelectorAll('[data-sheet]')].map(el=>({el,text:[...el.querySelectorAll('text')]}));
$('diagram').insertAdjacentHTML('beforeend','<defs><clipPath id="concept-reveal" clipPathUnits="userSpaceOnUse"><rect/><rect/><rect/></clipPath></defs><g id="concept-surface" transform="translate(2880 0)" aria-hidden="true" pointer-events="none"><rect rx="3"/><rect rx="3"/><rect rx="3"/></g>');
const conceptSurface=$('concept-surface'),conceptRects=[...conceptSurface.children],conceptClips=[...$('concept-reveal').children];
let conceptMotion=null,conceptAlpha=1,conceptTextAlpha=1;
const clamp=x=>Math.min(1,Math.max(0,x));
const ease=x=>x*x*x*(x*(x*6-15)+10);
const ramp=(a,b,x)=>ease(clamp((x-a)/(b-a)));
const timing={opening:2400,return:2200,step:1450,route:2900,minimumStep:650,copy:260};
const walkthrough=[
 {label:'Request',parts:['capability','address'],body:section('One byte at `v + 6`','A supplied capability grants the seven-byte interval <code>[v, v + 7)</code>. The instruction requests one byte at <code>v + 6</code>.')+section('Example assumptions','The capability is tagged, unsealed and permits loads. The virtual address has a valid, readable mapping.'),takeaway:'<strong>Authority belongs to the pointer.</strong> The requested byte and the capability used to reach it are different values.'},
 {label:'Checks',parts:['capability','address','inputs','cap-check','page-check','bounds'],body:section('Capability authority','Check tag, permissions and applicable seal conditions. The complete interval <code>[v + 6, v + 7)</code> fits within the grant.')+section('Page authority','The TLB/MMU translates the same virtual address and checks the mapping’s read permissions. Page protection remains necessary alongside the capability check.'),takeaway:'<strong>Object and page protection work together.</strong> Both obligations apply to the same memory request.'},
 {label:'Permission',parts:['cap-check','page-check','join','grant','bounds'],body:section('Both conditions allow this load','The one-byte request fits the capability and satisfies the assumed mapping permissions.')+section('The whole width matters','A two-byte request at the same address would extend to <code>v + 8</code>, beyond this grant. Every byte of the operation must fit.'),takeaway:'<strong>A valid mapping alone is insufficient.</strong> The actual access also needs sufficient capability authority.'},
 {label:'Data',parts:['grant','data'],body:section('The addressed byte is returned','A cache hit can supply the byte. A miss requires further lookup in the memory hierarchy.')+section('Data and capability transport differ','An ordinary byte load returns data. The capability’s validity tag belongs to its authority; a byte does not acquire that tag.'),takeaway:'<strong>The grant constrains the read.</strong> Full capability loads and stores additionally preserve the capability’s protected metadata.'}
];
const accessParts=[...document.querySelectorAll('[data-access-part]')];
let walkIndex=-1;
function updateWalk(){
 const s=slides[contentIndex<0?current:contentIndex],active=s.id==='checks'&&walkIndex>=0,step=walkthrough[walkIndex];
 $('walk-controls').hidden=s.id!=='checks';$('walk-start').hidden=active;$('walk-nav').hidden=!active;
 for(const part of accessParts){const focus=active&&step.parts.includes(part.dataset.accessPart);part.style.opacity=active&&!focus?'.32':'1';part.classList.toggle('access-focus',focus);}
 document.querySelector('[data-load-detail]').toggleAttribute('hidden',!active||walkIndex!==3);
 const rule=active?'[v + 6, v + 7) ⊆ [v, v + 7)':'base ≤ a  and  a + w ≤ limit';
 const note=active?'One-byte load · seven-byte authority · non-wrapping arithmetic':'The complete byte interval must fit; arithmetic must not wrap.';
 for(const [id,value] of [['access-rule',rule],['access-rule-note',note]])if($(id).textContent!==value)$(id).textContent=value;
 $('explanation').innerHTML=active?step.body:s.body||'';$('takeaway').innerHTML=D.inline(active?step.takeaway:s.takeaway||'');
 if(active||headingIndex===current)$('subtitle').textContent=active?'One illustrative byte load, followed from authority to data.':s.subtitle;
 $('diagram-caption').textContent=active?'Illustrative valid load · logical obligations, not a cycle trace':s.caption||'';
 $('diagram-description').textContent=active?`${s.description} Walkthrough step ${walkIndex+1}: ${step.label}. ${$('explanation').textContent}`:s.description;
 $('stage').dataset.loadStep=active?String(walkIndex+1):'overview';
 $('replay').hidden=current===0||reduced.matches||active;
 if(active){$('walk-status').textContent=`${walkIndex+1} / ${walkthrough.length} · ${step.label}`;$('walk-back').disabled=walkIndex===0;$('walk-next').disabled=walkIndex===walkthrough.length-1;}
}
function setWalk(step){
 if(slides[current].id!=='checks'||step< -1||step>=walkthrough.length)return;
 walkIndex=step;updateWalk();
 if(step===-1)$('walk-start').focus();else if(document.activeElement===$('walk-start'))$('walk-next').focus();else if(document.activeElement.disabled)$('walk-reset').focus();
}
function path(id){const p=[];for(let n=nodes[id];n;n=nodes[n.parent])p.unshift(n.id);return p;}
function targetWeights(id){const active=path(id);return Object.fromEntries(Object.keys(layers).map(k=>[k,active.includes(k)?1:0]));}
function cancel(){token++;cancelAnimationFrame(raf);if(cancelTween){cancelTween(false);cancelTween=null;}$('stage').classList.remove('moving');}
function tween(ms,paint,ticket){return new Promise(resolve=>{let start;cancelTween=resolve;function tick(now){if(ticket!==token){resolve(false);return;}start??=now;const p=clamp((now-start)/ms);paint(ease(p),p);render();if(p<1)raf=requestAnimationFrame(tick);else{cancelTween=null;resolve(true);}}raf=requestAnimationFrame(tick);});}
function fitted(r){const aspect=$('diagram').clientWidth/Math.max(1,$('diagram').clientHeight),w=Math.max(r[2],r[3]*aspect),h=w/aspect;return [r[0]+r[2]/2-w/2,r[1]+r[3]/2-h/2,w,h];}
function render(){
 // Change the opening heading only while it is invisible, in either direction.
 const visibleHeading=photo<1||contentIndex===photoIndex?(photo<.58?photoIndex:contentIndex===photoIndex?topologyIndex:contentIndex):contentIndex;
 if(headingIndex!==visibleHeading){const s=slides[visibleHeading];headingIndex=visibleHeading;$('eyebrow').textContent=s.chapter;$('title').textContent=s.title;$('subtitle').textContent=s.subtitle;$('source').textContent=s.source||'';$('source').hidden=!s.source;if(s.url)$('source').href=location.protocol==='file:'?s.url:s.url.replace(/\.md(?=#|$)/,'.html');else $('source').removeAttribute('href');}
 const v=fitted(camera);$('diagram').setAttribute('viewBox',v.join(' '));['x','y','width','height'].forEach((k,i)=>$('viewport-rect').setAttribute(k,camera[i]));
 for(const [id,els] of Object.entries(layers)){
  const alpha=weights[id]||0;
  // Retire overview labels before detail text appears; surfaces bridge the zoom.
  for(const label of els.labels)label.setAttribute('opacity',1-ramp(0,.2,alpha));
  els.cover.setAttribute('opacity',1-ramp(.25,.65,alpha));
  els.detail.setAttribute('opacity',ramp(.35,.95,alpha));
 }
 for(const sheet of document.querySelectorAll('[data-sheet]'))sheet.style.display=sheet.dataset.sheet===logicalNode?'':'none';
 renderConcept();
 for(const context of programContexts)context.setAttribute('opacity',programContextAlpha);
 const diagram=$('diagram');
 diagram.style.transform='none';
 if(photo<1){
  const stage=$('stage').getBoundingClientRect(),ox=stage.width*.5,oy=stage.height*.55;
  // The raster moves only 3%; the resolution-independent perimeter carries the transition.
  const z=1+.03*ramp(0,.3,photo);
  $('opening').style.transform=`scale(${z})`;
  $('opening').style.opacity=viewAlpha*(1-ramp(.2,.53,photo));
  const bounds=diagram.getBoundingClientRect(),px=bounds.width/v[2];
  const x=bounds.left-stage.left-v[0]*px,y=bounds.top-stage.top-v[1]*px;
  const target=[[x,y],[x+1000*px,y],[x+1000*px,y+509*px],[x,y+509*px]];
  const resolve=ramp(.2,.76,photo),quad=window.OPENING_ANCHORS.map((p,i)=>{
   const sx=ox+z*(p[0]/100*stage.width-ox),sy=oy+z*(p[1]/100*stage.height-oy);
   return [sx+(target[i][0]-sx)*resolve,sy+(target[i][1]-sy)*resolve];
  });
  $('opening-frame').setAttribute('viewBox',`0 0 ${stage.width} ${stage.height}`);
  $('die-outline').setAttribute('d',quad.map((p,i)=>(i?'L':'M')+p.join(' ')).join(' ')+' Z');
  $('die-outline').style.strokeDashoffset=1-ramp(.025,.29,photo);
  $('opening-frame').style.opacity=viewAlpha*ramp(0,.08,photo)*(1-ramp(.86,1,photo));
  diagram.style.opacity=viewAlpha*ramp(.64,.94,photo);
  $('stage').style.setProperty('--opening-labels',ramp(.77,1,photo));
 }else{diagram.style.opacity=String(viewAlpha);$('opening').style.opacity='0';$('opening-frame').style.opacity='0';}
 $('hero-label').style.opacity=contentIndex===photoIndex?viewAlpha*(1-ramp(0,.3,photo)):0;
 document.querySelector('.heading').style.opacity=viewAlpha*headingAlpha*Math.max(1-ramp(.02,.21,photo),ramp(.73,.97,photo));
 $('source').style.opacity=viewAlpha*headingAlpha*Math.max(1-ramp(.36,.53,photo),ramp(.59,.76,photo));
 $('cover-credits').style.opacity=viewAlpha;
 const body=(contentIndex===photoIndex?0:ramp(.76,1,photo))*copyAlpha*viewAlpha;
 for(const id of ['explanation-column','takeaway','diagram-caption'])$(id).style.opacity=body;
 $('walk-start').disabled=$('stage').classList.contains('moving');
 $('stage').dataset.motion=photo<1&&photo>0?'emergence':conceptMotion?'concept-'+conceptMotion.kind:$('stage').classList.contains('moving')?'camera':'still';
}
function resetConcept(){conceptMotion=null;conceptAlpha=conceptTextAlpha=1;}
function settle(i){resetConcept();programBridge=false;programContextAlpha=headingAlpha=1;viewAlpha=1;photo=i===photoIndex?0:1;logicalNode=map[slides[i].id];camera=[...nodes[logicalNode].frame];weights=targetWeights(logicalNode);copyAlpha=1;render();}
function route(a,b){const pa=path(a),pb=path(b);let same=0;while(same<pa.length&&same<pb.length&&pa[same]===pb[same])same++;return [...pa.slice(same-1,-1).reverse(),...pb.slice(same)];}
function interpolateCamera(start,finish,u){
 const w=start[2]*Math.pow(finish[2]/start[2],u),h=start[3]*Math.pow(finish[3]/start[3],u);
 return [start[0]+start[2]/2+(finish[0]+finish[2]/2-start[0]-start[2]/2)*u-w/2,start[1]+start[3]/2+(finish[1]+finish[3]/2-start[1]-start[3]/2)*u-h/2,w,h];
}
async function travel(to,ticket){
 const points=route(logicalNode,to);
 if(!points.length){if(camera.every((v,i)=>Math.abs(v-nodes[to].frame[i])<1e-8))return true;points.push(to);}
 const perEdge=Math.min(timing.step,Math.max(timing.minimumStep,timing.route/points.length));
 for(const id of points){
  const start=[...camera],finish=nodes[id].frame,fromWeights={...weights},toWeights=targetWeights(id);logicalNode=id;
  const ok=await tween(perEdge,(u,p)=>{
   camera=interpolateCamera(start,finish,u);
   const reveal=ramp(.08,.86,p);for(const k of Object.keys(layers))weights[k]=(fromWeights[k]||0)+((toWeights[k]||0)-(fromWeights[k]||0))*reveal;
  },ticket);if(!ok)return false;
 }
 return true;
}
async function followProgram(i,ticket){
 const to=map[slides[i].id];programBridge=true;$('stage').classList.add('moving');
 if(logicalNode!==to){
  const from=logicalNode,[x,y,w,h]=programAnchors[from],start=[...camera];
  const focus=[x-45,y-128,w+90,h+256];
  const alpha=programContextAlpha,heading=headingAlpha,copy=copyAlpha,view=viewAlpha;
  // Approach the actual program. Its surroundings retire; the landmark stays visible.
  if(!await tween(1300,(u,p)=>{
   camera=interpolateCamera(start,focus,u);
   programContextAlpha=alpha*(1-ramp(.15,.86,p));headingAlpha=heading*(1-ramp(.05,.55,p));copyAlpha=copy*(1-ramp(0,.5,p));
   viewAlpha=view+(1-view)*ramp(0,.3,p);
  },ticket))return;
  // Rebase at identical screen geometry. The next diagram is context around this
  // program, not a loader or verifier physically contained inside it.
  const next=programAnchors[to];camera=[camera[0]+next[0]-x,camera[1]+next[1]-y,camera[2],camera[3]];
  logicalNode=to;weights=targetWeights(to);publish(i);render();
 }else if(contentIndex!==i)publish(i);
 const start=[...camera],alpha=programContextAlpha,heading=headingAlpha,copy=copyAlpha,view=viewAlpha;
 if(!await tween(1450,(u,p)=>{
  camera=interpolateCamera(start,nodes[to].frame,u);
  programContextAlpha=alpha+(1-alpha)*ramp(.06,.75,p);headingAlpha=heading+(1-heading)*ramp(.12,.65,p);copyAlpha=copy+(1-copy)*ramp(.3,.9,p);
  viewAlpha=view+(1-view)*ramp(0,.3,p);
 },ticket))return;
 programBridge=false;$('stage').classList.remove('moving');render();
}
function conceptKind(from,to){return conceptBoundaries[from+'|'+to]||conceptBoundaries[to+'|'+from];}
function renderConcept(){
 for(const {el,text} of conceptSheets){
  el.style.opacity=conceptAlpha;
  for(const label of text)label.style.opacity=conceptTextAlpha;
  if(conceptMotion?.phase==='reveal'&&el.dataset.sheet===logicalNode)el.setAttribute('clip-path','url(#concept-reveal)');else el.removeAttribute('clip-path');
 }
 conceptSurface.style.display=conceptMotion?'':'none';if(!conceptMotion)return;
 const m=conceptMotion,p=m.progress,reveal=m.phase==='reveal',count=m.kind==='panel'?1:m.kind==='split'?2:3;
 conceptSurface.style.opacity=reveal?1-ramp(.5,.9,p):ramp(.18,.38,p);
 for(let k=0;k<3;k++){
  const visible=k<count;conceptRects[k].style.display=visible?'':'none';conceptClips[k].setAttribute('width',0);if(!visible)continue;
  const order=m.direction>0?k:count-1-k;
  let origin,tile,finish,tilt=0;
  if(m.kind==='panel'){origin=m.anchor;tile=[380,180,240,200];finish=[-15,-10,1030,620];tilt=2.2*m.direction;}
  else if(m.kind==='split'){
   origin=[m.anchor[0]+k*m.anchor[2]/2,m.anchor[1],m.anchor[2]/2,m.anchor[3]];
   tile=[265+k*250,180,220,200];finish=[-15+k*515,-10,515,620];tilt=(k?1:-1)*1.7*m.direction;
  }else{origin=[-15,-10+k*620/3,1030,620/3];tile=[180,181+k*82,640,56];finish=origin;}
  const progress=reveal?ramp(.1+order*.045,.76+order*.045,p):ramp(.3+order*.04,1,p);
  const a=reveal?tile:origin,b=reveal?finish:tile,r=a.map((v,j)=>v+(b[j]-v)*progress);
  const angle=tilt*(reveal?1-ramp(0,.22,p):ramp(.55,1,p));
  for(const el of [conceptRects[k],conceptClips[k]])['x','y','width','height'].forEach((attr,j)=>el.setAttribute(attr,r[j]));
  conceptRects[k].setAttribute('fill',reveal?'none':'#fff');conceptRects[k].setAttribute('stroke','#94b5a8');conceptRects[k].setAttribute('stroke-width','1.5');
  conceptRects[k].setAttribute('transform',`rotate(${angle} ${r[0]+r[2]/2} ${r[1]+r[3]/2})`);
 }
}
async function changeConcept(i,ticket,kind){
 const source=logicalNode,to=map[slides[i].id],sheet=conceptSheets.find(s=>s.el.dataset.sheet===source).el;
 const candidates=[...sheet.querySelectorAll('rect')].map(r=>['x','y','width','height'].map(a=>Number(r.getAttribute(a)))).filter(r=>r[2]>=200&&r[3]>=60&&r[3]<400);
 const anchor=candidates.sort((a,b)=>b[2]*b[3]-a[2]*a[3])[0]||[320,225,360,130];
 const duration=kind==='split'?[680,1120]:kind==='rows'?[560,1160]:[620,1080];
 conceptMotion={kind,phase:'retire',progress:0,direction:Math.sign(names.indexOf(to)-names.indexOf(source)),anchor};
 $('stage').classList.add('moving');
 const heading=headingAlpha,copy=copyAlpha,view=viewAlpha;
 if(!await tween(duration[0],(_,p)=>{
  conceptMotion.progress=p;conceptTextAlpha=1-ramp(0,.3,p);conceptAlpha=1-ramp(.2,.75,p);
  headingAlpha=heading*(1-ramp(0,.48,p));copyAlpha=copy*(1-ramp(0,.4,p));viewAlpha=view+(1-view)*ramp(0,.3,p);
 },ticket))return;
 // The title changes while hidden. The next drawing is revealed in place;
 // its text never rotates, scales independently or inherits a motion blur.
 logicalNode=to;camera=[...nodes[to].frame];weights=targetWeights(to);publish(i);
 conceptMotion.phase='reveal';conceptMotion.progress=0;render();
 if(!await tween(duration[1],(_,p)=>{
  conceptMotion.progress=p;conceptAlpha=ramp(.14,.56,p);conceptTextAlpha=ramp(.74,1,p);
  headingAlpha=ramp(.16,.64,p);copyAlpha=ramp(.46,.96,p);
 },ticket))return;
 resetConcept();headingAlpha=copyAlpha=viewAlpha=1;$('stage').classList.remove('moving');render();
}
async function reframe(i,ticket){
 $('stage').classList.add('moving');
 const start=viewAlpha;
 if(!await tween(280,u=>viewAlpha=start*(1-u),ticket))return;
 const to=map[slides[i].id];resetConcept();programBridge=false;programContextAlpha=headingAlpha=1;logicalNode=to;camera=[...nodes[to].frame];weights=targetWeights(to);photo=i===photoIndex?0:1;copyAlpha=1;publish(i);render();
 if(!await tween(560,u=>viewAlpha=u,ticket))return;
 $('stage').classList.remove('moving');render();
}
async function move(i,ticket){
 const target=map[slides[i].id];
 if(conceptMotion)return reframe(i,ticket);
 if(programAnchors[logicalNode]&&programAnchors[target]&&(logicalNode!==target||programBridge))return followProgram(i,ticket);
 const kind=conceptKind(logicalNode,target);if(kind&&!programBridge)return changeConcept(i,ticket,kind);
 if(programBridge||nodes[logicalNode].sheet||nodes[target].sheet)return reframe(i,ticket);
 publish(i);viewAlpha=1;
 $('stage').classList.add('moving');copyAlpha=.3;
 const to=map[slides[i].id];
 if(i===photoIndex){if(!await travel('hardware',ticket))return;const start=photo;if(start>0&&!await tween(timing.return*start,(_,p)=>photo=start*(1-p),ticket))return;}
 else{
  if(photo<1){const start=photo;if(!await tween(timing.opening*(1-start),(_,p)=>photo=start+(1-start)*p,ticket))return;logicalNode='hardware';}
  if(nodes[to].sheet)return reframe(i,ticket);
  if(!await travel(to,ticket))return;
 }
 if(ticket!==token)return;$('stage').classList.remove('moving');
 const alpha=copyAlpha;await tween(timing.copy,u=>copyAlpha=alpha+(1-alpha)*u,ticket);
}
function hashIndex(){const id=location.hash.replace(/^#\/?/,'');return Math.max(0,names.indexOf(aliases[id]||id));}
function publish(i){
 contentIndex=i;const s=slides[i];$('stage').dataset.slide=s.id;$('stage').dataset.layout=s.layout||'standard';
 $('description').textContent=s.description;$('diagram-title').textContent=s.title;$('diagram-description').textContent=s.description;
 $('counter').textContent=`${String(i+1).padStart(2,'0')} / ${slides.length}`;$('previous').disabled=i===0;$('next').disabled=i===slides.length-1;
 document.title=s.title+' · cBPF';
 updateWalk();
}
function show(i,animate=true){
 if(i<0||i>=slides.length||i===current)return;const previous=current;cancel();current=i;walkIndex=-1;lastFrom=Math.max(0,previous);const ticket=token;
 history.replaceState(null,'','#'+slides[i].id);
 if(animate&&previous>=0&&!reduced.matches)move(i,ticket);else{publish(i);settle(i);}
}
$('previous').onclick=()=>show(current-1);$('next').onclick=()=>show(current+1);
$('walk-start').onclick=()=>setWalk(0);$('walk-back').onclick=()=>setWalk(walkIndex-1);$('walk-next').onclick=()=>setWalk(walkIndex+1);$('walk-reset').onclick=()=>setWalk(-1);
$('replay').onclick=async()=>{cancel();const ticket=token,end=current;await move(lastFrom,ticket);if(ticket===token)await move(end,ticket);};

$('fullscreen').onclick=()=>{const action=document.fullscreenElement?document.exitFullscreen():document.documentElement.requestFullscreen();action?.catch(()=>{});};
document.addEventListener('fullscreenchange',()=>{$('fullscreen').setAttribute('aria-label',document.fullscreenElement?'Exit fullscreen':'Enter fullscreen');});
document.addEventListener('keydown',e=>{
 if(e.key==='Escape'&&walkIndex>=0){e.preventDefault();setWalk(-1);return;}
 if(e.key==='Escape'&&parent!==window){parent.postMessage({type:'cbpf-close-architecture'},location.protocol==='file:'?'*':location.origin);return;}
 if(e.altKey||e.ctrlKey||e.metaKey||e.target.closest('input,textarea,select,[contenteditable]'))return;if([' ','Enter'].includes(e.key)&&e.target.closest('button,a'))return;
 if(e.key.toLowerCase()==='f'){e.preventDefault();$('fullscreen').click();return;}
 if(e.key.toLowerCase()==='r'&&!$('replay').hidden){e.preventDefault();$('replay').click();return;}
 if(['ArrowRight','ArrowDown','PageDown',' '].includes(e.key)){e.preventDefault();show(current+(e.shiftKey?-1:1));}
 if(['ArrowLeft','ArrowUp','PageUp'].includes(e.key)){e.preventDefault();show(current-1);}
 if(e.key==='Home'){e.preventDefault();show(0,false);}if(e.key==='End'){e.preventDefault();show(slides.length-1,false);}
 if(/^[1-9]$/.test(e.key))show(Number(e.key)-1,false);if(e.key==='0')show(9,false);if(e.key==='-')show(names.indexOf('findings'),false);
});
reduced.addEventListener('change',()=>{cancel();publish(current);settle(current);updateWalk();});
new ResizeObserver(render).observe($('stage'));
addEventListener('hashchange',()=>show(hashIndex(),false));show(hashIndex(),false);
})();
