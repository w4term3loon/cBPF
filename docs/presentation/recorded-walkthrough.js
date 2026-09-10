/* Fixed recorded-evidence panels, not executable BPF or a live demonstration. */
window.CBPF_RECORDED_PANELS = {
 'spatial-input':['ACTUAL BPF · KEY 1',[
  '5: call bpf_map_lookup_elem#1','6: if r0 == 0x0 goto pc+5','7: r1 = *(u8 *)(r0 +6)',
  '8: r1 += 1','9: *(u8 *)(r0 +6) = r1','10: r0 = r1','11: exit'],
 'INHERITED ARRAY LAYOUT',[
  'key_size = 4    max_entries = 2','value_size = 7  stride = 8','',
  'key 0: [0 1 2 3 4 5 6][pad]','key 1: [0 1 2 3 4 5 6][pad]',
  '                    ^ byte 6','NULL branch returns zero'],
 'The fixture supplies the key; normal verification precedes this valid execution.'],
 'spatial-analysis':['AFTER LOOKUP · OBSERVED STATE',[
  'R0_w=map_value_or_null(', '  id=1, off=0, ks=4, vs=7, imm=0)', '',
  '6: if r0 == 0x0 goto pc+5', '', 'vs=7: logical map-value size', 'nullable: access not yet allowed'],
 'NON-NULL PATH · OBSERVED STATE',[
  'R0_w=map_value(', '  off=0, ks=4, vs=7, imm=0)', '',
  '7: r1 = *(u8 *)(r0 +6)', '', 'width 1 at offset 6 fits [0,7)', 'NULL and extent checks unchanged'],
 'Observed abstract state is not a serialized capability bound. This provider patch changes no verifier checks.'],
 'spatial-handoff':['INHERITED VERIFIER INSTRUMENTATION',[
  'save_aux_ptr_type', '  insn_aux_data[pc].ptr_type', 'finalize_bpf_jit_memory_roots',
  '  prog->aux->jit_memory_roots = roots;', '', 'jit_memory_contract_version / valid',
  '  -> bpf_jit_validate_prog', 'used_maps / used_map_cnt -> map token'],
 'SEPARATE JIT ANALYSIS',[
  'bpf_cheri_build_authority', '  reconstructs kinds + NULL refinement',
  '  ctx.authority[pc].regs[r].kind', '', 'build_insn consumes the kind:',
  '  capability move / memory encoding', 'reconstructed roots match summary', 'certificate uses this JIT analysis'],
 'Source-inspected handoff. Runtime length comes separately from map->value_size, not a verifier interval.'],
 'spatial-binding':['cBPF · ACTUAL PROVIDER C',[
  'cap = authority->root;', 'value = (unsigned long)array->value +',
  '  (u64)array->elem_size *', '  (index & array->index_mask);',
  'cap = cheri_address_set(cap, value);', 'cap = cheri_bounds_set_exact(', '  cap, map->value_size);', '/* descriptor checks omitted */'],
 'EXTRACTED · SAME PROVIDER',[
  'c7: retained allocation capability', 'x6: selected address, using stride',
  'x3: extent from map->value_size', 'c1: selected-value capability',
  '+0xe0  scvalue c1, c7, x6', '+0xe4  scbndse c1, c1, x3', '',
  'length 7; tag 1; permissions 0x30001'],
 'Provider-local c7 is distinct from the JIT program’s c7 on the next slides.',
 {left:[4,5,6],right:[4,5]}],
 'spatial-transport':['SOURCE · INHERITED HYBRID HANDOFF',[
  'provider -> gateway -> c0', '', 'emit_cheri_cap_mov(', '  r0, A64_R(0), ctx);', '',
  'BPF R0 maps to native c7', 'not a uniform R0 -> c0 rename'],
 'ACTUAL RETAINED NATIVE WORD 72',[
  '0xffff8000813f7e18', 'c2c1d007    mov c7, c0', '',
  'c0: complete lookup return', 'c7: complete native BPF result', '',
  'address + bounds + permissions + tag', 'NULL test does not replace c7'],
 'New provider, inherited transport. Inspection follows the returned capability to native use.'],
 'spatial-native':['ILLUSTRATIVE CONVENTIONAL FORMS',[
  'ldrb w0, [x7, #6]', 'strb w0, [x7, #6]', '',
  'one byte; address register x7', 'displacement 6', '',
  'No baseline kernel was built.', 'Morello address forms use ambient DDC.'],
 'EXTRACTED · KEY-ONE NATIVE IMAGE',[
  'word 75 / 0xffff8000813f7e24', 'e20064e0   ldurb w0, [c7, #6]', '',
  'word 77 / 0xffff8000813f7e2c', 'e20060e0   sturb w0, [c7, #6]', '',
  'one byte; capability base c7', 'same c7; scalar increment in between'],
 'The explicit capability operand is the enforcement input. Only the inspected sequence is established.'],
 'spatial-evidence':['BEFORE · KEY 1',[
  'offset    0  1  2  3  4  5  6', 'bytes    11 22 33 44 55 66 29', '',
  'selected v = 0xffff000000df8318', 'capability length = 7', 'native image = 392 bytes / 98 words', 'ordinary verifier accepts 14 BPF insns'],
 'AFTER · ONE TEST_RUN',[
  'offset    0  1  2  3  4  5  6', 'bytes    11 22 33 44 55 66 2a', '',
  'byte 6: 0x29 -> 0x2a (41 -> 42)', 'first six bytes unchanged', 'return = readback = 42', 'no padding access in this run'],
 'Recorded execution plus prior image inspection. A length-eight grant would also allow this byte access.'],
 'spatial-rejection':['KEY 0 · LOAD AND STORE MATRIX',[
  'offset,width    exact7 stride8 both16', '6,1 last byte   permit permit  permit',
  '6,2 crossing    reject permit  permit', '7,1 padding     reject permit  permit',
  '8,1 next value  reject reject  permit', '4,2 interior    permit permit  permit', '',
  'same base, permissions, access forms'],
 'CASE 3 · ACTUAL PADDING LOAD FAULT',[
  'base = 0xffff000000c62f10; length = 7', 'c2 cursor = base + 7; displacement = 0',
  'PC = fault PC = 0xffff8000801c4780', 'e2000448   ldurb w8, [c2]',
  'FSC = 0x2a (bounds)', 'destination sentinel unchanged', 'all 16 fixture bytes unchanged',
  'wider roots permit the padding load'],
 'Synthetic native validation. Separate BPF admission: four accepts, six rejects, zero executions.',
 {left:[1,2]}],
 'ownership-binding':['FULL-CAPABILITY A ALIAS · EXTRACTED',[
  'word 67: str c19, [csp, #0]', 'word 79: ldr c21, [csp, #0]', '',
  'logical spill: 8 bytes', 'native sidecar: 16-byte capability', '',
  'A -> private cell A', 'B -> private cell B (same object)'],
 'ORDERED GATE OBSERVATIONS',[
  'acquire A, B:              refs = 3', 'consume A: clear private validity',
  'then provider decrement:  refs = 2', '', 'PC 13: read B -> 42',
  'PC 17: present retained A', 'public A: tagged + canonical', 'private A: invalid'],
 'The public tag survives. Current acquisition validity is protected software state, not global tag revocation.'],
 'ownership-evidence':['LINKED GATEWAY · FAILURE EXCERPT',[
  '...             // restore saved state', 'cmn x0, #1      // then test sentinel',
  'b.ne ...        // success skips select', 'mov c14, c13    // failure: epilogue',
  '...             // zero result; set c30', '...             // clear scratch regs',
  'retr c14        // direct to word 117', 'normal exit: ret c30 stub at word 116'],
 'OBSERVED TERMINAL EFFECTS',[
  'reject consumed A: no read / decrement', 'skip continuation: PC 19 and PC 20',
  'epilogue clears sidecar + registers', 'clean live B exactly once (wrapper)',
  '2 acquisitions; 2 total releases', '1 cleanup release; 1 successful read', 'return = 0; baseline refs = 1'],
 'Two synthetic negatives: stale read and repeated release. Positive releases both explicitly and returns 42.',
 {left:[6],right:[0,1,3]}],
 'release-eligibility':['SAME ACQUISITION OBSERVATION',[
  'A identity = unchanged', 'A live = true', 'object and bounds = unchanged', '',
  'owning caller F0 requests release', 'borrowing callback F1 requests release', '',
  '(A, live) cannot distinguish them'],
 'CALLBACK POLICY NEEDS MORE',[
  'current = owner = F0: permit', 'current = F1; owner = F0: reject', '',
  'callback-local B may be released', 'local obligations checked at exit', '',
  'cBPF: no callback-owner relation', 'consume-once is only one policy part'],
 'Analytical counterexample, not another experiment or a new general theorem.'],
 'implementation-scope':['POLICY-SPECIFIC CORE',[
  'spatial: 193 added / 1 deleted', '5 paths over inherited e6c69574 tree', '',
  'ownership: ~841 physical core lines', 'runtime 330 + compiler 435', 'header 27 + integration 49',
  '25 C functions + assembly gateway', 'base b96da308; snapshot 89c0ece'],
 'INHERITED AND SUPPORT · SEPARATE',[
  'spatial JIT / platform: inherited', 'ownership platform: +51 / -24', '',
  'test fixtures and recovery: excluded', 'checks and packaging: excluded',
  'raw evidence and copies: excluded', 'mixed spans counted conservatively'],
 'The inventory gives paths, exclusion spans and counting commands. Size describes scope, not security.']
};
