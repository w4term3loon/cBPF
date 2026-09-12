/* Retained excerpts and observations for the presentation, never live execution. */
window.CBPF_RECORDED = {
 input: {
  bpf: [
   '5: call bpf_map_lookup_elem#1',
   '6: if r0 == 0x0 goto pc+5',
   '7: r1 = *(u8 *)(r0 +6)',
   '8: r1 += 1',
   '9: *(u8 *)(r0 +6) = r1',
   '10: r0 = r1',
   '11: exit'
  ],
  keySize: 4, entries: 2, valueSize: 7, stride: 8, selectedKey: 1
 },
 analysis: {
  nullable: 'R0_w=map_value_or_null(id=1, off=0, ks=4, vs=7, imm=0)',
  refined: ['R0_w=map_value(', '  off=0, ks=4, vs=7, imm=0)'],
  branch: '6: if r0 == 0x0 goto pc+5',
  access: '7: r1 = *(u8 *)(r0 +6)'
 },
 construction: {
  symbol: 'cbpf_array_value_cap', address: '0xffff8000801c1e78',
  selection: [
   'cap = authority->root;',
   'value = (unsigned long)array->value +',
   '  (u64)array->elem_size *',
   '  (index & array->index_mask);'
  ],
  addressSet: 'cap = cheri_address_set(cap, value);',
  boundsSet: ['cap = cheri_bounds_set_exact(', '  cap, map->value_size);'],
  native: [
   ['+0x5c', 'ldr c7, [x8, #0x60]'],
   ['+0xdc', 'umaddl x6, w9, w4, x5'],
   ['+0xe0', 'scvalue c1, c7, x6'],
   ['+0xe4', 'scbndse c1, c1, x3']
  ]
 },
 transport: {
  source: 'emit_cheri_cap_mov(r0, A64_R(0), ctx);',
  instruction: 'mov c7, c0', word: 72,
  address: '0xffff8000813f7e18', encoding: 'c2c1d007'
 },
 native: {
  extracted: [
   {word:75, address:'0xffff8000813f7e24', encoding:'e20064e0', instruction:'ldurb w0, [c7, #6]'},
   {word:77, address:'0xffff8000813f7e2c', encoding:'e20060e0', instruction:'sturb w0, [c7, #6]'}
  ],
  illustrative: ['ldrb w0, [x7, #6]', 'strb w0, [x7, #6]'],
  baselineSource: 'b96da308', imageBytes: 392, imageWords: 98
 },
 valid: {
  before: ['11','22','33','44','55','66','29'],
  after: ['11','22','33','44','55','66','2a'],
  selectedAddress: '0xffff000000df8318', result: 42
 },
 selectivity: {
  // Pair the same starting address at two widths; retained outcomes are unchanged.
  rows: [
   ['6 / 1', 'Last byte', 'permit', 'permit', 'permit'],
   ['6 / 2', 'Crosses bound', 'reject', 'permit', 'permit'],
   ['7 / 1', 'Padding', 'reject', 'permit', 'permit'],
   ['8 / 1', 'Next value', 'reject', 'reject', 'permit'],
   ['4 / 2', 'Interior', 'permit', 'permit', 'permit']
  ],
  operations: 30, permitted: 22, rejected: 8,
  fault: {case:3, instruction:'ldurb w8, [c2]', encoding:'e2000448',
   base:'0xffff000000c62f10', pc:'0xffff8000801c4780', offset:7, length:7, fsc:'0x2a'}
 },
 substitution: {
  observed: true, status: 'OBSERVED TRUSTED CONTROL',
  // Independent receipt: evidence/current/spatial-selectivity/substitution/results.json.
  rows: [['A','A','0x29'], ['B','B','0x87'], ['A','B','0x87']],
  instruction: 'ldurb w8, [c2]', encoding: 'e2000448', offset: 6, width: 1,
  length: 7, permissions: '0x30001', binding: [true, true, false],
  pc: '0xffff8000801c4b08', baseA: '0xffff000000c60f10', baseB: '0xffff000000c60f18'
 },
 ownership: {
  spill: 'str c19, [csp, #0]', reload: 'ldr c21, [csp, #0]',
  spillWord: 67, reloadWord: 79,
  failure: ['cmn x0, #1', 'b.ne ...', 'mov c14, c13', 'retr c14'],
  rejectPC: 17, epilogueWord: 117, normalStubWord: 116,
  skippedPCs: [19,20], acquisitions: 2, releases: 2, cleanupReleases: 1,
  reads: 1, baselineReferences: 1, negativeReturn: 0
 }
};
