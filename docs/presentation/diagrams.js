/* Editable functional diagrams. Coordinates express relationships, never silicon area. */
(() => {
'use strict';
const rect=(x,y,w,h,c='block')=>`<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="3" class="${c}"/>`;
// Backticks mark code notation in both diagram labels and slide prose.
const inline=(text,svg=false)=>text.replace(/`([^`]+)`/g,(_,code)=>svg?`<tspan class="code">${highlightCode(code)}</tspan>`:`<code>${highlightCode(code,false)}</code>`);
const txt=(x,y,t,c='label',a='middle')=>`<text x="${x}" y="${y}" class="${c}" text-anchor="${a}">${inline(t,true)}</text>`;
const box=(x,y,w,h,t,c='block',sub='')=>rect(x,y,w,h,c)+txt(x+w/2,y+h/2+(sub?-5:8),t)+ (sub?txt(x+w/2,y+h/2+23,sub,'small'):'');
const wire=(d,c='wire',arrow=true)=>`<path d="${d}" class="${c}" ${arrow?'marker-end="url(#arrow)"':''}/>`;
const link=d=>wire(d,'cap-wire').replace('marker-end=', 'marker-start="url(#arrow)" marker-end=');
const defs='<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10Z" fill="#73858a"/></marker><pattern id="padding" width="8" height="8" patternUnits="userSpaceOnUse"><path d="M0 8 L8 0" stroke="#b89166" stroke-width="1"/></pattern></defs>';
function registers(){return `
${txt(0,34,'AArch64 register view','small','start')}${box(475,0,450,70,'`Xn`: 64-bit address','address')}
${wire('M700 75 V195')}${txt(665,155,'Overlapping view','small','end')}${txt(40,173,'Morello `Cn`','label','start')}
${box(25,200,450,106,'Metadata: 64 bits','cap','Encoded bounds, permissions, …')}${box(475,200,450,106,'Address: 64 bits','address','The low half is still `Xn`')}
${rect(943,200,45,106,'tag')}${txt(965,261,'`T`','tag-text')}${txt(965,340,'Tag','small')}
${txt(475,348,'128-bit representation + 1 protected tag','label')}
${wire('M250 306 V401 H360','cap-wire')}${wire('M700 306 V401 H640')}${box(365,367,270,75,'`GetBounds`','cap','Decode using address')}
${wire('M500 442 V487','cap-wire')}${txt(500,520,'Reconstructed interval `[base, limit)`','title')}`;}
function checks(){
 const part=(name,body)=>`<g data-access-part="${name}">${body}</g>`;
 return `<g data-access-diagram>
 ${part('capability',box(0,35,255,80,'Metadata + tag','cap'))}
 ${part('address',box(0,350,255,80,'Address `a`, width `w`','address'))}
 ${part('inputs',wire('M255 75 H330 V145 H370','cap-wire')+wire('M255 390 H310 V204 H370')+wire('M310 390 H370'))}
 ${part('cap-check',box(375,105,345,130,'Capability checks','cap','Tag, bounds, permissions')+txt(547,261,'Applicable seal conditions also apply','tiny'))}
 ${part('page-check',box(375,340,345,105,'TLB / MMU','block','Translation + page permissions'))}
 ${part('join',wire('M720 170 H780 V280 H850','cap-wire')+wire('M720 392 H780 V280 H850'))}
 ${part('grant',box(855,225,140,110,'Access','accent','Both allow'))}
 <g data-load-detail hidden>${part('data',wire('M925 335 V400','cap-wire')+box(750,405,245,90,'Data byte','cap','Cache or memory'))}</g>
 ${part('bounds','<text id="access-rule" x="0" y="535" class="title code" text-anchor="start">base ≤ a  and  a + w ≤ limit</text><text id="access-rule-note" x="0" y="570" class="small" text-anchor="start">The complete byte interval must fit; arithmetic must not wrap.</text>')}
 </g>`;
}
function memory(){return `
${txt(0,31,'SAVE AND RESTORE THE SAME CAPABILITY','small','start')}
${[0,355,710].map((x,i)=>txt(x+140,102,i===1?'Memory slot':'Register','label')+rect(x,135,225,116,'cap')+txt(x+112,180,'Address','label')+txt(x+112,220,'Bounds + permissions','small')+rect(x+235,135,45,116,'tag')+txt(x+257,200,'1','tag-text code')+txt(x+257,280,'Tag','tiny')).join('')}
${wire('M283 194 H349','cap-wire')}${txt(316,173,'Store','small')}${wire('M638 194 H704','cap-wire')}${txt(671,173,'Load','small')}
${txt(0,315,'The full 128-bit representation and its validity tag survive.','small','start')}
${wire('M0 354 H990','wire',false)}${txt(0,395,'IF ORDINARY BYTES OVERWRITE THE SAVED SLOT','small','start')}
${rect(0,425,225,116,'address')}${txt(112,471,'Written bytes','label')}${txt(112,509,'Saved slot changed','small')}${rect(235,425,45,116,'soft')}${txt(257,490,'0','label code')}${txt(257,570,'Tag','tiny')}
${wire('M283 484 H424')}${txt(355,461,'Load','small')}${box(430,425,560,116,'No valid capability','address','Cannot authorize a memory access')}`;}
function pipeline(){return `<g data-program-context="ebpf">
${txt(0,27,'USERSPACE','small','start')}${box(0,56,220,92,'C source → LLVM','soft')}${wire('M220 102 H296')}${box(301,56,250,92,'eBPF bytecode','soft')}${wire('M551 102 H627')}${box(632,56,365,92,'Loader: `bpf()`','soft')}
${wire('M810 148 V228')}${wire('M0 184 H1000','wire dash',false)}${txt(0,216,'KERNEL AT LOAD TIME','small','start')}
${box(630,246,367,90,'Verifier','cap','Abstract state + interface rules')}${wire('M630 292 H554')}${box(293,246,255,90,'JIT compiler','block','Accepted bytecode')}${wire('M420 336 V468')}
${txt(290,387,'Install native program','small','end')}${wire('M815 336 V510')}${txt(960,387,'Interpreter alternative*','small','end')}
${wire('M0 411 H1000','wire dash',false)}${txt(0,445,'KERNEL AT RUN TIME','small','start')}
${box(0,468,210,85,'Attached hook','block')}${wire('M210 510 H315')}${wire('M815 510 H670','wire',true)}
${txt(990,581,'*Where supported / configured','tiny','end')}</g><g data-program-anchor="ebpf">${box(320,468,350,80,'eBPF program','cap','Runs at a selected hook')}</g>`;}
function priorWork(){return `
${txt(0,34,'AEE: APPROXIMATION ENFORCED EXECUTION','title','start')}
${box(0,82,300,94,'Verifier approximation','soft')}${wire('M300 129 H359')}${box(365,82,300,94,'Runtime enforcement','cap')}${wire('M665 129 H725')}${box(731,82,263,94,'Covered effect','block')}
${txt(0,220,'Object granularity already exists; safety rules remain trusted.','small','start')}
${txt(0,321,'LEAF: MORELLO eBPF RFC','title','start')}
${box(0,371,390,102,'Native eBPF compartment','cap')}${wire('M390 422 H471')}${box(477,371,517,102,'Helper / kfunc boundary','block','Pointer authority + capability ABI')}
${txt(0,523,'Morello supplies isolation mechanisms; kernel interfaces need binding.','small','start')}
${txt(0,577,'cBPF narrows the question to two explicit interface permissions.','small','start')}`;}
const escapeText=s=>s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
// Lexical color only: preserve the displayed excerpts and whitespace verbatim.
const codeTokens=/(?<comment>\/\*.*?\*\/|\/\/.*$)|(?<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|\b(?<register>[cxwr](?:[12]?\d|3[01])|csp|sp|czr|xzr|wzr|R\d+(?:_w)?|PCC|DDC)\b|\b(?<op>b\.ne|scvalue|scbndse|ldurb|sturb|ldrb|strb|ldr|str|umaddl|add|cmn|mov|retr|ret|blrs|call|exit|if|goto|return)\b|\b(?<type>unsigned|long|u64|u8|NULL|true|false)\b|\b(?<permit>permit)\b|\b(?<reject>reject)\b|\b(?<number>0x[0-9a-fA-F]+|[0-9a-f]{8}|\d+)\b|\b(?<function>(?:cheri|emit|bpf)_\w+|save_aux_ptr_type|finalize_bpf_jit_memory_roots|build_insn|[A-Za-z_]\w*(?=\())/g;
function highlightCode(source,svg=true){
 const tag=svg?'tspan':'span';
 let markup='',end=0;
 for(const token of source.matchAll(codeTokens)){
  const kind=Object.keys(token.groups).find(key=>token.groups[key]!==undefined);
  markup+=escapeText(source.slice(end,token.index))+`<${tag} class="syntax-${kind}">${escapeText(token[0])}</${tag}>`;
  end=token.index+token[0].length;
 }
 return markup+escapeText(source.slice(end));
}
// Each recorded view uses the visual structure of its subject, not a shared panel pair.
const R=window.CBPF_RECORDED;
const code=(x,y,line,c='snippet',a='start')=>'<text x="'+x+'" y="'+y+'" class="'+c+'" text-anchor="'+a+'" xml:space="preserve">'+highlightCode(line)+'</text>';
const codeLines=(x,y,lines,step=42,c='snippet')=>lines.map((line,i)=>code(x,y+i*step,line,c)).join('');
const rule=(y)=>wire('M0 '+y+' H1750','paper-line',false);
const heading=(x,y,t)=>txt(x,y,t,'research-label','start');
const sentence=(x,y,t,c='research-body',a='start')=>txt(x,y,t,c,a);
function question(){return [
 heading(0,55,'ONE LOGICAL MAP VALUE'),
 ...Array.from({length:8},(_,i)=>rect(i*94,122,86,100,i<7?'cap':'address')+code(i*94+43,184,i<7?String(i):'pad','research-byte','middle')),
 wire('M0 253 V275 H650 V253','cap-wire',false),
 sentence(325,325,'7 logical bytes','research-title','middle'),
 sentence(325,381,'8-byte storage stride','research-body','middle'),
 heading(1010,55,'TWO INDEPENDENT ACQUISITIONS'),
 code(1120,180,'A','research-symbol','middle'),code(1560,180,'B','research-symbol','middle'),
 wire('M1120 204 V270 H1340 V305','cap-wire'),wire('M1560 204 V270 H1340','cap-wire',false),
 box(1100,310,480,86,'One live object','soft'),
 sentence(1340,459,'Consume A, preserve B','research-title','middle')
].join('');}
function spatialQuestion(){return [
 heading(0,35,'ORIGINAL VERIFIER FAILURE'),
 sentence(0,106,'ALU32 bitwise operations','research-title'),
 sentence(0,154,'AND, OR, XOR','research-body'),
 wire('M505 112 H599'),
 sentence(635,106,'Incorrect bounds','research-title'),
 wire('M1035 112 H1140'),
 sentence(1170,106,'Out-of-bounds access','research-title'),
 sentence(1170,154,'Kernel memory','research-body'),
 rule(214),
 heading(0,264,'ARCHIVED cBPF METADATA-READ STAGE'),
 heading(0,321,'RETURNED AUTHORITY'),heading(1080,321,'RECORDED OUTCOME'),
 sentence(0,380,'Exact selected value','research-title'),
 sentence(1080,380,'Bounds fault','research-title research-reject'),
 wire('M0 411 H1750','paper-line',false),
 sentence(0,464,'Whole allocation','research-title'),
 sentence(1080,464,'Read completes','research-title mint')
].join('');}
function ownershipQuestion(){return [
 heading(0,33,'PUBLISHED CALLBACK FAILURE'),
 sentence(0,112,'Verifier accounts for','research-body'),
 sentence(0,158,'one invocation','research-title'),
 code(650,144,'release(A)','research-code'),
 sentence(0,282,'Helper can invoke','research-body'),
 sentence(0,328,'the callback again','research-title'),
 code(650,310,'release(A)','research-code'),
 wire('M945 293 H1128','wire'),
 code(1170,310,'release(A)','research-code'),
 sentence(1210,362,'same caller-owned right','research-body research-reject'),
 rule(408),
 heading(0,453,'PROJECTED cBPF QUESTION'),
 sentence(0,508,'Consume A once','research-title'),
 sentence(625,508,'Reject every A alias','research-title research-reject'),
 sentence(1230,508,'Keep B usable','research-title mint')
].join('');}
function spatialInput(){return [
 heading(0,30,'RECORDED BPF'),
 rect(0,170,778,47,'snippet-focus'),rect(0,258,778,47,'snippet-focus'),
 codeLines(18,110,R.input.bpf,44,'research-code'),
 heading(990,30,'TWO ARRAY VALUES'),
 code(990,87,'value_size = 7','research-code'),
 code(1410,87,'stride = 8','research-code'),
 ...[0,1].map((key)=>sentence(895,185+key*139,'Key '+key,'research-body')+
  Array.from({length:8},(_,i)=>rect(990+i*94,128+key*139,86,92,i===7?'address':key===1?'cap':'soft')+
   code(1033+i*94,184+key*139,i<7?String(i):'pad','research-byte','middle')).join('')),
 wire('M990 380 V398 H1634 V380','cap-wire',false),
 sentence(1312,447,'Selected logical value','research-title','middle'),
 wire('M1597 473 V367','cap-wire'),
 sentence(1694,491,'Byte 6','research-body','end')
].join('');}
function spatialAnalysis(){return [
 heading(0,30,'OBSERVED VERIFIER STATE'),
 code(875,105,R.analysis.nullable,'research-code','middle'),
 code(875,188,R.analysis.branch,'research-code','middle'),
 wire('M875 215 V252 H320 V312','wire'),
 wire('M875 252 H1235 V312','cap-wire'),
 sentence(275,297,'NULL','research-label','end'),
 sentence(1280,297,'NON-NULL','research-label','start'),
 code(320,372,'R0 = 0','research-code','middle'),
 sentence(320,438,'Return zero','research-title','middle'),
 codeLines(970,368,R.analysis.refined,41,'research-code'),
 code(970,468,R.analysis.access,'research-code'),
 sentence(970,519,'1 byte at offset 6 fits [0, 7)','research-body mint')
].join('');}
function spatialHandoff(){return [
 heading(0,27,'VERIFIER SUMMARY: SUPPORTED ROOT PROFILE'),
 code(0,92,'save_aux_ptr_type','research-code-small'),
 code(0,132,'finalize_bpf_jit_memory_roots','research-code-small'),
 wire('M510 105 H585'),
 code(620,92,'prog->aux->jit_memory_roots','research-code-small'),
 sentence(620,132,'Contract version and validity','research-body'),
 wire('M1110 105 H1190'),
 code(1230,92,'bpf_jit_validate_prog','research-code-small'),
 sentence(1230,132,'Checks the supported profile','research-body'),
 wire('M930 156 V204','wire dash',false),
 sentence(972,195,'Root sets must agree','research-body'),
 rule(221),
 heading(0,267,'SEPARATE JIT ANALYSIS: INSTRUCTION SELECTION'),
 code(0,329,'bpf_cheri_build_authority','research-code-small'),
 wire('M510 320 H585'),
 code(620,329,'ctx.authority[pc].regs[r].kind','research-code-small'),
 wire('M1163 320 H1198'),
 code(1230,329,'build_insn','research-code-small'),
 sentence(1230,370,'Capability moves and accesses','research-body'),
 rule(403),
 heading(0,449,'RUNTIME: LOGICAL EXTENT'),
 code(0,505,'map->value_size','research-code'),
 wire('M490 492 H800','cap-wire'),
 code(855,505,'cheri_bounds_set_exact','research-code')
].join('');}
function spatialBinding(){return [
 heading(0,26,'ACTUAL PROVIDER C'),heading(1035,26,'EXTRACTED LINKED INSTRUCTIONS'),
 codeLines(0,86,R.construction.selection,37,'research-code-small'),
 code(1035,87,R.construction.native[0][1],'research-code'),
 sentence(960,87,R.construction.native[0][0],'research-detail','end'),
 code(1035,172,R.construction.native[1][1],'research-code'),
 sentence(960,172,R.construction.native[1][0],'research-detail','end'),
 rule(224),
 code(0,291,R.construction.addressSet,'research-code-small'),
 wire('M815 280 H870','cap-wire'),
 code(1035,291,R.construction.native[2][1],'research-code'),
 sentence(960,291,R.construction.native[2][0],'research-detail','end'),
 rule(329),
 codeLines(0,389,R.construction.boundsSet,37,'research-code-small'),
 wire('M815 397 H870','cap-wire'),
 code(1035,410,R.construction.native[3][1],'research-code'),
 sentence(960,410,R.construction.native[3][0],'research-detail','end'),
 rule(457),
 code(0,513,'c7','research-code'),sentence(65,513,'retained root','research-body'),
 code(400,513,'x6','research-code'),sentence(465,513,'stride-selected address','research-body'),
 code(970,513,'x3','research-code'),code(1035,513,'map->value_size','research-code-small'),
 code(1430,513,'c1','research-code'),sentence(1495,513,'value capability','research-body')
].join('');}
function spatialTransport(){return [
 heading(0,31,'INHERITED HYBRID GATEWAY'),
 sentence(0,126,'Provider result','research-body'),
 code(155,239,'c0','research-symbol','middle'),
 wire('M330 205 H528','cap-wire'),
 code(895,238,R.transport.instruction,'research-native','middle'),
 wire('M1260 205 H1445','cap-wire'),
 code(1600,239,'c7','research-symbol','middle'),
 sentence(1600,126,'Native BPF R0','research-body','middle'),
 sentence(895,308,'Extracted native word 72','research-body','middle'),
 sentence(895,372,'Address, bounds, permissions and tag stay together','research-title','middle'),
 rule(425),
 heading(0,478,'JIT SOURCE'),
 code(435,487,R.transport.source,'research-code')
].join('');}
function spatialNative(){return [
 heading(0,29,'EXTRACTED FROM THE KEY-ONE NATIVE IMAGE'),
 ...R.native.extracted.map((row,i)=>heading(0,108+i*119,'WORD '+row.word)+
  code(0,150+i*119,row.encoding,'research-code-small')+
  code(420,135+i*119,row.instruction,'research-native')),
 wire('M660 276 V300 H620 V320','wire',false),sentence(620,357,'Scalar data','research-body','middle'),
 wire('M823 276 V320','cap-wire',false),sentence(823,357,'Capability','research-body mint','middle'),
 wire('M960 276 V302 H1085 V320','wire',false),sentence(1085,357,'Offset 6','research-body','middle'),
 sentence(1480,147,'1-byte load','research-title','middle'),
 sentence(1480,266,'1-byte store','research-title','middle'),
 rule(405),
 heading(0,453,'ILLUSTRATIVE ARM64 BASELINE'),
 code(0,515,R.native.illustrative[0],'research-code'),
 code(940,515,R.native.illustrative[1],'research-code')
].join('');}
function spatialEvidence(){return [
 heading(0,30,'RECORDED HEX BYTES'),
 ...Array.from({length:7},(_,i)=>sentence(265+i*145,101,String(i),'research-detail','middle')),
 sentence(0,197,'Before','research-body'),sentence(0,343,'After','research-body'),
 rect(1069,126,132,254,'snippet-focus'),
 ...R.valid.before.map((b,i)=>code(265+i*145,201,b,'research-hex'+(i===6?' mint':''),'middle')),
 ...R.valid.after.map((b,i)=>code(265+i*145,347,b,'research-hex'+(i===6?' mint':''),'middle')),
 wire('M1135 221 V288','cap-wire'),
 sentence(1217,270,'+1','research-body mint'),
 wire('M211 405 V425 H1048 V405','wire',false),
 sentence(630,478,'Six bytes unchanged','research-title','middle'),
 sentence(1530,101,'RETURN AND READBACK','research-label','middle'),
 code(1530,309,String(R.valid.result),'research-result','middle'),
 sentence(1530,407,'One TEST_RUN','research-body','middle')
].join('');}
function spatialRejection(){return [
 heading(0,30,'OFFSET / WIDTH'),heading(500,30,'EXACT 7'),heading(690,30,'STRIDE 8'),heading(880,30,'BOTH 16'),
 rect(0,65,1085,108,'snippet-focus'),
 ...R.selectivity.rows.map((row,i)=>code(18,108+i*55,row[0],'research-code')+
  sentence(166,108+i*55,row[1],'research-body')+
  row.slice(2).map((outcome,j)=>sentence(500+j*190,108+i*55,outcome,'research-body '+(outcome==='reject'?'research-reject':'mint'))).join('')),
 sentence(0,383,'30 accesses: 22 permits, 8 faults','research-detail'),
 heading(580,383,'16 = WHOLE VALUE STORAGE'),
 wire('M1120 0 V395','paper-line',false),
 heading(1170,30,R.substitution.status),
 heading(1170,85,'INTENT'),heading(1370,85,'OPERAND'),heading(1620,85,'BYTE'),
 rect(1160,224,590,53,'snippet-focus'),
 ...R.substitution.rows.map((row,i)=>row.map((value,j)=>
  code([1210,1430,1620][j],140+i*60,value,'research-code'+(i===2?' research-reject':''))).join('')),
 sentence(1170,317,'A intended, exact B used','research-body research-reject'),
 sentence(1170,373,R.substitution.observed?'All three loads permitted':'Expected: all three permit','research-body'),
 rule(411),
 heading(0,453,'RECORDED PADDING FAULT'),
 code(520,453,R.selectivity.fault.instruction,'research-code'),
 sentence(900,453,'FSC 0x2a','research-body research-reject'),
 sentence(0,512,'Sentinel and all 16 fixture bytes unchanged','research-body'),
 heading(1170,453,'B OPERAND AT BYTE SIX'),
 code(1170,507,R.substitution.instruction,'research-code'),
 sentence(1530,507,'fits B','research-body mint')
].join('');}
function ownershipBinding(){return [
 heading(0,29,'EXTRACTED FULL-CAPABILITY ALIAS TRANSPORT'),
 code(0,105,R.ownership.spill,'research-code'),
 wire('M490 92 H730','cap-wire'),
 code(775,105,R.ownership.reload,'research-code'),
 sentence(0,162,'Words 67 and 79 use a 16-byte sidecar','research-body'),
 sentence(990,162,'Public A stays tagged and canonical','research-body mint'),
 rule(205),
 heading(0,266,'PRIVATE STATE'),
 sentence(655,260,'Acquire A and B','research-title','middle'),
 sentence(1090,260,'Consume A','research-title','middle'),
 sentence(1520,260,'Read B','research-title','middle'),
 wire('M675 281 H1060','wire'),wire('M1110 281 H1490','wire'),
 sentence(0,352,'A','research-title'),
 sentence(655,352,'live','research-title mint','middle'),
 sentence(1090,352,'cleared','research-title research-reject','middle'),
 sentence(1520,352,'cleared','research-title research-reject','middle'),
 sentence(0,433,'B','research-title'),
 sentence(655,433,'live','research-title mint','middle'),
 sentence(1090,433,'live','research-title mint','middle'),
 sentence(1520,433,'42 at PC 13','research-title mint','middle'),
 sentence(0,512,'Reference count','research-body'),
 code(655,512,'3','research-code','middle'),code(1090,512,'2','research-code','middle'),code(1520,512,'2','research-code','middle'),
 sentence(1090,308,'clear before decrement','research-detail','middle')
].join('');}
function ownershipEvidence(){return [
 heading(0,30,'SOFTWARE OWNERSHIP REJECTION'),
 sentence(0,119,'Reject consumed A','research-emphasis research-reject'),
 sentence(0,183,'PC 17, before the stale effect','research-body'),
 wire('M500 115 H600','wire'),
 sentence(640,119,'Skip continuation','research-emphasis'),
 sentence(640,183,'PC 19 and PC 20 do not run','research-body'),
 wire('M1140 115 H1238','wire'),
 sentence(1278,119,'Clean B once','research-emphasis mint'),
 sentence(1278,183,'Wrapper restores refs = 1','research-body'),
 rule(233),
 heading(0,283,'FAILURE PATH, AFTER SAVED-STATE RESTORATION'),
 code(0,353,R.ownership.failure[0],'research-code'),
 code(0,399,R.ownership.failure[1],'research-code-small'),
 code(460,353,R.ownership.failure[2],'research-code'),
 sentence(460,408,'Omitted: zero result, restore c30,','research-detail'),
 sentence(460,443,'clear scratch registers','research-detail'),
 code(1100,353,R.ownership.failure[3],'research-code'),
 wire('M1310 340 H1434','cap-wire'),
 sentence(1470,329,'Executive epilogue','research-body'),
 sentence(1470,373,'word 117','research-title mint'),
 sentence(1470,426,'Scrub sidecar','research-detail'),
 sentence(1470,461,'and registers','research-detail'),
 sentence(0,511,'Normal exit uses the restricted ret c30 stub at word 116','research-body'),
 sentence(1430,511,'2 acquired, 2 released','research-body','middle')
].join('');}
function releaseEligibility(){return [
 heading(0,30,'SAME A, SAME LIVE STATE'),
 heading(0,117,'REQUEST CONTEXT'),heading(760,117,'IDENTITY'),heading(1070,117,'LIVE'),heading(1340,117,'MAY RELEASE'),
 rule(151),
 sentence(0,231,'Owning caller F0','research-title'),
 code(800,231,'A','research-code'),sentence(1100,231,'yes','research-body'),
 sentence(1370,231,'permit','research-title mint'),
 rule(272),
 sentence(0,351,'Borrowing callback F1','research-title'),
 code(800,351,'A','research-code'),sentence(1100,351,'yes','research-body'),
 sentence(1370,351,'reject first release','research-title research-reject'),
 rule(402),
 sentence(0,467,'cBPF tracks whether A was consumed','research-title'),
 sentence(0,521,'The upstream repair also needs callback ownership and local-leak checks','research-body')
].join('');}
function implementationScope(){return [
 heading(0,28,'SPATIAL PROVIDER AND INTEGRATION'),heading(980,28,'OWNERSHIP CORE'),
 sentence(0,145,'+193 / −1','research-stat'),
 sentence(980,145,'≈ 841','research-stat'),
 sentence(0,210,'Changed lines across 5 paths','research-title'),
 sentence(980,210,'Physical lines, 25 C functions and gateway','research-body'),
 code(0,269,'base e6c69574','research-code-small'),
 code(980,269,'base b96da308','research-code-small'),
 rule(322),
 heading(0,381,'INHERITED'),
 sentence(345,381,'Spatial JIT and platform, ownership platform extraction (+51 / −24)','research-body'),
 heading(0,456,'SUPPORTING WORK'),
 sentence(345,456,'Fixtures, recovery, validation, packaging and evidence copies excluded','research-body'),
 sentence(0,520,'Comments and blank lines included, mixed spans classified, canonical sources counted once','research-detail')
].join('');}
function findings(){return [
 heading(0,26,'DISTINCTION'),heading(720,26,'REQUIRED REPRESENTATION'),heading(1430,26,'SUPPORT'),
 ...[
  ['Storage stride','Logical extent'],
  ['Object address','Acquisition identity'],
  ['Public identity','Current private validity'],
  ['One rejected operation','Termination and cleanup']
 ].map(([left,right],i)=>code(0,119+i*117,String(i+1).padStart(2,'0'),'research-code-small')+
  sentence(92,119+i*117,left,'research-title')+
  sentence(624,119+i*117,'≠','research-title','middle')+
  sentence(720,119+i*117,right,'research-title mint')+
  (i<3?wire('M0 '+(157+i*117)+' H1340','paper-line',false):'')),
 sentence(1430,107,'Spatial matrix','research-body'),
 sentence(1430,150,'30 observations','research-detail'),
 wire('M1380 204 V511','paper-line',false),
 sentence(1430,325,'Shared ownership','research-body'),
 sentence(1430,368,'controls','research-body')
].join('');}
function conclusion(){return [
 heading(0,31,'SPATIAL'),
 sentence(0,115,'The selected value sets the authority','research-emphasis'),
 sentence(0,173,'Valid native use and selective bounds rejection','research-body'),
 rule(238),
 heading(0,296,'OWNERSHIP'),
 sentence(0,380,'Each acquisition keeps its own validity','research-emphasis'),
 sentence(0,438,'Consumed A rejects, continuation stops, cleanup releases B once','research-body'),
 sentence(0,525,'Hardware protects authority while software assigns and maintains the right','research-title mint')
].join('');}
const recordedSheets={
 'spatial-input':spatialInput,'spatial-analysis':spatialAnalysis,
 'spatial-handoff':spatialHandoff,'spatial-binding':spatialBinding,
 'spatial-transport':spatialTransport,'spatial-native':spatialNative,
 'spatial-evidence':spatialEvidence,'spatial-rejection':spatialRejection,
 'ownership-binding':ownershipBinding,'ownership-evidence':ownershipEvidence,
 'release-eligibility':releaseEligibility,'implementation-scope':implementationScope
};

function scene(){
 const normal=[-15,-10,1030,620], nodes={};
 const frame=(t,r)=>[t.x+t.s*r[0],t.y+t.s*r[1],t.s*r[2],t.s*r[3]];
 const plain=(id,parent,r,t)=>{nodes[id]={id,parent,frame:frame(t,r),portal:false};};
 function portal(id,parent,slot,t,cover,draw,view=normal){
  const scale=Math.min(slot[2]/view[2],slot[3]/view[3]);
  const x=slot[0]+(slot[2]-view[2]*scale)/2-view[0]*scale;
  const y=slot[1]+(slot[3]-view[3]*scale)/2-view[1]*scale;
  const child={x:t.x+t.s*x,y:t.y+t.s*y,s:t.s*scale};
  nodes[id]={id,parent,frame:frame(child,view),portal:true};
  return `<g data-portal="${id}"><g data-cover="${id}">${cover}</g><g data-detail="${id}" opacity="0">${rect(...slot,'detail-ground')}<g transform="translate(${x} ${y}) scale(${scale})">${draw(child)}</g></g></g>`;
 }
 function coreScene(t){
  const reg=box(260,30,430,85,'Capability registers','cap','Address, metadata, tag');
  const data=`${box(260,160,165,85,'Address','block','generation')}${box(460,160,230,85,'Load / store','cap','Capability checks')}${wire('M345 245 V300')}${wire('M425 202 H460')}${wire('M575 245 V300','cap-wire')}${wire('M425 340 H460')}${box(260,300,165,80,'TLB / MMU','block')}${box(460,300,230,80,'L1 data + tags','cap')}`;
  const regDetail=portal('registers','core',[266,34,418,77],t,reg,registers);
  const dataDetail=portal('checks','core',[253,153,444,234],t,data,checks);
  return `${box(15,30,195,85,'`PCC`','cap','`PC` + authority')}
   ${wire('M112 115 V160','cap-wire')}${wire('M580 115 V160','cap-wire')}${wire('M345 115 V160')}
   ${box(15,160,195,85,'Fetch / branch','cap','Execute + bounds')}
   ${wire('M112 245 V300')}${box(15,300,195,80,'L1 instruction','block')}
   ${wire('M112 380 V424 H345 V444','wire',false)}${wire('M575 380 V424 H345 V444')}
   ${box(15,445,675,55,'Private L2 cache with tags','cap')}${regDetail}${dataDetail}`;
 }
 function hardware(t){
  let s=rect(0,0,1000,509,'outline')+txt(20,31,'MORELLO SoC','small','start');
  [20,515].forEach((x,k)=>{
   s+=rect(x,55,465,249,'soft')+txt(x+18,84,`Rainier cluster ${k}`,'label','start');
   [0,1].forEach(j=>{
    const cx=x+20+j*220;
    const cover=rect(cx,105,205,146,'cap')+txt(cx+102,148,`Core ${k*2+j}`)+txt(cx+102,180,'L1 I + D','small')+rect(cx+10,204,185,35,'soft')+txt(cx+102,228,'Private L2','small');
    s+=k===0&&j===0?portal('core','hardware',[cx+3,108,199,140],t,cover,coreScene,[0,0,720,520]):cover;
   });
   s+=box(x+20,265,425,28,'DSU shared L3','cap')+wire(`M${x+122} 251 V265`,'cap-wire',false)+wire(`M${x+342} 251 V265`,'cap-wire',false)+link(`M${x+232} 304 V347`);
  });
  let mem=box(100,347,800,55,'CMN-Skeena coherent interconnect','cap');
  [110,630].forEach(x=>{mem+=link(`M${x+130} 402 V435`)+box(x,435,260,55,'DMC-Bing','cap')+link(`M${x+130} 490 V544`)+box(x,544,260,53,'External DDR4','block');});
  return s+portal('memory','hardware',[95,337,810,262],t,mem,memory);
 }
 function software(t){
  plain('linux','software',[0,185,1000,345],t);
  const cover=box(620,410,350,80,'eBPF program','cap','Runs at a selected hook');
  return `<g data-program-context="software">${txt(20,24,'USERSPACE','small','start')}
   ${box(25,45,330,75,'Application','soft','Own virtual address space')}${box(565,45,410,75,'BPF loader / control tool','soft')}
   ${wire('M190 120 V185')}${wire('M770 120 V185')}${txt(250,160,'System calls cross a privilege boundary','small','start')}
   ${rect(0,185,1000,345,'outline')}${txt(25,221,'LINUX KERNEL','small','start')}
   ${box(25,267,265,90,'Processes + memory','block')}${box(330,267,250,90,'Files + devices','block')}${box(620,267,350,90,'Networking + tracing','block')}
   ${wire('M795 357 V405','cap-wire')}${txt(770,392,'Selected hook','small','end')}
   ${txt(30,435,'Privileged kernel execution','label','start')}${txt(30,474,'Admission and access policy still matter.','small','start')}
   ${wire('M500 530 V579')}${txt(535,566,'Machine instructions','small','start')}
   ${box(0,584,1000,66,'Morello cores, caches and memory','soft')}</g><g data-program-anchor="software">${cover}</g>`;
 }

 const origin={x:0,y:0,s:1}, sw={x:1440,y:0,s:1};
 plain('world',null,[-40,-50,2520,900],origin);
 plain('hardware','world',[-18,-8,1036,620],origin);
 plain('software','world',[-15,-10,1030,675],sw);
 const sheets={title:()=>'',question,ebpf:pipeline,'prior-work':priorWork,'spatial-question':spatialQuestion,'ownership-question':ownershipQuestion,...recordedSheets,findings,conclusion};
 const sheetTransform={x:2880,y:0,s:1};
 for(const id of Object.keys(sheets)){plain(id,'world',id in recordedSheets||['question','spatial-question','ownership-question','findings','conclusion'].includes(id)?[-15,-10,1780,550]:normal,sheetTransform);nodes[id].sheet=true;}
 const sheetMarkup=Object.entries(sheets).map(([id,draw])=>`<g data-sheet="${id}" transform="translate(2880 0)" style="display:none">${draw()}</g>`).join('');
 const markup=`<g data-scene="hardware">${hardware(origin)}</g>
  ${wire('M1020 310 H1210 V700 H1410','wire dash')}${txt(1210,275,'Execution platform','small')}
  <g data-scene="software" transform="translate(1440 0)">${software(sw)}</g>${sheetMarkup}`;
 return {markup,nodes};
}
window.CBPF_DIAGRAMS={defs,scene,inline};
})();
