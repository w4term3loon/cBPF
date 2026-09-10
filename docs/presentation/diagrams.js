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
${txt(0,34,'AArch64 register view','small','start')}${box(475,0,450,70,'`Xn` — 64-bit address','address')}
${wire('M700 75 V195')}${txt(665,155,'Overlapping view','small','end')}${txt(40,173,'Morello `Cn`','label','start')}
${box(25,200,450,106,'Metadata · 64 bits','cap','Encoded bounds, permissions, …')}${box(475,200,450,106,'Address · 64 bits','address','The low half is still `Xn`')}
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
 ${part('cap-check',box(375,105,345,130,'Capability checks','cap','Tag · bounds · permissions')+txt(547,261,'Applicable seal conditions also apply','tiny'))}
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
${wire('M810 148 V228')}${wire('M0 184 H1000','wire dash',false)}${txt(0,216,'KERNEL · LOAD TIME','small','start')}
${box(630,246,367,90,'Verifier','cap','Abstract state + interface rules')}${wire('M630 292 H554')}${box(293,246,255,90,'JIT compiler','block','Accepted bytecode')}${wire('M420 336 V468')}
${txt(290,387,'Install native program','small','end')}${wire('M815 336 V510')}${txt(960,387,'Interpreter alternative*','small','end')}
${wire('M0 411 H1000','wire dash',false)}${txt(0,445,'KERNEL · RUN TIME','small','start')}
${box(0,468,210,85,'Attached hook','block')}${wire('M210 510 H315')}${wire('M815 510 H670','wire',true)}
${txt(990,581,'*Where supported / configured','tiny','end')}</g><g data-program-anchor="ebpf">${box(320,468,350,80,'eBPF program','cap','Runs at a selected hook')}</g>`;}
function priorWork(){return `
${txt(0,34,'AEE · APPROXIMATION ENFORCED EXECUTION','title','start')}
${box(0,82,300,94,'Verifier approximation','soft')}${wire('M300 129 H359')}${box(365,82,300,94,'Runtime enforcement','cap')}${wire('M665 129 H725')}${box(731,82,263,94,'Covered effect','block')}
${txt(0,220,'Object granularity already exists; safety rules remain trusted.','small','start')}
${txt(0,321,'LEAF · MORELLO eBPF RFC','title','start')}
${box(0,371,390,102,'Native eBPF compartment','cap')}${wire('M390 422 H471')}${box(477,371,517,102,'Helper / kfunc boundary','block','Pointer authority + capability ABI')}
${txt(0,523,'Morello supplies isolation mechanisms; kernel interfaces need binding.','small','start')}
${txt(0,577,'cBPF narrows the question to two explicit interface permissions.','small','start')}`;}
function question(){return `
${txt(0,55,'ONE LOGICAL MAP VALUE','small','start')}${txt(0,104,'Logical value: `7` bytes; stride: `8` bytes','title','start')}
${txt(0,197,'TWO INDEPENDENT ACQUISITIONS','small','start')}${txt(0,246,'`A` and `B`: same object, separate rights','title','start')}
${wire('M0 318 H995','wire',false)}${txt(0,370,'OUR ROUTE','small','start')}
${box(0,415,285,104,'The Morello chip','cap','Pointers with restrictions')}${wire('M285 467 H354')}${box(360,415,275,104,'Linux + eBPF','block','Programs using resources')}${wire('M635 467 H704')}${box(710,415,285,104,'Two interface grants','soft','Value · acquisition')}`;}
function valueBytes(y=148){return Array.from({length:8},(_,i)=>rect(i*118,y,112,104,i<7?'cap':'address')+txt(i*118+56,y+44,String(i),'label code')+txt(i*118+56,y+78,i<7?'value':'pad','small')).join('');}
function spatialQuestion(){return `
${txt(0,35,'A LOOKUP SELECTS ONE LOGICAL VALUE','small','start')}
${wire('M0 118 V94 H938 V118','wire',false)}${txt(469,76,'Storage `stride = 8` bytes','label')}${valueBytes()}
${wire('M0 277 V301 H820 V277','cap-wire',false)}${txt(410,342,'Logical value = `7` bytes','title')}
${box(0,398,940,92,'Hypothetical constructor: `length = stride`','address')}
${txt(0,551,'Which part of this grant did the lookup never promise?','title','start')}`;}
function ownershipQuestion(){return `
${txt(0,33,'TWO ACQUIRES · ONE OBJECT','small','start')}
${box(0,90,278,100,'`A`','cap','First acquisition')}${box(357,90,278,100,'Copy of `A`','cap','Same acquired right')}${box(714,90,278,100,'`B`','soft','Independent acquisition')}
${wire('M278 140 H350','cap-wire')}${wire('M138 190 V266 H498 V314','wire')}${wire('M498 190 V266','wire',false)}${wire('M853 190 V266 H498','wire',false)}
${box(298,320,400,89,'Same live object','block','Same address and extent')}
${txt(0,486,'After a valid consume of `A`:','title','start')}${txt(0,530,'`A`’s alias must lose permission; `B` must retain its own.','label','start')}
${txt(0,584,'An object’s bounds cannot encode which acquisition was consumed.','small','start')}`;}
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
function codeSheet(leftTitle,left,rightTitle,right,note,emphasis={}){
 const panel=(x,title,lines,kind,focus=[])=>rect(x,48,830,394,kind)+txt(x+24,22,title,'title','start')+
  lines.map((line,i)=>(focus.includes(i)?rect(x+10,71+i*41,810,40,'snippet-focus'):'')+
   `<text x="${x+24}" y="${94+i*41}" class="snippet${focus.includes(i)?' emphasized':''}" xml:space="preserve">${highlightCode(line)}</text>`).join('');
 return panel(0,leftTitle,left,'soft',emphasis.left)+panel(920,rightTitle,right,'cap',emphasis.right)+
  wire('M846 245 H902','cap-wire')+txt(0,496,escapeText(note),'snippet-note','start');
}
const recordedSheets=Object.fromEntries(Object.entries(window.CBPF_RECORDED_PANELS).map(([id,args])=>[id,()=>codeSheet(...args)]));
function conclusion(){return `
${txt(0,30,'REUSABLE DECISION','small','start')}${txt(650,30,'OBLIGATION / COST','small','start')}
${rect(0,66,992,124,'soft')}${txt(24,109,'Use logical extent, not storage stride','label','start')}${txt(24,149,'Exact value authority → hardware bounds','small','start')}${txt(650,110,'Exact representability','small','start')}${txt(650,149,'Actual operand use','small','start')}
${rect(0,219,992,124,'soft')}${txt(24,262,'Use acquisition identity, not object address','label','start')}${txt(24,302,'Private validity → consume-once gate','small','start')}${txt(650,262,'Per-acquisition state','small','start')}${txt(650,301,'Full transport + mediation','small','start')}
${rect(0,372,992,124,'cap')}${txt(24,415,'Check the right at the covered effect','label','start')}${txt(24,455,'A shared design rule, two separate studies','small','start')}${txt(650,415,'Trusted assignment','small','start')}${txt(650,454,'Faithful translation','small','start')}
${txt(0,569,'A precise unit of permission makes the guarantee defensible.','title','start')}`;}
function findings(){return `
${txt(0,27,'PREPARATION IN LINUX','small','start')}
${box(0,56,260,70,'Verifier','block')}${wire('M260 90 H323')}${box(329,56,260,70,'JIT compiler','block')}${wire('M589 90 H652')}${box(658,56,334,70,'Prepared native code','block')}
${txt(0,183,'RUN TIME · SELECTED VALUE','small','start')}
${box(0,206,260,98,'Exact grant','cap','`[v, v + 7)`')}${wire('M260 255 H323','cap-wire')}${box(329,206,260,98,'Capability operand','cap')}${wire('M589 255 H652','cap-wire')}${box(658,206,334,98,'Core access checks','cap','Hardware bounds + permissions')}
${txt(0,362,'RUN TIME · ACQUIRED REFERENCE','small','start')}
${box(0,383,260,98,'Acquisition identity','soft','`A` differs from `B`')}${wire('M260 432 H323')}${box(329,383,260,98,'Full copies / spill','cap')}${wire('M589 432 H652')}${box(658,383,334,98,'Private validity gate','soft','Software before the effect')}
${rect(0,525,992,72,'outline')}${txt(496,553,'Morello core + tagged memory path','label')}${txt(496,581,'Capability integrity and transport support both bounded profiles.','small')}`;}

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
  const reg=box(260,30,430,85,'Capability registers','cap','Address · metadata · tag');
  const data=`${box(260,160,165,85,'Address','block','generation')}${box(460,160,230,85,'Load / store','cap','Capability checks')}${wire('M345 245 V300')}${wire('M425 202 H460')}${wire('M575 245 V300','cap-wire')}${wire('M425 340 H460')}${box(260,300,165,80,'TLB / MMU','block')}${box(460,300,230,80,'L1 data + tags','cap')}`;
  const regDetail=portal('registers','core',[266,34,418,77],t,reg,registers);
  const dataDetail=portal('checks','core',[253,153,444,234],t,data,checks);
  return `${box(15,30,195,85,'`PCC`','cap','`PC` + authority')}
   ${wire('M112 115 V160','cap-wire')}${wire('M580 115 V160','cap-wire')}${wire('M345 115 V160')}
   ${box(15,160,195,85,'Fetch / branch','cap','Execute + bounds')}
   ${wire('M112 245 V300')}${box(15,300,195,80,'L1 instruction','block')}
   ${wire('M112 380 V424 H345 V444','wire',false)}${wire('M575 380 V424 H345 V444')}
   ${box(15,445,675,55,'Private L2 cache · data + tags','cap')}${regDetail}${dataDetail}`;
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
   s+=box(x+20,265,425,28,'DSU · shared L3','cap')+wire(`M${x+122} 251 V265`,'cap-wire',false)+wire(`M${x+342} 251 V265`,'cap-wire',false)+link(`M${x+232} 304 V347`);
  });
  let mem=box(100,347,800,55,'CMN-Skeena · coherent interconnect','cap');
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
   ${box(0,584,1000,66,'Morello cores · caches · memory system','soft')}</g><g data-program-anchor="software">${cover}</g>`;
 }

 const origin={x:0,y:0,s:1}, sw={x:1440,y:0,s:1};
 plain('world',null,[-40,-50,2520,900],origin);
 plain('hardware','world',[-18,-8,1036,620],origin);
 plain('software','world',[-15,-10,1030,675],sw);
 const sheets={title:()=>'',question,ebpf:pipeline,'prior-work':priorWork,'spatial-question':spatialQuestion,'ownership-question':ownershipQuestion,...recordedSheets,findings,conclusion};
 const sheetTransform={x:2880,y:0,s:1};
 for(const id of Object.keys(sheets)){plain(id,'world',id in recordedSheets?[-15,-10,1780,550]:normal,sheetTransform);nodes[id].sheet=true;}
 const sheetMarkup=Object.entries(sheets).map(([id,draw])=>`<g data-sheet="${id}" transform="translate(2880 0)" style="display:none">${draw()}</g>`).join('');
 const markup=`<g data-scene="hardware">${hardware(origin)}</g>
  ${wire('M1020 310 H1210 V700 H1410','wire dash')}${txt(1210,275,'Execution platform','small')}
  <g data-scene="software" transform="translate(1440 0)">${software(sw)}</g>${sheetMarkup}`;
 return {markup,nodes};
}
window.CBPF_DIAGRAMS={defs,scene,inline};
})();
