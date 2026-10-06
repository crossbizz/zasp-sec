import pathlib,hashlib
p=pathlib.Path('/workspace/zasp-sec/services/platform/migrations/tools');original=(p/'build-ordered-current-development.mjs').read_text();text=original
text=text.replace("import fs from 'node:fs';","import fs from 'node:fs';\nimport {readOrderedCurrentLinuxProvenanceV1,linuxProvenanceInputSHA256} from './ordered-current-linux-provenance-v1.mjs';\nimport {admitOrderedCurrentNative379PacketV2} from './ordered-current-native379-packet-v2.mjs';")
text=text.replace('const built=buildManifest({format:1',"const linuxProvenance=readOrderedCurrentLinuxProvenanceV1();\nconst historicalGenerator=fs.readFileSync(new URL('./build-ordered-current-development.mjs',import.meta.url));\nif(sha(historicalGenerator)!=='"+hashlib.sha256(original.encode()).hexdigest()+"')throw Error('Linux successor historical generator source drift');\nconst sourceRelease={format:1",1)
text=text.replace('postgres:supplement.provenance.postgres,pgcrypto:supplement.provenance.pgcrypto,','postgres:linuxProvenance.identity.version,pgcrypto:linuxProvenance.identity.pgcrypto,',1)
text=text.replace("generatorSHA256:sha(fs.readFileSync(new URL(import.meta.url))),moduleSHA256:withCurrentBuildSourceInventory({","generatorSHA256:sha(fs.readFileSync(new URL(import.meta.url))),moduleSHA256:withCurrentBuildSourceInventory({\n    'ordered-current-linux-provenance-v1.json':linuxProvenanceInputSHA256,\n    'ordered-current-linux-provenance-v1.mjs':sha(fs.readFileSync(new URL('./ordered-current-linux-provenance-v1.mjs',import.meta.url))),",1)
text=text.replace('facts,entries:[]});',"facts,entries:[]};\nconst baselineModules=Object.fromEntries(Object.entries(sourceRelease.moduleSHA256).filter(([name])=>!['ordered-current-linux-provenance-v1.json','ordered-current-linux-provenance-v1.mjs'].includes(name)));\nconst baselineBuilt=buildManifest({...sourceRelease,postgres:supplement.provenance.postgres,pgcrypto:supplement.provenance.pgcrypto,generatorSHA256:sha(historicalGenerator),moduleSHA256:baselineModules});\nconst built=buildManifest(sourceRelease);",1)
text=text.replace("const outputs=[","checkpoint.linuxSuccessor={format:'ordered-current-linux-successor-v1',status:'SOURCE-PROVENANCE-ONLY',installable:false,nativeVerified:false,expectedFromTarget:false,descriptorSHA256:linuxProvenanceInputSHA256,identitySHA256:linuxProvenance.evidence.identitySHA256,observedVersion:linuxProvenance.identity.version,historicalReferenceVersion:supplement.provenance.postgres};\nconst outputs=[",1)
# Only output URLs are namespaced. Every historical input URL remains exact.
a=text.index('const outputs=[');b=text.index('const privateOutputs=[',a);text=text[:a]+text[a:b].replace("new URL('ordered_current/","new URL('ordered_current/linux-successor-v1/")+text[b:]
text=text.replace("!['--write','--check','--write-private-reference','--check-private-reference'].includes(process.argv[2])","!['--write','--check'].includes(process.argv[2])")
text=text.replace("process.argv[2].endsWith('-private-reference')?privateOutputs:outputs","outputs")
extra=r'''
// These APIs return source-only proposals. They never admit a runtime packet.
export function buildOrderedCurrentLinuxSuccessorV1(){
 if(arguments.length!==0)throw Error('Linux successor caller authority refused');
 readOrderedCurrentLinuxProvenanceV1();
 return structuredClone({format:'ordered-current-linux-successor-v1',installable:false,nativeVerified:false,expectedFromTarget:false,manifest:built,facts:built.facts,outputs:Object.fromEntries(outputs.map(([url,value])=>[url.pathname.split('/').at(-1),value]))});
}
let fullDelta;
export function analyzeOrderedCurrentLinuxSuccessorV1(){
 if(arguments.length!==0)throw Error('Linux successor borrowed baseline refused');
 readOrderedCurrentLinuxProvenanceV1();
 if(fullDelta)return structuredClone(fullDelta);
 const oldFacts=new Map(baselineBuilt.facts.map(f=>[canonicalOrderedJSON([f.kind,f.identity]),f]));
 const newFacts=new Map(built.facts.map(f=>[canonicalOrderedJSON([f.kind,f.identity]),f]));
 const changed=[],added=[],removed=[];
 for(const [key,next]of newFacts){const before=oldFacts.get(key);if(!before)added.push(next);else if(canonicalOrderedJSON(before)!==canonicalOrderedJSON(next))changed.push({kind:next.kind,identity:next.identity,beforeSHA256:sha(canonicalOrderedJSON(before)),afterSHA256:sha(canonicalOrderedJSON(next)),before:before.fact,after:next.fact});}
 for(const [key,before]of oldFacts)if(!newFacts.has(key))removed.push(before);
 const expected=(value)=>value.facts.map(r=>'('+[literal(r.kind),literal(r.identity),literal(canonicalOrderedJSON(r.fact))+'::jsonb'].join(',')+')').join(',\n');
 const assemble=(value)=>sql.replace('-- ordered-current:embedded-expectations',()=> 'INSERT INTO zasp_authorization80_ordered_current.registration(singleton,format_version,profile_checksum,manifest_sha256) VALUES(true,1,'+literal(compiled.checksum)+','+literal(value.payloadSHA256)+');\n'+'INSERT INTO zasp_authorization80_ordered_current.expected(kind,identity,fact) VALUES\n'+expected(value)+';');
 const baselineModule=assemble(baselineBuilt),nextModule=assemble(built);
 // The v2 packet is independently source-regenerated under its original pins.
 // We enumerate all original programs and literal impacts, not a v3 admission.
 const packet=admitOrderedCurrentNative379PacketV2();
 if(packet.controls.length!==589||packet.controls.reduce((n,c)=>n+c.program.steps.length,0)!==6348||canonicalOrderedJSON(packet.expectedFacts)!==canonicalOrderedJSON(baselineBuilt.facts))throw Error('Linux successor complete baseline packet mismatch');
 const substitutions=[{kind:'manifest-payload',before:baselineBuilt.payloadSHA256,after:built.payloadSHA256}];
 const programs=packet.controls.map(c=>({id:c.id,phase:c.phase,stepCount:c.program.steps.length,programSHA256:sha(canonicalOrderedJSON(c.program)),steps:c.program.steps.map((step,index)=>{
  let proposed=step.sql;const spans=[];
  for(const sub of substitutions){let at=0;while((at=step.sql.indexOf(sub.before,at))>=0){spans.push({kind:sub.kind,start:at,end:at+sub.before.length,beforeSHA256:sha(sub.before),afterSHA256:sha(sub.after)});at+=sub.before.length;}proposed=proposed.replaceAll(sub.before,sub.after);}
  return {index,id:step.id,role:step.role,expectedSHA256:sha(canonicalOrderedJSON(step.expected)),beforeSQLSHA256:sha(step.sql),proposedSQLSHA256:sha(proposed),literalSpans:spans};
 })}));
 const guard="IF provenance->>'postgres' IS DISTINCT FROM pg_catalog.version() THEN RETURN false; END IF;";
 if(!baselineModule.includes(guard)||!nextModule.includes(guard))throw Error('Linux successor exact guard changed');
 fullDelta={format:'ordered-current-linux-successor-delta-v1',observations:'source-derived-delta-only; no SQL execution or runtime packet admission',baselineFacts:baselineBuilt.facts.length,successorFacts:built.facts.length,added,removed,changed,functionalFactsEqual:added.length===0&&removed.length===0&&changed.every(f=>f.kind==='build'&&f.identity==='provenance'),baselineManifestSHA256:baselineBuilt.fileSHA256,successorManifestSHA256:built.fileSHA256,baselineModuleSHA256:sha(baselineModule),successorModuleSHA256:sha(nextModule),guardSameBytes:true,guardSHA256:sha(guard),privateRoutineDefinitions:privateClosure.facts.filter(f=>f.kind==='routine').map(f=>({identity:f.identity,beforeSHA256:sha(canonicalOrderedJSON(f)),afterSHA256:sha(canonicalOrderedJSON(f)),sameBytes:true})),rules:packet.rules.length,sites:packet.rules.reduce((n,r)=>n+r.sites.length,0),controlCount:programs.length,stepCount:programs.reduce((n,c)=>n+c.stepCount,0),programs,programMeaning:'Complete original source-derived589/6348; only enumerated manifest literal substitution proposals, not complete successor runtime control compilation. Every expectation/role/program identity retained. Later versioned packet must independently recompile all dependent metadata/preimages and compare full control structures.',limits:structuredClone(packet.limits),phases:structuredClone(packet.phases),outputs:outputs.map(([url,value])=>({name:url.pathname.split('/').at(-1),sha256:sha(value),bytes:Buffer.byteLength(value)}))};
 return structuredClone(fullDelta);
}
'''
text+=extra
(p/'build-ordered-current-linux-successor-v1.mjs').write_text(text)
private=pathlib.Path('/workspace/.zasp-cloud-owned/linux-successor-source-tdd');(private/'historical-generator-source.sha256').write_text(hashlib.sha256(original.encode()).hexdigest()+'\n')
