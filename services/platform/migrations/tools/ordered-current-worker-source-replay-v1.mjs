// Native19 source replay evidence. This verifies only the immutable Go
// release artifact and records explicit refusals; native output is excluded.
import fs from 'node:fs';
import crypto from 'node:crypto';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const artifactURL=new URL('./ordered-current-worker-source-closure-v1-artifacts/native19-worker-release.json',import.meta.url);
const catalogURL=new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json',import.meta.url);
const expected=Object.freeze({
 artifactSHA256:'4ad7d7218fff014766d92d8af7522ed5bb382b95e5fa1e12d9be70a407543425',
 format:'zasp-worker-compiled-release-v1', profile:'canonical61-temporal78-authorization79-80-worker-v1',
 checksum:'5b129ed0592dde0af626a47bb656a572e009c1cefa182293429a454727af7bf9',
 sourceSHA256:'233c2caf66299ad50ee1a573c116746c905a885612a72980b6ce41c916a68850', sourceBytes:829825,
 catalogChecksum:'5b129ed0592dde0af626a47bb656a572e009c1cefa182293429a454727af7bf9',
 owner:'zasp_discovery_authority', acl:'{zasp_discovery_authority=X/zasp_discovery_authority}',
});
const rows=Object.freeze([
 ['zasp_authorization79.fingerprint()','5cdcb702d357af423d463efe775cdc4bf2ba772601e84b08739d36475cdca956','af32db47b84ecb92727e0288a1895305d63fe85df04280374bed2f201bd34a13',954,'consumer'],
 ['zasp_authorization80_temporal.fingerprint()','5479fd3c26ac96108d545ba6b72c257e74509e51627ef0fe387b5dae39a6ab35','c3642037d0043ca2ce53d4f399a07b5a6d55c8bbbcf2cd3f13f21d6c88bd925c',995,'consumer'],
 ['zasp_authorization80_temporal.projected68()','be14788ffa75b858b53599ad250a5948127fde3571a89a806b518af0a0501c5c','f8dad8b8179f7ea191894c198213ac8ae0e9af3fc07cd5145d9681c127276515',980,'consumer'],
 ['zasp_authorization80_temporal.projected72()','2a9e747bbeeda34e4d88a1887aaa9c09c1a6f158301d9863f01589dcbde7333e','a10af9ad27427675cdd74b6457b730fda8d34a309e4adc345310cc32db36f1a9',980,'consumer'],
 ['zasp_authorization80_temporal.projected_domain()','01c1860e7525eb21f4ab8dfb39ae24908f9641c75a090f0ac462270dc1d3b17a','eaaca814a4be11d684bbd4a9c8787c39fbcb028d56b35802ef957a11f5468b49',990,'consumer'],
 ['zasp_ordered_public62.fingerprint()','8b1213693ca9483d45b9a51b2b826295cbf427ba13958824c09529a691962c8c','0193bce1e0669d106167c1c05743c5acd5f9c6a441367b0c3d673b68ceb01195',955,'consumer'],
 ['zasp_temporal68.predecessor_ready(text,text)','8c13d47619b46ce17719029d7f78f5a35efe661712bd647856290c3f896f5d67','ff2c95d52e16210ff40cea9cad99616eee5f2c2af1ef2998dd69ecf8d1f027c6',119914,'higher'],
 ['zasp_temporal68.ready(text,text)','727f1cd8a85272ba3be4c8dae5a6d8473146306848a43c4ebfdaedc13ececd35','f29bf4b6187fe2aa7376044284edf35b9e0e885aa987d4791831d16196096f8b',7871,'higher'],
 ['zasp_temporal69.fingerprint()','e3ffc65d5cdef28b346e287d26544e814a1bf61b3fea41b9b7aef6ace0ee1a6b','c5414faec8e3b45f3f198ba94237bd2995b3c39c5e2c46d832a7212bb19af0fc',949,'consumer'],
 ['zasp_temporal76.executor74_fingerprint()','657872e08adb170a9e447eb88474bd35384ea9a38e850aadcd268ef01d7ba72f','5a43ac437b370f0f3975579101e6d05a1bef54482d1f7ac8286c399de681b6da',960,'consumer'],
 ['zasp_temporal77.base67_fingerprint()','771d60847cbfe23736f8d07fd25ed1fb12b3eb1a174e2b78832a6e4c00ac233e','76d39113ed60019844f329c2dcb016f8957c0199c33f3fe6767b18d5225ec860',117393,'higher'],
 ['zasp_temporal78.fingerprint()','0ae7074fca8c29edf1fe5ef85bfa68641428fd41468d2446c0d746ddaf70fc50','23f21233160cece16eaeccf5796ec4821533b560ce71e7e1a1e0b3ecb7f0f749',949,'consumer'],
 ['zasp_temporal78.ready(text,text)','aa46d19826db1780244188d43b799aea6748c0747075f74758ee533bf678aaf6','c54753cd7326e7efbbe26af9760e004d2d8716c7c583d5f34a6c27784c7400e7',25122,'higher'],
 ['zasp_authorization80_worker.fingerprint()','233c2caf66299ad50ee1a573c116746c905a885612a72980b6ce41c916a68850','4219ab65a0f4d142189f039df11044f0579a9af603b040f0ee0aafd6ea7e32cd',11569,'worker-wrapper'],
 ['zasp_authorization80_worker.catalog_ready()','233c2caf66299ad50ee1a573c116746c905a885612a72980b6ce41c916a68850','3b46aa8607e042925c3cc56b66605244a0a6fe9ff2db41fcd339c8e6c7bebac8',11755,'worker-wrapper'],
 ['zasp_authorization80_worker.test74_effect_source(text,jsonb)','5b7e9da001e1dc37f075cd5b5de8d14366a4ebe266bd2c00760a6252f22d185b','deb2d1559a49f064d32cb4a15140d44278d8055e684bc4fcdb5a433e771985f0',4300,'worker-tail-effect'],
 ['zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)','1b35fa9580ad123d705e7a819c2f331dcd818ee43fd44fbdd9a06fd67063c0e8','cdafb1ba4e542132ab39a69b218251b198bbbc535d5e23d6d5914367c0c11429',6638,'worker-tail-lifecycle'],
].map(([identity,sourceSHA256,definitionSHA256,definitionBytes,category])=>({identity,sourceSHA256,definitionSHA256,definitionBytes,category})));
const exactDefinitions=Object.freeze({
 'zasp_authorization79.fingerprint()':['079ec62f0f720ad956aca2614093701877dcfa0094e56c781cbde572d691742d',954],
 'zasp_authorization80_temporal.fingerprint()':['284a7670fba7e149def6964d080694d100876bc4bfec36a6e1ba50e4bec78c6d',995],
 'zasp_authorization80_temporal.projected68()':['644154419e3a8efe11347ec35f71bdb3c7361f87089796914008efd08a98aef7',980],
 'zasp_authorization80_temporal.projected72()':['854710213d0c79dbdd21954527f8c60606fab88dc6f5e9a276d053c03a377710',980],
 'zasp_authorization80_temporal.projected_domain()':['18d540807398454068dec0475c138dc076cf7716448f0b8cde7095fcadbecaf5',990],
 'zasp_ordered_public62.fingerprint()':['e13491491a9bb3873884553dbafd2d1286c05d4d7110d2a4a2cac6e53fe91ed8',955],
 'zasp_temporal68.predecessor_ready(text,text)':['c6eed3d3fd1aad9eb53690e2a1e364dc576e1910224af2fec91813189c944bb6',119914],
 'zasp_temporal68.ready(text,text)':['f9557bcb94debad45801d1715181e4592c47be92fa79005b3c811b6281757f83',7871],
 'zasp_temporal69.fingerprint()':['a05b5c3a51f4f31fb0127ccd7275e54e411f710e56d76088eee6c53ddb372b18',949],
 'zasp_temporal76.executor74_fingerprint()':['eeeee1f5537fbbfc0c7632e81eac07f067b2bd80dddecf512a8259fcc075baf5',960],
 'zasp_temporal77.base67_fingerprint()':['ae6456305a2ffc9aa054dd32e085fd7595859714c1cdf56946c8d837c082e907',117393],
 'zasp_temporal78.fingerprint()':['48a239da1b4b6805c4e2bc04b6e2341fb0a67d79bbf510a3b69386575862c735',949],
 'zasp_temporal78.ready(text,text)':['a6a988fd4b42b6c63dc66b34a2de51476a0bfe9452ef4536b061206d120999ac',25122],
 'zasp_authorization80_worker.fingerprint()':['4219ab65a0f4d142189f039df11044f0579a9af603b040f0ee0aafd6ea7e32cd',11569],
 'zasp_authorization80_worker.catalog_ready()':['3b46aa8607e042925c3cc56b66605244a0a6fe9ff2db41fcd339c8e6c7bebac8',11755],
 'zasp_authorization80_worker.test74_effect_source(text,jsonb)':['aef69f5699654144fda8e41179a24d1432b142422fba4bb3a4cd830259da87ed',4300],
 'zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)':['03f167c0cd69fdcb273593d53268cf1d3aa81b601f34a5fa60558dde465dab71',6638],
});
const exactFactSHA256=Object.freeze({
 'zasp_authorization80_worker.test74_effect_source(text,jsonb)':'60ce2dba06789d8904001e31870b0a02ddad9262dc252d60271c21a190bd4271',
 'zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)':'661743088f23cff353385c8d425bbcf88005ee3cb1c1b798b9de1b48a180e70c',
});
const exactFrames=Object.freeze({...Object.fromEntries(rows.map(row=>[row.identity,{owner:'zasp_discovery_authority',acl:row.identity==='zasp_temporal68.ready(text,text)'?'{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority,zasp_security_agent_api=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}':'{zasp_discovery_authority=X/zasp_discovery_authority}',language:row.identity.startsWith('zasp_temporal68.predecessor_ready')?'plpgsql':'sql',volatility:'s',security_definer:['zasp_authorization80_temporal.fingerprint()','zasp_authorization80_temporal.projected68()','zasp_authorization80_temporal.projected72()','zasp_authorization80_temporal.projected_domain()','zasp_temporal68.predecessor_ready(text,text)','zasp_temporal68.ready(text,text)','zasp_temporal78.ready(text,text)','zasp_authorization80_worker.fingerprint()','zasp_authorization80_worker.catalog_ready()'].includes(row.identity),config:['search_path=pg_catalog, public'],arguments:['zasp_temporal68.predecessor_ready(text,text)','zasp_temporal68.ready(text,text)','zasp_temporal78.ready(text,text)'].includes(row.identity)?'c text, f text':'',result:['zasp_temporal68.predecessor_ready(text,text)','zasp_temporal68.ready(text,text)','zasp_temporal78.ready(text,text)','zasp_authorization80_worker.catalog_ready()'].includes(row.identity)?'boolean':'text'}])),
 'zasp_authorization80_worker.test74_effect_source(text,jsonb)':{owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}',language:'plpgsql',volatility:'v',security_definer:true,config:['search_path=pg_catalog, public'],arguments:'phase text, q jsonb',result:'jsonb'},
 'zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)':{owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}',language:'plpgsql',volatility:'v',security_definer:true,config:['search_path=pg_catalog, public'],arguments:'phase text, q jsonb',result:'jsonb'},
});
const exactSpans=Object.freeze({
 'zasp_authorization79.fingerprint()':[587947,588895,'8f2820a8a50ef4985722703106e7b988ee07447a7e728ac4a669171a54d6f828','a3bffc0d55e960fc4b9ba233c8eeba63f367f007df9ba0eb37e34ec6bb042a00'],
 'zasp_authorization80_temporal.fingerprint()':[266592,267585,'8a7062a3ad0a6b24e0f0473b9848540265ea870816e687e57b1b98cec2b9b1ae','0fde1324803d5cb9b8aff5fb62e56fa3a3faf1adc6bf17f39a07af0c4a14bb8d'],
 'zasp_authorization80_temporal.projected68()':[264630,265606,'c5c5b414fc77a733139c57e60c1127151d707623c4e442a1e3ead2afef26640f','1782880ced20ac9230c543d93e64292443477b2a742e60d20c564aab75cc1361'],
 'zasp_authorization80_temporal.projected72()':[287500,288480,'41e09ad4c0808cc261570a15387fae0d2eb07367d54b557901b888852b0cef4a','829710c308583f54d55fe97f34a931bce24a9a30b4353aa48f52b319bbc5e8fd'],
 'zasp_authorization80_temporal.projected_domain()':[265607,266591,'b711ab7b5079f8f2b0d1c8a2cddbd28ebb206758233fa0f1d44e359a34596ab8','25fc7e8a4a5b2782d02bc2bee96469cbe354ea74c77919014c8a7b2101058fee'],
 'zasp_ordered_public62.fingerprint()':[295814,296763,'b74a013a34128d8182652cd5dcc749303ad077f7c0134682aa1317ed9c23a875','17405e12d315514e925a9b431d141613f507755f707675b2937bf19fafe1e4b8'],
 'zasp_temporal69.fingerprint()':[452532,453487,'56e418f16038f4390db29006915f5093a2308f4c07201783d0c92214ab3ea57d','534bfddac036cdb8aa0020be1ab86a9a9c8b948ddb1d37cef0fb2c136f9ea5e1'],
 'zasp_temporal76.executor74_fingerprint()':[263679,264629,'c132d13f1857fcb7a6d6948055da4b253703646097df86674916184cf53be734','98b0d9a64415be0f40d844d3a02361fcf73527434258a6ca2eaee5fe09e9d670'],
 'zasp_temporal78.fingerprint()':[587003,587946,'0a33721fae82835cfa1b61be5f303f34c112e0855c11934f0b254087e1685ac7','c465e2bed58a2be8f35cda526dca81e62473d8564770219a45697e67bff5ea00'],
 'zasp_authorization80_worker.fingerprint()':[15231,26783,'b01fb96c2cc7db1cdc43e27e7d5728504675a4b791c39f83dcfd98036cb1c58d','1598fc17fea78fdc02051c636a1d84b643d615cf7b54e421b42db906baede91f'],
 'zasp_authorization80_worker.catalog_ready()':[26784,38514,'24339d87d09ad2d7cb3807c2520d0ab10a3b19c226b42b6076287a072f6558cc','28bc26660db8eae036fd2f36bc215fcf2e27c1aba6d2c7c42d5d6a58e73c5016'],
 'zasp_authorization80_worker.test74_effect_source(text,jsonb)':[88133,92611,'5b7e9da001e1dc37f075cd5b5de8d14366a4ebe266bd2c00760a6252f22d185b','7f2d70d3fa899610cd4f3abe064821fe7ebe524ce2325ba4a3d26fa4bc9f6e82'],
 'zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)':[161122,167771,'1b35fa9580ad123d705e7a819c2f331dcd818ee43fd44fbdd9a06fd67063c0e8','4f85e19801e8a27a33da2892c937aa2550e0852603aab8ca4c8595f897d5ec1f'],
});

const readDefault=()=>({releaseRaw:fs.readFileSync(artifactURL),catalog:JSON.parse(fs.readFileSync(catalogURL))});
const bodyOf=definition=>{const start=definition.indexOf('$function$'),end=definition.lastIndexOf('$function$');if(start<0||end<=start)throw Error('native19 catalog definition delimiter');return definition.slice(start+10,end);};
function sourceBodyForCatalog(identity,body){
 if(identity==='zasp_authorization80_worker.test74_effect_source(text,jsonb)'){
  const lock1=" PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));\n";
  const lock2=" PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||x.organization_id,0));\n";
  if(body.split(lock1).length!==2||body.split(lock2).length!==2)throw Error('native20 effect source transform anchor');
  return {body:body.replace(lock1,'').replace(lock2,''),recipe:'remove-exact-profile-lock-anchors-v1'};
 }
 if(identity==='zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)'){
  const needle='zasp_authorization80_worker.test74_stop_evidence';
  if(body.split(needle).length!==2)throw Error('native20 lifecycle source transform anchor');
  return {body:body.replace(needle,'zasp_temporal74.stop_evidence'),recipe:'map-exact-predecessor-stop-call-v1'};
 }
 return {body,recipe:'identity-v1'};
}
function sourceDefinitionForFact(catalogDefinition,sourceBody){
 const start=catalogDefinition.indexOf('$function$'),end=catalogDefinition.lastIndexOf('$function$');
 if(start<0||end<=start)throw Error('native20 catalog definition delimiter');
 return catalogDefinition.slice(0,start+10)+sourceBody+catalogDefinition.slice(end);
}
function parseDeclarations(source,targetIdentities=new Set(rows.map(row=>row.identity))){
 const out=new Map(),re=/(?:CREATE(?: OR REPLACE)? FUNCTION)\s+([A-Za-z0-9_]+\.[A-Za-z0-9_]+)\s*\(([^)]*)\)/g;
 for(const match of source.matchAll(re)){const rawArgs=match[2].replace(/\s+/g,' ').trim(),rawIdentity=match[1]+'('+rawArgs+')',canonicalArgs=rawArgs?rawArgs.split(',').map(arg=>arg.trim().replace(/^[A-Za-z_][A-Za-z0-9_]*\s+/,'')).join(','):'';const identity=targetIdentities.has(rawIdentity)?rawIdentity:match[1]+'('+canonicalArgs+')';if(!targetIdentities.has(identity))continue;const tail=source.slice(match.index),tagMatch=tail.match(/\sAS (\$[A-Za-z0-9_]*\$)/);if(!tagMatch)continue;const tag=tagMatch[1],close=tail.indexOf(tag+';');if(close<0)throw Error('native19 source closing delimiter');const end=match.index+close+tag.length+1;if(out.has(identity))throw Error('native19 duplicate source span '+identity);out.set(identity,{identity,start:match.index,end,raw:source.slice(match.index,end),tag});}
 return out;
}
function readRelease(raw){
 let artifact;try{artifact=JSON.parse(Buffer.from(raw).toString('utf8'));}catch{throw Error('native19 release JSON');}
 if(sha(raw)!==expected.artifactSHA256||artifact.format!==expected.format||artifact.profile!==expected.profile||artifact.checksum!==expected.checksum||artifact.source_sha256!==expected.sourceSHA256||typeof artifact.source!=='string'||sha(artifact.source)!==expected.sourceSHA256||artifact.source.length!==expected.sourceBytes)throw Error('native19 release identity');
 return artifact;
}
function catalogRow(catalog,identity){const candidates=catalog.functions?.filter(value=>value.identity===identity)??[];const row=candidates.length===1?candidates[0]:null;if(candidates.length!==1&&identity.startsWith('zasp_authorization80_worker.test74_'))throw Error(`native20 catalog candidate ${identity} ${candidates.length===0?'missing':'duplicate'}`);const acl=exactFrames[identity]?.acl??(identity==='zasp_temporal68.ready(text,text)'?'{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority,zasp_security_agent_api=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}':expected.acl);if(!row||row.owner!==expected.owner||row.acl!==acl||typeof row.definition!=='string')throw Error('native19 catalog frame '+identity);return row;}

export function native19WorkerSourceReplay(options={}){
 const defaults=readDefault(),release=readRelease(options.releaseRaw??defaults.releaseRaw),catalog=options.catalog??defaults.catalog;
 if(options.expectedChecksum!==undefined&&options.expectedChecksum!==expected.checksum)throw Error('native19 stale profile checksum');
 const declarations=parseDeclarations(release.source),accepted=[],evidence=[];
 for(const spec of rows){const row=catalogRow(catalog,spec.identity),span=declarations.get(spec.identity),expectedDefinition=exactDefinitions[spec.identity],expectedFrame=exactFrames[spec.identity];if(!expectedDefinition||sha(row.definition)!==expectedDefinition[0]||row.definition.length!==expectedDefinition[1])throw Error('native19 exact definition authority '+spec.identity);for(const field of ['owner','acl','language','volatility','security_definer','config','arguments','result'])if(JSON.stringify(row[field])!==JSON.stringify(expectedFrame[field]))throw Error('native19 exact frame authority '+spec.identity+' '+field);const item={ruleId:'worker-line-5',kind:'routine',identity:spec.identity,rawFactSHA256:sha(row.definition),sourceSHA256:spec.sourceSHA256,definitionSHA256:expectedDefinition[0],definitionBytes:expectedDefinition[1],owner:row.owner,acl:row.acl,frame:expectedFrame,sourceArtifactSHA256:expected.artifactSHA256,profileChecksum:expected.checksum};if(span){const expectedSpan=exactSpans[spec.identity];if(!expectedSpan||span.start!==expectedSpan[0]||span.end!==expectedSpan[1]||sha(span.raw)!==expectedSpan[2]||sha(span.raw.slice(span.raw.indexOf(span.tag)+span.tag.length,span.raw.lastIndexOf(span.tag+';')))!==expectedSpan[3])throw Error('native19 exact source span authority '+spec.identity);item.sourceSpan=[span.start,span.end];item.sourceRawSHA256=sha(span.raw);item.sourceBodySHA256=sha(span.raw.slice(span.raw.indexOf(span.tag)+span.tag.length,span.raw.lastIndexOf(span.tag+';')));}
  if(spec.category==='higher'){item.status='refused';item.reason='higher-region source has no complete independently replayable function span';evidence.push(item);continue;}
  if(!span){item.status='refused';item.reason='source function span missing';evidence.push(item);continue;}
 const sourceBody=span.raw.slice(span.raw.indexOf(span.tag)+span.tag.length,span.raw.lastIndexOf(span.tag+';')),catalogBody=bodyOf(row.definition),mapped=sourceBodyForCatalog(spec.identity,sourceBody);
 if(mapped.body!==catalogBody)throw Error('native19 source/deparse body mismatch '+spec.identity);
  item.status='accepted';item.category=spec.category;item.transform=spec.category==='worker-wrapper'?'pg_get_functiondef-v1-wrapper-v1':mapped.recipe;item.sourceMappedBodySHA256=sha(mapped.body);if(exactFactSHA256[spec.identity])item.factSHA256=exactFactSHA256[spec.identity];if(spec.category.startsWith('worker-tail-')){item.replacementDefinition=sourceDefinitionForFact(row.definition,sourceBody);item.replacementFactSHA256=sha(JSON.stringify({acl:row.acl,definition:item.replacementDefinition,owner:row.owner}));}accepted.push(item);
 }
 return {version:'native19-worker-definition-replay-v1',profileChecksum:expected.checksum,sourceArtifactSHA256:expected.artifactSHA256,builder:{kind:'go-authorizationWorkerProfileSource',compiler:'pg_get_functiondef-v1',sourceBytes:expected.sourceBytes,sourceSHA256:expected.sourceSHA256},accepted,refused:evidence,registration:{ruleId:'worker-line-2',kind:'worker_registration',identity:'["worker-line-2","[\\"zasp_authorization80_worker.registration\\",true]"]',status:'refused',expectedFingerprint:'6100b85f9c853430105b2033d028bbeb8d65c7596099217af63f5cee70313534',rawFactSHA256:sha(catalog.registration?.[0]?.fingerprint??'6100b85f9c853430105b2033d028bbeb8d65c7596099217af63f5cee70313534'),profileChecksum:expected.catalogChecksum,reason:'registration is derived only after all 15 definitions and the complete 34-branch worker fact set are source-closed'}};
}
export {expected as native19WorkerSourceReplayManifest,rows as native19WorkerDefinitionRows,parseDeclarations,sourceDefinitionForFact};
