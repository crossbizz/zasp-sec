// Versioned reference-only query for the remaining reviewed source projections.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {canonicalOrderedJSON,orderedFactTypes} from './build-ordered-current-integrity.mjs';
import {compileOrderedCollector} from './ordered-current-catalog.mjs';
import {buildOrderedReferenceNeeds} from './ordered-current-reference-needs.mjs';
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const evidence=new URL('./ordered-current-worker-source-closure-v1-artifacts/',import.meta.url);
const pinned=(name,pin)=>{const raw=fs.readFileSync(new URL(name.replace(/^ordered-current-/,''),evidence));if(sha(raw)!==pin)throw Error('immutable reference changed '+name);return JSON.parse(raw);};
const catalogPin='b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077',sourcePin='be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6',compilerPin='4ad7d7218fff014766d92d8af7522ed5bb382b95e5fa1e12d9be70a407543425';
const catalog=pinned('ordered-current-effective-catalog1.json',catalogPin),source=pinned('ordered-current-effective-contract3.json',sourcePin),compiled=pinned('ordered-current-inventory-compiled.json',compilerPin);
if(compiled.checksum!=='5b129ed0592dde0af626a47bb656a572e009c1cefa182293429a454727af7bf9'||sha(compiled.source)!=='233c2caf66299ad50ee1a573c116746c905a885612a72980b6ce41c916a68850')throw Error('independent compiler source changed');
const referencePin='484a5c749d6750e0af783147f0d12efed6c9e4ebce1daf5bd5eec4eda643d23b';
const reference=pinned('ordered-current-supplementary-reference1.json',referencePin),needs=buildOrderedReferenceNeeds(source,catalog);
const sql=compileOrderedCollector(needs.rules).sql+'\n',rulesText=canonicalOrderedJSON(needs.rules),sitesText=canonicalOrderedJSON(needs.sites);
const sourcePins={};
for(const identity of [...new Set(needs.sites.map(s=>s.identity))]){
  const node=source.nodes.find(n=>n.identity===identity);
  sourcePins[identity]={sourceSHA256:node.sourceSHA256,definitionSHA256:node.definitionSHA256,frameSHA256:sha(canonicalOrderedJSON(Object.fromEntries(['owner','acl','config','security_definer','language','volatility','strict','result','arguments','parallel','leakproof','cost','rows'].map(k=>[k,node[k]]))))};
}
const modules={};for(const name of ['build-ordered-current-supplementary3.mjs','ordered-current-reference-needs.mjs','ordered-current-temporal72.mjs','ordered-current-temporal-selectors.mjs','ordered-current-public-selectors.mjs','ordered-current-catalog.mjs','ordered-current-static-catalog.mjs','build-ordered-current-integrity.mjs'])modules[name]=sha(fs.readFileSync(new URL(name,import.meta.url)));
const fieldTypes={};for(const rule of needs.rules)for(const field of rule.fields){fieldTypes[rule.kind]??={};const type=orderedFactTypes[rule.kind]?.[field];if(!type)throw Error('missing field type');fieldTypes[rule.kind][field]=type;}
const contract={format:'ordered-current-supplementary-query-v1',status:'REFERENCE-CAPTURE-ONLY',predecessorContractFileSHA256:'b59111a99e3fa275c7f550eaacb4f98e0636e7132326d0dc2e5c0a58be2c9af5',
  sqlSHA256:sha(sql),rulesSHA256:sha(rulesText),sitesSHA256:sha(sitesText),sourcePins,modules,
  compilerChecksum:compiled.checksum,compiledSourceSHA256:sha(compiled.source),compilerArtifactSHA256:compilerPin,catalog1FileSHA256:catalogPin,sourceContractSHA256:sourcePin,
  requiredRole:'zasp_discovery_authority',requiredSearchPath:['pg_catalog'],requiredTimeZone:'UTC',requiredPostgres:reference.postgres,requiredServerVersionNum:reference.serverVersionNum,
  priorReferenceFileSHA256:referencePin,maxRows:needs.maxRows,maxBytes:16777216,categoryMaxRows:needs.categoryMaxRows,ruleMaxRows:needs.ruleMaxRows,rules:needs.rules,sites:needs.sites,fieldTypes,
  unresolvedObligations:needs.obligations,referenceGaps:needs.pending,boundNotes:needs.boundNotes,
  rawInputRuleIds:needs.rules.filter(r=>r.id.startsWith('raw-transform:')).map(r=>r.id),
  rawInputDisposition:'Raw transform facts are intermediate reference inputs only, not release comparison facts. Exact original transformations and live/cardinality/binding errors remain required.'};
if(process.argv.length!==3||!['--write','--check'].includes(process.argv[2]))throw Error('use --write or --check');
const text=JSON.stringify(contract,null,2)+'\n';
for(const [name,data] of [['ordered-current-supplementary-query-contract3.json',text],['ordered-current-supplementary-select3.sql',sql],['ordered-current-supplementary-rules3.json',rulesText],['ordered-current-supplementary-sites3.json',sitesText]]){
  const path=new URL(name,evidence);if(process.argv[2]==='--check'){if(fs.readFileSync(path,'utf8')!==data)throw Error('reference output differs '+name);}else fs.writeFileSync(path,data);
}
console.log(JSON.stringify({status:contract.status,contractFileSHA256:sha(text),sqlSHA256:sha(sql),rulesSHA256:sha(rulesText),sitesSHA256:sha(sitesText),rules:needs.rules.length,sites:needs.sites.length,maxRows:needs.maxRows,categoryMaxRows:needs.categoryMaxRows,rawInputRules:contract.rawInputRuleIds.length}));
