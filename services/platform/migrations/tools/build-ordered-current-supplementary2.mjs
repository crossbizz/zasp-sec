// Fixed reference-only query emission. Does not connect, execute or bless data.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {canonicalOrderedJSON,orderedFactTypes} from './build-ordered-current-integrity.mjs';
import {compileOrderedCollector,orderedReferenceInput,countOrderedReferenceCandidates} from './ordered-current-catalog.mjs';
import {lowerOrderedRuntimeCatalog} from './ordered-current-runtime-selectors.mjs';
import {lowerOrderedProductCatalog} from './ordered-current-product-selectors.mjs';
import {lowerOrderedRoleProfileCatalog} from './ordered-current-role-profile.mjs';
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const evidence=new URL('./ordered-current-worker-source-closure-v1-artifacts/',import.meta.url);
const pinRead=(name,pin)=>{const raw=fs.readFileSync(new URL(name.replace(/^ordered-current-/,''),evidence));if(sha(raw)!==pin)throw Error('reference pin changed '+name);return JSON.parse(raw);};
const catalogPin='b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077';
const contractPin='be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6';
const compiledPin='4ad7d7218fff014766d92d8af7522ed5bb382b95e5fa1e12d9be70a407543425';
const catalog=pinRead('ordered-current-effective-catalog1.json',catalogPin),sourceContract=pinRead('ordered-current-effective-contract3.json',contractPin);
const compiled=pinRead('ordered-current-inventory-compiled.json',compiledPin);
if(compiled.checksum!=='5b129ed0592dde0af626a47bb656a572e009c1cefa182293429a454727af7bf9'||sha(compiled.source)!=='233c2caf66299ad50ee1a573c116746c905a885612a72980b6ce41c916a68850')throw Error('compiled source identity changed');
const runtime=lowerOrderedRuntimeCatalog(sourceContract),product=lowerOrderedProductCatalog(sourceContract);
const roleProfile=lowerOrderedRoleProfileCatalog(sourceContract);
const rules=[...runtime.rules,...product.rules,...roleProfile.rules],sites=[...runtime.sites,...product.sites,...roleProfile.sites];
const sql=compileOrderedCollector(rules).sql+'\n';
// These are candidate-set bounds, not generated expected fact values. A view
// may expose fewer rows (notably information_schema); no value is approximated.
const metadata=orderedReferenceInput(catalog);
for(const row of [...metadata])for(const [base,alias] of [['column','column_name'],['column','information_column'],['constraint','global_constraint'],['policy','policy_view'],['index','index_view']])if(row.kind===base)metadata.push({...row,kind:alias});
if(catalog.domain_constraints.length!==0)throw Error('domain bound requires explicit reference metadata adapter');
const ruleMaxRows=countOrderedReferenceCandidates(rules,metadata),categoryMaxRows={};
// The profile bound is its original count=1 admission obligation, not a row
// filter or invented reference value. An extra row must exceed capture bounds.
ruleMaxRows['role-profile:current-profile']=1;
for(const rule of rules){if(!Number.isSafeInteger(ruleMaxRows[rule.id])||ruleMaxRows[rule.id]<1)throw Error('missing finite reference candidate bound '+rule.id);categoryMaxRows[rule.kind]=(categoryMaxRows[rule.kind]??0)+ruleMaxRows[rule.id];}
const maxRows=Object.values(ruleMaxRows).reduce((sum,n)=>sum+n,0);
if(maxRows>10000)throw Error('reference row bound exceeds reviewed ceiling');
const sourcePins={};
for(const identity of [...new Set(sites.map(s=>s.identity))]){
  const node=sourceContract.nodes.find(n=>n.identity===identity);
  sourcePins[identity]={sourceSHA256:node.sourceSHA256,definitionSHA256:node.definitionSHA256,frameSHA256:sha(canonicalOrderedJSON(Object.fromEntries(['owner','acl','config','security_definer','language','volatility','strict','result','arguments','parallel','leakproof','cost','rows'].map(key=>[key,node[key]]))))};
}
const fieldTypes={};for(const rule of rules)for(const field of rule.fields){fieldTypes[rule.kind]??={};const type=orderedFactTypes[rule.kind]?.[field];if(!type)throw Error('missing typed projection');fieldTypes[rule.kind][field]=type;}
const modules={};for(const name of ['build-ordered-current-supplementary2.mjs','ordered-current-role-profile.mjs','ordered-current-runtime-selectors.mjs','ordered-current-product-selectors.mjs','ordered-current-catalog.mjs','build-ordered-current-integrity.mjs'])modules[name]=sha(fs.readFileSync(new URL(name,import.meta.url)));
const contract={format:'ordered-current-supplementary-query-v1',status:'REFERENCE-CAPTURE-ONLY',predecessorContractFileSHA256:'2f93f8390aa4897b7bd6c273ed524f55cf4e360692158e4af4868ddd9bd5bcae',sqlSHA256:sha(sql),rulesSHA256:sha(canonicalOrderedJSON(rules)),sitesSHA256:sha(canonicalOrderedJSON(sites)),sourcePins,modules,
  compilerChecksum:compiled.checksum,compiledSourceSHA256:sha(compiled.source),compilerArtifactSHA256:compiledPin,catalog1FileSHA256:catalogPin,sourceContractSHA256:contractPin,
  requiredRole:'zasp_discovery_authority',requiredSearchPath:['pg_catalog'],requiredTimeZone:'UTC',maxRows,maxBytes:16777216,categoryMaxRows,ruleMaxRows,rules,sites,fieldTypes,
  unresolvedObligations:[...runtime.obligations,...product.obligations,...roleProfile.obligations],referenceGaps:[...runtime.unsupported,...product.unsupported,...roleProfile.unsupported]};
const text=JSON.stringify(contract,null,2)+'\n';
if(process.argv.length!==3||!['--write','--check'].includes(process.argv[2]))throw Error('use --write or --check');
for(const [name,value] of [['ordered-current-supplementary-select2.sql',sql],['ordered-current-supplementary-query-contract2.json',text],['ordered-current-supplementary-rules2.json',canonicalOrderedJSON(rules)],['ordered-current-supplementary-sites2.json',canonicalOrderedJSON(sites)]]){
  const path=new URL(name,evidence);if(process.argv[2]==='--check'){if(fs.readFileSync(path,'utf8')!==value)throw Error('supplementary output differs '+name);}else fs.writeFileSync(path,value);
}
console.log(JSON.stringify({status:contract.status,contractFileSHA256:sha(text),sqlSHA256:sha(sql),rulesSHA256:contract.rulesSHA256,sitesSHA256:contract.sitesSHA256,rules:rules.length,sites:sites.length,maxRows,categoryMaxRows}));
