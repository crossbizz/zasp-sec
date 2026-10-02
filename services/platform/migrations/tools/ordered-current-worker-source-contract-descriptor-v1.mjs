// Deterministic migration of the pinned source contract to the current Go
// worker checksum. Only the approved profile token changes.
import fs from 'node:fs';
import crypto from 'node:crypto';
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const oldSHA='5fed1f43b6475087e16ba4f1ab1db6d6827f508bf9160b13c05e6ef8f6a975e8';
const predecessorSHA='008c60757dabf6b5a5935fdc472ce7a9b9c1965fb959b7b565b61d3e1eb8b45c';
const currentSHA='be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6';
const oldChecksum='e12fb150ebaf718d39883a8e6e3b63caac90fb05409895e0fc832e717ab46960';
const newChecksum='5b129ed0592dde0af626a47bb656a572e009c1cefa182293429a454727af7bf9';
const sourceURL=new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',import.meta.url);
const catalogURL=new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json',import.meta.url);
const compiledURL=new URL('./ordered-current-worker-source-closure-v1-artifacts/inventory-compiled.json',import.meta.url);
const currentCatalogSHA=sha(fs.readFileSync(catalogURL));
const currentCompiledSHA=sha(fs.readFileSync(compiledURL));
const currentCompiled=JSON.parse(fs.readFileSync(compiledURL));
const migrate=value=>{if(typeof value==='string')return value.replaceAll(oldChecksum,newChecksum);if(Array.isArray(value))return value.map(migrate);if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,migrate(item)]));return value;};
const normalizeHashes=contract=>{if(contract.inputs&&typeof contract.inputs==='object'){contract.inputs.catalogFileSHA256=currentCatalogSHA;contract.inputs.compiledFileSHA256=currentCompiledSHA;contract.inputs.compiledChecksum=currentCompiled.checksum;}for(const node of contract.nodes??[]){if(typeof node.source==='string'&&typeof node.definition==='string'){node.sourceSHA256=sha(node.source);node.definitionSHA256=sha(node.definition);}}for(const row of contract.materializedObligations??[]){const node=contract.nodes?.find(candidate=>candidate.identity===row.identity);if(node){row.sourceSHA256=node.sourceSHA256;row.definitionSHA256=node.definitionSHA256;}}for(const region of contract.higherRegions??[]){const node=contract.nodes?.find(candidate=>candidate.identity===region.identity);if(node)region.sourceSHA256=node.sourceSHA256;for(const [field,hashField] of [['prefix','prefixSHA256'],['suffix','suffixSHA256'],['originalExpression','originalExpressionSHA256']])if(typeof region[field]==='string')region[hashField]=sha(region[field]);}return contract;};
export function regenerateCurrentWorkerSourceContract(raw=fs.readFileSync(sourceURL)){
 const inputSHA=sha(raw),contract=JSON.parse(raw);
 if(inputSHA===oldSHA){const output=Buffer.from(JSON.stringify(normalizeHashes(migrate(contract)),null,2)+'\n');return {output,sha256:sha(output),changed:true};}
 // The approved predecessor and current descriptor currently have the same
 // canonical bytes.  Keep the predecessor branch explicit for future
 // migrations, but never report a current-state no-op as a change.
 if(inputSHA===predecessorSHA&&predecessorSHA!==currentSHA){const output=Buffer.from(JSON.stringify(normalizeHashes(contract),null,2)+'\n');return {output,sha256:sha(output),changed:true};}
 if(inputSHA===currentSHA){const output=Buffer.from(JSON.stringify(normalizeHashes(contract),null,2)+'\n');return {output,sha256:sha(output),changed:sha(output)!==inputSHA};}
 if(contract.format!=='ordered-current-effective-contract-v3')throw Error('worker source contract format');
 throw Error('worker source contract input pin');
}
if(process.argv[1]?.endsWith('ordered-current-worker-source-contract-descriptor-v1.mjs')){const result=regenerateCurrentWorkerSourceContract();fs.writeFileSync(sourceURL,result.output);process.stdout.write(JSON.stringify({sha256:result.sha256,changed:result.changed})+'\n');}
