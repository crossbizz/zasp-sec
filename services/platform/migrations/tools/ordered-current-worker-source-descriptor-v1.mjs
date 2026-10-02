// Official source-descriptor regeneration for the current Go worker profile.
// Only the source-authorized profile token and compiled checksum are changed;
// every other catalog byte and row remains exact.
import fs from 'node:fs';
import crypto from 'node:crypto';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const oldSHA='036c92946205f854600cd0ef0e7ebbd1f8bc672c1a5e23d070ef198959abebec';
const currentSHA='b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077';
const oldChecksum='e12fb150ebaf718d39883a8e6e3b63caac90fb05409895e0fc832e717ab46960';
const newChecksum='5b129ed0592dde0af626a47bb656a572e009c1cefa182293429a454727af7bf9';
const sourceURL=new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json',import.meta.url);
const targetIdentities=new Set([
 'zasp_authorization79.fingerprint()','zasp_authorization80_temporal.fingerprint()',
 'zasp_authorization80_temporal.projected68()','zasp_authorization80_temporal.projected72()',
 'zasp_authorization80_temporal.projected_domain()','zasp_ordered_public62.fingerprint()',
 'zasp_temporal68.predecessor_ready(text,text)','zasp_temporal68.ready(text,text)',
 'zasp_temporal69.fingerprint()','zasp_temporal76.executor74_fingerprint()',
 'zasp_temporal77.base67_fingerprint()','zasp_temporal78.fingerprint()',
 'zasp_temporal78.ready(text,text)',
]);
export function regenerateCurrentWorkerCatalog(raw=fs.readFileSync(sourceURL)){
 if(sha(raw)===currentSHA){const current=JSON.parse(raw);if(current.compiled_checksum!==newChecksum)throw Error('worker source descriptor current checksum');return {output:Buffer.from(raw),sha256:currentSHA,changedRows:[]};}
 if(sha(raw)!==oldSHA)throw Error('worker source descriptor input pin');
 const catalog=JSON.parse(raw),rows=catalog.functions.filter(row=>targetIdentities.has(row.identity));
 if(rows.length!==13||rows.some(row=>typeof row.definition!=='string'||!row.definition.includes(oldChecksum)))throw Error('worker source descriptor target closure');
 for(const row of rows)row.definition=row.definition.replaceAll(oldChecksum,newChecksum);
 if(catalog.compiled_checksum!==oldChecksum)throw Error('worker source descriptor checksum');
 catalog.compiled_checksum=newChecksum;
 const output=Buffer.from(JSON.stringify(catalog));
 return {output,sha256:sha(output),changedRows:rows.map(row=>row.identity)};
}
if(process.argv[1]?.endsWith('ordered-current-worker-source-descriptor-v1.mjs')){
 const result=regenerateCurrentWorkerCatalog();
 fs.writeFileSync(sourceURL,result.output);
 process.stdout.write(JSON.stringify({sha256:result.sha256,changedRows:result.changedRows.length})+'\n');
}
