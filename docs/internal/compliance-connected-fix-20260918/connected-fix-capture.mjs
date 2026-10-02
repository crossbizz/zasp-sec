import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const base='.superpowers/sdd/2026-09-18-compliance-production-plan';
const files=[
 'services/platform/migrations/sql/fragments/compliance_jobs.sql',
 'services/platform/migrations/compliance_release.go',
 'services/platform/migrations/sql/0056_production_compliance.up.sql',
 'services/platform/migrations/sql/0056_production_compliance.down.sql',
 'services/platform/apiserver/compliance_connected_postgres_test.go',
 'services/platform/apiserver/compliance_http.go',
 'app/features/sessions/SessionsComplianceView.tsx',
 'app/features/sessions/SessionsComplianceView.test.tsx',
 'apps/web/api/administration-decoders.ts',
 'apps/web/api/compliance-decoders.test.ts',
 'openapi/openapi.yaml','apps/web/api/generated.ts',
 'scripts/production-combined-e2e.mjs',
];
const hash=body=>execFileSync('git',['hash-object','--stdin'],{input:body,encoding:'utf8'}).trim();
if(process.argv[2]==='add') {
 const entries=JSON.parse(fs.readFileSync(path.join(base,'connected-fix-before.json')));
 for(const file of process.argv.slice(3)){if(entries.some(entry=>entry.file===file))throw new Error('already captured '+file);const body=fs.existsSync(file)?fs.readFileSync(file):null;const dest=path.join(base,'connected-fix-before',file);if(body){fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,body);}entries.push({file,before:body?hash(body):null});}
 fs.writeFileSync(path.join(base,'connected-fix-before.json'),JSON.stringify(entries,null,2));console.log(entries);
} else if(process.argv[2]==='before') {
 const entries=files.map(file=>{const body=fs.existsSync(file)?fs.readFileSync(file):null; const dest=path.join(base,'connected-fix-before',file); if(body){fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,body);}return {file,before:body?hash(body):null};});
 fs.writeFileSync(path.join(base,'connected-fix-before.json'),JSON.stringify(entries,null,2));
 console.log(entries);
} else {
 const entries=JSON.parse(fs.readFileSync(path.join(base,'connected-fix-before.json')));let patch='';
 for(const entry of entries){entry.after=fs.existsSync(entry.file)?hash(fs.readFileSync(entry.file)):null;if(entry.after===entry.before)continue; const old=entry.before?path.join(base,'connected-fix-before',entry.file):'/dev/null';try{execFileSync('git',['diff','--no-index','--',old,entry.file],{encoding:'utf8'});}catch(e){patch+=e.stdout.replaceAll('a/'+old,'a/'+entry.file).replaceAll('b/'+entry.file,'b/'+entry.file);}}
 fs.writeFileSync(path.join(base,'connected-fix-blobs.json'),JSON.stringify(entries,null,2));fs.writeFileSync(path.join(base,'connected-fix-scoped.patch'),patch);console.log(entries);
}
