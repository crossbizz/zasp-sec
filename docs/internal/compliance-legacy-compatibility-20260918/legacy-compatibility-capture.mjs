import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const base='.superpowers/sdd/2026-09-18-compliance-production-plan';
const files=['app/features/sessions/SessionsComplianceView.tsx','app/features/sessions/SessionsComplianceView.test.tsx','app/features/sessions/ComplianceEvidenceView.tsx','app/features/sessions/compliance-api.ts','apps/web/api/compliance-decoders.test.ts','services/platform/agentsec-api/compliance_composition_test.go','services/platform/agentsec-api/compliance_browser_process_test.go','scripts/production-combined-e2e.mjs'];
const hash=body=>execFileSync('git',['hash-object','--stdin'],{input:body,encoding:'utf8'}).trim();
if(process.argv[2]==='add-decoder'){
 const file='apps/web/api/compliance-decoders.ts',body=fs.readFileSync(file),dest=path.join(base,'legacy-compatibility-before',file);
 const entries=JSON.parse(fs.readFileSync(`${base}/legacy-compatibility-before.json`));if(entries.some(e=>e.path===file))throw new Error('already captured');fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,body);entries.push({path:file,before:hash(body)});fs.writeFileSync(`${base}/legacy-compatibility-before.json`,JSON.stringify(entries,null,2));
}else if(process.argv[2]==='before'){
 const entries=files.map(file=>{const body=fs.readFileSync(file),dest=path.join(base,'legacy-compatibility-before',file);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,body);return {path:file,before:hash(body)};});fs.writeFileSync(`${base}/legacy-compatibility-before.json`,JSON.stringify(entries,null,2));console.log(entries);
}else{
 const entries=JSON.parse(fs.readFileSync(`${base}/legacy-compatibility-before.json`));let patch='';for(const e of entries){e.after=hash(fs.readFileSync(e.path));if(e.after===e.before)continue;const old=path.join(base,'legacy-compatibility-before',e.path);try{execFileSync('git',['diff','--no-index','--',old,e.path],{encoding:'utf8'});}catch(err){patch+=err.stdout.replaceAll('a/'+old,'a/'+e.path);}}fs.writeFileSync(`${base}/legacy-compatibility-blobs.json`,JSON.stringify(entries,null,2));fs.writeFileSync(`${base}/legacy-compatibility-scoped.patch`,patch);console.log(entries);
}
