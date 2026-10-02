import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
const base='.superpowers/sdd/2026-09-18-compliance-production-plan';
const mode=process.argv[2];assert.ok(['before-browser','after'].includes(mode));
const suffix=process.argv[3]??'';
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const walk=dir=>fs.existsSync(dir)?fs.readdirSync(dir,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(`${dir}/${e.name}`):[`${dir}/${e.name}`]):[];
const inputs=execFileSync('git',['ls-files','--cached','--others','--exclude-standard','-z','app','apps','services','scripts','openapi','.github','package.json','package-lock.json','vite.config.ts','tsconfig.json'],{encoding:'utf8'}).split('\0').filter(file=>file&&fs.existsSync(file));
const identities=Object.fromEntries([...new Set([...inputs,...walk('dist')])].sort().map(file=>[file,hash(file)]));
fs.writeFileSync(`${base}/legacy-compatibility-${mode}${suffix}-identities.json`,JSON.stringify(identities,null,2));
if(mode==='after')assert.deepEqual(identities,JSON.parse(fs.readFileSync(`${base}/legacy-compatibility-before-browser${suffix}-identities.json`)),'source/build drift during browser run');
const previous=new Map();
for(const name of ['task-1','task-2','task-3','task-4','task-4-fix-1','task-5','task-5-fix-1','task-4-final-fix','task-4-final-fix-2','compliance-ci','connected-fix']){
 const manifest=JSON.parse(fs.readFileSync(`${base}/${name}-blobs.json`));for(const entry of (Array.isArray(manifest)?manifest:manifest.files))previous.set(entry.path??entry.file,typeof entry.after==='string'?entry.after:entry.after?.gitBlob);
}
const before=new Map(JSON.parse(fs.readFileSync(`${base}/legacy-compatibility-before.json`)).map(entry=>[entry.path,entry.before]));
const reviewed=[];for(const [file,expected] of previous){const current=execFileSync('git',['hash-object',file],{encoding:'utf8'}).trim();assert.equal(before.has(file)?before.get(file):current,expected,'prior review identity drift '+file);reviewed.push({file,previous:expected,current,reused:current===expected});}
fs.writeFileSync(`${base}/legacy-compatibility-reused-identities.json`,JSON.stringify(reviewed,null,2));console.log(`Frozen ${Object.keys(identities).length} source/build files; matched ${reviewed.length} previous reviewed identities; ${reviewed.filter(e=>e.reused).length} unchanged.`);
