import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
const root='/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917';
const dir=path.join(root,'docs/internal/group-mapping-update-20260918/green');
if(process.argv.includes('--before-comment')){
 const saved=path.join(dir,'runtime-tested-connector_rejection_transaction.go.txt');
 if(fs.existsSync(saved))throw Error('Comment baseline already exists');
 fs.copyFileSync(path.join(root,'services/platform/apiserver/connector_rejection_transaction.go'),saved);
 process.exit(0);
}
const files=['administration_repository.go','connector_rejection_transaction.go','group_mapping_update_postgres_test.go','group_mapping_contention_postgres_test.go'].map(f=>'services/platform/apiserver/'+f);
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const final=process.argv.includes('--after');let manifest='',patch='';
for(const file of files){const source=path.join(root,file),before=path.join(dir,'before',file),after=path.join(dir,'after',file);fs.mkdirSync(path.dirname(before),{recursive:true});
 if(!final){if(fs.existsSync(before)||fs.existsSync(before+'.absent'))continue;if(fs.existsSync(source))fs.copyFileSync(source,before);else fs.writeFileSync(before+'.absent','absent\n');continue;}
 if(!fs.existsSync(before)&&!fs.existsSync(before+'.absent'))throw Error('Missing BEFORE '+file);
 if(!fs.existsSync(source))continue;const data=fs.readFileSync(source);fs.mkdirSync(path.dirname(after),{recursive:true});fs.writeFileSync(after,data);
 manifest+=`${file}\nBEFORE ${fs.existsSync(before)?hash(fs.readFileSync(before)):'ABSENT'}\nAFTER ${hash(data)}\n`;
 const result=spawnSync('/usr/bin/diff',['-u','--label','a/'+file,'--label','b/'+file,fs.existsSync(before)?before:'/dev/null',source],{cwd:root,encoding:'utf8'});if(result.status>1)throw Error(result.stderr);patch+=result.stdout;
}
if(final){
 fs.writeFileSync(path.join(dir,'source-manifest.log'),manifest);fs.writeFileSync(path.join(dir,'scoped.patch'),patch);
 let checked=0,migrations=0;
 for(const line of fs.readFileSync(path.join(root,'docs/internal/group-mapping-update-20260918/after-source.log'),'utf8').split('\n')){
  const match=line.match(/^([a-f0-9]{64}) {2}(.+)$/);if(!match||files.includes(match[2]))continue;
  if(hash(fs.readFileSync(path.join(root,match[2])))!==match[1])throw Error('Unexpected source drift '+match[2]);checked++;if(match[2].startsWith('services/platform/migrations/'))migrations++;
 }
 const docker=spawnSync('/usr/local/bin/docker',['ps','-a','--format','{{.ID}} {{.Names}}'],{cwd:root,encoding:'utf8'});if(docker.status!==0)throw Error(docker.stderr);
 if(/zasp-(group-mapping|connector-rejection)/.test(docker.stdout))throw Error('Owned fixture container remains');
 fs.writeFileSync(path.join(dir,'cleanup.log'),`${checked} other apiserver/runtime/migration source files unchanged; ${migrations} migration files unchanged.\nOwned fixture containers absent. Other containers not touched:\n${docker.stdout}`);
}
