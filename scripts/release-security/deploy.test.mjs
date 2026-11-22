import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {runAWSRelease,sameResources} from './deploy.mjs';
import {sha256} from './trust.mjs';

const ordinary='apiVersion: v1\nkind: Pod\nmetadata: {name: serving}\nspec: {containers: [{name: product, image: "registry/agent@sha256:abc"}]}\n';
const hook='apiVersion: batch/v1\nkind: Job\nmetadata: {name: migrate, annotations: {"helm.sh/hook": pre-upgrade}}\n';
test('AWS wrapper refuses before the mutating Helm command for wrong values, hooks, authority or target',async t=>{
 const dir=await mkdtemp(path.join(os.tmpdir(),'zasp-aws-admit-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 const key=generateKeyPairSync('ed25519'),expected=ordinary+'---\n'+hook;
 const candidate=JSON.stringify({format:'zasp.release.candidate.v1',renderedSha256:sha256(expected),deploymentTarget:{profile:'aws',release:'zasp',namespace:'zasp',context:'owned-staging'},productImages:{api:'approved-api'}});
 await writeFile(path.join(dir,'rendered.yaml'),expected);await writeFile(path.join(dir,'candidate.json'),candidate);await writeFile(path.join(dir,'candidate.json.sig'),sign(null,Buffer.from(candidate),key.privateKey).toString('base64'));
 const opts={dir,args:[],env:{ZASP_RELEASE_EVIDENCE_DIR:dir,ZASP_RELEASE_BUILD_PUBLIC_KEY:key.publicKey.export({type:'spki',format:'pem'})},release:'zasp',namespace:'zasp',authorize:async()=>({candidateSha256:sha256(candidate),commit:'a'.repeat(40)})};
 const values=path.join(dir,'values.yaml');await writeFile(values,'app: staging\n');
 async function exercise(change={},settings={}){
   let mutate=0;
   const execute=(bin,args)=>{
     if(bin==='kubectl')return settings.context??'owned-staging';
     if(bin==='git'||bin==='tar')return '';
     if(args.includes('template'))return settings.render??expected;
     if(args.includes('--dry-run=server'))return JSON.stringify({name:'zasp',namespace:'zasp',manifest:ordinary,hooks:[{manifest:settings.hook??hook}]});
     assert.equal(bin,'helm');assert.ok(args.includes('--post-renderer'));assert.ok(args.includes('--reset-values'));mutate++;return '';
   };
   try{await runAWSRelease({...opts,args:['-f',values],...change,execute});return mutate;}
   catch(error){assert.equal(mutate,0);throw error;}
 }
 assert.equal(await exercise(),1);assert.equal(await exercise({mode:'check',apiImage:'approved-api'}),0);
 await assert.rejects(exercise({},{render:expected.replace('serving','other')}),/different candidate render/);
 await assert.rejects(exercise({},{hook:hook.replace('migrate','other')}),/differs/);
 await assert.rejects(exercise({},{context:'other'}),/target/);
 await assert.rejects(exercise({args:['--post-renderer','other']}),/Unsupported/);
 await assert.rejects(exercise({authorize:async()=>{throw Error('missing evidence');}}),/missing evidence/);
 await assert.rejects(exercise({mode:'check',apiImage:'wrong'}),/Bootstrap image/);
 assert.equal(await readFile(values,'utf8'),'app: staging\n');
});
test('live post-render check permits formatting changes and rejects resource omission or substitution',()=>{
 sameResources(ordinary+'---\n'+hook,ordinary+'\n',true);
 assert.throws(()=>sameResources(ordinary+'---\n'+hook,ordinary,false),/differs/);
 assert.throws(()=>sameResources(ordinary,ordinary.replace('sha256:abc','sha256:bad'),true),/differs/);
});
