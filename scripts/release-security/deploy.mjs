#!/usr/bin/env node
import {execFileSync} from 'node:child_process';
import {mkdtemp, mkdir, rm, writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadAll, JSON_SCHEMA} from 'js-yaml';
import {verifyPromotion} from './verify.mjs';
import {readBound, requireThat, sha256, verifySigned} from './trust.mjs';

const self=fileURLToPath(import.meta.url);
const repoRoot=fileURLToPath(new URL('../../',import.meta.url));
function sorted(value){
  if(Array.isArray(value))return value.map(sorted);
  if(value && typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,sorted(value[key])]));
  return value;
}
function resources(raw, regularOnly){
  return loadAll(raw,{schema:JSON_SCHEMA}).filter(x=>x && (!regularOnly || !x.metadata?.annotations?.['helm.sh/hook'])).map(x=>JSON.stringify(sorted(x))).sort();
}
export function sameResources(expected,actual,regularOnly=false){
  const a=resources(expected,regularOnly), b=resources(actual,false);
  requireThat(a.length>0 && a.length===b.length && a.every((x,i)=>x===b[i]),'Helm output differs from approved release resources');
}
function cli(bin,args,options={}){
  return execFileSync(bin,args,{maxBuffer:32*1024**2,encoding:'utf8',stdio:['ignore','pipe','pipe'],...options});
}
export async function runAWSRelease({args,release,namespace,mode='apply',apiImage,repo=repoRoot,env=process.env,execute=cli,authorize=verifyPromotion}){
  requireThat(/^[a-z0-9][a-z0-9-]{0,52}$/.test(release) && /^[a-z0-9][a-z0-9-]{0,62}$/.test(namespace),'Invalid Helm target');
  requireThat(['check','apply'].includes(mode),'Unknown release action');
  const dir=env.ZASP_RELEASE_EVIDENCE_DIR;
  const receipt=await authorize({dir,repo,env});
  const {value:c,sha256:bound}=await verifySigned(path.join(dir,'candidate.json'),env.ZASP_RELEASE_BUILD_PUBLIC_KEY,'zasp.release.candidate.v1');
  requireThat(receipt.candidateSha256===bound,'Build attestation changed');
  if(apiImage!==undefined) requireThat(apiImage===c.productImages?.api,'Bootstrap image differs from approved candidate');
  const target=c.deploymentTarget;
  const context=execute('kubectl',['config','current-context']).trim();
  requireThat(target?.profile==='aws' && target.namespace===namespace && target.release===release && target.context===context && context.length>0,'Deployment target differs from approved build');
  const expected=await readBound(path.join(dir,'rendered.yaml'),32*1024**2);
  requireThat(sha256(expected)===c.renderedSha256,'Approved render changed');
  const stage=await mkdtemp(path.join(os.tmpdir(),'zasp-aws-release-'));
  try {
    const chart=path.join(stage,'product'), archives=path.join(stage,'chart.tar');
    await mkdir(chart);await writeFile(path.join(stage,'approved.yaml'),expected,{mode:0o400});
    execute('git',['-C',repo,'archive','--format=tar','--output='+archives,receipt.commit+':deploy/staging/product']);
    execute('tar',['-xf',archives,'-C',chart]);
    const values=[], upgradeOptions=[];
    for(let i=0;i<args.length;i++){
      const flag=args[i];
      if(flag==='-f'||flag==='--values'){
        const staged=path.join(stage,'values-'+i);
        const location=args[++i];requireThat(typeof location==='string' && location.length>0,'Missing values file');
        await writeFile(staged,await readBound(location,16*1024**2),{mode:0o400});
        values.push('-f',staged);
      } else if(['--set','--set-string','--set-json','--set-literal'].includes(flag)){
        const setting=args[++i];requireThat(typeof setting==='string' && setting.includes('='),'Missing Helm setting');
        values.push(flag,setting);
      } else if(['--wait','--atomic','--wait-for-jobs'].includes(flag))upgradeOptions.push(flag);
      else if(flag==='--timeout'){const t=args[++i];requireThat(typeof t==='string' && /^(?:\d+[hms])+$/.test(t),'Invalid Helm timeout');upgradeOptions.push(flag,t);}
      else throw Error('Unsupported override for a signed deployment');
    }
    const scope=['--kube-context',context,'-n',namespace];
    const local=execute('helm',[...scope,'template',release,chart,...values]);
    requireThat(sha256(Buffer.from(local))===c.renderedSha256,'Helm values produce a different candidate render');
    const command=[...scope,'upgrade','--install',release,chart,'--create-namespace','--reset-values',...values,...upgradeOptions];
    const dry=execute('helm',[...command,'--dry-run=server','--output','json']);
    const prefix='Release "'+release+'" does not exist. Installing it now.';
    const json=dry.trimStart().startsWith(prefix)?dry.trimStart().slice(prefix.length).trimStart():dry;
    const plan=JSON.parse(json);
    requireThat(plan.name===release && plan.namespace===namespace && typeof plan.manifest==='string' && Array.isArray(plan.hooks??[]),'Helm did not return a scoped release');
    const hooks=(plan.hooks??[]).map(h=>{requireThat(typeof h.manifest==='string','Unreadable hook manifest');return h.manifest;});
    sameResources(expected.toString('utf8'),[plan.manifest,...hooks].join('\n---\n'));
    if(mode==='check') return;
    // Helm 3 processes ordinary resources through its post-renderer. Hooks
    // were checked in the read-only server dry run above. The chart and values
    // consumed by both invocations come from this private staging directory.
    execute('helm',[...command,'--post-renderer',self,'--post-renderer-args','post-render'],
      {env:{...env,ZASP_APPROVED_RENDER:path.join(stage,'approved.yaml')},stdio:['ignore','inherit','inherit']});
  } finally { await rm(stage,{recursive:true,force:true}); }
}
if(process.argv[1] && path.resolve(process.argv[1])===self){
  try{
    if(process.argv[2]==='post-render'){
      const approved=await readBound(process.env.ZASP_APPROVED_RENDER,32*1024**2);
      const chunks=[];let size=0;
      for await(const chunk of process.stdin){size+=chunk.length;requireThat(size<=32*1024**2,'Unexpected Helm render size');chunks.push(chunk);}
      const bytes=Buffer.concat(chunks);
      sameResources(approved.toString('utf8'),bytes.toString('utf8'),true);
      process.stdout.write(bytes);
    }else{
      requireThat(['apply','check'].includes(process.argv[2]),'Expected apply, check or post-render');
      await runAWSRelease({mode:process.argv[2],apiImage:process.env.ZASP_BOOTSTRAP_CHECK_IMAGE,release:process.argv[3],namespace:process.argv[4],args:process.argv.slice(5)});
    }
  }catch(error){console.error(error.status===undefined?error.message:'Production release tool failed; inspect private runner diagnostics.');process.exitCode=1;}
}
