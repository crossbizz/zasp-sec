#!/usr/bin/env node
import {execFileSync} from 'node:child_process';
import {appendFile, mkdtemp, mkdir, rm, writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadAll, JSON_SCHEMA} from 'js-yaml';
import {verifyPromotion} from './verify.mjs';
import {checkTestedMain, validateProductionResources, protectEvaluationRelease} from './production-cd.mjs';
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
export function runAWSRelease(options) {
  return runSignedRelease({...options, profile: 'aws'});
}

export function installVPSProduction(options = {}) {
  return runSignedRelease({...options, args: [], release: 'agentsec', namespace: 'zasp', mode: 'install', profile: 'vps-production'});
}

export function upgradeProduction(options = {}) {
  return runSignedRelease({...options, args: [], release: 'agentsec', namespace: 'zasp', mode: 'apply', profile: 'vps-production'});
}

async function runSignedRelease({args,release,namespace,profile,mode='apply',apiImage,repo=repoRoot,env=process.env,execute=cli,authorize=verifyPromotion,currentMain=checkTestedMain}){
  requireThat(/^[a-z0-9][a-z0-9-]{0,52}$/.test(release) && /^[a-z0-9][a-z0-9-]{0,62}$/.test(namespace),'Invalid Helm target');
  requireThat(['check','apply'].includes(mode) || profile === 'vps-production' && mode === 'install','Unknown release action');
  const production = profile === 'vps-production';
  const dir=env.ZASP_RELEASE_EVIDENCE_DIR;
  const receipt=await authorize({dir,repo,env});
  const {value:c,sha256:bound}=await verifySigned(path.join(dir,'candidate.json'),env.ZASP_RELEASE_BUILD_PUBLIC_KEY,'zasp.release.candidate.v1');
  requireThat(receipt.candidateSha256===bound,'Build attestation changed');
  if(apiImage!==undefined) requireThat(apiImage===c.productImages?.api,'Bootstrap image differs from approved candidate');
  const target=c.deploymentTarget;
  const context=execute('kubectl',['config','current-context']).trim();
  requireThat(target?.profile===profile && target.namespace===namespace && target.release===release && target.context===context && context.length>0,'Deployment target differs from approved build');
  const expected=await readBound(path.join(dir,'rendered.yaml'),32*1024**2);
  requireThat(sha256(expected)===c.renderedSha256,'Approved render changed');
  const scope=['--kube-context',context,'-n',namespace];
  const confirmInstallation = () => {
    const uid = env.ZASP_VPS_CLUSTER_UID;
    const owner = env.ZASP_VPS_INSTALLATION_ID;
    requireThat(/^[-a-z0-9]{1,63}$/.test(owner ?? '') && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(uid ?? '') &&
      context === env.ZASP_VPS_KUBE_CONTEXT && uid === target.clusterUID && owner === target.installationID,
      'The protected cluster context, UID or installation identity differs from its signed target');
    const readNamespace = name => JSON.parse(execute('kubectl', ['--context',context,'get','namespace',name,'-o','json'])).metadata;
    const system = readNamespace('kube-system'), application = readNamespace(namespace);
    requireThat(system?.name === 'kube-system' && system.uid === uid && application?.name === namespace &&
      application.labels?.['zasp.io/installation'] === owner, 'Kubernetes cluster identity or application namespace ownership changed');
  };
  if (production) {
    confirmInstallation();
    requireThat((env.HELM_DRIVER || 'secret') === 'secret', 'Production requires Helm Secret storage');
    validateProductionResources(expected);
    const evaluation = JSON.parse(execute('helm', [...scope, 'list', '--all', '--filter', '^zasp$', '--output', 'json']));
    requireThat(Array.isArray(evaluation), 'Unreadable evaluation release list');
    let preserved;
    if (evaluation.length > 0) {
      preserved = JSON.parse(execute('helm', [...scope, 'status', 'zasp', '--output', 'json']));
      requireThat(preserved.name === 'zasp' && preserved.namespace === namespace, 'Unexpected evaluation release');
      protectEvaluationRelease(expected, [], preserved);
    }
    if (mode === 'install') {
      const existing = JSON.parse(execute('helm', [...scope, 'list', '--all', '--filter', '^agentsec$', '--output', 'json']));
      requireThat(Array.isArray(existing) && existing.length === 0, 'Initial product install requires an unused production release name');
    } else {
      requireThat(receipt.commit === env.GITHUB_SHA, 'Production release commit differs from this run');
      const identity = JSON.parse(execute('kubectl', ['--context', context, 'auth', 'whoami', '-o', 'json']));
      requireThat(identity.status?.userInfo?.username === 'system:serviceaccount:zasp:zasp-cd', 'Expected the namespace-scoped production CD identity');
      // Helm can delete objects omitted from a later chart. Check the release
      // being replaced as well as the signed candidate, before a server dry run.
      const products = JSON.parse(execute('helm', [...scope, 'list', '--all', '--filter', '^agentsec$', '--output', 'json']));
      requireThat(Array.isArray(products), 'Unreadable product release list');
      if (products.length === 0) return {installed:false};
      const installed = JSON.parse(execute('helm', [...scope, 'status', release, '--output', 'json']));
      requireThat(installed.name === release && installed.namespace === namespace && installed.info?.status === 'deployed', 'Expected the installed production product release');
      validateProductionResources(installed.manifest, installed.hooks);
      if (preserved) protectEvaluationRelease(installed.manifest, installed.hooks, preserved);
      const previous = installed.config?.global?.releaseCommit;
      if (previous !== undefined) {
        requireThat(/^[a-f0-9]{40}$/.test(previous), 'Invalid previous release commit');
        execute('git', ['-C', repo, 'merge-base', '--is-ancestor', previous, receipt.commit]);
      }
    }
  }
  const stage=await mkdtemp(path.join(os.tmpdir(),'zasp-signed-release-'));
  try {
    const chart=path.join(stage,'product'), archives=path.join(stage,'chart.tar');
    await mkdir(chart);await writeFile(path.join(stage,'approved.yaml'),expected,{mode:0o400});
    execute('git',['-C',repo,'archive','--format=tar','--output='+archives,receipt.commit+':deploy/staging/product']);
    execute('tar',['-xf',archives,'-C',chart]);
    const values=[], upgradeOptions=[];
    if (production) {
      const operatorValues = path.join(stage, 'operator.yaml');
      const overlay = path.join(stage, 'production.yaml');
      const imageValues = path.join(stage, 'candidate-images.json');
      const productImages = {};
      for (const [role, key] of Object.entries({
        web: 'web', api: 'agentsecApi', worker: 'agentsecWorker', 'redteam-worker': 'redTeamWorker',
        'attack-lab-runner': 'attackLabRunner', 'event-ingest': 'eventIngest', 'gateway-control': 'gatewayControl',
        'runtime-gateway': 'runtimeGateway', 'sensor-agent': 'sensorAgent',
      })) {
        requireThat(/^.+@sha256:[a-f0-9]{64}$/.test(c.productImages?.[role]), 'Missing promoted image digest for ' + role);
        productImages[key] = c.productImages[role];
      }
      await writeFile(overlay, execute('git', ['-C', repo, 'show', receipt.commit + ':deploy/vps/production/values.yaml']), {mode:0o400});
      await writeFile(operatorValues, await readBound(path.join(dir, 'production-values.yaml'), 16*1024**2), {mode:0o400});
      await writeFile(imageValues, JSON.stringify({global:{productImages, releaseCommit:receipt.commit}}), {mode:0o400});
      values.push('-f',operatorValues,'-f',overlay,'-f',imageValues);
      upgradeOptions.push('--atomic','--wait','--wait-for-jobs','--timeout','20m');
    }
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
    const local=execute('helm',[...scope,'template',release,chart,...values]);
    requireThat(sha256(Buffer.from(local))===c.renderedSha256,'Helm values produce a different candidate render');
    const command = mode === 'install'
      ? [...scope,'install',release,chart,...values,...upgradeOptions]
      : [...scope,'upgrade',...(production?[]:['--install']),release,chart,...(production?[]:['--create-namespace']),'--reset-values',...values,...upgradeOptions];
    const dry=execute('helm',[...command,'--dry-run=server','--output','json']);
    const prefix='Release "'+release+'" does not exist. Installing it now.';
    const json=dry.trimStart().startsWith(prefix)?dry.trimStart().slice(prefix.length).trimStart():dry;
    const plan=JSON.parse(json);
    requireThat(plan.name===release && plan.namespace===namespace && typeof plan.manifest==='string' && Array.isArray(plan.hooks??[]),'Helm did not return a scoped release');
    const hooks=(plan.hooks??[]).map(h=>{requireThat(typeof h.manifest==='string','Unreadable hook manifest');return h.manifest;});
    sameResources(expected.toString('utf8'),[plan.manifest,...hooks].join('\n---\n'));
    if(mode==='check') return;
    if (production) {
      if (mode !== 'install') requireThat(await currentMain({env}), 'The candidate is no longer the latest tested main commit');
      confirmInstallation();
    }
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
    }else if(process.argv[2]==='install-vps-production' && process.argv.length===3){
      await installVPSProduction();
    }else if(process.argv[2]==='upgrade-production' && process.argv.length===3){
      const outcome = await upgradeProduction();
      const summary = outcome?.installed === false
        ? 'Production upgrade skipped. Install the first signed agentsec product release in namespace zasp before enabling future upgrades.'
        : 'The signed agentsec product release in namespace zasp passed the production upgrade and readiness checks.';
      console.log(summary);
      if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, summary + '\n');
    }else{
      requireThat(['apply','check'].includes(process.argv[2]),'Expected apply, check or post-render');
      await runAWSRelease({mode:process.argv[2],apiImage:process.env.ZASP_BOOTSTRAP_CHECK_IMAGE,release:process.argv[3],namespace:process.argv[4],args:process.argv.slice(5)});
    }
  }catch(error){console.error(error.status===undefined?error.message:'Production release tool failed; inspect private runner diagnostics.');process.exitCode=1;}
}
