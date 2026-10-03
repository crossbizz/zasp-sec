import {lstat,realpath,mkdtemp,mkdir,chmod,open}from 'node:fs/promises';
import {constants}from 'node:fs';import path from 'node:path';import {fileURLToPath}from 'node:url';
import {spawnOwnedCommand}from './owned-command.mjs';
import {loadOfficialHeldTool,spawnHeldTool,closeHeldTool}from './official-held-tools.mjs';
import {observeRetainedAllocation}from './owned-runtime-lifetime.mjs';
// Only Go's invocation-time prefix varies; the complete official payload stays fixed.
function canonicalVersionLogTime(value){
 const match=/^([0-9]{4})\/([0-9]{2})\/([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})$/.exec(value);if(!match)return false;
 const [year,month,day,hour,minute,second]=match.slice(1).map(Number);if(year<1||month<1||month>12||day<1||day>31||hour>23||minute>59||second>59)return false;
 const date=new Date(0);date.setUTCFullYear(year,month-1,day);date.setUTCHours(hour,minute,second,0);
 return date.getUTCFullYear()===year&&date.getUTCMonth()===month-1&&date.getUTCDate()===day&&date.getUTCHours()===hour&&date.getUTCMinutes()===minute&&date.getUTCSeconds()===second;
}
const profiles=Object.freeze({temporal:{url:'https://github.com/temporalio/cli/releases/download/v1.9.1/temporal_cli_1.9.1_linux_amd64.tar.gz',size:45298806,args:['--version'],version:result=>result.stdout==="temporal version 1.9.1 (Server 1.32.0, UI 2.54.1)\n"&&result.stderr===""},openfga:{url:'https://github.com/openfga/openfga/releases/download/v1.21.0/openfga_1.21.0_linux_amd64.tar.gz',size:21232870,args:['version'],version:result=>result.stdout===""&&canonicalVersionLogTime(result.stderr.slice(0,19))&&result.stderr.slice(19)===" OpenFGA version `v1.21.0` build from `ab557c5592670c899de35297e7aa067015f06502` on `2026-09-20T16:11:15Z` \n"}});
const refuse=()=>{throw Error('hosted runtime tool intake unavailable');};
const RESERVE=2684354560n,BUDGET=536870912n,MARGIN=33554432n;
const absolute=value=>typeof value==='string'&&path.isAbsolute(value)&&path.normalize(value)===value&&![...value].some(character=>{const code=character.codePointAt(0);return code<=0x1f||code===0x7f;});
async function create(base){const info=await lstat(base);if(!info.isDirectory()||info.isSymbolicLink()||info.uid!==process.getuid()||(info.mode&0o022)!==0||await realpath(base)!==base)refuse();const root=await mkdtemp(path.join(base,'zasp-browser-runtime-'));await chmod(root,0o700);const archives=path.join(root,'archives'),raw=path.join(root,'raw');await mkdir(archives,{mode:0o700});await mkdir(raw,{mode:0o700});return {root,archives,raw};}
async function finite(owner,settings,signal){let stopping,timer,timedOut=false;const stop=()=>stopping??=owner.stop();const abort=()=>{void stop().catch(()=>{});};signal.addEventListener('abort',abort,{once:true});if(signal.aborted)abort();timer=setTimeout(()=>{timedOut=true;abort();},settings.timeout);let result,error;try{result=await owner.completed;}catch(cause){error=cause;}finally{clearTimeout(timer);signal.removeEventListener('abort',abort);if(stopping)await stopping;}if(error||timedOut||signal.aborted)refuse();return result;}
const defaults={create,observe:root=>observeRetainedAllocation([root]),run:async(executable,args,settings,signal)=>{const owner=spawnOwnedCommand(executable,args,settings);const result=await finite(owner,settings,signal);if(result.status!==0||result.signal||result.outputLimitExceeded)refuse();},load:loadOfficialHeldTool,version:async(tool,args,settings,signal)=>finite(await spawnHeldTool(tool,args,settings),settings,signal),close:closeHeldTool,setTimer:setTimeout,clearTimer:clearTimeout,publish:async(file,bytes)=>{const before=await lstat(file);if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||before.uid!==process.getuid()||(before.mode&0o022)!==0)refuse();const handle=await open(file,constants.O_WRONLY|constants.O_APPEND|constants.O_NOFOLLOW);try{const held=await handle.stat();if(held.dev!==before.dev||held.ino!==before.ino)refuse();await handle.writeFile(bytes);await handle.sync();const after=await lstat(file);if(after.dev!==held.dev||after.ino!==held.ino||after.nlink!==1)refuse();}finally{await handle.close();}}};
// Official archive validation and ELF/FD custody remain in the existing loader.
// This step retains those owned inputs for the real later service consumer.
export async function prepareHostedRuntimeTools(config,adapters=defaults){
 if(process.platform!=='linux'||process.arch!=='x64'||!config||Object.getPrototypeOf(config)!==Object.prototype||Object.keys(config).length!==2||!absolute(config.runnerTemp)||!absolute(config.githubEnv))refuse();
 const controller=new AbortController(),tools=[];let paths,timer,sampling=Promise.resolve(),stopped=false,failed=false;
 const check=(value,start=false)=>{if(typeof value.free!=='bigint'||typeof value.allocated!=='bigint'||value.allocated<0n||value.allocated>BUDGET||value.free<(start?RESERVE+BUDGET+MARGIN:RESERVE))refuse();};
 const sample=()=>{if(stopped)return;sampling=(async()=>{try{check(await adapters.observe(paths.root));}catch{failed=true;controller.abort();}finally{if(!stopped&&!controller.signal.aborted)timer=adapters.setTimer(sample,100);}})();};
 try{
  paths=await adapters.create(config.runnerTemp);if(!paths||![paths.root,paths.archives,paths.raw].every(absolute)||path.dirname(paths.archives)!==paths.root||path.dirname(paths.raw)!==paths.root||paths.archives===paths.raw||path.dirname(paths.root)!==config.runnerTemp)refuse();
  check(await adapters.observe(paths.root),true);timer=adapters.setTimer(sample,100);
  const transport={PATH:'/usr/bin:/bin',HOME:paths.root,LANG:'C.UTF-8'};for(const key of ['HTTPS_PROXY','HTTP_PROXY','NO_PROXY','https_proxy','http_proxy','no_proxy','SSL_CERT_FILE','CURL_CA_BUNDLE'])if(typeof process.env[key]==='string')transport[key]=process.env[key];
  const toolEnvironment={PATH:'/usr/bin:/bin',HOME:paths.root,LANG:'C.UTF-8'};
  for(const name of ['temporal','openfga']){
   const profile=profiles[name],archive=path.join(paths.archives,name+'.tar.gz');
   if(controller.signal.aborted)refuse();
   await adapters.run('/usr/bin/curl',['--disable','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--max-time','90','--max-filesize',String(profile.size),'--output',archive,profile.url],{cwd:paths.root,env:transport,timeout:95000,maxOutputBytes:16384},controller.signal);
   if(controller.signal.aborted)refuse();await chmod(archive,0o400);
   const tool=await adapters.load(name,archive,path.join(paths.raw,name+'-held'));tools.push(tool);if(controller.signal.aborted)refuse();
   const result=await adapters.version(tool,profile.args,{cwd:paths.root,env:toolEnvironment,timeout:5000,maxOutputBytes:16384},controller.signal);
   if(controller.signal.aborted||result.status!==0||result.signal||result.outputLimitExceeded||typeof result.stdout!=='string'||typeof result.stderr!=='string'||Buffer.byteLength(result.stdout)+Buffer.byteLength(result.stderr)>16384||!profile.version(result))refuse();
   check(await adapters.observe(paths.root));
  }
 }catch{failed=true;controller.abort();}
 finally{stopped=true;adapters.clearTimer(timer);await sampling;for(const tool of tools.reverse()){try{await adapters.close(tool);}catch{failed=true;}}}
 if(failed||controller.signal.aborted||!paths)refuse();
 // Export only after all finite producers and opaque tool handles have joined.
 // Failure leaves evidence/state in the owned RunnerTemp root; never emits raw errors.
 try{check(await adapters.observe(paths.root));await adapters.publish(config.githubEnv,`ZASP_BROWSER_RUNTIME_ARCHIVE_ROOT=${paths.archives}\nZASP_BROWSER_RUNTIME_RAW_ROOT=${paths.raw}\n`);}catch{refuse();}
 return Object.freeze({prepared:true,archiveRoot:paths.archives,rawRoot:paths.raw,actualServices:false,currentAPIReady:false,browserAcceptance:false,native:false,production:false,ledger:false});
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{await prepareHostedRuntimeTools({runnerTemp:process.env.RUNNER_TEMP,githubEnv:process.env.GITHUB_ENV});console.log('Pinned owned runtime tools prepared; services not started.');}
 catch{console.error('::error::Pinned owned runtime tool intake failed.');process.exitCode=1;}
}
