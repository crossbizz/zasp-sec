import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const PACKAGE='github.com/zasp-ai/zasp-sec/services/platform/agentsec-migrate';
const FAILURE='TestAuthorizationRuntimeProfileInnerFailureDiagnostic';
const SUCCESS='TestAuthorizationRuntimeProfileInnerSuccessOrder';
const STEPS=Object.freeze(['up-temporal-domain','up-temporal-executor','up-temporal-workflow','up-temporal-compatibility','up-temporal-legacy-tests','up-temporal-discovery','up-temporal-admission','up-temporal-test-executor','up-temporal-test-selector','up-temporal-human-admission','up-temporal-automatic-sources','up-temporal-finding-response','up-authorization-temporal-identity-profile','up-authorization-worker-profile']);
const SUBS=Object.freeze(STEPS.flatMap(step=>['install','forward-readiness'].map(stage=>`${FAILURE}/${step}/${stage}`)));
const TESTS=Object.freeze([FAILURE,...SUBS,SUCCESS]);
const REFUSAL=Object.freeze({classification:'unclassified-refusal',topCount:0,subCount:0});
const SOURCE_SHA='8108ac45747d66422273cde94783ca20c1f85c6fc072fc2d313fbf634c77ecf3';
const STDOUT_CAP=8*1024*1024,STDERR_CAP=256*1024,DEADLINE=240000;
const ARGV=Object.freeze(['test','-C','services/platform','-mod=readonly','-p=1','-count=1','-json','-timeout=2m','./agentsec-migrate','-run','^TestAuthorizationRuntimeProfileInner(FailureDiagnostic|SuccessOrder)$']);
function parseFlatEvent(line){
 if(line.length>65536)return null;
 const seen=new Set();let cursor=0;
 const whitespace=()=>{while(cursor<line.length&&/\s/.test(line[cursor]))cursor++;};
 const token=()=>{const expression=/"(?:[^"\\]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null/y;expression.lastIndex=cursor;const match=expression.exec(line);if(!match)return null;cursor=expression.lastIndex;return match[0];};
 whitespace();if(line[cursor++]!=='{')return null;whitespace();
 while(line[cursor]!=='}'){
  const rawKey=token();if(rawKey===null||rawKey[0]!=='"')return null;const key=JSON.parse(rawKey);if(seen.has(key))return null;seen.add(key);whitespace();if(line[cursor++]!==':')return null;whitespace();if(token()===null)return null;whitespace();if(line[cursor]===','){cursor++;whitespace();if(line[cursor]==='}')return null;}else if(line[cursor]!=='}')return null;
 }
 cursor++;whitespace();if(cursor!==line.length)return null;
 return JSON.parse(line);
}
export function classifyInnerDiagnosticRun({stdout,stderr,exitCode,normalClose}){
 try{
  if(typeof stdout!=='string'||typeof stderr!=='string'||stderr!==''||Buffer.byteLength(stdout)>STDOUT_CAP||!normalClose||![0,1].includes(exitCode)||!stdout.endsWith('\n'))return REFUSAL;
  const lines=stdout.slice(0,-1).split('\n');if(lines.length>4096||lines.some(line=>line===''))return REFUSAL;
  const states=new Map(TESTS.map(name=>[name,{run:false,terminal:null,assertions:0,runOutput:0,terminalOutput:0}]));
  let runIndex=0,started=false,finished=false,packageTerminal=null,packageResult=null,packageFooter=null,packageResultOutput=0,packageFooterOutput=0;
  for(let index=0;index<lines.length;index++){
   const event=parseFlatEvent(lines[index]);if(!event)return REFUSAL;
   if(Object.keys(event).some(key=>!['Time','Action','Package','Test','Elapsed','Output'].includes(key)))return REFUSAL;
   if(event.Package!==PACKAGE||typeof event.Time!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(event.Time)||!['start','run','output','pass','fail'].includes(event.Action))return REFUSAL;
   if(('Elapsed'in event)&&(!['pass','fail'].includes(event.Action)||typeof event.Elapsed!=='number'||!Number.isFinite(event.Elapsed)||event.Elapsed<0))return REFUSAL;
   if(('Output'in event)!==(event.Action==='output')||('Test'in event&&(!states.has(event.Test)||typeof event.Test!=='string')))return REFUSAL;
   if(finished)return REFUSAL;
   if(event.Action==='start'){if(started||index!==0||'Test'in event||'Elapsed'in event)return REFUSAL;started=true;continue;}
   if(!started)return REFUSAL;
   if(event.Test!==undefined){
    const state=states.get(event.Test);
    if(event.Action==='run'){if(state.run||state.terminal!==null||event.Test!==TESTS[runIndex++])return REFUSAL;if(event.Test===SUCCESS&&states.get(FAILURE).terminal===null)return REFUSAL;state.run=true;continue;}
    if(!state.run||state.terminal!==null)return REFUSAL;
    if(event.Action==='pass'||event.Action==='fail'){if(event.Test===FAILURE&&SUBS.some(name=>states.get(name).terminal===null))return REFUSAL;state.terminal=event.Action;continue;}
    if(event.Action!=='output'||typeof event.Output!=='string')return REFUSAL;
    if(event.Output===`=== RUN   ${event.Test}\n`){state.runOutput++;continue;}
    const terminal=/^[ \t]*--- (PASS|FAIL): ([^ \t]+) \([0-9]+(?:\.[0-9]+)?s\)\n$/.exec(event.Output);
    if(terminal&&terminal[2]===event.Test){state.terminalOutput++;state.renderedTerminal=terminal[1].toLowerCase();continue;}
    if(SUBS.includes(event.Test)&&/^[ \t]+authorization_runtime_profile_inner_diagnostic_test\.go:[0-9]+: closed inner step\/stage diagnostic absent\n$/.test(event.Output)){state.assertions++;continue;}
    return REFUSAL;
   }
   if(event.Action==='output'){
    if(typeof event.Output!=='string'||runIndex!==TESTS.length||[...states.values()].some(state=>state.terminal===null))return REFUSAL;
    if(event.Output==='PASS\n'||event.Output==='FAIL\n'){if(packageResultOutput!==0||packageFooterOutput!==0)return REFUSAL;packageResultOutput++;packageResult=event.Output.slice(0,-1).toLowerCase();continue;}
    const match=/^(ok[ \t]+|FAIL[ \t]+)([^\t ]+)\t[0-9]+(?:\.[0-9]+)?s\n$/.exec(event.Output);
    if(!match||match[2]!==PACKAGE||packageResultOutput!==1||packageFooterOutput!==0)return REFUSAL;packageFooterOutput++;packageFooter=match[1].startsWith('ok')?'pass':'fail';continue;
   }
   if(!['pass','fail'].includes(event.Action)||index!==lines.length-1)return REFUSAL;
   finished=true;packageTerminal=event.Action;
  }
  if(!finished||packageResultOutput!==1||packageFooterOutput!==1||packageTerminal!==packageResult||packageTerminal!==packageFooter)return REFUSAL;
  for(const state of states.values())if(!state.run||state.terminal===null||state.runOutput!==1||state.terminalOutput!==1||state.renderedTerminal!==state.terminal)return REFUSAL;
  const allPass=exitCode===0&&packageTerminal==='pass'&&[...states.values()].every(state=>state.terminal==='pass'&&state.assertions===0);
  if(allPass)return {classification:'all-tests-pass',topCount:2,subCount:28};
  if(exitCode===1&&packageTerminal==='fail'&&states.get(FAILURE).terminal==='fail'&&states.get(FAILURE).assertions===0&&states.get(SUCCESS).terminal==='pass'&&states.get(SUCCESS).assertions===0&&SUBS.every(name=>states.get(name).terminal==='fail'&&states.get(name).assertions===1))return {classification:'genuine-body-red',topCount:2,subCount:28};
  return REFUSAL;
 }catch{return REFUSAL;}
}
function summary(result){
 const severity=result.classification==='all-tests-pass'?'notice':'error';
 return `::${severity}::Current profile inner diagnostics: ${result.classification}; tops=${result.topCount}; subtests=${result.subCount}.\n`;
}
export async function runInnerDiagnosticObserver(dependencies={}){
 const launch=dependencies.spawn??spawn,read=dependencies.readFile??readFile,emit=dependencies.emit??(text=>process.stdout.write(text)),kill=dependencies.kill??process.kill.bind(process),timers=dependencies.timers??{setTimeout,clearTimeout};
 const cwd=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
 const testPath=path.join(cwd,'services/platform/agentsec-migrate/authorization_runtime_profile_inner_diagnostic_test.go');
 const check=async()=>createHash('sha256').update(await read(testPath)).digest('hex')===SOURCE_SHA;
 let result=REFUSAL,exit=1;
 try{
  if(!await check())throw new Error('fixed-source-refusal');
  const environment={...process.env,GOTOOLCHAIN:'local',GOENV:'off',GOWORK:'off',GOFLAGS:'',GOPRIVATE:'',GONOPROXY:'',GONOSUMDB:'',GOPROXY:'off',GOSUMDB:'off',CGO_ENABLED:'0'};
  const child=launch('go',[...ARGV],{cwd,env:environment,detached:true,stdio:['ignore','pipe','pipe']});
  const observed=await new Promise(resolve=>{
   let bytes=0,errorBytes=0,parts=[],errorParts=[],refused=false,closed=false,deadline,escalation;
   const stop=()=>{if(refused)return;refused=true;try{kill(-child.pid,'SIGTERM');}catch{/* Closed or unavailable child remains refused. */}escalation=timers.setTimeout(()=>{try{kill(-child.pid,'SIGKILL');}catch{/* Close remains required. */}},2000);};
   deadline=timers.setTimeout(stop,DEADLINE);
   child.stdout.on('data',buffer=>{bytes+=buffer.length;if(bytes>STDOUT_CAP){stop();return;}parts.push(buffer);});
   child.stderr.on('data',buffer=>{errorBytes+=buffer.length;if(errorBytes>STDERR_CAP){stop();return;}errorParts.push(buffer);});
   child.on('error',()=>{stop();});
   child.on('close',async(code,signal)=>{
    if(closed)return;closed=true;timers.clearTimeout(deadline);
    const groupAbsent=()=>{if(!Number.isInteger(child.pid)||child.pid<=0)return false;try{kill(-child.pid,0);return false;}catch(error){return error?.code==='ESRCH';}};
    let groupEmpty=groupAbsent();
    if(!groupEmpty&&Number.isInteger(child.pid)&&child.pid>0){
     stop();
     groupEmpty=await new Promise(finish=>{
      let samples=0;
      const observe=()=>{if(groupAbsent()){finish(true);return;}if(++samples>=160){try{kill(-child.pid,'SIGKILL');}catch{/* Unresolved cleanup remains refused. */}finish(false);return;}timers.setTimeout(observe,25);};
      observe();
     });
    }
    if(escalation!==undefined)timers.clearTimeout(escalation);
    resolve({stdout:Buffer.concat(parts).toString('utf8'),stderr:Buffer.concat(errorParts).toString('utf8'),exitCode:code,normalClose:!refused&&signal===null&&groupEmpty});
   });
  });
  if(!await check())throw new Error('fixed-source-post-refusal');
  result=classifyInnerDiagnosticRun(observed);
  exit=result.classification==='all-tests-pass'?0:(Number.isInteger(observed.exitCode)&&observed.exitCode>0&&observed.exitCode<256?observed.exitCode:1);
 }catch{/* Only the fixed refusal summary is emitted. */}
 try{emit(summary(result));}catch{exit=exit||1;}
 return exit;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const exit=process.argv.length===2?await runInnerDiagnosticObserver():1;
 process.exitCode=exit;
}
