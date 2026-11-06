import { OwnedAPIStartupError } from './owned-api-startup-wait.mjs';
const CLASSES=new Map([
 ['build|./agentsec-migrate','go-migration-build'],
 ['test|-c|./agentsec-api','go-api-test-compile'],
 ['test|-c|./agentsec-worker','go-worker-test-compile'],
 ['build|./agentsec-worker','go-worker-build'],
 ['build|.','go-cli-build'],
]);
const CURRENT_PROFILE_COMMANDS=new Map([
 ['up-to-60','current-profile-up-to-60'],
 ['up-authorization-runtime-profile','current-profile-up-authorization-runtime-profile'],
 ['register-temporal-executor-principals','current-profile-register-temporal-executor-principals'],
 ['register-authorization-verifier','current-profile-register-authorization-verifier'],
 ['register-identity-session-verifier','current-profile-register-identity-session-verifier'],
 ['register-identity-webhook-verifier','current-profile-register-identity-webhook-verifier'],
 ['register-worker-authorization-verifier','current-profile-register-worker-authorization-verifier'],
 ['register-compensation-authorization-verifier','current-profile-register-compensation-authorization-verifier'],
]);
const CURRENT_PROFILE_INNER_STEPS=new Set(["up-to-60", "up-temporal-domain", "up-temporal-executor", "up-temporal-workflow", "up-temporal-compatibility", "up-temporal-legacy-tests", "up-temporal-discovery", "up-temporal-admission", "up-temporal-test-executor", "up-temporal-test-selector", "up-temporal-human-admission", "up-temporal-automatic-sources", "up-temporal-finding-response", "up-authorization-temporal-identity-profile", "up-authorization-worker-profile"]);
export function browserCommandFailureAnnotation(executable,args,kind,stderr,diagnostic){
 if(kind!=='deadline'&&kind!=='nonzero-exit')return null;
 let label='other-command';
 if(typeof executable==='string'&&executable.startsWith('/')&&executable.endsWith('/agentsec-migrate')&&Array.isArray(args)&&args.length===1&&typeof args[0]==='string')label=CURRENT_PROFILE_COMMANDS.get(args[0])??label;
 if(executable==='go'&&Array.isArray(args)){
  if(args.length===4&&args[0]==='build'&&args[1]==='-o'&&typeof args[2]==='string'&&typeof args[3]==='string')label=CLASSES.get('build|'+args[3])??label;
  if(args.length===5&&args[0]==='test'&&args[1]==='-c'&&args[2]==='-o'&&typeof args[3]==='string'&&typeof args[4]==='string')label=CLASSES.get('test|-c|'+args[4])??label;
 }
 let cancellationRequested;
 try{
  if(diagnostic&&typeof diagnostic==='object'&&!Array.isArray(diagnostic)&&Object.keys(diagnostic).length===2&&Object.hasOwn(diagnostic,'context')&&Object.hasOwn(diagnostic,'cancellationRequested')){
   const context=diagnostic.context,canceled=diagnostic.cancellationRequested;
   const fixed=new Map([['owned-projection-reconcile','owned-projection-reconcile'],['owned-projection-revision','owned-projection-revision']]).get(context);
   if(fixed&&typeof canceled==='boolean'){label=fixed;cancellationRequested=canceled;}
  }
 }catch{/* Diagnostic input cannot replace the original command failure. */}
 const annotation=`::error title=Compliance browser command failed::Observed command class: ${label}; failure: ${kind}${cancellationRequested===undefined?'':`; cancellation-requested=${cancellationRequested}`}.`;
 if(label!=='current-profile-up-authorization-runtime-profile'||kind!=='nonzero-exit'||typeof stderr!=='string'||stderr.length>512)return annotation;
 const match=/^ZASP_AUTHORIZATION_RUNTIME_PROFILE_FAILED_STEP=([a-z0-9-]+);STAGE=(install|forward-readiness)\n$/.exec(stderr);
 if(!match||match[0]!==stderr||!CURRENT_PROFILE_INNER_STEPS.has(match[1]))return annotation;
 return `${annotation} Observed inner step: ${match[1]}; stage: ${match[2]}.`;
}

const PHASE_ANNOTATIONS=new Map(['services', 'command-builds', 'schema-bootstrap', 'browser-assertions', 'postgres-startup', 'postgres-instrumentation', 'postgres-principal-provisioning', 'compliance-fixture-provisioning', 'compliance-runtime-services', 'compliance-current-postgres', 'compliance-current-principals', 'compliance-current-schema', 'compliance-current-fixture', 'compliance-current-seed', 'compliance-current-fixture-sql', 'compliance-current-keys', 'compliance-reconcile-build', 'compliance-current-profile', 'controlled-identity-startup', 'policy-history-startup', 'api-startup', 'api-ready', 'web-startup', 'web-ready', 'tls-provisioning', 'proxy-startup', 'browser-startup'].map(phase=>[phase,`::error title=Compliance browser phase failed::Observed phase: ${phase}.`]));
export function emitComplianceBrowserPhaseFailure(phase,emit){
 try{emit(PHASE_ANNOTATIONS.get(phase)??'::error title=Compliance browser phase failed::Observed phase: unavailable.');}catch{/* Diagnostics must not replace the original failure. */}
}
export function emitComplianceMigrationFailure(emit){
 try{emit('::error title=Compliance browser schema bootstrap failed::Observed branch: up-to-48 migration returned nonzero.');}catch{/* Preserve the existing handled-command failure. */}
}

const COMPLIANCE_API_CHILD_STAGES = new Set(['config-load', 'owned-inputs', 'storage-path', 'bounded-deadline', 'runtime-build', 'serve']);
export function emitComplianceAPIChildFailure(output, emit, startupError, childObservation) {
 let stage = 'unavailable';
 if (typeof output === 'string' && output.length <= 16_384 && (output.length !== 16_384 || !output.split('\n')[0].includes('ZASP_COMPLIANCE_API_FAILED_STAGE'))) {
  const lines = output.split('\n');
  const partial = lines.pop();
  const witnesses = lines.filter(line => line.includes('ZASP_COMPLIANCE_API_FAILED_STAGE'));
  if (witnesses.length === 1 && !partial.includes('ZASP_COMPLIANCE_API_FAILED_STAGE')) {
   const value = witnesses[0].slice('ZASP_COMPLIANCE_API_FAILED_STAGE='.length);
   if (COMPLIANCE_API_CHILD_STAGES.has(value) && witnesses[0] === `ZASP_COMPLIANCE_API_FAILED_STAGE=${value}`) stage = value;
  }
 }
 try { emit(`::error title=Compliance API startup failed::Observed child stage: ${stage}.`); } catch { /* Preserve the original readiness error. */ }
 if (stage === "runtime-build" && typeof output === "string" && output.length <= 16_384 && output.includes("ZASP_COMPLIANCE_API_FAILED_DEPENDENCY")) emitComplianceAPIDependencyFailure(output, emit);
 emitComplianceAPIStartupProgress(output, emit);
 emitComplianceAPIReadinessObservations(output, emit);
 if (startupError !== undefined) emitComplianceAPIStartupFailure(startupError, emit);
 emitComplianceAPIChildExit(childObservation, emit);
}

const joinedAPIObservations = new WeakSet();
const childSignals = new Set(['SIGABRT','SIGALRM','SIGBUS','SIGFPE','SIGHUP','SIGILL','SIGINT','SIGKILL','SIGPIPE','SIGQUIT','SIGSEGV','SIGTERM','SIGTRAP','SIGUSR1','SIGUSR2','SIGXCPU','SIGXFSZ']);
const fatalRanks = new Map([['unknown',0],['testfail',1],['panic',2],['runtimefatal',3],['testtimeout',4]]);

// Observe the actual child's streams and close event. Retain only bounded line
// prefixes and closed scalar facts; the existing raw-output parser is separate.
// startChild has no capture-overflow killer, so its outputLimitExceeded is false.
export function observeComplianceAPIChild(child) {
 if(!child||typeof child.once!=='function'||typeof child.stdout?.on!=='function'||typeof child.stderr?.on!=='function')return async()=>undefined;
 let joined,resolveJoined,characters=0,fatal='unknown';
 const completed=new Promise(resolve=>{resolveJoined=resolve;});
 const classify=line=>{
  let category='unknown';
  if(/^panic: test timed out after /.test(line))category='testtimeout';
  else if(/^fatal error: /.test(line))category='runtimefatal';
  else if(/^panic: /.test(line))category='panic';
  else if(/^--- FAIL: TestComplianceBrowserAPIProcess(?:[ /\t(]|$)/.test(line)||line==='FAIL')category='testfail';
  if(fatalRanks.get(category)>fatalRanks.get(fatal))fatal=category;
 };
 const streamObserver=()=>{
  let prefix='';
  return chunk=>{
   if(joined||(!Buffer.isBuffer(chunk)&&typeof chunk!=='string'))return;
   const text=typeof chunk==='string'?chunk:chunk.toString('utf8');
   characters=Math.min(16_385,characters+text.length);
   let offset=0;
   for(let end;(end=text.indexOf('\n',offset))>=0;){
    prefix+=text.slice(offset,Math.min(end,offset+1024-prefix.length));
    classify(prefix);prefix='';offset=end+1;
   }
   prefix+=text.slice(offset,offset+1024-prefix.length);
  };
 };
 const stdout=streamObserver(),stderr=streamObserver();
 child.stdout.on('data',stdout);child.stderr.on('data',stderr);
 child.once('close',(status,signal)=>{
  child.stdout.removeListener('data',stdout);child.stderr.removeListener('data',stderr);
  joined=Object.freeze({status:Number.isSafeInteger(status)&&status>=0&&status<=255?status:'unavailable',signal:signal===null?'none':childSignals.has(signal)?signal:'unavailable',outputLimitExceeded:false,truncated:characters>16_384,fatal});
  joinedAPIObservations.add(joined);resolveJoined(joined);
 });
 return async()=>{
  if(joined)return joined;
  // A readiness deadline while the child is still alive must never wait for
  // that lifetime. After actual exit, allow only a bounded inherited-pipe join.
  if(!(Number.isSafeInteger(child.exitCode)&&child.exitCode>=0)&&!(typeof child.signalCode==='string'&&child.signalCode.length>0))return undefined;
  let timer;
  try{return await Promise.race([completed,new Promise(resolve=>{timer=setTimeout(()=>resolve(undefined),2000);})]);}
  finally{clearTimeout(timer);}
 };
}

function emitComplianceAPIChildExit(observation,emit){
 if(!observation||!joinedAPIObservations.has(observation))return;
 try{emit(`::error title=Compliance API child exit::Observed exit=${observation.status}; signal=${observation.signal}; outputLimitExceeded=${observation.outputLimitExceeded}; truncated=${observation.truncated}; fatal=${observation.fatal}.`);}catch{/* Preserve the original readiness failure. */}
}

const COMPLIANCE_DEPENDENCY_PHASES = new Set(["audit-export", "authorization-components", "authorization-readiness", "compliance-export", "composition", "composition-authorization", "composition-inputs", "connector-lifecycle", "connector-oauth", "connector-providers", "connector-secrets", "construction-context", "core-postgres", "core-repositories", "current-authorization", "edge-middleware", "handler-composition", "identity-authenticator", "identity-repository", "identity-webhook", "native-identity-provider", "native-services", "operational-middleware", "policy-history", "policy-surface", "product-middleware", "production-handlers", "public-surface", "reference-providers", "runtime-inputs", "security-agent-postgres", "security-agent-repositories", "temporal-observer", "ticket-services"]);
export function emitComplianceAPIDependencyFailure(output, emit) {
 let phase = 'unavailable';
 if (typeof output === 'string' && output.length <= 16_384 && (output.length !== 16_384 || !output.split('\n')[0].includes('ZASP_COMPLIANCE_API_FAILED_'))) {
  const lines = output.split('\n'); const partial = lines.pop();
  const stages = lines.filter(line => line.includes('ZASP_COMPLIANCE_API_FAILED_STAGE'));
  const dependencies = lines.filter(line => line.includes('ZASP_COMPLIANCE_API_FAILED_DEPENDENCY'));
  if (stages.length === 1 && stages[0] === 'ZASP_COMPLIANCE_API_FAILED_STAGE=runtime-build' && dependencies.length === 1 && !partial.includes('ZASP_COMPLIANCE_API_FAILED_')) {
   const value = dependencies[0].slice('ZASP_COMPLIANCE_API_FAILED_DEPENDENCY='.length);
   if (COMPLIANCE_DEPENDENCY_PHASES.has(value) && dependencies[0] === 'ZASP_COMPLIANCE_API_FAILED_DEPENDENCY='+value) phase = value;
  }
 }
 try { emit('::error title=Compliance API dependency failed::Observed dependency phase: '+phase+'.'); } catch { /* Preserve the original readiness error. */ }
}

const COMPLIANCE_API_STARTUP_REASONS = new Set(['inputs', 'child-exited', 'canceled', 'deadline', 'body-limit']);
export function emitComplianceAPIStartupFailure(error, emit) {
 let reason = 'unavailable';
 try {
  if (error instanceof OwnedAPIStartupError) {
   for (const value of COMPLIANCE_API_STARTUP_REASONS) {
    if (error.message === `owned API startup refused: ${value}`) reason = value;
   }
  }
 } catch { /* Untrusted error properties do not replace the readiness failure. */ }
 try { emit(`::error title=Compliance API readiness failed::Observed readiness reason: ${reason}.`); } catch { /* Preserve the original readiness error. */ }
}

// Only complete, unique fixture watchdog witnesses may cross into CI annotations.
// The watchdog never emits its private stack sample or arbitrary error content.
export function emitComplianceAPIStartupProgress(output, emit) {
 if (typeof output !== 'string' || output.length > 16_384) return;
 const lines = output.split('\n'); const partial = lines.pop();
 const prefix = 'ZASP_COMPLIANCE_API_PROGRESS=';
 const witnesses = lines.filter(line => line.includes(prefix));
 if (witnesses.length !== 1 || partial.includes(prefix) || (output.length === 16_384 && lines[0].includes(prefix))) return;
 const match = /^ZASP_COMPLIANCE_API_PROGRESS=(runtime-build|serve|unavailable);ACTIVE=(current-projection|authorization-readiness|postgres-connect|native-services|composition|serve|unavailable)$/.exec(witnesses[0]);
 if (!match || match[0] !== witnesses[0]) return;
 try { emit(`::error title=Compliance API startup progress::Observed startup phase: ${match[1]}; active application class: ${match[2]}.`); } catch { /* Preserve readiness failure. */ }
}

const constructorReadinessPhases=new Set(['maintenance-owner','connector-config','connector-authorizer','connector-key','connector-pool','connector-executor','connector-authority','connector-repository','connector-reconciler','approval-config','approval-authorizer','approval-key','approval-pool','approval-executor','approval-reconciler']);
// These fixed fixture outcomes describe failed readiness; they are never a
// substitute for the original readiness result or deployed acceptance.
export function emitComplianceAPIReadinessObservations(output, emit) {
 if (typeof output !== 'string' || output.length > 16_384) return;
 const prefix = 'ZASP_COMPLIANCE_READINESS=';
 const lines = output.split('\n'); const partial = lines.pop();
 const witnesses = lines.filter(line => line.includes(prefix));
 if (witnesses.length === 0 || witnesses.length > 16 || partial.includes(prefix) || (output.length === 16_384 && lines[0].includes(prefix))) return;
 const observations = new Set();
 for (const line of witnesses) {
  const match = /^ZASP_COMPLIANCE_READINESS=([a-z-]+):(passed|refused|deadline|cancelled)$/.exec(line);
  if (!match || match[0] !== line || (!['services','core-metadata','security-agent-metadata','components'].includes(match[1]) && (!constructorReadinessPhases.has(match[1]) || match[2]==='passed'))) return;
  const value = match[1] + ':' + match[2];
  if (observations.has(value)) return;
  observations.add(value);
 }
 try { emit('::error title=Compliance API readiness observations::Observed fixed outcomes: ' + [...observations].sort().join(', ') + '.'); } catch { /* Preserve the original readiness failure. */ }
}
