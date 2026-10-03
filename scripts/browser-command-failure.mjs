const CLASSES=new Map([
 ['build|./agentsec-migrate','go-migration-build'],
 ['test|-c|./agentsec-api','go-api-test-compile'],
 ['test|-c|./agentsec-worker','go-worker-test-compile'],
 ['build|./agentsec-worker','go-worker-build'],
 ['build|.','go-cli-build'],
]);
export function browserCommandFailureAnnotation(executable,args,kind){
 if(kind!=='deadline'&&kind!=='nonzero-exit')return null;
 let label='other-command';
 if(executable==='go'&&Array.isArray(args)){
  if(args.length===4&&args[0]==='build'&&args[1]==='-o'&&typeof args[2]==='string'&&typeof args[3]==='string')label=CLASSES.get('build|'+args[3])??label;
  if(args.length===5&&args[0]==='test'&&args[1]==='-c'&&args[2]==='-o'&&typeof args[3]==='string'&&typeof args[4]==='string')label=CLASSES.get('test|-c|'+args[4])??label;
 }
 return `::error title=Compliance browser command failed::Observed command class: ${label}; failure: ${kind}.`;
}

const PHASE_ANNOTATIONS=new Map(['services', 'command-builds', 'schema-bootstrap', 'browser-assertions', 'postgres-startup', 'postgres-instrumentation', 'postgres-principal-provisioning', 'compliance-fixture-provisioning', 'controlled-identity-startup', 'policy-history-startup', 'api-startup', 'api-ready', 'web-startup', 'web-ready', 'tls-provisioning', 'proxy-startup', 'browser-startup'].map(phase=>[phase,`::error title=Compliance browser phase failed::Observed phase: ${phase}.`]));
export function emitComplianceBrowserPhaseFailure(phase,emit){
 try{emit(PHASE_ANNOTATIONS.get(phase)??'::error title=Compliance browser phase failed::Observed phase: unavailable.');}catch{/* Diagnostics must not replace the original failure. */}
}
export function emitComplianceMigrationFailure(emit){
 try{emit('::error title=Compliance browser schema bootstrap failed::Observed branch: up-to-48 migration returned nonzero.');}catch{/* Preserve the existing handled-command failure. */}
}
