const phases=new Set(['unattributed','state-allocation','retained-input','retained-roots','retained-allocation-observe','retained-startup-budget','retained-sampler-start','retained-temporal-custody','retained-openfga-custody','retained-service-start','retained-sampled-resource','retained-cleanup','service-input','service-tool-capabilities','service-model-bytes','service-tool-verification','service-root-create','service-token-generate','service-token-file','service-ports','service-temporal-start','service-openfga-start','service-temporal-namespace','service-temporal-listener','service-openfga-http-listener','service-openfga-grpc-listener','service-openfga-listeners','service-openfga-health','service-openfga-store','service-model-publish','service-model-readback','service-model-equality','service-startup-cleanup']);
const kinds=new Set(['refused','cleanup-incomplete']);
const observations=new WeakMap();
const object=value=>value!==null&&(typeof value==='object'||typeof value==='function');
export function recordOwnedRuntimeStartupFailure(error,phase,kind='refused'){
 if(object(error)&&phases.has(phase)&&kinds.has(kind)&&!observations.has(error))observations.set(error,Object.freeze({phase,kind}));
 return error;
}
export function carryOwnedRuntimeStartupFailure(original,replacement){
 const value=object(original)?observations.get(original):undefined;
 if(value&&object(replacement)&&!observations.has(replacement))observations.set(replacement,value);
 return replacement;
}
export function describeOwnedRuntimeStartupFailure(error){return object(error)?observations.get(error)??null:null;}
export function ownedRuntimeStartupFailureAnnotation(error){
 const value=describeOwnedRuntimeStartupFailure(error)??{phase:'unattributed',kind:'refused'};
 return `::error::Observed owned runtime startup: phase=${value.phase}; failure=${value.kind}.\n`;
}
export async function withOwnedRuntimeStartupDiagnostics(action,enabled,emit=text=>process.stdout.write(text)){
 try{return await action();}catch(error){if(enabled){try{emit(ownedRuntimeStartupFailureAnnotation(error));}catch{/* Diagnostic emission cannot replace the original startup refusal. */}}throw error;}
}
