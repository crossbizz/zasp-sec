import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import ts from 'typescript';
const helper=await import('./browser-command-failure.mjs');
const source=fs.readFileSync(new URL('./production-combined-e2e.mjs',import.meta.url),'utf8');
const tree=ts.createSourceFile('published.mjs',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS);
assert.equal(tree.parseDiagnostics.length,0);
const mounted=tree.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text==='exerciseComplianceBrowser');
const startAPI=mounted.body.statements.find(n=>n.getText(tree).startsWith('const startAPI=async(')).getText(tree);
const stages=['config-load','owned-inputs','storage-path','bounded-deadline','runtime-build','serve'];
const marker=stage=>`ZASP_COMPLIANCE_API_FAILED_STAGE=${stage}`;
const expected=stage=>`::error title=Compliance API startup failed::Observed child stage: ${stage}.`;
test('closed child marker parser emits only six fixed failed stages',()=>{
 assert.equal(typeof helper.emitComplianceAPIChildFailure,'function');
 for(const stage of stages){const emitted=[];helper.emitComplianceAPIChildFailure(`CANARY_SECRET\n${marker(stage)}\nFAIL CANARY_DSN`,v=>emitted.push(v));assert.deepEqual(emitted,[expected(stage)]);}
});
test('missing malformed duplicate ambiguous and oversized evidence refuses without raw values',()=>{
 assert.equal(typeof helper.emitComplianceAPIChildFailure,'function');
 for(const output of ['CANARY_SECRET',marker('CANARY_URL'),`${marker('config-load')}\n${marker('serve')}`,`${marker('serve')}\n${marker('serve')}`,`prefix ${marker('serve')}`,`${marker('serve')} CANARY`,`${marker('serve')}\n${marker('UNKNOWN')}`,`\t${marker('serve')}`,null,{},'x'.repeat(16385)]){const emitted=[];helper.emitComplianceAPIChildFailure(output,v=>emitted.push(v));assert.deepEqual(emitted,[expected('unavailable')]);}
});
function parsedCatch({stage='runtime-build',mode=true,emitterFails=false}){
 const calls=[],emitted=[],owned=Error('CANARY_WAIT_SECRET'),wrappers=[];
 const execute=new Function('startChild','waitForOwnedAPIStartup','apiEnvironment','apiBinary','healthPort','complianceBrowserMode','emitComplianceAPIChildFailure','console','Error',`return(async()=>{let api;let compliancePhase='browser-assertions';${startAPI}try{await startAPI(false);}catch(error){return {error,phase:compliancePhase};}})();`);
 const result=execute(()=>{calls.push('spawn');return {output:()=>{calls.push('output');return 'CANARY_SECRET\n'+(stage?marker(stage)+'\n':'unknown');}};},async()=>{calls.push('ready');throw owned;},{},'/owned/api',13,mode,helper.emitComplianceAPIChildFailure,{error:x=>{if(emitterFails)throw Error('CANARY_EMITTER');emitted.push(x);}},function(message){const error=Error(message);wrappers.push(error);return error;});
 return {result,calls,emitted,wrappers};
}
test('actual readiness catch emits fixed child stage preserving original wrapper and prior order',async()=>{
 for(const stage of [...stages,null]){const h=parsedCatch({stage});const result=await h.result;assert.equal(result.error,h.wrappers[0]);assert.equal(result.phase,'api-ready');assert.deepEqual(h.calls,['spawn','ready','output','output']);assert.deepEqual(h.emitted,[expected(stage??'unavailable'),'::error title=Compliance API readiness failed::Observed readiness reason: unavailable.']);assert.doesNotMatch(h.emitted.join(''),/CANARY|SECRET|URL/);}
});
test('other modes and emitter faults cannot replace the original readiness wrapper',async()=>{
 for(const options of [{mode:false},{emitterFails:true}]){const h=parsedCatch(options);const result=await h.result;assert.equal(result.error,h.wrappers[0]);assert.deepEqual(h.emitted,[]);assert.deepEqual(h.calls,options.mode===false?['spawn','ready','output']:['spawn','ready','output','output']);}
});
test('all actual published Go producer markers join the same closed parser roster',()=>{
 const go=fs.readFileSync(new URL('../services/platform/agentsec-api/compliance_browser_process_test.go',import.meta.url),'utf8');
 const start=go.indexOf('func complianceBrowserFailureMarker(');assert.ok(start>0);
 const returned=[...go.slice(start).matchAll(/return "(ZASP_COMPLIANCE_API_FAILED_STAGE=[^"]+)"/g)].map(match=>match[1]);
 assert.deepEqual(returned,[...stages,'unavailable'].map(marker));
 for(const output of returned){const emitted=[];helper.emitComplianceAPIChildFailure(output+'\n',x=>emitted.push(x));assert.deepEqual(emitted,[expected(output.slice('ZASP_COMPLIANCE_API_FAILED_STAGE='.length))]);}
});
test('actual sliced output refuses leading fragments and unterminated marker lines',()=>{
 const witnessed=marker('serve');const full='prefix '+witnessed+'\n'+'x'.repeat(16384-witnessed.length-1);const tail=full.slice(-16384);assert.equal(tail.length,16384);assert.ok(tail.startsWith(witnessed));
 for(const output of [tail,witnessed,'prefix\n'+witnessed,witnessed+'\n'+'x'.repeat(16384-witnessed.length-1)]){const emitted=[];helper.emitComplianceAPIChildFailure(output,x=>emitted.push(x));assert.deepEqual(emitted,[expected('unavailable')]);}
 const complete='x'.repeat(16384-witnessed.length-2)+'\n'+witnessed+'\n';const emitted=[];helper.emitComplianceAPIChildFailure(complete,x=>emitted.push(x));assert.deepEqual(emitted,[expected('unavailable')]);
});

test('exact tail boundary retains leading marker poison in ambiguous evidence refusal',()=>{
 for(const leading of [marker('serve'),marker('UNKNOWN'),'prefix '+marker('config-load')]){const trailing='\n'+marker('runtime-build')+'\n';const output=leading+'x'.repeat(16384-leading.length-trailing.length)+trailing;assert.equal(output.length,16384);const emitted=[];helper.emitComplianceAPIChildFailure(output,x=>emitted.push(x));assert.deepEqual(emitted,[expected('unavailable')]);}
});
