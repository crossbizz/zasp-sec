import {spawn} from 'node:child_process';
import fs from 'node:fs';
const base='.superpowers/sdd/2026-09-18-compliance-production-plan';
const node='/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node';
const env={...process.env,PATH:'/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin',GOTOOLCHAIN:'local',GOPROXY:'off',GOSUMDB:'off',GOCACHE:'/private/tmp/zasp-budget-go-cache'};
const names=['ConflictClassification','PersistedAttributionAndHistoricalBytes','PersistedEmptyFindingReferences','ExportBindsRequestedJobAndCanonicalFilters','ExportsRepository','HTTPMountedPublicLifecycle','HTTPMountedDenials','HTTPDownloadNoDisclosureBeforeConsume','HTTPStrictInputs','ReadFailureClassification','EvidenceStrictDecoding','RepositoryBindsScopeAndRejectsUnsafeInput','WorkerPersistedBytes','WorkerCleanupReceipt','WorkerHeartbeat','ReplayOutcomes','RuntimeRendersFrozenSnapshot','RuntimeCandidatesRejectUnsafeWire','RuntimeConfiguration','RuntimeComposedLifecycle','RuntimeListenerFailureJoinsPolling','StorageFactoryBoundary','APIProductionComposition','APIConfiguration','ExplicitReleaseCommands'];
const pattern='^TestCompliance('+names.join('|')+')$|^TestRegisterForwardRelease(ChecksExactSchemaAfterPrincipals|StopsOnFailedAuthorityOrReadiness)$';
const packages=['./apiserver','./agentsec-worker','./agentsec-api','./agentsec-migrate'];
const nodeTests=['scripts/browser-prerequisites.test.mjs','scripts/browser-e2e-helpers.test.mjs','scripts/production-combined-e2e.test.mjs','scripts/owned-command.test.mjs','scripts/owned-browser-postgres.test.mjs','scripts/bounded-signal-cleanup.test.mjs','scripts/compliance-browser-bytes.test.mjs','openapi/openapi.test.mjs','openapi/generated-client.test.mjs','openapi/identity-admin.test.mjs'];
async function run(label,exe,args,cwd=process.cwd()){
 label+=process.argv[3]??'';
 const log=fs.createWriteStream(`${base}/connected-fix-${label}.log`);
 const command=JSON.stringify({exe,args,cwd});fs.appendFileSync(`${base}/connected-fix-commands.jsonl`,command+'\n');console.log('START '+label+' '+command);
 const child=spawn(exe,args,{cwd,env,stdio:['ignore','pipe','pipe']});for(const stream of [child.stdout,child.stderr])stream.on('data',chunk=>log.write(chunk));
 const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve);});await new Promise(resolve=>log.end(`\nEXIT_STATUS=${code}\n`,resolve));console.log('END '+label+' exit='+code);if(code!==0)throw new Error(label+' failed');
}
switch(process.argv[2]){
 case 'ui':await run('ui',node,['node_modules/vitest/vitest.mjs','run','--reporter=dot']);break;
 case 'node':await run('node',node,['--test',...nodeTests]);await run('openapi-check','npm',['run','openapi:check']);await run('openapi-lint','npm',['run','openapi:lint']);break;
 case 'contract':await run('openapi-check','npm',['run','openapi:check']);await run('openapi-lint','npm',['run','openapi:lint']);break;
 case 'go':await run('go-enumeration','/opt/homebrew/bin/go',['test',...packages,'-list',pattern],process.cwd()+'/services/platform');await run('go-race','/opt/homebrew/bin/go',['test','-race',...packages,'-run',pattern,'-count=1','-v'],process.cwd()+'/services/platform');break;
 case 'build':await run('types',node,['node_modules/typescript/bin/tsc','--noEmit']);await run('lint','npm',['run','lint']);await run('harness-lint',node,['node_modules/eslint/bin/eslint.js','scripts/production-combined-e2e.mjs']);await run('build','npm',['run','build']);break;
 case 'browser':env.ZASP_COMBINED_E2E_COMPLIANCE='true';await run('browser',node,['scripts/production-combined-e2e.mjs']);break;
 default:throw new Error('choose ui/node/go/build/browser');
}
