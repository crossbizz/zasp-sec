import { parseConnectorNativeObservation } from './connector-acceptance-groups.mjs';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, chmod, lstat, statfs, stat, readdir, symlink, realpath, rename } from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { observeHostedMemory } from './hosted-memory-observation.mjs';
import {openSync,writeSync,fsyncSync,closeSync,constants} from 'node:fs';
import { captureStart, observeOwnedListener } from './owned-listener.mjs';
import { spawnOwnedCommand } from './owned-command.mjs';
import { loadOfficialHeldTool, spawnHeldTool, closeHeldTool, verifyHeldTool } from './official-held-tools.mjs';

// Existing authenticated enqueue application group; no added cases, production credentials or deployment.
const image = 'postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba';
const pins = {
  "services/platform/agentsec-api/bounded_parallel_readiness_test.go": "4a82a77cf64184177b7f7bde1ee56d736e5d9bd6624b7174e9f45e9a48043951",
  "services/platform/agentsec-api/authorization_runtime_readiness.go": "33d0478de4ed7db1b79ad12fe63fb117965bb95cef770f999ab4ef35f015284d",
  "services/platform/apiserver/authorization_readiness.go": "ad1a94117de4e63b9c7ef15faf4c4744e6a6675b44ad6da1d7991cb63fcb683a",
  "services/platform/apiserver/current_authorization_health_probe_test.go": "09361c7c963d5f3d508b9c534d92c5b7d6bcf2f19c4c46b8413088c0b974c593",
  "services/platform/apiserver/current_authorization_health_probe.go": "3bed74745ef1056405965605ea6c45b949e842bf29065e8665e7900ec3cd8a66",
  "services/platform/apiserver/connector_maintenance_catalog_diagnostic_test.go": "fb4add6de1bfad2e20311e5da0fb82f215eacb456ea588de8bbea2a890566868",
  "services/platform/agentsec-api/connector_callback_runtime.go": "69c0fe154628058709eaf886369e3aa92aee8a9526a1bebda091ad8147c6cd95",
  "services/platform/agentsec-api/connector_maintenance_runtime.go": "ac74dd00dc05e34e72a06962ad8d7a8f13d18bf64c0fe6e46fdbd520f4b09bab",
  "services/platform/agentsec-api/production_runtime.go": "e051cec9987f311462d7f3d6b63a9ee07373a9b2e82e5bee9d320bc627605a34",
  "services/platform/agentsec-api/runtime.go": "bace8cadfe7ab3f982cfc779ebff5493590a9156bf4a2cbdf31e7be82d69e975",
  "services/platform/agentsec-worker/authorization_worker_runtime.go": "18ed70e4f9a8efbefb6cb623f493465739a29de81cae4340e3629d0dda7a7abe",
  "services/platform/apiserver/connector_enqueue_provenance_postgres_test.go": "d6039cfa0d1673a5cf29e68e209b73c2cb6aeefd715e4d7805d3690b8ab0afde",
  "services/platform/apiserver/connector_handler.go": "e8a28640de67507a0676a882cc627bc20910d4fc55c606b08c9bc6663de76eb0",
  "services/platform/apiserver/connector_maintenance_callback_database.go": "68daa6030d5ad5e51dbcd95c5c7d3a77160dc74bafea1a986049b937bf787efc",
  "services/platform/apiserver/connector_maintenance_callback_resolver.go": "995c5238f7e4fa4a58a5d35218234600beaec374f67bb36f5a363a77357c7585",
  "services/platform/apiserver/connector_maintenance_enqueue_database.go": "df803820e44feadcbe41f4778cd50ee20edbfa1847fb82d0d9abcc39f3a962ac",
  "services/platform/apiserver/connector_maintenance_enqueue_postgres_test.go": "76da1cc4969e8ad84f3f61410e2be98e6ecc48facf1e42ec10b82ab66d93628e",
  "services/platform/apiserver/connector_maintenance_repository.go": "12ae3d8d18cda869818522852509340687372558fbbfb3ff1826171008d2b119",
  "services/platform/apiserver/connector_reconciler.go": "3170126141cde2be045e2a04727a1c9658a0100cfd610ea45ea3a7c5d359689d",
  "services/platform/authorization/connector_maintenance_projection.go": "e9189565c21f4d16c3f06c3cf89b35e57b1cef5e5bb51b1ff49da02349dcd7b8",
  "services/platform/authorization/worker_current_maintenance.go": "77e382687cc15c54bd3065a10caeb607921c7ee89f3f6ad373c8d645c01d9246",
  "services/platform/cmd/zasp-authorization-reconcile/main.go": "bdaa8815eb14bf35e19d4a5e76764f623ce0277c9d04ebfbfc9f120dba244a6d",
  "services/platform/connectormaintenance/authority.go": "378b2b151fe9978ca28a3c40d024c52bff7d3f0b83267839ef1dd61ee3946441",
  "services/platform/connectormaintenance/executor.go": "24ac12fb20e753ec433464e6220bc7aaf4127fb9e7e3803831553bb75e7a40f3",
  "services/platform/connectormaintenancecutover/coordinator.go": "d2867a6154c9df7b00a6e575d08cdcf33e6e7bf1d71b493baa7428334af286fe",
  "services/platform/connectormaintenancecutover/fga.go": "d3b9b4bea7f707e802c11e62c3e331477a3ff23a5f8d2049125155fd9e2bcb46",
  "services/platform/connectormaintenancecutover/model.json": "329f49e1f2effecbe1a0e9caf6c89be939b1e36e034155d74977bfc82c73cc2c",
  "services/platform/connectormaintenancecutover/process_linux.go": "6096f7c304818c7e6ebc31d3940bacf75932b9f2971c8c529316ebee92cede54",
  "services/platform/connectormaintenancecutover/raw_model.go": "4a5732177b025ec3e7306dd1186c2c358d59a3b7df235e53e12f34384ecc6d3e",
  "services/platform/connectormaintenancecutover/sql.go": "baaa4fe83a4689b053387fc7a8a3abe34d6130384d4197e244aab1c21f5a20b8",
  "services/platform/migrations/production_connector_enqueue_provenance.go": "793b230a8572fbfbed2a4702e1513bfa90afac596a8d0707ae047bbdf8bacc36",
  "services/platform/migrations/production_connector_maintenance.go": "18b0989e395e85f18a78f5f51aee06eb1f969fba79a66650754bfc3858d055cd",
  "services/platform/migrations/sql/connector_enqueue_provenance.sql": "32b3f8cbe175b5256ff4542cdff044d6d060e0240d24632bf3d057f3553a5c13",
  "services/platform/migrations/sql/connector_maintenance_profile.sql": "966bfbeba5976b2c7edb78853b884e118955462eba5e8b627c21a12e1449bdef",
  "services/platform/runtimeservices/config.go": "5cd087e846c9106c07c0734f06937e727c25fb04887dbfdf8d78da4c70e48731",
  "services/platform/migrations/production_approval_maintenance_profile.go": "2e98fa960c2e7b42b2a6a343b4ff47059c0d23fac83dbed887d2868f1b9c99f3",
  "services/platform/migrations/production_approval_maintenance_successor.go": "6817964c5c0dfcabe7ea9f65caf5b7840f6d9e4d29a1ec39b00e1b03b0fa6eca",
  "services/platform/migrations/production_approval_maintenance_profile_test.go": "5592e136c7578bac21bf698c675762b28b68b46a37b1d2ed7670e2d707150a6a",
  "services/platform/connectormaintenancecutover/readback_defaults.json": "d4c42d89fa77b89513e732b6d5bdd206c808111096307d38784cc6f1ba639835",
  "services/platform/connectormaintenancecutover/readback_test.go": "e4970d8ef25f042e9948abb5cbb0557c32988a50bd80b3bcddd6c8f74a8da23a",
  "services/platform/agentsec-migrate/main.go": "f9bccafecba7ceb576f1673a369143d49ec807bc30ef438e4103543467ca234e",
  "services/platform/agentsec-migrate/maintenance_profile_commands_test.go": "d972fdf1601462a73bf98a08fbc085ec57b31ffec63180f25e45a38695779119",
  "services/platform/agentsec-worker/authorization_worker_activation_config_test.go": "3b66404d7740592ad2c42e6491861e26f11788b3b6be0b7e68cbe9a6c20bca23",
  "services/platform/apiserver/approval_activation_postgres_test.go": "4a40ff1c879cd4c1af951ba8bc812d0d9ea81a360c856fcde4235b63581ae6e5",
  "services/platform/apiserver/connector_maintenance_callback_restart_postgres_test.go": "fe1f04ee8d9d6c78814a05df0fb976f4aedd5f1667e648c5342fbc14ea1d46bf",
  "services/platform/apiserver/connector_maintenance_lifecycle_postgres_test.go": "bfa570c34198136d1d3d88909e08ef6b0737abcee7465b0617f1fe2b3b4f35c0",
  "services/platform/apiserver/connector_maintenance_pkce_recovery_test.go": "c9f81b86c14f4fa76c24a830371cdec7ce8ac5d2b1a34fee4a994719d3c6a797",
  "services/platform/authorization/worker.go": "6717074205fbaf48d970b1a6bdbc6613779d492a388c6d6446fe78608ff3efe4",
  "services/platform/authorization/worker_approval_activation_test.go": "15e44850678ba5b9b385023555fcc501eca600c53c1f912dbf799841387d7b0b",
  "services/platform/authorization/worker_approval_origin.go": "6f83d9f2998fdf8d94beb69e3c4c15fe11037a8bb386303a831f5f1dfee8a69f",
  "services/platform/cmd/zasp-authorization-reconcile/hold_test.go": "07465bbdeb1bcb66a865f855279fe1b764063aba0f17bbcdfecb5726eef9ffe6",
  "services/platform/cmd/zasp-controlled-maintenance-cutover/main.go": "90a0e4a39acaf006571f2a3a610bf1b8b4881c39645fbea10cb5c81290eea5e8",
  "services/platform/cmd/zasp-controlled-maintenance-cutover/main_test.go": "a8e1b3d97076b74daa29f60e117b9ca0f370bcd627d9819152b418c992e8da74",
  "services/platform/cmd/zasp-maintenance-register/main.go": "f2f2ac05671b7738f3c12b1206e7865cff514606189da3a82c888732acd60fc9",
  "services/platform/cmd/zasp-maintenance-register/main_test.go": "5ae1660fd2e5de9961c459d619cf291ae6d730896d9126c2074f68ed2c8069c0",
  "services/platform/connectormaintenancecutover/combined.go": "b841c26caee24f7948d43ec72b1b2d2dc53ce0661845af73a9f417ae93091f84",
  "services/platform/connectormaintenancecutover/coordinator_test.go": "26ce6254da116eb381365e2c90ae97e4c7366d829168e5a55438b40dc8ba9a90",
  "services/platform/migrations/production_approval_activation_profile.go": "a770b962f1c3f3622a368d32d19f865231f458a1c36d2db764056fb60f6faea2",
  "services/platform/migrations/production_approval_activation_profile_test.go": "4d1c29736e796e8e9deecd7845a0ad6ba2e3948043427e2cc88c57b32fdfdf16",
  "services/platform/migrations/sql/approval_activation_profile.sql": "f256e35509c6573b85fda9babb8e5d87641927c5246d5d1408f98a0159cd139d",
  "services/platform/runtimeservices/approval_activation_config_test.go": "d288ebc83684b8d49bdfab4fabb30bf4e65dc530f327ea06e205c415bd7195df",
  "services/platform/apiserver/approval_activation_flow_test.go": "2d6a704c607d9d222760a490eec2e1717825bbcb962c66a954a01e43b023ac49",
  "services/platform/apiserver/connector_preparation_stage_test.go": "338c9d4717d2c505f3af9d153d3dfcd58a4027a98c7232e0daa4316bfd466e37"
};
const top='TestConnectorMaintenanceAuthenticatedOAuthEnqueuePostgres';
const cases=['genuine_same_transaction_origin_and_immutable_enrichment','rollback_removes_every_enqueue_and_provenance_write'];
const helperPins={
  "scripts/connector-acceptance-groups.test.mjs": "a246ad0a5086babec48fc9a662f1828eb983e92169baeaaf8fcf898bbaddb6d8",
  "scripts/connector-acceptance-groups.mjs": "2fc9c54b8076ea344b2ad9897d8cbea99cc546547c551965c1e5ffa87db05429",
  "docs/internal/evidence/cloud-2026-10-07/native-service-readiness/openfga/09-pg-non-glibc-libs-manifest.json": "96642e82997ffd2caf2893a5ecc0116ad2aef6e982df2d929f3efda4e04f3474",
  "services/platform/apiserver/authorization_integration_mutations_postgres_test.go": "5e4beb04b2409ad9b11b89c017ada5e2eccffd78a87bdd5692d40670f12a2ba0",
  "scripts/hosted-memory-observation.mjs": "70c2ae837d040be4756842e4016acbc4eebd6bae3d8c992aba2a80e2a097ba75",
  "scripts/owned-command.mjs": "50b5481d008546a713ac730cb933108be66b2f08226ced8bc47deaea14e95ec8",
  "scripts/owned-fixed-fd-command.mjs": "15c38bd9d627124b7d81e5fe9b96dd3c4af8757b33f2204a9dce4b86e93e5693",
  "scripts/official-held-tools.mjs": "451dad7212561fc02e1f5b03280672c9d900a5ac644a665c022deafa9f72dfdd",
  "scripts/owned-listener.mjs": "3e5a4357fb53a412d0c38ab608c49543cf1bf74b2bb624022791a8bb6d1a43de",
  "services/platform/apiserver/postgres_integration_test.go": "0d908c53cdea021e4c60adc412a04d631fd58c0b0544e7cce723884ea4002a42",
  "services/platform/apiserver/approval_maintenance_owned_fga_test.go": "e505c27d07bde5948d7ec4f4612ffc28ccb2b68f37bebc842e91cec0d5066647"
};
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const root=process.cwd();const selfSHA256=hash(await readFile(new URL(import.meta.url)));
assert.equal(process.version,'v22.23.1');
assert.ok(path.isAbsolute(process.env.RUNNER_TEMP??''));
const out=await mkdtemp(path.join(process.env.RUNNER_TEMP,'connector-authenticated-enqueue-'));
const end=performance.now()+1500_000;
let tokenForRedaction='', canceled=false, finished=false, refused=false, container, tool, fga, fgaPort, grpcPort, fgaStart;
const owners=new Set();let phase='source-admission';
const receipt={scope:'authenticated OAuth enqueue captured-inactive application integration only',completed:false,activated:false,production:false,testPins:pins,helperPins,selfSHA256,pgImage:image,commands:[],authStatuses:[],normalCleanup:false};
function lateRefusal(reason){let fd;try{fd=openSync(path.join(out,'late-refusal.json'),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);const bytes=Buffer.from(JSON.stringify({completed:false,reason})+'\n');let offset=0;while(offset<bytes.length){const written=writeSync(fd,bytes,offset,bytes.length-offset);assert.ok(written>0);offset+=written;}fsyncSync(fd);closeSync(fd);fd=undefined;const directory=openSync(out,constants.O_RDONLY|constants.O_DIRECTORY);try{fsyncSync(directory);}finally{closeSync(directory);}}catch{/* Refusal or bounded retry is handled by the enclosing guard. */}finally{if(fd!==undefined)try{closeSync(fd);}catch{/* Refusal or bounded retry is handled by the enclosing guard. */}}}
function signal(){canceled=true; if(finished){lateRefusal('late-signal');process.exit(1);} for(const owner of owners)void owner.stop().catch(()=>{refused=true;});}
process.on('SIGTERM',signal);process.on('SIGINT',signal);
function failureClass(error){return ['ENOENT','EACCES','EPERM','ENOSPC','ETIMEDOUT','ECONNREFUSED','ERR_ASSERTION'].includes(error?.code)?error.code:'other-refusal';}
function guard(){assert.ok(!canceled&&!refused&&performance.now()<end,'owned integration refused');}
async function floors(){
 const values={workspaceFreeBytes:null,scratchFreeBytes:null,memoryHeadroomBytes:null};let step='workspace-statfs';
 try{
  for(const [dir,min,key]of [[root,1500000000,'workspaceFreeBytes'],[out,100000000,'scratchFreeBytes']]){step=key==='workspaceFreeBytes'?'workspace-statfs':'scratch-statfs';const v=await statfs(dir);values[key]=v.bavail*v.bsize;step=key==='workspaceFreeBytes'?'workspace-floor':'scratch-floor';assert.ok(values[key]>=min);}
  step='portable-memory-observation';const observation=await observeHostedMemory();const available=observation.availableBytes;receipt.memoryObservationBasis=observation.basis;receipt.memoryObservation={hostAvailableBytes:observation.hostAvailableBytes,finiteAncestorLimits:observation.finiteAncestorLimits,visibleGroupsObserved:observation.visibleGroupsObserved};
  values.memoryHeadroomBytes=available;step='memory-floor';assert.ok(available>=268435456);receipt.resourceSnapshot=values;
 }catch(error){receipt.resourceSnapshot=values;receipt.resourceRefusal={step,class:failureClass(error)};throw error;}
}
let sampling, samplingStopped=false;const sampler=setInterval(()=>{if(samplingStopped||sampling)return;sampling=floors().catch(()=>{refused=true;for(const owner of owners)void owner.stop().catch(()=>{});}).finally(()=>{sampling=undefined;});},250);const aggregateTimer=setTimeout(()=>{refused=true;for(const owner of owners)void owner.stop().catch(()=>{});},1500_000);
const closed={PATH:process.env.PATH,LANG:'C.UTF-8',HOME:path.join(out,'home'),TMPDIR:out,GOENV:'off',GOWORK:'off',GOTOOLCHAIN:'local',GOFLAGS:'',GOPRIVATE:'',GONOPROXY:'',GONOSUMDB:'',GOSUMDB:'sum.golang.org',GOPROXY:'https://proxy.golang.org',GOCACHE:path.join(out,'go-cache'),GOMODCACHE:path.join(out,'module-cache'),GOMEMLIMIT:'256MiB',GOGC:'20',GOMAXPROCS:'2',PGOPTIONS:'-c jit=off'};
for(const key of ['HTTPS_PROXY','HTTP_PROXY','NO_PROXY','https_proxy','http_proxy','no_proxy','SSL_CERT_FILE','CURL_CA_BUNDLE'])if(typeof process.env[key]==='string')closed[key]=process.env[key];
function postgresFailureCategories(output){const categories=[['initdb:','initdb-command-refused'],['postgres did not become ready:','server-readiness-refused'],['error while loading shared libraries:','child-shared-library-loader'],['cannot be run as root','root-user-refused'],['Permission denied','filesystem-permission-refused'],['permission denied','filesystem-permission-refused'],['could not access directory','required-directory-unavailable'],['No such file or directory','required-file-unavailable'],['does not belong to PostgreSQL','share-file-version-refused'],['is not the same version as initdb','backend-version-refused'],['could not execute command','backend-exec-refused'],['GLIBC_PRIVATE','glibc-private-linkage-refused'],['invalid locale','locale-refused'],['could not load library','postgres-extension-library-refused'],['owned PostgreSQL cleanup failed:','owned-pg-cleanup-refused'],['not the same version as initdb','backend-version-refused'],['symbol lookup error','child-symbol-lookup-refused'],['GLIBC_','glibc-symbol-version-observed'],['not found in the same directory','backend-sibling-unavailable']];const labels=[];for(const [pattern,label]of categories)if(output.includes(pattern)&&!labels.includes(label))labels.push(label);return labels;}
function initdbDiagnostic(stderr){
 // Only the pinned tool's pre-credential local error lines; never FGA/API output.
 assert.equal(tokenForRedaction,'');
 const lines=stderr.split(/\r?\n/).filter(line=>line.startsWith('initdb:')).slice(0,4);
 for(let line of lines){line=line.replaceAll(out,'[owned-runtime]');for(const key of ['HTTPS_PROXY','HTTP_PROXY','NO_PROXY','https_proxy','http_proxy','no_proxy'])if(typeof closed[key]==='string'&&closed[key])line=line.replaceAll(closed[key],'[redacted-env]');line=line.slice(0,512).replaceAll('%','%25').replaceAll('\r','%0D').replaceAll('\n','%0A');console.log('::notice title=Owned initdb diagnostic::'+line);}
}
function nativeDiagnostic(result,timed){
 const allowed=[top,...cases.map(name=>top+'/'+name)];const diagnostic={status:Number.isInteger(result.status)?result.status:null,signal:['SIGTERM','SIGKILL','SIGINT','SIGABRT','SIGSEGV'].includes(result.signal)?result.signal:null,timed,outputLimitExceeded:result.outputLimitExceeded,counts:{run:0,pass:0,fail:0,skip:0},failedCases:[],locations:[],jsonMalformed:false,fixtureStages:[],sqlStates:[],canonicalVersions:[],fixtureErrorCategory:null,postgresCategories:[],migrationDiagnostics:[],rollbackDiagnostic:null,catalogDiagnostic:null,catalogKinds:[],cutoverPrepareStages:[],cutoverActivationStages:[],preparationStages:[]};
 const fixedStages=["postgres-start", "postgres-connect", "canonical-install", "fixture-data", "projection-pool", "owned-fga-model", "tuple-writer", "fga-checker", "projection-configure", "projection-reconcile", "registered-api-connect", "registered-api-role", "database-current-authority", "browser-authentication", "token-authentication", "authorization-resolver", "connector-registry", "reference-registry", "workflow-handler", "router", "canonical-cutover", "data-plane-roles", "data-plane-principals", "current-authorization-modules", "execution-roles", "execution-principals", "temporal-authorization-modules", "current-authorization-replay", "verifier-registration"];const locations=new Set();for(const line of result.stdout.split('\n').filter(Boolean)){let row;try{row=JSON.parse(line);}catch{diagnostic.jsonMalformed=true;continue;}if(allowed.includes(row.Test)&&['run','pass','fail','skip'].includes(row.Action)){diagnostic.counts[row.Action]++;if(row.Action==='fail')diagnostic.failedCases.push(row.Test);}if(typeof row.Output==='string'){
 const observed=parseConnectorNativeObservation(row.Output);if(observed?.kind==='catalog-summary'&&diagnostic.catalogDiagnostic===null)diagnostic.catalogDiagnostic=observed.value;else if(observed?.kind==='catalog-object'&&diagnostic.catalogKinds.length<9&&!diagnostic.catalogKinds.some(value=>value.kind===observed.value.kind))diagnostic.catalogKinds.push(observed.value);else if(observed?.kind==='cutover'&&diagnostic.cutoverPrepareStages.length<4&&!diagnostic.cutoverPrepareStages.includes(observed.stage))diagnostic.cutoverPrepareStages.push(observed.stage);else if(observed?.kind==='activation'&&diagnostic.cutoverActivationStages.length<4&&!diagnostic.cutoverActivationStages.includes(observed.stage))diagnostic.cutoverActivationStages.push(observed.stage);else if(observed?.kind==='preparation'&&diagnostic.preparationStages.length<4&&!diagnostic.preparationStages.includes(observed.stage))diagnostic.preparationStages.push(observed.stage);


 for(const label of postgresFailureCategories(row.Output))if(!diagnostic.postgresCategories.includes(label))diagnostic.postgresCategories.push(label);

 for(const match of row.Output.matchAll(/connector migration phase=(worker-profile|approval-profile|connector-profile|oauth-competing-attempt|oauth-first-attempt) statement=(oauth-admission|private-query|approval-definitions|connector-definitions|capture-definitions|namespace-bootstrap|organization-reference|registration-insert|authority-selection) SQLSTATE=([0-9A-Z]{5}) target=(unknown|zasp_organizations|zasp_security_agent_approval_notifications|zasp_authorization80_worker|zasp_authorization80_temporal|zasp_temporal78|zasp_approval_maintenance|zasp_connector_provenance|zasp_connector_maintenance|zasp_discovery_authority|registration) position=([0-9]{1,7}) reason=(unknown|attestation|fence|scope|oauth-catalog|oauth-registration|oauth-fingerprint|oauth-provenance|oauth-principal|oauth-source|cleanup-source|oauth-expired|task-purpose|task-source|task-witness)(?:\s|$)/g))if(diagnostic.migrationDiagnostics.length<16&&Number(match[5])<=2000000)diagnostic.migrationDiagnostics.push({phase:match[1],statement:match[2],sqlState:match[3],target:match[4],position:Number(match[5]),reason:match[6]});
 for(const match of row.Output.matchAll(/connector fixture stage=([a-z-]+)/g))if(fixedStages.includes(match[1])&&diagnostic.fixtureStages.length<32)diagnostic.fixtureStages.push(match[1]);
 for(const match of row.Output.matchAll(/connector fixture SQLSTATE=([0-9A-Z]{5})(?:\s|$)/g))if(diagnostic.sqlStates.length<16)diagnostic.sqlStates.push(match[1]);
 for(const match of row.Output.matchAll(/failed after canonical version ([0-9]{1,4})(?:\s|$)/g))if(diagnostic.canonicalVersions.length<16)diagnostic.canonicalVersions.push(Number(match[1]));
 if(row.Output.includes('connector rollback result=admitted'))diagnostic.rollbackDiagnostic='admitted';else if(row.Output.includes('connector rollback result=non-postgres-error'))diagnostic.rollbackDiagnostic='non-postgres-error';
 if(row.Output.includes('connector fixture errorCategory=non-postgres-or-unclassified'))diagnostic.fixtureErrorCategory='non-postgres-or-unclassified';
 for(const match of row.Output.matchAll(/(?:connector_maintenance_enqueue_postgres_test|connector_enqueue_provenance_postgres_test|authorization_integration_mutations_postgres_test|authorization_projection_fga_test|approval_maintenance_owned_fga_test|postgres_integration_test)\.go:[0-9]{1,6}:/g))locations.add(match[0].slice(0,-1));}
}
 diagnostic.locations=[...locations].slice(0,16);diagnostic.failedCases=diagnostic.failedCases.slice(0,10);receipt.nativeDiagnostic=diagnostic;
 const scalar=n=>Number.isInteger(n)?String(n):'unobserved';console.log('::notice title=Connector native command outcome::status='+scalar(diagnostic.status)+'; timed='+String(timed)+'; signal='+(diagnostic.signal??'none')+'; cap='+String(diagnostic.outputLimitExceeded)+'; namedRUN='+diagnostic.counts.run+'; namedPASS='+diagnostic.counts.pass+'; namedFAIL='+diagnostic.counts.fail+'; namedSKIP='+diagnostic.counts.skip+'; failedCases='+diagnostic.failedCases.join(',')+'; sourceLocations='+diagnostic.locations.join(',')+'; postgresCategories='+diagnostic.postgresCategories.join(',')+'; fixtureStages='+diagnostic.fixtureStages.join(',')+'; SQLSTATE='+diagnostic.sqlStates.join(',')+'; canonicalVersions='+diagnostic.canonicalVersions.join(',')+'; fixtureErrorCategory='+(diagnostic.fixtureErrorCategory??'none')+'; rollbackDiagnostic='+(diagnostic.rollbackDiagnostic??'none')+'; migrationDiagnostics='+JSON.stringify(diagnostic.migrationDiagnostics)+'; catalogDiagnostic='+JSON.stringify(diagnostic.catalogDiagnostic)+'; catalogKinds='+JSON.stringify(diagnostic.catalogKinds)+'; cutoverPrepareStages='+diagnostic.cutoverPrepareStages.join(',')+'; cutoverActivationStages='+diagnostic.cutoverActivationStages.join(',')+'; preparationStages='+diagnostic.preparationStages.join(',')+'; JSONMalformed='+String(diagnostic.jsonMalformed)+'. No deployment readiness established.');
}
async function run(exe,args,seconds=60,env=closed,cleanup=false){if(!cleanup){guard();await floors();guard();}const owner=spawnOwnedCommand(exe,args,{cwd:root,env,maxOutputBytes:8*1024*1024});owners.add(owner);let timed=false;const timer=setTimeout(()=>{timed=true;void owner.stop().catch(()=>{refused=true;});},cleanup?seconds*1000:Math.min(seconds*1000,end-performance.now()));let result;
 try{result=await owner.completed;receipt.commands.push({command:exe==='docker'?'docker':path.basename(exe),status:result.status,signal:result.signal,outputLimitExceeded:result.outputLimitExceeded,stdoutBytes:Buffer.byteLength(result.stdout),stderrBytes:Buffer.byteLength(result.stderr),stdoutSHA256:hash(result.stdout),stderrSHA256:hash(result.stderr)});if(exe==='go'&&args[0]==='test')nativeDiagnostic(result,timed);if(['owned-initdb-tool-smoke','owned-raw-postgres-version-probe'].includes(phase)){const observation={status:result.status,signal:result.signal,timed,outputLimitExceeded:result.outputLimitExceeded,categories:postgresFailureCategories(result.stdout+'\n'+result.stderr),stdoutBytes:Buffer.byteLength(result.stdout),stderrBytes:Buffer.byteLength(result.stderr)};if(phase==='owned-initdb-tool-smoke')receipt.initdbToolSmoke=observation;else receipt.rawPostgresVersionProbe=observation;console.log('::notice title=Owned PostgreSQL prerequisite::phase='+phase+'; status='+String(result.status)+'; timed='+String(timed)+'; signal='+(result.signal??'none')+'; cap='+String(result.outputLimitExceeded)+'; categories='+observation.categories.join(',')+'. Tool compatibility only; no product test or deployment acceptance.');}if(phase==='owned-initdb-tool-smoke'&&result.status!==0)initdbDiagnostic(result.stderr);assert.ok(!timed&&(cleanup||!canceled)&&result.status===0&&!result.signal&&!result.outputLimitExceeded,'owned command refused');if(!cleanup)guard();return result;}
 finally{clearTimeout(timer);await owner.stop();owners.delete(owner);}
}
async function port(){const server=net.createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});const value=server.address().port;await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));return value;}
async function absent(pid){try{process.kill(pid,0);return false;}catch(error){assert.equal(error.code,'ESRCH');return true;}}
async function sessionEmpty(sid){const names=(await readdir('/proc')).filter(name=>/^[0-9]+$/.test(name));assert.ok(names.length<=8192);for(const name of names){let row;try{row=await readFile('/proc/'+name+'/stat','utf8');}catch(error){if(error.code==='ENOENT')continue;throw error;}assert.ok(row.length<=16384);const fields=row.slice(row.lastIndexOf(')')+1).trim().split(/\s+/);if(Number(fields[3])===sid)return false;}return true;}
async function bindable(value){const s=net.createServer();await new Promise((resolve,reject)=>{s.once('error',reject);s.listen(value,'127.0.0.1',resolve);});await new Promise(resolve=>s.close(resolve));}
async function auth(url,token){guard();const response=await fetch(url,{method:'GET',redirect:'error',signal:AbortSignal.timeout(5000),headers:token?{Authorization:'Bearer '+token}: {}});try{let bytes=0;for await(const chunk of response.body){bytes+=chunk.length;assert.ok(bytes<=65536);}return response.status;}finally{await response.body?.cancel().catch(()=>{});}}
async function sourcePins(){receipt.sourceBinding='runner-self';assert.equal(hash(await readFile(new URL(import.meta.url))),selfSHA256);for(const [file,pin]of Object.entries({...pins,...helperPins})){receipt.sourceBinding=file;assert.equal(hash(await readFile(path.join(root,file))),pin);}receipt.sourceBinding='all-pins-matched';}
try{
 phase='initial-resource-floor';await floors();phase='source-admission';await sourcePins();for(const name of ['home','go-cache','module-cache'])await mkdir(path.join(out,name),{mode:0o700});
 phase='go-tool-version';assert.match((await run('go',['version'],5)).stdout,/^go version go1\.26\.8 linux\/amd64\n$/);
 const sums={};for(const file of ['services/platform/go.mod','services/platform/go.sum'])sums[file]=hash(await readFile(path.join(root,file)));
 phase='locked-module-prime';await run('go',['list','-C','services/platform','-mod=readonly','-deps','-test','./apiserver'],300);
 for(const [file,pin]of Object.entries(sums))assert.equal(hash(await readFile(path.join(root,file))),pin);
 phase='pinned-postgres-intake';await run('docker',['--host=unix:///var/run/docker.sock','pull',image],180);
 const inspected=JSON.parse((await run('docker',['--host=unix:///var/run/docker.sock','image','inspect',image])).stdout);assert.ok(inspected.length===1&&inspected[0].RepoDigests.includes(image));
 container=(await run('docker',['--host=unix:///var/run/docker.sock','create','--name','zasp-connector-pg-extract-'+randomBytes(8).toString('hex'),'--network=none','--read-only','--entrypoint=/bin/true',image])).stdout.trim();assert.match(container,/^[a-f0-9]{64}$/);
 const pg=path.join(out,'pg');await mkdir(pg,{mode:0o700});await mkdir(path.join(pg,'root/usr/lib/postgresql'),{mode:0o700,recursive:true});await mkdir(path.join(pg,'root/usr/share/postgresql'),{mode:0o700,recursive:true});
 for(const [source,destination]of [['/usr/lib/postgresql/18',path.join(pg,'root/usr/lib/postgresql/18')],['/usr/share/postgresql/18',path.join(pg,'root/usr/share/postgresql/18')],['/usr/lib/x86_64-linux-gnu',path.join(pg,'root/usr/lib/x86_64-linux-gnu')]])await run('docker',['--host=unix:///var/run/docker.sock','cp','-L',container+':'+source,destination]);
 // Resolve the image's top-level sample symlink in the container, not on the host.
 const sampleDirectory=path.join(pg,'root/usr/share/postgresql/18');assert.equal(await realpath(sampleDirectory),sampleDirectory);
 const retainedSample=path.join(pg,'postgresql.conf.sample.official'),sample=path.join(sampleDirectory,'postgresql.conf.sample');
 await run('docker',['--host=unix:///var/run/docker.sock','cp','-L',container+':/usr/share/postgresql/18/postgresql.conf.sample',retainedSample]);
 const sampleStat=await lstat(retainedSample);assert.ok(sampleStat.isFile()&&sampleStat.size>0&&sampleStat.size<=131072);
 // Rename replaces a copied symlink without following its potentially absolute target.
 await rename(retainedSample,sample);assert.ok((await lstat(sample)).isFile());const sampleBytes=await readFile(sample);assert.equal(sampleBytes.length,sampleStat.size);receipt.postgresSample={bytes:sampleBytes.length,sha256:hash(sampleBytes),source:'same-pinned-image-dereferenced-file'};
 await run('docker',['--host=unix:///var/run/docker.sock','rm',container]);container=undefined;
 const bin=path.join(pg,'bin');await mkdir(bin,{mode:0o700});
 const libraryNames=JSON.parse(await readFile(path.join(root,"docs/internal/evidence/cloud-2026-10-07/native-service-readiness/openfga/09-pg-non-glibc-libs-manifest.json"), 'utf8'));assert.ok(Array.isArray(libraryNames)&&libraryNames.length===179);
 const childLibraries=path.join(pg,'non-glibc-child-libraries');await mkdir(childLibraries,{mode:0o700});const uniqueLibraryNames=new Set();const libraryRoot=await realpath(path.join(pg,'root/usr/lib/x86_64-linux-gnu'));
 for(const row of libraryNames){guard();assert.ok(typeof row.name==='string'&&/^[A-Za-z0-9_.+-]{1,128}$/.test(row.name)&&!uniqueLibraryNames.has(row.name));assert.ok(!/^(?:ld-|libc\.|libm\.|libpthread|libdl\.|librt\.|libutil\.|libnss)/.test(row.name));uniqueLibraryNames.add(row.name);const source=await realpath(path.join(libraryRoot,row.name));assert.ok(source.startsWith(libraryRoot+'/')&&(await stat(source)).isFile());await symlink(source,path.join(childLibraries,row.name));}
 receipt.postgresChildLibraryCount=uniqueLibraryNames.size;

 assert.ok((await lstat(path.join(pg,'root/usr/share/postgresql/18/postgres.bki'))).isFile());
 for(const name of ['postgres','initdb','pg_ctl','pg_isready','psql','pg_config']){
  const binary=path.join(pg,'root/usr/lib/postgresql/18/bin',name);assert.ok((await lstat(binary)).isFile());
  const prefix=name==='initdb'?`set -- -L '${pg}/root/usr/share/postgresql/18' "$@"\n`:name==='pg_ctl'?`set -- -p '${bin}/postgres' "$@"\n`:name==='pg_config'?`if [ "$#" -eq 1 ] && [ "$1" = --bindir ]; then printf '%s\\n' '${bin}'; exit 0; fi\n`:'';
  await writeFile(path.join(bin,name),`#!/bin/sh\nset -eu\nexport LD_LIBRARY_PATH='${childLibraries}'\n${prefix}exec '${pg}/root/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2' --library-path '${pg}/root/usr/lib/x86_64-linux-gnu:${pg}/root/usr/lib/postgresql/18/lib' '${binary}' "$@"\n`,{mode:0o500,flag:'wx'});
 }
 const testEnv={...closed,GOPROXY:'off',PATH:bin+':'+closed.PATH,ZASP_P7_MODEL_TEST:'1'};
 assert.equal((await run(path.join(bin,'postgres'),['--version'],5,testEnv)).stdout,"postgres (PostgreSQL) 18.3 (Debian 18.3-1.pgdg12+1)\n");
 phase='owned-raw-postgres-version-probe';const rawVersion=await run(path.join(pg,'root/usr/lib/postgresql/18/bin/postgres'),['--version'],5,{...testEnv,LD_LIBRARY_PATH:childLibraries});assert.equal(rawVersion.stdout,"postgres (PostgreSQL) 18.3 (Debian 18.3-1.pgdg12+1)\n");
 phase='owned-initdb-tool-smoke';await run(path.join(bin,'initdb'),['--no-locale','--encoding=UTF8','--auth-local=trust','--auth-host=trust','--username=zasp_e2e','-D',path.join(out,'initdb-tool-smoke-data')],30,testEnv);
 phase='pinned-openfga-intake';const archive=path.join(out,'openfga.tar.gz');
 await run('/usr/bin/curl',['--disable','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--max-time','90','--max-filesize','21232870','--output',archive,'https://github.com/openfga/openfga/releases/download/v1.21.0/openfga_1.21.0_linux_amd64.tar.gz'],95);await chmod(archive,0o400);
 tool=await loadOfficialHeldTool('openfga',archive,path.join(out,'openfga-held'));receipt.fgaTool=await verifyHeldTool(tool);
 const token=tokenForRedaction=randomBytes(32).toString('hex'),tokenFile=path.join(out,'token');await writeFile(tokenFile,token,{mode:0o600,flag:'wx'});
 fgaPort=await port();grpcPort=await port();assert.notEqual(fgaPort,grpcPort);
 phase='owned-openfga-start';fga=await spawnHeldTool(tool,['run'],{cwd:out,env:{PATH:'/usr/bin:/bin',HOME:closed.HOME,TMPDIR:out,OPENFGA_HTTP_ADDR:'127.0.0.1:'+fgaPort,OPENFGA_GRPC_ADDR:'127.0.0.1:'+grpcPort,OPENFGA_DATASTORE_ENGINE:'memory',OPENFGA_AUTHN_METHOD:'preshared',OPENFGA_AUTHN_PRESHARED_KEYS:token,OPENFGA_PLAYGROUND_ENABLED:'false',OPENFGA_METRICS_ENABLED:'false',OPENFGA_LOG_LEVEL:'warn'},maxOutputBytes:65536});owners.add(fga);fgaStart=await captureStart(fga.child.pid);const executable=await stat('/proc/'+fga.child.pid+'/exe');assert.equal(executable.dev,receipt.fgaTool.device);assert.equal(executable.ino,receipt.fgaTool.inode);
 let serviceExited=false;void fga.completed.then(()=>{serviceExited=true;},()=>{serviceExited=true;});
 const url='http://127.0.0.1:'+fgaPort,readyEnd=performance.now()+30000;
 for(;;){guard();assert.ok(!serviceExited&&performance.now()<readyEnd);try{await observeOwnedListener({pid:fga.child.pid,start:fgaStart,port:fgaPort});await observeOwnedListener({pid:fga.child.pid,start:fgaStart,port:grpcPort});const health=await auth(url+'/healthz',null),denied=await auth(url+'/stores',null),wrong=await auth(url+'/stores',randomBytes(32).toString('hex')),allowed=await auth(url+'/stores',token);if(health===200&&denied===401&&wrong===401&&allowed===200){receipt.authStatuses=[health,denied,wrong,allowed];break;}}catch{/* Refusal or bounded retry is handled by the enclosing guard. */}await new Promise(resolve=>setTimeout(resolve,100));}
 testEnv.ZASP_P6_NATIVE_OPENFGA_URL=url;testEnv.ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE=tokenFile;
 phase='authenticated-oauth-enqueue';const test=await run('go',['test','-C','services/platform','-json','-race','-p=1','-count=1','-timeout=10m','-run','^'+top+'$','./apiserver'],650,testEnv);
 phase='exact-roster-and-postgres-cleanup';const rows=test.stdout.trim().split('\n').map(line=>JSON.parse(line));assert.ok(rows.every(row=>row.Action!=='fail'&&row.Action!=='skip'));
 const expected=[top,...cases.map(name=>top+'/'+name)];for(const action of ['run','pass'])assert.deepEqual(rows.filter(row=>row.Action===action&&row.Test).map(row=>row.Test).sort(),expected.slice().sort());assert.equal(rows.filter(row=>row.Action==='pass'&&!row.Test).length,1);
 const outputs=rows.map(row=>row.Output??'').join('');const joined=[...outputs.matchAll(/joined owned PostgreSQL pid=(\d+).*pg_ctl exit=0 server Wait exit=0 normal-exit/g)];assert.equal(joined.length,1);assert.ok(await absent(Number(joined[0][1])));
 assert.ok(!test.stdout.includes(token)&&!test.stderr.includes(token));receipt.test={names:expected,tops:1,subcases:2,skips:0,packagePass:true,postgresNormalJoined:true,postgresPIDAbsent:true};
 await sourcePins();for(const [file,pin]of Object.entries(sums))assert.equal(hash(await readFile(path.join(root,file))),pin);
}catch(error){receipt.failedPhase=phase;receipt.failureClass=failureClass(error);refused=true;}
finally{phase='owned-service-cleanup';
 for(const owner of [...owners].reverse()){try{await owner.stop();const result=await owner.completed;if(owner===fga){assert.ok(result.status===0&&!result.signal&&!result.outputLimitExceeded);assert.ok(!result.stdout.includes(tokenForRedaction)&&!result.stderr.includes(tokenForRedaction));receipt.fgaNormalJoined=true;receipt.fgaPIDAbsent=await absent(owner.child.pid);assert.ok(receipt.fgaPIDAbsent);receipt.fgaSessionAbsent=await sessionEmpty(owner.child.pid);assert.ok(receipt.fgaSessionAbsent);}}catch{refused=true;}owners.delete(owner);}
 if(tool)try{await closeHeldTool(tool);}catch{refused=true;}
 if(container)try{await run('docker',['--host=unix:///var/run/docker.sock','rm',container],30,closed,true);container=undefined;}catch{refused=true;}
 if(fgaPort&&grpcPort)try{await bindable(fgaPort);await bindable(grpcPort);receipt.fgaPortsBindable=true;}catch{refused=true;}
}
samplingStopped=true;clearInterval(sampler);clearTimeout(aggregateTimer);if(sampling)await sampling;
try{await floors();await sourcePins();}catch{refused=true;}
receipt.normalCleanup=owners.size===0&&!container&&receipt.fgaNormalJoined===true&&receipt.fgaPortsBindable===true&&receipt.fgaSessionAbsent===true;
receipt.completed=!refused&&!canceled&&performance.now()<end&&receipt.normalCleanup&&receipt.test?.packagePass===true;
await writeFile(path.join(out,'result.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600,flag:'wx'});
finished=true;console.log(JSON.stringify(receipt));
if(!receipt.completed||canceled||refused||performance.now()>=end){const value=n=>Number.isSafeInteger(n)&&n>=0?String(n):'unobserved';const resource=receipt.resourceSnapshot??{};console.error('::error title=Connector authenticated enqueue integration::phase='+ (receipt.failedPhase??phase)+'; class='+(receipt.failureClass??'other-refusal')+'; resource='+(receipt.resourceRefusal?.step??'not-refused')+'; resourceClass='+(receipt.resourceRefusal?.class??'none')+'; workspaceBytes='+value(resource.workspaceFreeBytes)+'; scratchBytes='+value(resource.scratchFreeBytes)+'; memoryHeadroomBytes='+value(resource.memoryHeadroomBytes)+'; binding='+(receipt.sourceBinding??'unobserved')+'. Authenticated enqueue integration refused; no deployment readiness established.');process.exitCode=1;}else console.log('Connector authenticated OAuth enqueue: existing 1 top / 2 subcases PASS; owned PG/FGA normal cleanup. No runtime activation or deployment acceptance.');

if(canceled||refused||performance.now()>=end){lateRefusal('terminal-refusal');process.exitCode=1;}
