import hashlib, json, os, pathlib, subprocess, tempfile

SOURCE = pathlib.Path('/tmp/zasp-cloud-evidence/Stytch-disposable-session-bounded-source-v4/run.mjs')
PIN = '6558e13100d68e3c565cacc8885a8e7088e5070847175c44784a0dc07ac40e21'
NODE = '/tmp/zasp-cloud-tools/node-v22.23.1-linux-x64/bin/node'
ROOT = pathlib.Path('/tmp/zasp-cloud-evidence/Stytch-wrapper-offline-controls')
raw = SOURCE.read_bytes()
assert hashlib.sha256(raw).hexdigest() == PIN
replacement = "const {fetch: wireFetch, EnvHttpProxyAgent}=require('undici');"
assert raw.decode().count(replacement) == 1

FAKE = r'''
const CASE=__CASE__;
const TEST_ORG='organization-test-11111111-1111-4111-8111-111111111111';
const TEST_MEMBER='member-test-22222222-2222-4222-8222-222222222222';
let fixtureOrganization=null, fixtureMember=null, fixtureDeleted=false, fixtureDeletes=0;
const fixtureCalls=[];
function fixtureResponse(value,status=200){return new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});}
async function fixtureFetch(url,options){
 const path=new URL(url).pathname;
 fixtureCalls.push({method:options.method,kind:path.includes('/passwords/')?path.split('/').at(-1):options.method==='GET'?'owned-get':options.method==='DELETE'?'owned-delete':'owned-create'});
 if(options.method==='POST'&&path==='/v1/b2b/organizations'){
  const b=JSON.parse(options.body);
  fixtureOrganization={...b,organization_id:TEST_ORG};
  if(['create-uncertain-recover','create-uncertain-absent','create-uncertain-mismatch'].includes(CASE))throw new Error('SECRET-LEAK-CANARY');
  return fixtureResponse({organization:fixtureOrganization});
 }
 if(options.method==='POST'&&path==='/v1/b2b/passwords/migrate'){
  if(CASE==='cancel-migrate'){process.kill(process.pid,'SIGTERM');await new Promise(r=>setTimeout(r,20));throw new Error('SECRET-LEAK-CANARY');}
  const b=JSON.parse(options.body);fixtureMember={member_id:TEST_MEMBER,organization_id:TEST_ORG,email_address:b.email_address};
  return fixtureResponse({member_created:true,organization:fixtureOrganization,member:fixtureMember,member_id:TEST_MEMBER});
 }
 if(options.method==='POST'&&path==='/v1/b2b/passwords/authenticate'){
  return fixtureResponse({organization_id:TEST_ORG,organization:fixtureOrganization,member:fixtureMember,member_id:TEST_MEMBER,
    member_session:{member_session_id:'member-session-test-33333333-3333-4333-8333-333333333333',organization_id:TEST_ORG,member_id:TEST_MEMBER},
    member_authenticated:CASE!=='auth-refused',session_jwt:'TESTLOCAL-FIXTURE-JWT'});
 }
 if(options.method==='DELETE'&&path==='/v1/b2b/organizations/'+TEST_ORG){
  fixtureDeletes++;
  if(CASE==='cleanup-refused')return fixtureResponse({error_type:'TESTLOCAL'},503);
  fixtureDeleted=true;return fixtureResponse({organization_id:TEST_ORG});
 }
 if(options.method==='GET'){
  if(!fixtureOrganization||fixtureDeleted||CASE==='create-uncertain-absent')return fixtureResponse({error_type:'not_found'},404);
  if(CASE==='create-uncertain-mismatch')return fixtureResponse({organization:{...fixtureOrganization,organization_name:'FOREIGN-FIXTURE'}});
  return fixtureResponse({organization:fixtureOrganization});
 }
 throw new Error('Fixture unexpected request');
}
const __fixtureTransport={fetch:fixtureFetch,EnvHttpProxyAgent:class{async destroy(){}}};
process.on('exit',()=>{
 writeFileSync(__FIXTURE_META__,JSON.stringify({fixtureCalls,fixtureDeletes,fixtureDeleted}),{mode:0o600});
});
'''

cases = [
 ('normal', 0, True, True, 1),
 ('create-uncertain-recover', 1, False, True, 1),
 ('create-uncertain-absent', 1, False, False, 0),
 ('create-uncertain-mismatch', 1, False, False, 0),
 ('cancel-migrate', 1, False, True, 1),
 ('auth-refused', 1, False, True, 1),
 ('cleanup-refused', 1, False, False, 2),
]
observations=[]
for case, expected_rc, completed, absent, deletes in cases:
 directory=pathlib.Path(tempfile.mkdtemp(prefix='case-',dir=ROOT))
 meta=directory/'fixture-metadata.json'
 prefix="import {writeFileSync} from 'node:fs';\n"+FAKE.replace('__CASE__',json.dumps(case)).replace('__FIXTURE_META__',json.dumps(str(meta)))
 candidate=prefix+raw.decode().replace(replacement,'const {fetch: wireFetch, EnvHttpProxyAgent}=__fixtureTransport;')
 path=directory/'boundary.mjs';path.write_text(candidate);path.chmod(0o400)
 environment={'HOME':'/home/agent','PATH':'/usr/bin:/bin','STYTCH_PROJECT_ID':'project-test-fixture','STYTCH_SECRET':'secret-test-fixture'}
 run=subprocess.run([NODE,str(path)],env=environment,capture_output=True,text=True,timeout=5)
 (directory/'stdout.log').write_text(run.stdout);(directory/'stderr.log').write_text(run.stderr)
 assert 'SECRET-LEAK-CANARY' not in run.stdout+run.stderr,case+' leaked error'
 assert run.returncode==expected_rc,(case,run.returncode)
 summary=json.loads(run.stdout.strip())
 result_path=pathlib.Path(summary['resultPath'])
 assert str(result_path).startswith('/tmp/zasp-stytch-disposable-') and result_path.name=='result.json'
 actual=json.loads(result_path.read_text());metadata=json.loads(meta.read_text())
 assert actual['completed'] is completed and actual['cleanupAbsent'] is absent,case
 assert metadata['fixtureDeletes']==deletes,case
 assert all(x['kind'] in ['owned-create','migrate','authenticate','owned-delete','owned-get'] for x in metadata['fixtureCalls'])
 assert 'secret-test-fixture' not in result_path.read_text() and 'TESTLOCAL-FIXTURE-JWT' not in result_path.read_text()
 if case=='cancel-migrate':assert actual['cancelled'] is True
 if case=='create-uncertain-absent':assert actual['absenceObserved'] is True and 'uncertain' in actual['failure'].lower()
 if case=='create-uncertain-mismatch':assert 'create outcome uncertain' in actual['failure'].lower()
 observations.append({'case':case,'status':'PASS','childExit':run.returncode,'joined':True,'forced':False,'completed':completed,'cleanupAbsent':absent,'deleteCalls':deletes,'resultPath':str(result_path),'fixtureMetadataPath':str(meta)})
assert SOURCE.read_bytes()==raw
result={'status':'ACTUAL-WRAPPER-OFFLINE-CONTROLS-PASS','scope':'Seven own wrapper-boundary controls using injected fake transport and unchanged original proof; no vendor-internal or real-provider acceptance','wrapperSha256':PIN,'cases':observations,'networkCalls':False,'realCredentialsInherited':False,'repoSourceChanged':False,'sourceUnchanged':True}
out=ROOT/'result.json';out.write_text(json.dumps(result,indent=2)+'\n');out.chmod(0o600)
print(json.dumps({'status':result['status'],'cases':len(observations),'resultPath':str(out),'sha256':hashlib.sha256(out.read_bytes()).hexdigest()}))
