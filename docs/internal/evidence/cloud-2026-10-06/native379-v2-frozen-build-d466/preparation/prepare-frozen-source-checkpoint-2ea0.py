#!/usr/bin/env python3
"""Finite source-only preparation. Requires separately root-authorized exact commit.
Never starts PostgreSQL, invokes native tests, emits assembly, or captures receipts.
"""
import argparse, ctypes, hashlib, json, os, pathlib, re, signal, stat, subprocess, tarfile, time
P = pathlib.Path
FOUNDATION=P('/workspace/.zasp-cloud-owned/native379-v2-foundation-ouncz9k0')
REPO=P('/workspace/zasp-sec')
PLAN=P(__file__).parent
WIRE=P('/workspace/.zasp-cloud-owned/native379-v2-assertion-integration-HZNNAN/candidate-05f314-t2l_d_0s/canonical-wire.json')
EXPECTED_WIRE='ca7dd2ad47a4afcea9f0dfca48d10e5e4b8876c0daf6450c33a66776e830d5e9'
EXPECTED_IMPLEMENTATION='05f314d326b85a56f98370431dc8fb4d7088d9ac9ddf8c73eebf3261d2b4f3e8'
EXPECTED_COMPANION='ae73247dade4f3a2af08249da9634cab4cf5d3d214d83b13d1e1a3643969f6c8'
def sha(p):
 with P(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(p,x):
 with P(p).open('x') as f:json.dump(x,f,sort_keys=True,separators=(',',':'));f.write('\n')
 P(p).chmod(0o400)
def check_file(p):
 s=P(p).lstat()
 if not stat.S_ISREG(s.st_mode):raise RuntimeError('nonregular input')
def freeze(root):
 for base,dirs,files in os.walk(root):
  for name in files+dirs:
   p=P(base)/name
   if p.is_symlink():raise RuntimeError('symlink in owned immutable closure')
   p.chmod(stat.S_IMODE(p.stat().st_mode)&~0o222)
 root.chmod(stat.S_IMODE(root.stat().st_mode)&~0o222)
def immutable(p,roots):
 check_file(p)
 admitted=[r for r in roots if p.is_relative_to(r)]
 if not admitted or p.stat().st_mode&0o222:raise RuntimeError('unfrozen consumed input')
 r=max(admitted,key=lambda x:len(str(x)));q=p.parent
 while True:
  s=q.lstat()
  if not stat.S_ISDIR(s.st_mode) or s.st_mode&0o222:raise RuntimeError('unfrozen ancestor')
  if q==r:break
  q=q.parent

def main():
 ap=argparse.ArgumentParser()
 ap.add_argument('--authorized-source-commit',required=True)
 ap.add_argument('--reviewed-pg-binding',type=P)
 args=ap.parse_args();commit=args.authorized_source_commit
 if not re.fullmatch('[0-9a-f]{40}',commit):raise RuntimeError('exact root-authorized commit required')
 actual=subprocess.check_output(['git','rev-parse',commit+'^{commit}'],cwd=REPO,text=True,timeout=10).strip()
 if actual!=commit:raise RuntimeError('commit identity')
 source=FOUNDATION/'module-cache/owned-source';platform=source/'services/platform'
 if source.exists():raise RuntimeError('owned-source already exists; never resume or overwrite')
 if any((FOUNDATION/'build-cache').iterdir()) or any((FOUNDATION/'bin').iterdir()):raise RuntimeError('foundation cache/bin must be fresh empty')
 evidence=FOUNDATION/'outputs/frozen-source-preparation';evidence.mkdir(mode=0o700)
 tmp=FOUNDATION/'tmp';tmp.mkdir(mode=0o700)
 if sha(PLAN/'frozen-build-plan.json')!='462ab863b9e25e5ac4cc72f28ce06757d6da667cc3a674ef875776b887993253':raise RuntimeError('reviewed plan hash differs')
 for tool,pin in [(FOUNDATION/'go/bin/go','3fb44b0d47becc087cf9e6002366bfbf136d3e08460f12389dbd04687dcf0dd0'),(FOUNDATION/'module-cache/owned-tools/node/bin/node','93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068')]:
  check_file(tool)
  if sha(tool)!=pin:raise RuntimeError('reviewed tool executable differs')
 if args.reviewed_pg_binding and sha(args.reviewed_pg_binding)!='40f499a12a8b69daa2f2e6bf527d74e01a7fdd4110b18b025b9ea6887275a500':raise RuntimeError('root-reviewed PG metadata hash differs')
 # Linux subreaper lets this process join killed owned compiler descendants.
 if ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)!=0:raise RuntimeError('owned-process subreaper unavailable')
 pplan=json.loads((PLAN/'frozen-build-plan.json').read_text());env=dict(pplan['environment'],HOME=os.environ['HOME'],TZ='UTC',LANG='C')
 write(evidence/'environment.json',env)
 records=[]
 def run(label,argv,cwd,env_override=None,seconds=600,output=None,discard_stderr=False):
  started=time.monotonic();log=output or evidence/(label+'.log');timed_out=False
  with log.open('xb') as f:
   proc=subprocess.Popen(argv,cwd=cwd,env=dict(env,**(env_override or {})),stdout=f,stderr=subprocess.DEVNULL if discard_stderr else subprocess.STDOUT,start_new_session=True)
   try:status=proc.wait(timeout=seconds)
   except subprocess.TimeoutExpired:
    timed_out=True
    try:os.killpg(proc.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    status=proc.wait(timeout=30)
    # Adopted compiler descendants share this owned group. SIGKILL then reap all.
    while True:
     try:os.waitpid(-proc.pid,0)
     except ChildProcessError:break
  log.chmod(0o400);records.append({'label':label,'argv':argv,'cwd':str(cwd),'exit_code':status,'timed_out':timed_out,'seconds':round(time.monotonic()-started,6),'log_sha256':sha(log)})
  write(evidence/(label+'-record.json'),records[-1])
  if timed_out or status:raise RuntimeError('source preparation failed; see owned log '+label)
 archive=evidence/'exact-source.tar'
 run('archive-source',['/usr/bin/git','archive','--format=tar',commit],REPO,seconds=60,output=archive,discard_stderr=True);source.mkdir(mode=0o700)
 with tarfile.open(archive) as t:
  for member in t:
   rel=P(member.name)
   if rel.is_absolute() or '..' in rel.parts or not(member.isfile() or member.isdir()):raise RuntimeError('archive topology refused')
   target=source/rel
   if member.isdir():target.mkdir(parents=True,exist_ok=True,mode=0o700)
   else:
    target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with target.open('xb') as f:f.write(t.extractfile(member).read())
    target.chmod(0o700 if member.mode&0o111 else 0o600)
 checks={platform/'apiserver/authorization_worker_ordered_current_native379_v2_test.go':EXPECTED_IMPLEMENTATION,platform/'apiserver/authorization_worker_ordered_current_native379_v2_pins_test.go':EXPECTED_COMPANION,platform/'go.sum':'a99d2c9979401b020e8ce1c7818276f05c820dce5f43820566ba94121bf48825',platform/'go.mod':'3d0176805b0c3fa8ce90b3984650e9dae08baaa13dc2dcbdc5528493326756b0',WIRE:EXPECTED_WIRE}
 for p,pin in checks.items():
  check_file(p)
  if sha(p)!=pin:raise RuntimeError('reviewed source/pin identity differs')
 if not (source/'services/health/go.mod').is_file():raise RuntimeError('actual ../health replacement absent')
 tools=platform/'migrations/tools';artifacts=tools/'ordered-current-native379-packet-v2-artifacts'
 baseline={str(p.relative_to(source)):sha(p) for p in sorted(source.rglob('*')) if p.is_file()}
 write(evidence/'committed-source-file-manifest.json',baseline)
 pins=json.loads((artifacts/'generated-identities.json').read_text())['outputPins']
 output_dir=platform/'migrations/ordered_current';before={n:sha(output_dir/n) for n in pins}
 node=str(FOUNDATION/'module-cache/owned-tools/node/bin/node');go=str(FOUNDATION/'go/bin/go')
 run('generate-eight',[node,str(tools/'build-ordered-current-development.mjs'),'--write'],source,seconds=120)
 delta=[]
 for n,pin in pins.items():
  if sha(output_dir/n)!=pin:raise RuntimeError('generated output differs '+n)
  delta.append({'path':'services/platform/migrations/ordered_current/'+n,'git_sha256':before[n],'derived_sha256':pin,'changed':before[n]!=pin})
 write(evidence/'git-to-derived-output-delta.json',delta)
 finished={str(p.relative_to(source)):sha(p) for p in sorted(source.rglob('*')) if p.is_file()}
 allowed={'services/platform/migrations/ordered_current/'+n for n in pins}
 if set(finished)!=set(baseline) or any(finished[k]!=baseline[k] for k in baseline if k not in allowed):raise RuntimeError('unexpected source mutation from output generator')
 write(evidence/'finished-source-file-manifest.json',finished)
 run('check-eight',[node,str(tools/'build-ordered-current-development.mjs'),'--check'],source,seconds=120)
 run('repeat-generate-eight',[node,str(tools/'build-ordered-current-development.mjs'),'--write'],source,seconds=120)
 repeated={str(p.relative_to(source)):sha(p) for p in sorted(source.rglob('*')) if p.is_file()}
 if repeated!=finished or any(sha(output_dir/n)!=pin for n,pin in pins.items()):raise RuntimeError('repeat generation changed exact output/source bytes')
 write(evidence/'repeat-generation-proof.json',{'all_eight_sha256':pins,'complete_source_file_count':len(repeated),'complete_source_manifest_equal':True})
 wire=evidence/'reproduced-wire.json'
 run('reproduce-packet',[node,str(tools/'ordered-current-native379-packet-v2.mjs'),'--json'],source,seconds=120,output=wire,discard_stderr=True)
 if sha(wire)!=EXPECTED_WIRE:raise RuntimeError('exact reviewed packet reproduction differs')
 module_before={str(p.relative_to(FOUNDATION/'module-cache')):sha(p) for p in sorted((FOUNDATION/'module-cache').rglob('*')) if p.is_file() and not p.is_relative_to(source)}
 write(evidence/'before-build-module-tool-file-manifest.json',module_before)
 run('verify-modules',[go,'mod','verify'],platform,seconds=120)
 builds=[([go,'test','-c','-mod=readonly','-o',str(FOUNDATION/'bin/apiserver.test'),'./apiserver'],'build-apiserver'),([go,'test','-c','-mod=readonly','-o',str(FOUNDATION/'bin/migrations.test'),'./migrations'],'build-assembly'),([go,'build','-mod=readonly','-o',str(FOUNDATION/'bin/agentsec-migrate'),'./agentsec-migrate'],'build-cli')]
 for argv,label in builds:run(label,argv,platform,seconds=900)
 compiled_source={str(p.relative_to(source)):sha(p) for p in sorted(source.rglob('*')) if p.is_file()}
 if compiled_source!=finished:raise RuntimeError('Go compilation mutated finished source or module manifests')
 module_after={str(p.relative_to(FOUNDATION/'module-cache')):sha(p) for p in sorted((FOUNDATION/'module-cache').rglob('*')) if p.is_file() and not p.is_relative_to(source)}
 if module_after!=module_before:raise RuntimeError('Go verification/compilation mutated module/tool closure')
 write(evidence/'post-build-source-module-equality.json',{'complete_finished_source_equal':True,'complete_module_tool_equal':True,'source_files':len(compiled_source),'module_tool_files':len(module_after)})
 for p in (FOUNDATION/'bin').iterdir():p.chmod(0o500)
 freeze(FOUNDATION/'go');freeze(FOUNDATION/'module-cache')
 inv=evidence/'final-go-input-inventory.json'
 run('inventory',[str(FOUNDATION/'bin/apiserver.test'),'-test.run=^TestWorkerRegistrationReferenceBuildInputInventory$','-test.count=1','-test.v'],platform/'apiserver',{'ZASP_WORKER_REGISTRATION_INPUT_INVENTORY_OUTPUT':str(inv)},seconds=240)
 inv.chmod(0o400);b=json.loads(inv.read_text())
 for item in b['inputs']:
  path=P(item['path']);immutable(path,[platform,FOUNDATION/'go',FOUNDATION/'module-cache'])
  if sha(path)!=item['sha256']:raise RuntimeError('consumed input hash differs')
 b.update(controlled_path=env['PATH'],cache_policy='owned-trusted-go1.25.13',build_commands=[a for a,_ in builds],executable_sha256=sha(FOUNDATION/'bin/apiserver.test'),assembly_executable=str(FOUNDATION/'bin/migrations.test'),assembly_executable_sha256=sha(FOUNDATION/'bin/migrations.test'))
 # PG is only supplied as previously independently-reviewed metadata: no version/tool/server command here.
 if args.reviewed_pg_binding:
  pg=json.loads(args.reviewed_pg_binding.read_text())
  if set(pg)!= {'pg_binary_sha256','pg_extension_files'}:raise RuntimeError('closed reviewed PG metadata required')
  if set(pg['pg_binary_sha256'])!={'initdb','postgres','pg_isready','pg_ctl'}:raise RuntimeError('complete PG wrapper set required')
  for name,pin in pg['pg_binary_sha256'].items():
   if sha(P('/tmp/zasp-cloud-tools/postgres-18.3/bin')/name)!=pin:raise RuntimeError('PG wrapper hash differs')
  for p,pin in pg['pg_extension_files'].items():
   if sha(p)!=pin:raise RuntimeError('PG runtime/extension hash differs')
  b.update(pg)
 go_envelope=evidence/'go-build-envelope-candidate.json';write(go_envelope,b)
 authority=json.loads(wire.read_text())['authority'];manifest=json.loads((artifacts/'source-inputs.json').read_text());paths={source/rel for rel in manifest['files']}
 paths.update([P(node),output_dir/'development-module.sql',output_dir/'development-manifest.json',output_dir/'development-collector.sql',artifacts/'source-inputs.json',tools/'ordered-current-native379-packet-v2.mjs',tools/'ordered-current-native379-source-schema-v2.mjs',artifacts/'generated-identities.json',artifacts/'source-fact-delta.json'])
 if len(paths)!=1553:raise RuntimeError('exact Node envelope member count differs')
 for p in paths:immutable(p,[platform,FOUNDATION/'go',FOUNDATION/'module-cache'])
 v2={'version':'ordered-current-native379-frozen-build-v2','go_build_path':str(go_envelope),'go_build_sha256':sha(go_envelope),'packet_sha256':EXPECTED_WIRE,'source_inventory_sha256':authority['sourceInventorySHA256'],'generated_identities_sha256':authority['generatedIdentitiesSHA256'],'source_fact_delta_sha256':authority['sourceFactDeltaSHA256'],'node_executable':node,'node_sha256':sha(node),'module_path':str(output_dir/'development-module.sql'),'manifest_path':str(output_dir/'development-manifest.json'),'collector_path':str(output_dir/'development-collector.sql'),'node_generated_inputs':[{'path':str(p),'sha256':sha(p),'kind':'node-source','package':'ordered-current-native379-v2'} for p in sorted(paths)]}
 # Exact shared registrationReferenceInput schema: path, sha256, kind, package.
 write(evidence/'native379-v2-envelope-candidate.json',v2)
 run('source-controls',[str(FOUNDATION/'bin/apiserver.test'),'-test.run=^TestNative379V2','-test.count=1','-test.v'],platform/'apiserver',seconds=180)
 summary={'status':'SOURCE-ONLY-CANDIDATES-REQUIRE-INDEPENDENT-ROOT-REVIEW','source_commit':commit,'archive_sha256':sha(archive),'committed_source_files':len(baseline),'finished_source_files':len(finished),'inputs':len(b['inputs']),'modules':len(b['modules']),'input_sha256':b['input_sha256'],'node_inputs':len(paths),'generated_changed':sum(x['changed'] for x in delta),'GoEnvelopeSHA256':sha(go_envelope),'V2EnvelopeSHA256':sha(evidence/'native379-v2-envelope-candidate.json'),'pg_binding_supplied':bool(args.reviewed_pg_binding),'pg_binding_metadata_sha256':sha(args.reviewed_pg_binding) if args.reviewed_pg_binding else None,'native_execution':False,'source_only':True,'binary_sha256':{p.name:sha(p) for p in (FOUNDATION/'bin').iterdir()}}
 write(evidence/'summary.json',summary);print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
