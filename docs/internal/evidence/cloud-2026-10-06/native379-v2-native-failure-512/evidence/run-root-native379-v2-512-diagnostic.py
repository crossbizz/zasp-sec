import ast,ctypes,hashlib,json,os,pathlib,signal,stat,subprocess,time,uuid
P=pathlib.Path
script=P('/workspace/.zasp-cloud-owned/native379-v2-diagnostic-foundation-ntje6h8r/prepare-frozen-source.py')
def checked(path,expected):
 assert path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==expected
checked(script,'196e853984d19fb892f2bf28729d0041dc1b5a38cac8b19e5513ac9379543f67')
full_review=P('/tmp/zasp-cloud-evidence/runtime-continuation/native379-v2-independent-actual-diagnostic-frozen-envelope-review-512beb.json')
pg_review=P('/tmp/zasp-cloud-evidence/runtime-continuation/independent-provider-fresh-PG-runtime-review-512.json')
checked(full_review,'4eef778eeda584dbab283b5cee69042acacc47d2cf3fded7afb129d51fda1cd0')
checked(pg_review,'cefae52e3d0014e8122e6aaf289adfd56f95edfd21d8a4d40a2d474071b1fd08')
base=P('/workspace/.zasp-cloud-owned/native379-v2-diagnostic-foundation-ntje6h8r');prep=base/'outputs/frozen-source-preparation'
checked(prep/'go-build-envelope-candidate.json','816fe4fb0b7be143cb3715e6b9ae3be934f34c78d753657b7922f7862e86b9e4')
checked(prep/'native379-v2-envelope-candidate.json','000076387b815beb30c8f02818e0ef8fd9e3d3eb269fdd4280eaff2f08978aef')
checked(base/'bin/apiserver.test','2f2d85ac203f610d1f5f7d52dee2f3e88e092594b3ed8fcca37b24fc4508c9f4')
env=json.loads((prep/'environment.json').read_text())
assert set(env)==set('CGO_ENABLED GOARCH GOCACHE GOENV GOEXPERIMENT GOFLAGS GOMODCACHE GOOS GOPROXY GOROOT GOSUMDB GOTOOLCHAIN GOWORK HOME LANG PATH TMPDIR TZ'.split())
assert not any(k.startswith(('LD_','PG','ZASP_')) for k in env)
nonce=uuid.uuid4().hex;evidence=base/('outputs/native379-v2-root-attempt-512-diagnostic-'+nonce);evidence.mkdir(mode=0o700)
env.update(ZASP_ORDERED_CURRENT_NATIVE379_V2='1',ZASP_ORDERED_CURRENT_NATIVE379_V2_BUILD=str(prep/'native379-v2-envelope-candidate.json'),ZASP_ORDERED_CURRENT_NATIVE379_V2_BUILD_SHA256='000076387b815beb30c8f02818e0ef8fd9e3d3eb269fdd4280eaff2f08978aef',ZASP_ORDERED_CURRENT_NATIVE379_V2_OUTPUT=str(evidence/'native-result.json'))
assert ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)==0
records=[]
tree=ast.parse(script.read_text());defs=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ['sha','write']]
main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main');run=next(n for n in ast.walk(main) if isinstance(n,ast.FunctionDef) and n.name=='run')
exec(compile(ast.fix_missing_locations(ast.Module(body=defs+[run],type_ignores=[])),str(script),'exec'))
write(evidence/'closed-environment.json',env)
write(evidence/'root-launch-binding.json',{'source_commit':'512beb183a0f7994f8769fc6765e3e1b80af4523','nonce':nonce,'GoEnvelopeSHA256':'816fe4fb0b7be143cb3715e6b9ae3be934f34c78d753657b7922f7862e86b9e4','V2EnvelopeSHA256':env['ZASP_ORDERED_CURRENT_NATIVE379_V2_BUILD_SHA256'],'independent_full_review_sha256':sha(full_review),'independent_PG_review_sha256':sha(pg_review),'supervisor_sha256':sha(script),'scope':'root-owned bounded local native attempt; no product/provider authorization'})
try:
 run('actual-native379',[str(base/'bin/apiserver.test'),'-test.run=^TestP7OrderedCurrentIntegrityNativeV2$','-test.count=1','-test.v','-test.timeout=15m'],base/'module-cache/owned-source/services/platform/apiserver',seconds=930)
except RuntimeError:
 print(json.dumps({'supervisor_completed':True,'result_exists':(evidence/'native-result.json').exists(),'evidence':str(evidence),'record':records[-1]}),flush=True)
 raise SystemExit(records[-1]['exit_code'] or 1)
print(json.dumps({'supervisor_completed':True,'result_exists':(evidence/'native-result.json').exists(),'evidence':str(evidence),'record':records[-1]}),flush=True)
