import base64,hashlib,json,os,pathlib,shutil,stat,time,zipfile
P=pathlib.Path
root=P(__file__).resolve().parent
old=P('/workspace/.zasp-cloud-owned/native379-v2-foundation-ouncz9k0')
selection=P('/workspace/.zasp-cloud-owned/native379-v2-safe-diagnostic-3mutfah8/source/services/platform/go.sum')
started=time.monotonic();deadline=started+300

def bounded():
 if time.monotonic()>deadline:raise RuntimeError('bounded preparation time exceeded')
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(p,x):
 with p.open('x') as f:json.dump(x,f,sort_keys=True,indent=2);f.write('\n')
 p.chmod(0o400)
def roster(base,exclude=None):
 out={};size=0
 for directory,dirs,files in os.walk(base):
  bounded();dirs.sort();files.sort()
  if P(directory)==base and exclude in dirs:dirs.remove(exclude)
  for name in dirs+files:
   p=P(directory)/name;s=p.lstat()
   if p.is_symlink() or s.st_mode&0o222:raise RuntimeError('source closure not immutable regular topology')
  for name in files:
   p=P(directory)/name;s=p.stat()
   if not stat.S_ISREG(s.st_mode) or s.st_size>512*1024*1024:raise RuntimeError('source file bounds')
   out[p.relative_to(base).as_posix()]=sha(p);size+=s.st_size
   if len(out)>100000 or size>8*1024**3:raise RuntimeError('source roster bound')
 return out,size
for name in ['outputs','bin','build-cache','tmp']:(root/name).mkdir(mode=0o700)
if sha(selection)!='a99d2c9979401b020e8ce1c7818276f05c820dce5f43820566ba94121bf48825':raise RuntimeError('selection checksum identity')
checks={'go-tree-manifest.json':'c77a7fb1be6bb84df71bac58d8dedf0279cdc7393f25048313a497bf34c9bb59','module-preparation-manifest.json':'81c75bff956863325adaa4b68bcb03bca0d44fb37c685e7eaf65efa7b1633a14'}
for name,pin in checks.items():
 if sha(old/'outputs'/name)!=pin:raise RuntimeError('prior independently reviewed foundation proof differs')
modules=json.loads((old/'outputs/module-preparation-manifest.json').read_text())
metadata=json.loads((old/'outputs/retained-mod-metadata-manifest.json').read_text())
go_before,go_size=roster(old/'go');cache_before,cache_size=roster(old/'module-cache','owned-source')
if go_before!=json.loads((old/'outputs/go-tree-manifest.json').read_text()):raise RuntimeError('whole Go tree hash differs')
if go_before['bin/go']!='3fb44b0d47becc087cf9e6002366bfbf136d3e08460f12389dbd04687dcf0dd0' or cache_before['owned-tools/node/bin/node']!='93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068':raise RuntimeError('tool hash differs')
if shutil.disk_usage(root).free<go_size+cache_size+2*1024**3:raise RuntimeError('owned workspace capacity gate')

def copy(base,destination,files):
 destination.mkdir(mode=0o700)
 for relative,pin in files.items():
  bounded();src=base/relative;dst=destination/relative;dst.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
  with src.open('rb') as inp,dst.open('xb') as out:shutil.copyfileobj(inp,out,1024*1024)
  dst.chmod(stat.S_IMODE(src.stat().st_mode)&~0o222)
  if sha(dst)!=pin or sha(src)!=pin:raise RuntimeError('copy before/after hash drift')
 for directory,dirs,names in os.walk(destination,topdown=False):P(directory).chmod(0o500)
 print('copied and verified',destination.name,len(files),'files',flush=True)
copy(old/'go',root/'go',go_before);copy(old/'module-cache',root/'module-cache',cache_before)
# Only admitted ModuleCache top remains writable for the future new source archive.
(root/'module-cache').chmod(0o700)
sums={}
for line in selection.read_text().splitlines():
 fields=line.split()
 if len(fields)==3:sums[fields[0]+' '+fields[1]]=fields[2]
verified=[]
for m in modules:
 bounded();name,version=m['path'],m['version'];assert sums[name+' '+version]==m['sum'];assert sums[name+' '+version+'/go.mod']==m['go_mod_sum']
 quartet={ext:root/data['relative_path'] for ext,data in m['download_files'].items()}
 for ext,p in quartet.items():assert sha(p)==m['download_files'][ext]['sha256']
 package={};h=hashlib.sha256();prefix=name+'@'+version+'/'
 with zipfile.ZipFile(quartet['zip']) as archive:
  names=archive.namelist();assert names and len(names)==len(set(names))
  for n in sorted(names):
   bounded();assert n.startswith(prefix) and '\n'not in n and not n.endswith('/')
   relative=n[len(prefix):];assert relative and P(relative).as_posix()==relative and '..'not in P(relative).parts
   digest=hashlib.sha256(archive.read(n)).hexdigest();package[relative]=digest;h.update((digest+'  '+n+'\n').encode())
  archive_h1='h1:'+base64.b64encode(h.digest()).decode();assert archive_h1==m['sum'];assert quartet['ziphash'].read_text().strip()==archive_h1
  mod_raw=quartet['mod'].read_bytes();mod_h1='h1:'+base64.b64encode(hashlib.sha256((hashlib.sha256(mod_raw).hexdigest()+'  go.mod\n').encode()).digest()).decode();assert mod_h1==m['go_mod_sum']
  if prefix+'go.mod'in names:assert archive.read(prefix+'go.mod')==mod_raw
 package_dir=root/m['package_relative_path']
 actual={p.relative_to(package_dir).as_posix():sha(p) for p in sorted(package_dir.rglob('*')) if p.is_file()}
 assert actual==package
 verified.append({'path':name,'version':version,'sum':archive_h1,'go_mod_sum':mod_h1,'files':len(package),'exact_archive_extracted_closure':True})
for relative,pin in metadata.items():assert sha(root/'module-cache'/relative)==pin
licensed=next(m for m in modules if m['path']=='github.com/nexus-rpc/nexus-proto-annotations')
assert sha(root/licensed['package_relative_path']/'LICENSE')=='06847bcc52e67fceae1691299bdd42dbfdff138c91e3ea89811a7aa2827988d6'
assert not(root/'module-cache/owned-source').exists();assert not(root/'module-cache/github.com/nexus-rpc/nexus-proto-annotations@v0.1.0').exists()
write(root/'outputs/go-tree-manifest.json',go_before)
write(root/'outputs/module-tool-tree-manifest.json',cache_before)
write(root/'outputs/module-h1-verification.json',verified)
write(root/'outputs/retained-mod-metadata-manifest.json',metadata)
write(root/'outputs/prior-foundation-proof-bindings.json',{name:{'path':str(old/'outputs'/name),'sha256':sha(old/'outputs'/name)} for name in ['foundation-summary.json','go-tree-manifest.json','module-preparation-manifest.json','retained-mod-metadata-manifest.json']})
summary={'status':'TOOLS-AND-MODULES-ONLY-NOT-SOURCE-BINARY-ENVELOPE-OR-NATIVE-ADMISSION','root':str(root),'copiedFrom':str(old),'oldRootsModified':False,'ownedSourceCopied':False,'buildCacheCopied':False,'sourceSelectionGoSumSHA256':sha(selection),'goTreeFiles':len(go_before),'goTreeBytes':go_size,'moduleToolFiles':len(cache_before),'moduleToolBytes':cache_size,'verifiedExternalModules':len(verified),'selectedPackageFiles':sum(m['files']for m in verified),'retainedModMetadata':len(metadata),'GoSHA256':go_before['bin/go'],'NodeSHA256':cache_before['owned-tools/node/bin/node'],'buildCacheMode':'0700','buildCacheEmpty':not any((root/'build-cache').iterdir()),'tmpMode':'0700','binEmpty':not any((root/'bin').iterdir()),'frozenInputs':'Go tree and all externalModuleCache children read-only; ModuleCache root0700 solely for future committed owned-source integration and finalfreeze','seconds':round(time.monotonic()-started,6),'GoNodePGCommandsExecuted':False,'networkRequests':False,'nativeExecution':False}
write(root/'outputs/foundation-summary.json',summary);print(json.dumps(summary,indent=2),flush=True)
