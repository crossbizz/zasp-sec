import pathlib,tarfile,json,hashlib,os,posixpath,shutil,subprocess
b=pathlib.Path('/tmp/zasp-pg183-current');root=b/'root';root.mkdir();layers=[]
with tarfile.open(b/'image.tar') as outer:
 m=json.load(outer.extractfile('manifest.json'))[0];config=outer.extractfile(m['Config']).read();assert hashlib.sha256(config).hexdigest()=='3c67953c3a90a3a846b72e6cd2cfa418b0487e06156ed470dbbeaeb4cac09178'
 for name in m['Layers']:
  raw=outer.extractfile(name).read();assert hashlib.sha256(raw).hexdigest()==name.split('/')[-1];layers.append({'sha256':name.split('/')[-1],'bytes':len(raw)})
  import io
  with tarfile.open(fileobj=io.BytesIO(raw)) as t:
   for i in t:
    n=posixpath.normpath(i.name);assert not n.startswith('/') and '..' not in pathlib.PurePosixPath(n).parts
    if not n.startswith(('usr/lib/','usr/share/postgresql/','usr/share/locale/')):continue
    assert '.wh.' not in pathlib.PurePosixPath(n).name
    p=root/n;p.parent.mkdir(parents=True,exist_ok=True)
    assert str(p.parent.resolve()).startswith(str(root.resolve())+'/')
    if i.isdir():p.mkdir(exist_ok=True)
    elif i.isfile():
     if p.is_symlink():p.unlink()
     p.write_bytes(t.extractfile(i).read());p.chmod(i.mode)
    elif i.issym():
     target=i.linkname
     if target.startswith('/lib/'):target='/usr/lib/'+target[5:]
     if target.startswith('/'):target=os.path.relpath(root/target.lstrip('/'),p.parent)
     assert str((p.parent/target).resolve()).startswith(str(root.resolve())+'/')
     if os.path.lexists(p):p.unlink()
     p.symlink_to(target)
    elif i.islnk():
     target=root/posixpath.normpath(i.linkname);assert target.is_file();p.write_bytes(target.read_bytes());p.chmod(i.mode)
loader=root/'usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2';libs=root/'usr/lib/x86_64-linux-gnu';pg=root/'usr/lib/postgresql/18/bin';bin=b/'pg-bin';bin.mkdir();select=b/'pg-non-glibc-libs';select.mkdir()
hist=json.load(open('/workspace/zasp-sec/docs/internal/evidence/cloud-2026-10-07/native-service-readiness/openfga/09-pg-non-glibc-libs-manifest.json'))
for row in hist:
 name=row['name'];target=libs/name
 assert target.is_file();(select/name).symlink_to(target)
rows=[]
for name in ['initdb','pg_ctl','pg_isready','postgres','psql','pg_config']:
 p=bin/name;p.write_text('#!/bin/sh\nexport LD_LIBRARY_PATH='+str(select)+'\nexec '+str(loader)+' --library-path '+str(libs)+' '+str(pg/name)+' "$@"\n');p.chmod(0o700)
 r=subprocess.run([str(p),'--version'],capture_output=True,text=True,timeout=5);rows.append({'name':name,'path':str(p),'wrapperSHA256':hashlib.sha256(p.read_bytes()).hexdigest(),'binarySHA256':hashlib.sha256((pg/name).read_bytes()).hexdigest(),'exit':r.returncode,'version':r.stdout.strip(),'stderrBytes':len(r.stderr)})
d={'format':'fresh-spec29-official-PG183-native-tool-admission-v1','imageID':'sha256:3c67953c3a90a3a846b72e6cd2cfa418b0487e06156ed470dbbeaeb4cac09178','repoDigest':'postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba','layers':layers,'tools':rows,'loader':str(loader),'loaderSHA256':hashlib.sha256(loader.read_bytes()).hexdigest(),'libraryBindings':len(hist),'scope':'Cached official image saved read-only without container create/start; selected filesystem rederived and fresh native version checks only. No PG service/schema/test readiness.'}
out=b/'admission.json';out.write_text(json.dumps(d,indent=2)+'\n');print(json.dumps({'receipt':str(out),'sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'tools':rows}))
