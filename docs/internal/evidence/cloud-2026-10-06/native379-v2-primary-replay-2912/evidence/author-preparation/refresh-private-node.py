from pathlib import Path
import hashlib,json,shutil
r=Path(__file__).parent;s=r/'source';t=s/'services/platform/migrations/tools';go=s/'services/platform/apiserver/authorization_worker_ordered_current_native379_v2_test.go';h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();impl='a6e8befd933d9b02c0b513f7e982f6a7f3f9b7ce9b969122111d4fbff9be1cb2';assert h(go)==impl
checkpoint=r/'source-checkpoint-a6e8';checkpoint.mkdir(mode=0o700);shutil.copyfile(go,checkpoint/go.name);(checkpoint/go.name).chmod(0o400)
m=t/'ordered-current-native379-packet-v2-artifacts/source-inputs.json';old=json.loads(m.read_text());assert len(old['files'])==1544
for name,pin in old['files'].items():
 if name!=str(go.relative_to(s)):assert h(s/name)==pin,name
raw=m.read_text();assert raw.count('6d02b8f23bf4c53fbe6230cb536bd8f993cf78eb67abe1fd832b27badf8e324e')==1;raw=raw.replace('6d02b8f23bf4c53fbe6230cb536bd8f993cf78eb67abe1fd832b27badf8e324e',impl);m.write_text(raw);mh=h(m)
p=t/'ordered-current-native379-source-schema-v2.mjs';raw=p.read_text();assert raw.count('02ef1b7ce237fa49272bc7e8e778a6fd9e77bde9566b363f7821d770cb2bd989')==1;p.write_text(raw.replace('02ef1b7ce237fa49272bc7e8e778a6fd9e77bde9566b363f7821d770cb2bd989',mh));ph=h(p)
p=t/'ordered-current-native379-packet-v2.mjs';raw=p.read_text();assert raw.count('82c955587e6c6f5e8c26dd3a0377d38887ed2711a8d26a50766c9882a8ae3a88')==1;p.write_text(raw.replace('82c955587e6c6f5e8c26dd3a0377d38887ed2711a8d26a50766c9882a8ae3a88',ph));print(json.dumps({'GoSHA256':impl,'manifestSHA256':mh,'schemaSHA256':ph,'packetCompilerSHA256':h(p),'files':1544}))
