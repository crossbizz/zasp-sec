import pathlib,json,hashlib,re,shutil
P=pathlib.Path;r=P(__file__).parent;out=P((r/'publication-candidate-path.txt').read_text().strip());h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();manifest=json.loads((out/'publication-manifest.json').read_text());scan=out/'evidence/scans';scan.mkdir()
entries=[]
for label in ['expanded','packed']:
 report=r/('publication-'+label+'-gitleaks-report.json');d=json.loads(report.read_text());assert len(d)==8
 source=r/'candidate-2912-ju2e8yei/source-inputs.json';lines=source.read_text().splitlines()
 for x in d:
  line=lines[x['StartLine']-1];m=re.fullmatch(r'\s*"([^"]+)": "([0-9a-f]{64})",?',line);assert m;rel,digest=m.groups();assert h(r/'source'/rel)==digest
  entries.append({'scan':label,'RuleID':x['RuleID'],'reportedFile':x['File'],'line':x['StartLine'],'sourcePath':rel,'SHA256':digest,'classification':'public SHA256 of exact tracked source bytes, not authentication credential','independentClassificationReviewRequired':True})
 for kind in ['report.json','log']:
  src=r/('publication-'+label+'-gitleaks-'+kind if kind=='report.json' else 'publication-'+label+'-gitleaks.log');dest=scan/(label+'-'+kind);shutil.copyfile(src,dest)
record={'scope':'default Gitleaks dir scans, no config/baseline/rules exceptions; packed scan archive depth2 and exact expanded source scan','toolPath':'/tmp/zasp-cloud-tools/bin/gitleaks','toolSHA256':h(P('/tmp/zasp-cloud-tools/bin/gitleaks')),'scans':[{'kind':'expanded','exitCode':1,'findings':8,'argv':['/usr/bin/env','-i','PATH=/usr/bin:/bin','/usr/bin/timeout','-k','5s','120s','/tmp/zasp-cloud-tools/bin/gitleaks','dir',str(out.parent/(out.name+'-expanded-scan')),'--ignore-gitleaks-allow','--redact','--report-format','json','--report-path',str(r/'publication-expanded-gitleaks-report.json')]},{'kind':'packed','exitCode':1,'findings':8,'argv':['/usr/bin/env','-i','PATH=/usr/bin:/bin','/usr/bin/timeout','-k','5s','120s','/tmp/zasp-cloud-tools/bin/gitleaks','dir',str(out),'--max-archive-depth','2','--ignore-gitleaks-allow','--redact','--report-format','json','--report-path',str(r/'publication-packed-gitleaks-report.json')]}],'findingClassification':entries,'scanClaims':'Actual both scans exit1/8findings; NOT zero. Only proposed public-source-hash classification until independent review.'}
(scan/'scan-record-and-public-hash-classification.json').write_text(json.dumps(record,indent=2)+'\n')
for src in [r/'prepare-primary-publication.py',r/'finish-primary-publication.py']:
 dest=out/'evidence/author-preparation'/src.name;shutil.copyfile(src,dest)
# Retain actual predecessor failure proof without copying immutable foundation.
attempt=P('/workspace/.zasp-cloud-owned/native379-v2-diagnostic-foundation-ntje6h8r/outputs/native379-v2-root-attempt-512-diagnostic-fcf00fe6e6b448dea9e453a496c1615d');target=out/'evidence/original-root-failure';target.mkdir()
for p in attempt.iterdir():
 if p.is_file():shutil.copyfile(p,target/p.name)
# Recompute finite published roster; original representation metadata retained where available.
for p in sorted(out.rglob('*')):
 if not p.is_file() or p.name=='publication-manifest.json':continue
 key=str(p.relative_to(out))
 if key not in manifest['members']:manifest['members'][key]={'sha256':h(p),'bytes':p.stat().st_size,'originalSHA256':h(p),'originalBytes':p.stat().st_size,'encoding':'identity'}
 assert manifest['members'][key]['sha256']==h(p)
manifest['actualPublishedMemberCount']=len(manifest['members']);manifest['scanStatus']='two actual default scans exit1 with8public-source-SHA findings each; independent classification review required';manifest['componentCountClaims']='actual author23/independent23/Node6; no seven-test claim';(out/'publication-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
for p in out.rglob('*'):
 if p.is_file():p.chmod(0o400)
print(json.dumps({'directory':str(out),'members':len(manifest['members']),'manifestSHA256':h(out/'publication-manifest.json'),'publishedBytes':sum(x['bytes'] for x in manifest['members'].values())}))
