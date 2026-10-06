import pathlib,json,re,hashlib,subprocess,stat,collections
pub=pathlib.Path(__file__).parent;f=pathlib.Path('/workspace/.zasp-cloud-owned/native379-v2-diagnostic-foundation-ntje6h8r');repo=pathlib.Path('/workspace/zasp-sec');commit='512beb183a0f7994f8769fc6765e3e1b80af4523';sha=lambda b:hashlib.sha256(b).hexdigest();cache={};gitcache={};filecache={};paircache={};proof=[];pattern=re.compile(r'"((?:\\.|[^"\\])*)"\s*:\s*"([0-9a-f]{64})"')
for redname,rawname in [('original-metadata-redacted.json','private-original-literal-resolution.json'),('evidence-redacted.json','private-evidence-literal-resolution.json')]:
 redpath=pub/'security-scan'/redname;rawpath=pub/'security-scan'/rawname;red=json.loads(redpath.read_text());raw=json.loads(rawpath.read_text());assert len(red)==len(raw)
 def equivalent(item,rawflag):
  copy=dict(item)
  if rawflag:
   assert re.fullmatch('[0-9a-f]{52,64}',copy['Secret']);copy['Match']=copy['Match'].replace(copy['Secret'],'REDACTED');copy['Secret']='REDACTED'
  return json.dumps(copy,sort_keys=True,separators=(',',':'))
 assert collections.Counter(equivalent(i,False) for i in red)==collections.Counter(equivalent(i,True) for i in raw),'exact raw/redacted finding sets differ'
 for finding in raw:
  path=pathlib.Path(finding['File']);key=str(path)
  if key not in cache:cache[key]=(path.read_text().splitlines(),sha(path.read_bytes()))
  lines,mhash=cache[key];assert finding['StartLine']==finding['EndLine'];line=lines[finding['StartLine']-1];digest=finding['Secret'];pairKey=(key,finding['StartLine']);
  if pairKey not in paircache:
   paircache[pairKey]=collections.defaultdict(list)
   for m in pattern.finditer(line):paircache[pairKey][m.group(2)].append(m)
  possible=paircache[pairKey].get(digest,[]) if len(digest)==64 else [m for full,ms in paircache[pairKey].items() if full.startswith(digest) for m in ms]
  pairs=[m for m in possible if finding['Match'] in m.group(0)];assert pairs,(path.name,finding['StartLine'],'no exact matched assignment');references=[]
  for selected in pairs:
   fullDigest=selected.group(2);metadataKey=json.loads('"'+selected.group(1)+'"');name=path.name;actualPath=None;gitRef=None
   if name=='committed-source-file-manifest.json':
    gitRef=commit+':'+metadataKey
    if gitRef not in gitcache:gitcache[gitRef]=sha(subprocess.check_output(['git','show',gitRef],cwd=repo))
    actual=gitcache[gitRef];kind='PUBLIC-SHA256-OF-EXACT-COMMITTED-GIT-BLOB'
   else:
    if name=='go-tree-manifest.json':actualPath=f/'go'/metadataKey
    elif name in ['module-tool-tree-manifest.json','before-build-module-tool-file-manifest.json']:actualPath=f/'module-cache'/metadataKey
    elif name=='finished-source-file-manifest.json':actualPath=f/'module-cache/owned-source'/metadataKey
    elif metadataKey.startswith('/'):actualPath=pathlib.Path(metadataKey)
    elif metadataKey in ['agentsec-migrate','apiserver.test','migrations.test']:actualPath=f/'bin'/metadataKey
    elif metadataKey=='assembly_sha256':actualPath=f/'bin/agentsec-migrate'
    else:raise AssertionError(('unresolved',name,metadataKey))
    st=actualPath.lstat();resolvedPath=actualPath.resolve(strict=True)
    if actualPath.is_symlink():assert name in ['native379-v2-root-reviewed-pg-binding.json','go-build-envelope-candidate.json'] and metadataKey.startswith('/lib/'),str(actualPath)
    assert stat.S_ISREG(resolvedPath.lstat().st_mode),str(resolvedPath);actualKey=str(resolvedPath)
    if actualKey not in filecache:filecache[actualKey]=sha(resolvedPath.read_bytes())
    actual=filecache[actualKey];kind='PUBLIC-SHA256-OF-EXACT-RESOLVED-HOST-RUNTIME-FILE' if actualPath.is_symlink() else 'PUBLIC-SHA256-OF-EXACT-REGULAR-FILE-BYTES'
   assert fullDigest==actual and actual.startswith(digest),(path.name,metadataKey,'actual hash mismatch');references.append({'metadataKey':metadataKey,'assignmentStartColumn':selected.start()+1,'assignmentEndColumn':selected.end(),'classification':kind,'actualReference':gitRef if gitRef else str(actualPath),'resolvedRegularFile':None if gitRef else str(resolvedPath),'hostRuntimeSymlink':False if gitRef else actualPath.is_symlink(),'actualReferenceSHA256':actual,'verified':True})
  proof.append({'redactedReport':redname,'ruleID':finding['RuleID'],'fingerprint':finding['Fingerprint'],'metadataFile':str(path.relative_to(pub)),'metadataFileSHA256':mhash,'reportedLine':finding['StartLine'],'reportedColumns':[finding['StartColumn'],finding['EndColumn']],'matchedLiteral':digest,'matchedLiteralBytes':len(digest),'scannerChunkTruncatedSHA256Prefix':len(digest)<64,'fullMetadataSHA256':pairs[0].group(2),'references':references,'duplicateSameLiteralReferencesAreExplicit':len(references)>1,'verified':True})
summary={'scope':'ALL ACTUAL SCANNER FINDING LITERALS RESOLVED TO PUBLIC FILE/GIT SHA256; scans still FAILED, no ignore/config bypass or clearance','sourceCommit':commit,'findingCount':len(proof),'originalMetadataFindings':len(json.loads((pub/'security-scan/original-metadata-redacted.json').read_text())),'boundedEvidenceFindings':len(json.loads((pub/'security-scan/evidence-redacted.json').read_text())),'unresolvedFindings':0,'allMatchedValuesAreCompleteOrChunkTruncatedPublicSHA256References':True,'completeSHA256Matches':sum(not x['scannerChunkTruncatedSHA256Prefix'] for x in proof),'chunkTruncatedSHA256PrefixMatches':sum(x['scannerChunkTruncatedSHA256Prefix'] for x in proof),'privateMachineLiteralReports':'Used only exact literal resolution; no values printed; finding sets exactly equal redacted originals after standard redaction','longLineColumns':'Scanner columns are chunk-relative on long lines. Exact Match/Secret assignment used; no offset/entropy inference or invented coordinates. All duplicate same-digest assignment references explicitly verified.','uniqueRegularFilesIndependentlyRehashed':len(filecache),'uniqueGitBlobsIndependentlyHashed':len(gitcache),'reportHashes':{p.name:sha(p.read_bytes()) for p in (pub/'security-scan').glob('*resolution.json')},'pending':'Independent public-hash provenance review; no credential/security/native approval inferred','findings':proof}
(pub/'security-scan/public-hash-classification.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps({k:v for k,v in summary.items() if k!='findings'}))
