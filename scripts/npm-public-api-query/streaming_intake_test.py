import io,os,sys,tarfile,gzip,hashlib,unittest,subprocess,time
from unittest.mock import patch
sys.dont_write_bytecode=True
import streaming_intake as s

def oid(kind,b):return hashlib.sha1(kind.encode()+b' '+str(len(b)).encode()+b'\0'+b).hexdigest()
def fixture(tail=b'{"affected":[{"package":{"ecosystem":"PyPI","name":"other"},"versions":["1.0"]}]}', mutate=None):
 data={}; trees={}
 def blob(b):o=oid('blob',b);data[o]=b;return o
 def tree(rows):
  raw=b''.join(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(o) for mode,name,o in sorted(rows,key=lambda v:(v[1]+('/' if v[0]=='40000' else '')).encode()))
  o=oid('tree',raw);trees[o]=raw;return o
 a=blob(b'{"id":"GHSA-2345-6789-cfgh","published":"2020-01-01T00:00:00Z","modified":"2020-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example"},"versions":["1.2.0"]}],"database_specific":{"severity":"HIGH"}}')
 b=blob(tail); reviewed=tree([('100644','a.json',a)]); unreviewed=tree([('100644','b.json',b)]);ad=tree([('40000','github-reviewed',reviewed),('40000','unreviewed',unreviewed)]);root=tree([('40000','advisories',ad)])
 sequence=[('advisories',None),('advisories/github-reviewed',None),('advisories/github-reviewed/a.json',data[a]),('advisories/unreviewed',None),('advisories/unreviewed/b.json',data[b])]
 if mutate:sequence=mutate(sequence)
 raw=io.BytesIO()
 with tarfile.open(fileobj=raw,mode='w',format=tarfile.PAX_FORMAT,pax_headers={'comment':'a'*40}) as tar:
  for path,body in [('',None),*sequence]:
   entry=tarfile.TarInfo('advisory-database-'+'a'*40+('/'+path if path else ''))
   entry.mode=0o775 if body is None else 0o664;entry.type=tarfile.DIRTYPE if body is None else tarfile.REGTYPE;entry.size=len(body) if body is not None else 0
   tar.addfile(entry,io.BytesIO(body) if body is not None else None)
 return root,trees,raw.getvalue()

class Intake(unittest.TestCase):
 def test_complete_archive_connects_verified_records_and_no_omitted_tail(self):
  root,trees,archive=fixture();frames=[]
  result=s.verify_archive(io.BytesIO(archive),root,lambda o:trees[o],'a'*40,lambda x:frames.append(x),lambda:None)
  self.assertEqual(result['selectedFiles'],2);self.assertEqual(result['npmRecords'],1);self.assertEqual(frames[0]['type'],'npm');self.assertFalse(result['releaseAccepted'])
  root,trees,archive=fixture();changed=archive[:-1]+b'X'
  with self.assertRaises(s.Refused):s.verify_archive(io.BytesIO(changed),root,lambda o:trees[o],'a'*40,lambda x:None,lambda:None)
  for change in [lambda rows:rows[:-1],lambda rows:rows+[rows[-1]],lambda rows:rows[:2]+[(rows[2][0],b'altered')]+rows[3:],lambda rows:[rows[1],rows[0],*rows[2:]]]:
   root,trees,archive=fixture(mutate=change)
   with self.assertRaises(s.Refused):s.verify_archive(io.BytesIO(archive),root,lambda o:trees[o],'a'*40,lambda x:None,lambda:None)
 def test_paths_links_pax_tree_width_and_binary_frames_are_closed(self):
  root,trees,archive=fixture(); raw=bytearray(archive)
  with self.assertRaises(s.Refused):list(s.tree_entries(b'40000 ../x\0'+bytes(20)))
  with self.assertRaises(s.Refused):s.checked_tree('0'*40,trees[root])
  out=io.BytesIO();s.emit_frame({'type':'npm','record':{'affected':[]}},out);wire=out.getvalue();self.assertEqual(int.from_bytes(wire[:4],'big'),len(wire)-4)
  with self.assertRaises(s.Refused):s.emit_frame({'body':'x'*(1<<20)},io.BytesIO())
  with self.assertRaises(s.Refused):s.validate_pax({'GNU.sparse.name':'x'},'a'*40)
  with self.assertRaises(s.Refused):s.validate_pax({'comment':'b'*40},'a'*40)
  self.assertEqual(s.validate_pax({'comment':'a'*40},'a'*40),None)


 def test_persistent_batch_reader_uses_exact_object_frames_and_joins(self):
  raw=b'100644 file\0'+bytes(20);expected=oid('tree',raw)
  script="import sys\nraw="+repr(raw)+"\nfor request in sys.stdin.buffer:\n oid=request.strip();sys.stdout.buffer.write(oid+b' tree '+str(len(raw)).encode()+b'\\n'+raw+b'\\n');sys.stdout.buffer.flush()\n"
  real=subprocess.Popen
  def process(*a,**kw):return real([sys.executable,'-B','-u','-c',script],**kw)
  with patch.object(s.subprocess,'Popen',process):
   reader=s.BatchTrees('/owned/git','/owned/repo',lambda:None)
   try:self.assertEqual(reader.read(expected),raw);reader.close();self.assertEqual(reader.p.returncode,0)
   finally:reader.stop()

if __name__=='__main__':unittest.main()
