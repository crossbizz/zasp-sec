import crypto from 'node:crypto';
// Closed pinned source translation; unresolved transformations never become raw equality.
const historicalPins={
  "65.fingerprint":["aa4f2ab29e9b1c81a8b9e0da4f73de2accb039ce84365882a4a57a5970473072","a606299a4a5bd5c863265d7209c245d96611820a6c8ff8ec97e2e6e78566ac46",0],
  "66.fingerprint":["1ec22f54dd5c4658953d6c7a7fbc406a5bf01c3bd67b81954fdef275195b5edc","da1ed733ec5c56a1cd4aacec03d9a94ab54b98cbed1a94d443dd9b6e5b75dfd4",0],
  "67.base_fingerprint":["4c82e4587582f2a0d2edd52499a0d65ea224d89083c3444d3f6b3d135afe7aa9","3f9f793ea29cd864a19e0807cf3061c6224bccb4ee4e15477de54c2a11554f5c",0],
  "67.fingerprint":["f3dda0215658d125e02fc033647602f021ab917b605ea32b4d3ec50ce227b020","ee4a2f643d6ce40300dd7cdb480bc636d00466ff47ffc7e12c096777c7446f21",0],
  "68.fingerprint":["86d580cf58ef68b7db2d8519b043a7861fc294e05c8224559eb8c736624e05ca","b6fe245c87f5bd5313f1112eba9f873cc11d85110f604d5909b41cb849ff55d1",0],
  "69.fingerprint":["e3ffc65d5cdef28b346e287d26544e814a1bf61b3fea41b9b7aef6ace0ee1a6b","c5414faec8e3b45f3f198ba94237bd2995b3c39c5e2c46d832a7212bb19af0fc",0],
  "70.fingerprint":["508d05c6a882c6c60f521751a75e73eb0320e49cc84d663483a4532b2ae78243","4bb807323fccfc387d9d6bb141692ebc9ec06ef1e91755506cd35bee44cf446a",9],
  "71.fingerprint":["170f424022a86af42a9fd7e00573abddf44566df6cbd6aadef9f3847cbf07fcf","377f6d3de3a8bf702a6657d7accd76257fe44e26da301ef55d479bcd515615ea",9],
  "72.fingerprint":["1ec25170f7d2d2451c8dfb16ffefec0fbc7330eca7221638cb4c18ecdf74d41d","43b3d082bbec543ee3ba1717a090d2c4fef3305fdb41006a2338ff4422554725",0],
  "72.retained_execution_fingerprint":["5717960835e5732473eac93e43866ad6eced608a63ac393aa8c6752fb9089e64","2b9420f94abc111f2751e6fd4ff1dcb2501a1cc26657ba70d32f0e3e1908931b",7],
  "72.retained_precision_fingerprint":["65c56d5deaa809f9e751bec5878243569750653902d47ab299e98c504649d8b1","d818de30fd18ecfaf7901678f209a497686f7299aee204d33c39a4e3ed896cba",4],
  "73.fingerprint":["ffc8e725dca2ee8b5815a343c6c59fe4267e693156ba0d4ab73657b7f41059ae","63e60546045a88b0b0e17b91b27c6c93d8ce864ab7b178584a22958640633536",0],
  "74.fingerprint":["964b512abe7b8699e1e0ec54be6cfdb575f743fb045af10c6278eeb306b87d49","027e596cd9d68d9e24fed8b025ff964738b6e0687afa4d06e60803a90cbf3258",0],
  "74.outbox65_fingerprint":["bf41ba91b43a7990dbc90f78ccc3c96f596894c7a95bf0f597e406f670a9a7f7","7abb8b3f73465bb465bc1e0dc6d2bbafcdc5472302c1be88b9744375d9d4fb46",7],
  "74.owner66_fingerprint":["fa07210f2435498a8bc3089fec68c0d7217fac4cb49e998f9e84a7ede3da4ea9","82a8c8bd71866092d400ecf07221655c1740bdd6e9448ef7a12fba45e155a848",7],
  "75.fingerprint":["0bca58463f0f11314f63fe7800ec3dd22be6d96dbf52ba2bbb7046cd90d63a87","1e1d1af4b3314bd8cde1fe43c108659ee9b36f8ce2bd9d7ab59b669398f0ca07",11],
  "76.executor74_fingerprint":["657872e08adb170a9e447eb88474bd35384ea9a38e850aadcd268ef01d7ba72f","5a43ac437b370f0f3975579101e6d05a1bef54482d1f7ac8286c399de681b6da",0],
  "76.fingerprint":["7189e1537e779cf9011d129201d5eca54e4932455b1aa40a33d9bc80417e3c56","0cc5aed7dafe94d7c4c6622e12c55a3c4eb85e569187ab9794e355d4377ef5a5",0],
  "77.domain67_fingerprint":["a5d083b5b34d4658aee0c4226ff164f9cbca6ee0bb11474d20f2f75ceb8abbd7","75b979abf0553dbdf5250a9247069b2a423724db068538f5bdcdba1eabdef6a8",11],
  "77.fingerprint":["9d3653a189af7908d72e3021e706c800d01546fdf20e9bf3f556a8bbade408f5","981e93626e7b96a7385bfa975e5360895b36155398d8802eb183aca7b08553f5",0],
  "78.fingerprint":["0ae7074fca8c29edf1fe5ef85bfa68641428fd41468d2446c0d746ddaf70fc50","23f21233160cece16eaeccf5796ec4821533b560ce71e7e1a1e0b3ecb7f0f749",0],
  "78.predecessor73_fingerprint":["2bf78f04452ed244af78f1566e2b9358ce4d2068aa2f1568108829f84980a8b5","e4583cf6f31f7f5c8ac056eb2993a7d76f3ae009464778fbb99d27567d8e0ebd",10],
  "78.predecessor76_fingerprint":["336314fcf0f7bb05f1d99e5b655bfb78f70646a4e026e046c4d90abcb6feb8e2","923e6d0331ce700b03ed574482bedd881a49e10b2734b039842be5058c73af34",14],
  "78.predecessor77_fingerprint":["7f3460f9b71a3eb2d9dc9e96e81d32f8b70de2041408dd7e964a336204a29e6d","6381357469c4fde1b2bcb423f249623380912168ac4a12d31273bbd94c74c9b8",13],
};
const successorPins={
  "65.fingerprint":["aa4f2ab29e9b1c81a8b9e0da4f73de2accb039ce84365882a4a57a5970473072","a606299a4a5bd5c863265d7209c245d96611820a6c8ff8ec97e2e6e78566ac46",0],
  "66.fingerprint":["1ec22f54dd5c4658953d6c7a7fbc406a5bf01c3bd67b81954fdef275195b5edc","da1ed733ec5c56a1cd4aacec03d9a94ab54b98cbed1a94d443dd9b6e5b75dfd4",0],
  "67.base_fingerprint":["4c82e4587582f2a0d2edd52499a0d65ea224d89083c3444d3f6b3d135afe7aa9","3f9f793ea29cd864a19e0807cf3061c6224bccb4ee4e15477de54c2a11554f5c",0],
  "67.fingerprint":["f3dda0215658d125e02fc033647602f021ab917b605ea32b4d3ec50ce227b020","ee4a2f643d6ce40300dd7cdb480bc636d00466ff47ffc7e12c096777c7446f21",0],
  "68.fingerprint":["86d580cf58ef68b7db2d8519b043a7861fc294e05c8224559eb8c736624e05ca","b6fe245c87f5bd5313f1112eba9f873cc11d85110f604d5909b41cb849ff55d1",0],
  "69.fingerprint":["534bfddac036cdb8aa0020be1ab86a9a9c8b948ddb1d37cef0fb2c136f9ea5e1","a05b5c3a51f4f31fb0127ccd7275e54e411f710e56d76088eee6c53ddb372b18",0],
  "70.fingerprint":["508d05c6a882c6c60f521751a75e73eb0320e49cc84d663483a4532b2ae78243","4bb807323fccfc387d9d6bb141692ebc9ec06ef1e91755506cd35bee44cf446a",9],
  "71.fingerprint":["170f424022a86af42a9fd7e00573abddf44566df6cbd6aadef9f3847cbf07fcf","377f6d3de3a8bf702a6657d7accd76257fe44e26da301ef55d479bcd515615ea",9],
  "72.fingerprint":["1ec25170f7d2d2451c8dfb16ffefec0fbc7330eca7221638cb4c18ecdf74d41d","43b3d082bbec543ee3ba1717a090d2c4fef3305fdb41006a2338ff4422554725",0],
  "72.retained_execution_fingerprint":["5717960835e5732473eac93e43866ad6eced608a63ac393aa8c6752fb9089e64","2b9420f94abc111f2751e6fd4ff1dcb2501a1cc26657ba70d32f0e3e1908931b",7],
  "72.retained_precision_fingerprint":["65c56d5deaa809f9e751bec5878243569750653902d47ab299e98c504649d8b1","d818de30fd18ecfaf7901678f209a497686f7299aee204d33c39a4e3ed896cba",4],
  "73.fingerprint":["ffc8e725dca2ee8b5815a343c6c59fe4267e693156ba0d4ab73657b7f41059ae","63e60546045a88b0b0e17b91b27c6c93d8ce864ab7b178584a22958640633536",0],
  "74.fingerprint":["964b512abe7b8699e1e0ec54be6cfdb575f743fb045af10c6278eeb306b87d49","027e596cd9d68d9e24fed8b025ff964738b6e0687afa4d06e60803a90cbf3258",0],
  "74.outbox65_fingerprint":["bf41ba91b43a7990dbc90f78ccc3c96f596894c7a95bf0f597e406f670a9a7f7","7abb8b3f73465bb465bc1e0dc6d2bbafcdc5472302c1be88b9744375d9d4fb46",7],
  "74.owner66_fingerprint":["fa07210f2435498a8bc3089fec68c0d7217fac4cb49e998f9e84a7ede3da4ea9","82a8c8bd71866092d400ecf07221655c1740bdd6e9448ef7a12fba45e155a848",7],
  "75.fingerprint":["0bca58463f0f11314f63fe7800ec3dd22be6d96dbf52ba2bbb7046cd90d63a87","1e1d1af4b3314bd8cde1fe43c108659ee9b36f8ce2bd9d7ab59b669398f0ca07",11],
  "76.executor74_fingerprint":["98b0d9a64415be0f40d844d3a02361fcf73527434258a6ca2eaee5fe09e9d670","eeeee1f5537fbbfc0c7632e81eac07f067b2bd80dddecf512a8259fcc075baf5",0],
  "76.fingerprint":["7189e1537e779cf9011d129201d5eca54e4932455b1aa40a33d9bc80417e3c56","0cc5aed7dafe94d7c4c6622e12c55a3c4eb85e569187ab9794e355d4377ef5a5",0],
  "77.domain67_fingerprint":["a5d083b5b34d4658aee0c4226ff164f9cbca6ee0bb11474d20f2f75ceb8abbd7","75b979abf0553dbdf5250a9247069b2a423724db068538f5bdcdba1eabdef6a8",11],
  "77.fingerprint":["9d3653a189af7908d72e3021e706c800d01546fdf20e9bf3f556a8bbade408f5","981e93626e7b96a7385bfa975e5360895b36155398d8802eb183aca7b08553f5",0],
  "78.fingerprint":["c465e2bed58a2be8f35cda526dca81e62473d8564770219a45697e67bff5ea00","48a239da1b4b6805c4e2bc04b6e2341fb0a67d79bbf510a3b69386575862c735",0],
  "78.predecessor73_fingerprint":["2bf78f04452ed244af78f1566e2b9358ce4d2068aa2f1568108829f84980a8b5","e4583cf6f31f7f5c8ac056eb2993a7d76f3ae009464778fbb99d27567d8e0ebd",10],
  "78.predecessor76_fingerprint":["336314fcf0f7bb05f1d99e5b655bfb78f70646a4e026e046c4d90abcb6feb8e2","923e6d0331ce700b03ed574482bedd881a49e10b2734b039842be5058c73af34",14],
  "78.predecessor77_fingerprint":["7f3460f9b71a3eb2d9dc9e96e81d32f8b70de2041408dd7e964a336204a29e6d","6381357469c4fde1b2bcb423f249623380912168ac4a12d31273bbd94c74c9b8",13],
};
// The accepted recovery80 direct-frame fixture is a separately pinned
// successor of the historical contract: it contains the same source replay
// plus the reviewed 13 branch edits. Keep this profile distinct from the
// current generated successor; profile matching remains exact and cannot
// accept hybrids.
const framePins={
  "65.fingerprint":["aa4f2ab29e9b1c81a8b9e0da4f73de2accb039ce84365882a4a57a5970473072","a606299a4a5bd5c863265d7209c245d96611820a6c8ff8ec97e2e6e78566ac46",0],
  "66.fingerprint":["1ec22f54dd5c4658953d6c7a7fbc406a5bf01c3bd67b81954fdef275195b5edc","da1ed733ec5c56a1cd4aacec03d9a94ab54b98cbed1a94d443dd9b6e5b75dfd4",0],
  "67.base_fingerprint":["4c82e4587582f2a0d2edd52499a0d65ea224d89083c3444d3f6b3d135afe7aa9","3f9f793ea29cd864a19e0807cf3061c6224bccb4ee4e15477de54c2a11554f5c",0],
  "67.fingerprint":["f3dda0215658d125e02fc033647602f021ab917b605ea32b4d3ec50ce227b020","ee4a2f643d6ce40300dd7cdb480bc636d00466ff47ffc7e12c096777c7446f21",0],
  "68.fingerprint":["86d580cf58ef68b7db2d8519b043a7861fc294e05c8224559eb8c736624e05ca","b6fe245c87f5bd5313f1112eba9f873cc11d85110f604d5909b41cb849ff55d1",0],
  "69.fingerprint":["d36361132bc266195f79ba68ca924a3a563aa267383d02235dac6fe74041a9d5","90a11d27e52a03931ab685d81130023461805cd3c0e7be3d8481e60568c967de",0],
  "70.fingerprint":["508d05c6a882c6c60f521751a75e73eb0320e49cc84d663483a4532b2ae78243","4bb807323fccfc387d9d6bb141692ebc9ec06ef1e91755506cd35bee44cf446a",9],
  "71.fingerprint":["170f424022a86af42a9fd7e00573abddf44566df6cbd6aadef9f3847cbf07fcf","377f6d3de3a8bf702a6657d7accd76257fe44e26da301ef55d479bcd515615ea",9],
  "72.fingerprint":["1ec25170f7d2d2451c8dfb16ffefec0fbc7330eca7221638cb4c18ecdf74d41d","43b3d082bbec543ee3ba1717a090d2c4fef3305fdb41006a2338ff4422554725",0],
  "72.retained_execution_fingerprint":["5717960835e5732473eac93e43866ad6eced608a63ac393aa8c6752fb9089e64","2b9420f94abc111f2751e6fd4ff1dcb2501a1cc26657ba70d32f0e3e1908931b",7],
  "72.retained_precision_fingerprint":["65c56d5deaa809f9e751bec5878243569750653902d47ab299e98c504649d8b1","d818de30fd18ecfaf7901678f209a497686f7299aee204d33c39a4e3ed896cba",4],
  "73.fingerprint":["ffc8e725dca2ee8b5815a343c6c59fe4267e693156ba0d4ab73657b7f41059ae","63e60546045a88b0b0e17b91b27c6c93d8ce864ab7b178584a22958640633536",0],
  "74.fingerprint":["964b512abe7b8699e1e0ec54be6cfdb575f743fb045af10c6278eeb306b87d49","027e596cd9d68d9e24fed8b025ff964738b6e0687afa4d06e60803a90cbf3258",0],
  "74.outbox65_fingerprint":["bf41ba91b43a7990dbc90f78ccc3c96f596894c7a95bf0f597e406f670a9a7f7","7abb8b3f73465bb465bc1e0dc6d2bbafcdc5472302c1be88b9744375d9d4fb46",7],
  "74.owner66_fingerprint":["fa07210f2435498a8bc3089fec68c0d7217fac4cb49e998f9e84a7ede3da4ea9","82a8c8bd71866092d400ecf07221655c1740bdd6e9448ef7a12fba45e155a848",7],
  "75.fingerprint":["0bca58463f0f11314f63fe7800ec3dd22be6d96dbf52ba2bbb7046cd90d63a87","1e1d1af4b3314bd8cde1fe43c108659ee9b36f8ce2bd9d7ab59b669398f0ca07",11],
  "76.executor74_fingerprint":["76bcb5eee587b2e10dd6700dcb11a6fef45e21f8275e2fe4bc54398ad9b41882","f8bd2b66facd1ad63bb5c9e61ce36889bf79ee0555834af89d7d521cf9a10e7f",0],
  "76.fingerprint":["7189e1537e779cf9011d129201d5eca54e4932455b1aa40a33d9bc80417e3c56","0cc5aed7dafe94d7c4c6622e12c55a3c4eb85e569187ab9794e355d4377ef5a5",0],
  "77.domain67_fingerprint":["a5d083b5b34d4658aee0c4226ff164f9cbca6ee0bb11474d20f2f75ceb8abbd7","75b979abf0553dbdf5250a9247069b2a423724db068538f5bdcdba1eabdef6a8",11],
  "77.fingerprint":["9d3653a189af7908d72e3021e706c800d01546fdf20e9bf3f556a8bbade408f5","981e93626e7b96a7385bfa975e5360895b36155398d8802eb183aca7b08553f5",0],
  "78.fingerprint":["00d67a26c3ce62d1ab2cd8468c148620d31f69a5abf4410c4451212eea659fb2","47e83201f6c26f2e3a2160d535c68d9cd35b38b6d741d76b6ec0d372421948fd",0],
  "78.predecessor73_fingerprint":["2bf78f04452ed244af78f1566e2b9358ce4d2068aa2f1568108829f84980a8b5","e4583cf6f31f7f5c8ac056eb2993a7d76f3ae009464778fbb99d27567d8e0ebd",10],
  "78.predecessor76_fingerprint":["336314fcf0f7bb05f1d99e5b655bfb78f70646a4e026e046c4d90abcb6feb8e2","923e6d0331ce700b03ed574482bedd881a49e10b2734b039842be5058c73af34",14],
  "78.predecessor77_fingerprint":["7f3460f9b71a3eb2d9dc9e96e81d32f8b70de2041408dd7e964a336204a29e6d","6381357469c4fde1b2bcb423f249623380912168ac4a12d31273bbd94c74c9b8",13],
};
const sourceProfiles=[historicalPins,successorPins,framePins];

const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const eq=(field,value)=>({field,equals:value});
const any=(field,values)=>values.length===1?eq(field,values[0]):{any:values.map(v=>eq(field,v))};
const all=(...children)=>({all:children});
const not=child=>({not:child});
const strings=s=>[...s.matchAll(/'([^']*)'/g)].map(m=>m[1]);
const capture=(text,re)=>{const m=text.match(re);if(!m)throw Error('temporal source selector mismatch');return m[1];};
const refs=text=>[...new Set([...text.matchAll(/'([^']+)'::regclass/g)].map(m=>m[1]))];
// SQL is fully pinned before these bounded recognizers run; quoted text is never a callable edge.
const calls=text=>[...text.replace(/'(?:[^']|'')*'/g,m=>' '.repeat(m.length)).matchAll(/\b(zasp[a-z0-9_]+\.[a-z0-9_]+)\(([^()]*)\)/g)].map(m=>({name:m[1],arguments:m[2]}));
const targetList=text=>calls(text).map(c=>c.name+'('+c.arguments+')');
const listAfter=(text,pattern)=>strings(capture(text,pattern));
const fkFields=['relation','name','referenced_relation','trigger_relation','constraint_relation','function','event_bits','enabled','deferrable','deferred','argument_count','arguments','columns_text','when_text_or_empty'];

function executionSelector(branch,text) {
  const pub=eq('namespace','public');
  if(['table','column','policy'].includes(branch))return all(pub,any(branch==='table'?'name':'relation_name',listAfter(text,/c\.relname=ANY\(ARRAY\[([^\]]+)\]\)/)));
  if(branch==='constraint')return all(pub,{any:[{field:'relation_name',like:'zasp_discovery_execution_%'},...listAfter(text,/c\.relname IN\(([^)]+)\)/).map(n=>eq('relation_name',n))]},{any:[{field:'name',like:'zasp_execution_%'},not(eq('relation_name','zasp_integration_connections'))]});
  if(branch==='index')return all(pub,{field:'name',like:'zasp_execution_%'});
  if(branch==='function')return all(pub,{any:[{field:'name',like:'zasp_execution_%'},...listAfter(text,/p\.proname IN\(([^)]+)\)/).map(n=>eq('name',n))]},not(any('name',listAfter(text,/p\.proname NOT IN\(([^)]+)\)/))));
  if(branch==='trigger')return all(pub,{field:'name',like:'zasp_execution_%'});
  if(branch==='role')return any('name',listAfter(text,/r\.rolname=ANY\(ARRAY\[([^\]]+)\]\)/));
  throw Error('temporal source execution branch unknown');
}
function precisionSelector(branch,text) {
  if(branch==='function')return {any:[eq('namespace','zasp_precision_predecessor'),all(eq('namespace','public'),{any:[{field:'name',like:'%precision%'},{field:'name',like:'%precise%'},...listAfter(text,/p\.proname IN\(([^)]+)\)/).map(n=>eq('name',n))]})]};
  if(branch==='schema')return eq('name','zasp_precision_predecessor');
  if(branch==='constraint')return eq('name','zasp_runtime_precision_source_check');
  if(branch==='trigger')return all(any('relation',refs(capture(text,/(t\.tgrelid IN\([^)]*\))/))),not(all(eq('relation','public.zasp_runtime_stage_work'),eq('name','zasp_authorization80_runtime_stage_insert'))),not(all(eq('relation','public.zasp_discovery_outbox'),eq('name','zasp_temporal72_outbox_guard'))));
  throw Error('temporal source precision branch unknown');
}
function standardSelector(family,branch,text,namespace) {
  if(branch==='executor-function'||branch==='effective-policy-boundary')return any('identity',listAfter(text,/WHERE p\.oid IN\(([\s\S]+)\)\s*$/));
  if(branch==='executor-constraint')return all(eq('relation',refs(text)[0]),eq('name',capture(text,/k\.conname='([^']+)'/)));
  if(branch==='source-capture') {
    const pairs=[...text.matchAll(/\('([^']+)'::regclass,'([^']+)'\)/g)];
    if(pairs.length!==3)throw Error('temporal source capture pair mismatch');
    return {any:pairs.map(m=>all(eq('relation',m[1]),eq('name',m[2])))};
  }
  if(branch==='policy'&&family==='74.owner66_fingerprint')return {any:[eq('namespace',namespace),eq('name','zasp_temporal66_owner')]};
  if(branch==='trigger'&&family==='74.owner66_fingerprint')return {any:[eq('namespace',namespace),any('name',['zasp_temporal66_lease','zasp_temporal66_capture'])]};
  if(branch==='trigger'&&family==='78.predecessor77_fingerprint')return all(eq('namespace',namespace),not(all(any('relation',['zasp_temporal77.runtime_evaluations','zasp_temporal77.source_events']),any('name',['zasp_authorization80_worker_runtime_capture','zasp_authorization80_worker_runtime_no_truncate']))));
  if(branch==='owner-policy')return all(eq('relation',refs(text)[0]),eq('name',capture(text,/p\.polname='([^']+)'/)));
  if(text.includes(' FROM pg_trigger t WHERE '))return all(eq('relation',refs(text)[0]),eq('name',capture(text,/t\.tgname='([^']+)'/)));
  return eq('namespace',namespace);
}

function lowerBranch(family,branch,text,namespace) {
  const execution=family==='72.retained_execution_fingerprint',precision=family==='72.retained_precision_fingerprint';
  const selector=execution?executionSelector(branch,text):precision?precisionSelector(branch,text):standardSelector(family,branch,text,namespace);
  if(branch==='function'||['executor-function','effective-policy-boundary'].includes(branch)||(execution&&['table','policy','trigger','role'].includes(branch))) {
    return {transform:true,selector,required:'Preserve original selected fields and exact ordered replacement/normalization, ACL defaults/role ordering, original conditional saved-row lookup and its zero/multiple-row semantics, and every original frame/live identity condition. No raw definition/ACL equality substitute or frozen live value.'};
  }
  let kind=branch,fields,predicate;
  if(branch==='schema'){kind='namespace';fields=['name','owner','acl_text_or_empty'];}
  else if(branch==='table'){kind='relation';fields=['name','kind',...(text.includes('c.relpersistence')?['persistence']:[]),'owner','row_security','forced_row_security','acl_text_or_empty'];}
  else if(branch==='column'){
    kind=execution?'column_name':'column';
    fields=execution?['type','not_null','default_pretty_text_or_empty']:['relation_name','position','name','type','not_null','default_text_or_empty',...(text.includes('a.attacl')?['acl_text_or_empty']:[])];
  }
  else if(branch==='constraint'||branch==='executor-constraint'){
    kind=precision?'global_constraint':'constraint';
    fields=execution?['definition_pretty']:precision?['relation','name','validated','definition_pretty']:[...(branch==='constraint'?['relation_name']:[]),'name','definition','validated'];
  }
  else if(branch==='index')fields=execution?['definition_pretty']:['relation_name','definition','valid','ready'];
  else if(branch==='policy'||branch==='owner-policy'){
    kind='policy';
    fields=branch==='owner-policy'?['relation','name','permissive','command','roles','using','check']:[...(family==='74.owner66_fingerprint'?['namespace_name']:[]),'relation_name','name','command','permissive','roles','using','check'];
  }
  else if(branch==='foreign-key-trigger'){kind='foreign_key_trigger';fields=[...fkFields];}
  else if(branch==='saved'){kind='saved_function';fields=['signature','definition','owner','acl'];}
  else if(branch==='saved-constraint'){kind='saved_constraint';fields=['signature','definition'];}
  else if(['trigger','owner-trigger','capacity-trigger','human-trigger','definition-guard','source-capture','occurrence-guard'].includes(branch)){
    kind='trigger';
    const projection=text.slice(0,text.indexOf(' FROM '));
    fields=[...(projection.includes('t.tgrelid::regclass')?['relation']:[]),'name','enabled',precision?'definition_pretty':'definition',...(precision?['function_name','function_identity_arguments']:[])];
    if(text.includes('NOT t.tgisinternal'))predicate='user-triggers';
  } else throw Error('temporal source branch not handled');
  const base={id:'temporal:'+family+':'+branch,kind,namespaces:[],identities:[],fields};
  if(['saved_function','saved_constraint','foreign_key_trigger'].includes(kind))return {...base,namespaces:[namespace]};
  return {...base,selector,...(predicate?{predicate}:{})};
}

export function lowerOrderedTemporalCatalog(contract) {
  if(arguments.length!==1)throw Error('caller-provided temporal profile is forbidden');
  if(!contract||!Array.isArray(contract.nodes))throw Error('temporal source contract missing');
  const frameFor=family=>({owner:'zasp_discovery_authority',acl:'{zasp_discovery_authority=X/zasp_discovery_authority}',language:'sql',security_definer:family==='72.retained_execution_fingerprint',volatility:'s',parallel:'u',strict:false,leakproof:false,cost:100,rows:0,result:'text',arguments:''});
  const matchesProfile=profile=>Object.entries(profile).every(([family,[sourcePin,definitionPin]])=>{
    const identity='zasp_temporal'+family+'()',candidates=contract.nodes.filter(n=>typeof n?.identity==='string'&&n.identity.startsWith(identity.slice(0,-2)+'('));
    if(candidates.length!==1||candidates[0].identity!==identity)return false;
    const n=candidates[0],frame=frameFor(family);
    return typeof n.source==='string'&&typeof n.definition==='string'&&sha(n.source)===sourcePin&&n.sourceSHA256===sourcePin&&sha(n.definition)===definitionPin&&n.definitionSHA256===definitionPin&&!Object.entries(frame).some(([k,v])=>n[k]!==v)&&JSON.stringify(n.config)==='["search_path=pg_catalog, public"]';
  });
  const matchingProfiles=sourceProfiles.filter(matchesProfile);
  if(matchingProfiles.length!==1)throw Error('temporal source pin or frame mismatch');
  const pins=matchingProfiles[0];
  const rules=[],sites=[],obligations=[],unsupported=[];
  for(const [family,[sourcePin,definitionPin,count]] of Object.entries(pins)) {
    const identity='zasp_temporal'+family+'()',candidates=contract.nodes.filter(n=>typeof n?.identity==='string'&&n.identity.startsWith(identity.slice(0,-2)+'('));
    if(candidates.length!==1||candidates[0].identity!==identity)throw Error('temporal source missing, duplicate or overloaded');
    const n=candidates[0],frame=frameFor(family);
    if(typeof n.source!=='string'||typeof n.definition!=='string'||sha(n.source)!==sourcePin||n.sourceSHA256!==sourcePin||sha(n.definition)!==definitionPin||n.definitionSHA256!==definitionPin||Object.entries(frame).some(([k,v])=>n[k]!==v)||JSON.stringify(n.config)!=='["search_path=pg_catalog, public"]')throw Error('temporal source pin or frame mismatch');
    const site=(start,end,type)=>{
      const text=n.source.slice(start,end),s={family,identity,type,start:Buffer.byteLength(n.source.slice(0,start)),end:Buffer.byteLength(n.source.slice(0,end)),text,sha256:sha(text),sourceSHA256:sourcePin,definitionSHA256:definitionPin,...frame,config:[...n.config]};
      sites.push(s);return s;
    };
    const unresolved=(s,type,required,extra={})=>{
      const x={family,branch:s.type,type,siteSHA256:s.sha256,source:s.text,required,...extra};
      obligations.push(x);unsupported.push({...x,reason:required,disposition:'required original obligation; not installable or waived'});return x;
    };
    if(!count){
      const type=family==='68.fingerprint'?'delegate':'conditional-wrapper',s=site(0,n.source.length,type);
      unresolved(s,type,'Preserve original conditional demand, registration cardinality/values, exact callable body/owner/ACL/frame tests, NULL/error behavior and outgoing call identity under the original frame; do not hoist or recursively call originals from the collector.',{targets:targetList(s.text)});
      continue;
    }
    const starts=[0,...[...n.source.matchAll(/\n +UNION ALL /g)].map(m=>m.index)],digestStart=n.source.lastIndexOf('\n ) SELECT');
    if(starts.length!==count+1||digestStart<starts.at(-1))throw Error('temporal source branch coverage mismatch');
    const namespace=n.source.match(/nspname='(zasp_temporal[0-9]+)'/)?.[1];
    for(let i=0;i<starts.length;i++){
      const text=n.source.slice(starts[i],starts[i+1]??digestStart);
      const branch=text.match(/concat_ws\('\|','([a-z-]+)'/)?.[1]??text.match(/SELECT '([a-z-]+)'(?:::text)?(?: kind)?,/)?.[1]??(text.includes("'||zasp_")?'predecessor':null);
      if(!branch)throw Error('temporal source unrecognized fact site');
      const s=site(starts[i],starts[i+1]??digestStart,branch);
      if(branch==='prior'||branch==='predecessor'){
        unresolved(s,'predecessor','Preserve exact predecessor value/NULL propagation and concatenation under original frame without generic recursive original calls.',{targets:targetList(text)});continue;
      }
      const lowered=lowerBranch(family,branch,text,namespace);
      if(lowered.transform){unresolved(s,'original-transformation',lowered.required,{selector:lowered.selector});continue;}
      rules.push(lowered);
      const reasons=[];
      if(/'[^']+'::reg(namespace|class|procedure|role)/.test(text))reasons.push('original literal reg-object resolution and missing-object errors must be retained, not silently replaced with empty rows');
      if(lowered.kind==='foreign_key_trigger')reasons.push('exact internal FK constraint-source joined descriptor and independent reference tuples required; generated trigger names/OIDs are not keys');
      if(lowered.kind.startsWith('saved_'))reasons.push('exact saved signature/definition/owner/ACL values and full original table cardinality required; missing table must error');
      if(lowered.fields.some(f=>['namespace_name','default_pretty_text_or_empty','definition_pretty','function_name','function_identity_arguments'].includes(f)))reasons.push('exact original-frame projected fields/deparse and independent reference values required');
      if(reasons.length)unresolved(s,'descriptor-reference',reasons.join('; '),{ruleId:lowered.id});
    }
    const digest=site(digestStart,n.source.length,'digest'),json=family==='72.retained_execution_fingerprint';
    obligations.push({family,type:'digest-semantics',siteSHA256:digest.sha256,encoding:json?'jsonb-array':'sorted-lines',required:json?'Preserve exact JSON field names/types/NULL, row identities and cardinality, sorted kind/identity/definition JSONB aggregation, empty [] fallback, UTF8 and SHA256. Typed comparison is not byte-identical digest proof.':'Preserve original concat_ws NULL skipping, field-specific coalesces, UNION ALL cardinality, sorted newline string_agg including NULL empty aggregate, UTF8 and SHA256. Typed comparison is not byte-identical digest proof.'});
  }
  return {rules,sites,obligations,unsupported};
}
