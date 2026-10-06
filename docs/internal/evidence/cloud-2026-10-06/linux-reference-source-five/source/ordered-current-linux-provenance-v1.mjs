// Actual ROOT-owned isolated build identity only. This descriptor admits no
// functional catalog fact, RR/frame proof, native result or caller authority.
import fs from 'node:fs';
import crypto from 'node:crypto';
const descriptorURL=new URL('./ordered-current-linux-provenance-v1.json',import.meta.url);
export const linuxProvenanceInputSHA256='68425b6efc85e163c5028dadb4b8ff3ec219dfb5d7a8a2772c73a58a45dddfb5';
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const fail=()=>{throw Error('ordered-current Linux provenance refused');};
function canonical(value){
 if(value===null||typeof value==='string'||typeof value==='boolean')return JSON.stringify(value);
 if(typeof value==='number'){if(!Number.isSafeInteger(value))fail();return JSON.stringify(value);}
 if(typeof value!=='object')fail();
 if(Array.isArray(value)){
  const descriptors=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(value);
  if(Object.getPrototypeOf(value)!==Array.prototype||keys.some(key=>typeof key!=='string')||keys.length!==value.length+1||Object.values(descriptors).some(d=>!Object.hasOwn(d,'value')))fail();
  for(let i=0;i<value.length;i++)if(!Object.hasOwn(descriptors,String(i)))fail();
  return '['+Array.from({length:value.length},(_,i)=>canonical(descriptors[i].value)).join(',')+']';
 }
 if(Object.getPrototypeOf(value)!==Object.prototype)fail();
 const descriptors=Object.getOwnPropertyDescriptors(value);
 if(Reflect.ownKeys(value).some(key=>typeof key!=='string')||Object.values(descriptors).some(d=>!Object.hasOwn(d,'value')))fail();
 return '{'+Object.keys(descriptors).sort().map(key=>JSON.stringify(key)+':'+canonical(descriptors[key].value)).join(',')+'}';
}
function load(){
 if(!fs.lstatSync(descriptorURL).isFile())fail();
 const bytes=fs.readFileSync(descriptorURL);if(sha(bytes)!==linuxProvenanceInputSHA256)fail();
 const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),value=JSON.parse(text);
 if(value.format!=='ordered-current-linux-provenance-v1'||value.expectedFromTarget!==false||value.installable!==false||value.nativeVerified!==false)fail();
 if(sha(value.identityRawUTF8)!==value.evidence.identitySHA256||canonical(JSON.parse(value.identityRawUTF8))!==canonical(value.identity))fail();
 if(value.evidence.identitySHA256!=='f0a0c2453f34ca87c7f3b38a58462cc6476eef44f0d0d0c6c504bae8dbd794ac'||value.evidence.independentReviewSHA256!=='1f7300596e3b9af7f566d1fd70e3e25cf949ec63ec6ab747374fc7fda52db138')fail();
 return value;
}
export function readOrderedCurrentLinuxProvenanceV1(){if(arguments.length!==0)fail();return structuredClone(load());}
export function admitOrderedCurrentLinuxProvenanceV1(value){
 if(arguments.length!==1)fail();const admitted=load();if(canonical(value)!==canonical(admitted))fail();return structuredClone(admitted);
}
