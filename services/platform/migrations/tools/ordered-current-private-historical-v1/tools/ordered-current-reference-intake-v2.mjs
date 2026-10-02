// Offline, source-bound intake for the one reviewed frame-v2 A/B pair.
// This retains each exact observation and does not create installable facts.
import crypto from 'node:crypto';
import {readFixedOrderedConsolidatedReferencePairV2} from './ordered-current-consolidated-reference-v2-ab.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const fail=message=>{throw Error(`frame-v2 source-bound intake ${message}`);};
const inputFields=['aPacketRoot','aRaw','bPacketRoot','bRaw','compiledReleaseRaw','coverageRaw','sourceContractRaw'];
const source={
 compilerArtifactSHA256:'2ca5e151e304df622167ab5a313135acd28d8a010bc29638dd0e9c83f968395c',
 compilerChecksum:'f53752f15df1875e7c08ab6db39e91f08efdf5cf23bb2d6f86015fb22615a214',
 compiledSourceSHA256:'e04af1ed6cdaf40add80196b59214cc64f7f126c1d3f64801352a4bc20923b6e',
 sourceContractSHA256:'02b13c54ff1a543a4ca3a8f43fd2aa71e0334b04efea90afcf61cccf6a74e5cb',
 coverageSHA256:'67e214f69821c113b58078b5fc38e7504e33fb5748d7ad56de1fce01f85ed5c4',
};
const catalogSHA256='9cda05aa8d51f32b0b86d7997930e768b0b050308db26837093ff4fc6f6f35df';
const acceptedComparisonEvidence={
 reviewedImplementationSHA256:'7fde8d89aed2f57949e2188bd83eb106be5f1c221785d3ac4c3bb5484269366e',
 reviewSHA256:'2b38a98e07325cc79d49229a3f4572f57d67c066a592916d2b62ab07036ffa7d',
};

function sameFields(value){return value!==null&&typeof value==='object'&&!Array.isArray(value)&&JSON.stringify(Object.keys(value).sort())===JSON.stringify(inputFields);}
function json(raw,label){try{return JSON.parse(raw);}catch{fail(`${label} JSON`);}}
function bound(envelope){
 return envelope.sourceFrameVersion===2&&
  envelope.compilerArtifactSHA256===source.compilerArtifactSHA256&&
  envelope.compilerChecksum===source.compilerChecksum&&
  envelope.compiledSourceSHA256===source.compiledSourceSHA256&&
  envelope.sourceContractSHA256===source.sourceContractSHA256&&
  envelope.closureSHA256===source.coverageSHA256&&
  envelope.catalog1FileSHA256===catalogSHA256;
}

export function admitOrderedCurrentReferenceIntakeV2(input){
 if(!sameFields(input)||!Buffer.isBuffer(input.aRaw)||!Buffer.isBuffer(input.bRaw)||!Buffer.isBuffer(input.compiledReleaseRaw)||!Buffer.isBuffer(input.sourceContractRaw)||!Buffer.isBuffer(input.coverageRaw)||typeof input.aPacketRoot!=='string'||!input.aPacketRoot||typeof input.bPacketRoot!=='string'||!input.bPacketRoot)fail('input fields');
 if(sha(input.compiledReleaseRaw)!==source.compilerArtifactSHA256)fail('compiled release identity');
 if(sha(input.sourceContractRaw)!==source.sourceContractSHA256)fail('source contract identity');
 if(sha(input.coverageRaw)!==source.coverageSHA256)fail('coverage identity');
 const release=json(input.compiledReleaseRaw,'compiled release');
 if(release.format!=='zasp-worker-compiled-release-v1'||release.checksum!==source.compilerChecksum||release.source_sha256!==source.compiledSourceSHA256||typeof release.source!=='string'||sha(Buffer.from(release.source))!==source.compiledSourceSHA256)fail('compiled release binding');
 const admitted=readFixedOrderedConsolidatedReferencePairV2(input),{a,b,comparison,allowanceMetadata}=admitted;
 if(!bound(a)||!bound(b))fail('capture source binding');
 return {
  status:'SOURCE-BOUND-TYPED-OBSERVATIONS',
  installable:false,
  source:{...source},
  comparison,
  allowances:{...acceptedComparisonEvidence,...allowanceMetadata,disposition:'comparison-only-not-applied-to-observations'},
  provenance:{
   A:{captureSHA256:sha(input.aRaw),packetManifestSHA256:a.packetManifestSHA256,contractSHA256:a.contractSHA256,variant:a.variant,sessionUser:a.sessionUser},
   B:{captureSHA256:sha(input.bRaw),packetManifestSHA256:b.packetManifestSHA256,contractSHA256:b.contractSHA256,variant:b.variant,sessionUser:b.sessionUser},
  },
  observations:{A:a,B:b},
 };
}
