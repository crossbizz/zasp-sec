import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import test from "node:test";

import { SafeFailure, buildBuildEnvironment, fixedFailureLine, orchestrate, runBounded, runCLI, validateProofEnvironment } from "./run.mjs";

const successLine = "EKS Fargate egress proof passed: direct_denied=true proxy_allowed=true eni_attached=true cleanup=true.";

function validEnvironment() {
  return {
    PATH: "/fixed/bin", HOME: "/fixed/home", TMPDIR: "/fixed/tmp", GOCACHE: "/fixed/go-build", GOMODCACHE: "/fixed/go-mod",
    AWS_PROFILE: "ambient", HTTPS_PROXY: "http://ambient.invalid", KUBECONFIG: "/ambient/kubeconfig",
    AWS_M019_ISOLATED_TEST: "I_UNDERSTAND_THIS_APPLIES_A_DISPOSABLE_EKS_EGRESS_POLICY",
    AWS_M019_KUBECONFIG: "/owned/kubeconfig", AWS_M019_KUBE_CONTEXT: "proof-context", AWS_M019_CLUSTER_NAME: "proof-cluster",
    AWS_M019_REGION: "us-west-2", AWS_M019_FARGATE_PROFILE: "proof-profile", AWS_M019_PROFILE_NAMESPACE_PREFIX: "zasp-m019-",
    AWS_M019_PROFILE_LABEL_KEY: "zasp.agentsec.dev/fargate", AWS_M019_PROFILE_LABEL_VALUE: "true",
    AWS_M019_PROXY_URL: "https://proxy.example.test/canary", AWS_M019_DIRECT_URL: "https://undeclared.example.test/canary",
    AWS_M019_CANARY_TOKEN: "synthetic-token", AWS_M019_POD_SECURITY_GROUP_ID: "sg-0123456789abcdef0",
    AWS_M019_CLUSTER_SECURITY_GROUP_ID: "sg-11111111111111111", AWS_M019_PROXY_SECURITY_GROUP_ID: "sg-22222222222222222",
    AWS_M019_VPC_ID: "vpc-0123456789abcdef0", AWS_M019_DNS_CIDR: "10.0.0.2/32",
    AWS_M019_ACCESS_KEY_ID: "ABCDEFGHIJKLMNOPQRST", AWS_M019_SECRET_ACCESS_KEY: "synthetic-secret-value",
  };
}

test("capability gate requires every exact input before work", async () => {
  const proof=validateProofEnvironment(validEnvironment());
  assert.equal(Object.keys(proof).length,19);
  for(const name of Object.keys(proof)){const copy={...validEnvironment()};delete copy[name];assert.throws(()=>validateProofEnvironment(copy),error=>error instanceof SafeFailure&&error.category==="configuration");}
  let resolved=false; await assert.rejects(orchestrate({environment:{},resolveKubectl:async()=>{resolved=true;}})); assert.equal(resolved,false);
});

test("build and proof environments drop ambient provider proxy and profile state",()=>{
  const build=buildBuildEnvironment(validEnvironment());
  assert.equal(build.AWS_PROFILE,undefined);assert.equal(build.HTTPS_PROXY,undefined);assert.equal(build.KUBECONFIG,undefined);
  const proof=validateProofEnvironment(validEnvironment());assert.equal(proof.PATH,undefined);assert.equal(proof.AWS_PROFILE,undefined);
});

test("bounded child hard-kills and reaps combined-output overflow",async()=>{
  let killed=false;const child=fakeChild({stdoutChunks:[Buffer.alloc(9)],neverClose:true,onKill:()=>{killed=true;queueMicrotask(()=>child.emit("close",null,"SIGKILL"));}});
  await assert.rejects(runBounded("proof",[],{cwd:"/fixed",env:{},outputLimit:8,timeoutMs:1000},()=>child),error=>error instanceof SafeFailure);
  assert.equal(killed,true);
});

test("orchestrator builds offline runs allowlisted proof and cleans workspace",async()=>{
  const calls=[];let cleaned=false;
  const line=await orchestrate({environment:validEnvironment(),resolveKubectl:async()=>"/owned/kubectl",workspace:fakeWorkspace(()=>{cleaned=true;}),runImplementation:async(command,args,options)=>{calls.push({command,args,options});return calls.length===1?{code:0,signal:null,stdout:"",stderr:""}:{code:0,signal:null,stdout:`${successLine}\n`,stderr:""};}});
  assert.equal(line,successLine);assert.equal(cleaned,true);assert.equal(calls[0].options.env.GOPROXY,"off");assert.equal(calls[1].options.env.PATH,undefined);assert.equal(calls[1].options.timeoutMs,960000);
});

test("cleanup wins and CLI emits one fixed line",async()=>{
  let out="",err="";const code=await runCLI({environment:validEnvironment(),resolveKubectl:async()=>"/owned/kubectl",workspace:fakeWorkspace(()=>{throw new Error("secret");}),runImplementation:async()=>{throw new Error("provider");},writeOut:value=>{out+=value;},writeErr:value=>{err+=value;}});
  assert.equal(code,1);assert.equal(out,"");assert.equal(err,"EKS Fargate egress proof failed: cleanup rejected.\n");
});

test("only fixed categories cross the outer boundary",()=>{
  for(const category of ["configuration","provider","scheduling","canary","ownership","cleanup","deadline","panic"]){assert.equal(fixedFailureLine(new SafeFailure(category)),`EKS Fargate egress proof failed: ${category} rejected.`);}
  assert.equal(fixedFailureLine(new Error("secret")),"EKS Fargate egress proof failed: provider rejected.");
});

function fakeWorkspace(onCleanup){return{hasCandidate:()=>true,create:async()=>({path:"/fixed/zasp-m019-owned",dev:1,ino:2}),cleanup:async()=>onCleanup()};}
function fakeChild({stdoutChunks=[],code=0,signal=null,neverClose=false,onKill=()=>{}}={}){const child=new EventEmitter();child.stdout=new PassThrough();child.stderr=new PassThrough();child.kill=()=>{onKill();return true;};queueMicrotask(()=>{for(const chunk of stdoutChunks)child.stdout.write(chunk);if(!neverClose){child.stdout.end();child.stderr.end();child.emit("close",code,signal);}});return child;}
