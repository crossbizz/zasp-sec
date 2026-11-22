import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, writeFile, readFile, rm, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { stage } from "./stage.mjs";

test("Intune release staging binds PE architecture and exact approved hash and signer",async(t)=>{
  const temp=await mkdtemp(join(tmpdir(),"zasp-intune-"));
  t.after(()=>rm(temp,{recursive:true,force:true}));
  const input=join(temp,"fixture.exe"), output=join(temp,"release");
  const bytes=Buffer.alloc(256); bytes.writeUInt16LE(0x5a4d); bytes.writeUInt32LE(128,60); bytes.writeUInt32LE(0x4550,128); bytes.writeUInt16LE(0x8664,132);
  const sha=createHash("sha256").update(bytes).digest("hex"), signer="ab".repeat(20);
  await writeFile(input,bytes);
  await assert.rejects(stage(input,"f".repeat(64),signer,output),/approved release/);
  const release=await stage(input,sha,signer,output);
  assert.equal(release.architecture,"x64");
  assert.deepEqual((await readdir(join(output,"input"))).toSorted(),["Manage-ZaspCli.ps1","release.json","zaspctl.exe"]);
  assert.deepEqual(JSON.parse(await readFile(join(output,"input","release.json"),"utf8")),release);
  const detect=await readFile(join(output,"Detect-ZaspCli.ps1"),"utf8");
  assert.ok(detect.includes(sha)&&detect.includes(signer.toUpperCase())&&detect.includes("Get-AuthenticodeSignature"));
  await assert.rejects(stage(input,sha,signer,output),{code:"EEXIST"});
  assert.deepEqual(await readFile(join(output,"input","zaspctl.exe")),bytes);
  bytes.writeUInt16LE(0x014c,132); await writeFile(input,bytes);
  await assert.rejects(stage(input,sha,signer,output),/x64 or ARM64/);
});
