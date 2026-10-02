import { describe, expect, it } from "vitest";
import { createAPIClient } from "./client";
const id="pid_10000004-0000-4000-8000-000000000004";
const scope="pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
describe("compliance download transport",()=>{
 it("uses a four MiB attachment default while honoring explicit lower limits",async()=>{
  for(const [size,maximumResponseBytes,allowed] of [[1048577,undefined,true],[4194304,undefined,true],[4194305,undefined,false],[1048577,1048576,false]] as const){
   const client=createAPIClient({maximumResponseBytes,getExpectedScope:()=>scope,fetch:async()=>new Response("x".repeat(size),{headers:{"Content-Type":"text/plain","Cache-Control":"no-store","Content-Disposition":`attachment; filename="compliance-${id}.txt"`,"X-Content-Type-Options":"nosniff"}})});
   const request=client.POST("/api/v1/compliance/exports/{id}/download",{params:{path:{id},header:{"X-CSRF-Token":"c".repeat(32)}},body:{format:"human",token:"a".repeat(64)},parseAs:"blob"});
   if(allowed) expect((await request).data).toHaveProperty("size",size); else await expect(request).rejects.toMatchObject({kind:"response_too_large"});
  }
 });
 it("keeps ordinary JSON at its one MiB default",async()=>{
  const client=createAPIClient({fetch:async()=>new Response(JSON.stringify({text:"x".repeat(1048576)}),{headers:{"Content-Type":"application/json"}})});
  await expect(client.GET("/api/v1/compliance/controls")).rejects.toMatchObject({kind:"response_too_large"});
 });
 it("accepts bounded verified attachments with grants only in POST bodies",async()=>{
  let observed:Request|undefined;
  const client=createAPIClient({getCSRFToken:()=>"c".repeat(32),getExpectedScope:()=>scope,fetch:async request=>{observed=request;return new Response("frozen report",{headers:{"Content-Type":"text/plain; charset=utf-8","Cache-Control":"no-store","Content-Disposition":`attachment; filename="compliance-${id}.txt"`,"X-Content-Type-Options":"nosniff"}})}});
  const response=await client.POST("/api/v1/compliance/exports/{id}/download",{params:{path:{id},header:{"X-CSRF-Token":"c".repeat(32)}},body:{format:"human",token:"a".repeat(64)},parseAs:"blob"});
  expect(await (response.data as unknown as Blob).text()).toBe("frozen report");expect(observed?.url).not.toContain("a".repeat(64));expect(observed?.url).not.toContain("?");expect(await observed?.json()).toEqual({format:"human",token:"a".repeat(64)});
 });
 it("rejects empty successful download responses",async()=>{
  const client=createAPIClient({getCSRFToken:()=>"c".repeat(32),getExpectedScope:()=>scope,fetch:async()=>new Response(null,{status:204})});
  await expect(client.POST("/api/v1/compliance/exports/{id}/download",{params:{path:{id},header:{"X-CSRF-Token":"c".repeat(32)}},body:{format:"human",token:"a".repeat(64)},parseAs:"blob"})).rejects.toThrow();
 });
 it("rejects wrong filenames, cacheability and non-download text success",async()=>{
  for(const headers of [{"Content-Type":"text/plain","Cache-Control":"public","Content-Disposition":`attachment; filename="compliance-${id}.txt"`},{"Content-Type":"text/plain","Cache-Control":"no-store","Content-Disposition":"attachment; filename=../../secret.txt"}]){
   const client=createAPIClient({getCSRFToken:()=>"c".repeat(32),getExpectedScope:()=>scope,fetch:async()=>new Response("report",{headers})});
   await expect(client.POST("/api/v1/compliance/exports/{id}/download",{params:{path:{id},header:{"X-CSRF-Token":"c".repeat(32)}},body:{format:"human",token:"a".repeat(64)},parseAs:"blob"})).rejects.toThrow();
   await expect(client.GET("/api/v1/compliance/controls")).rejects.toThrow();
  }
 });
});
