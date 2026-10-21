import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { JSON_SCHEMA, load } from "js-yaml";
test("listAgents exposes exact presence-aware owner label query without widening inventory scopes",async()=>{
 const doc=load(await readFile(new URL("./openapi.yaml",import.meta.url),"utf8"),{schema:JSON_SCHEMA});
 const resolve=p=>p.$ref?p.$ref.split("/").slice(1).reduce((v,k)=>v[k],doc):p;
 const params=doc.paths["/api/v1/agents"].get.parameters.map(resolve);
 const owner=params.find(p=>p.name==="owner"&&p.in==="query");assert.ok(owner,"mounted owner query missing");
 assert.equal(owner.required,false);assert.equal(owner.allowEmptyValue,true);assert.equal(owner.schema.type,"string");assert.equal(owner.schema.maxLength,128);
 assert.match(owner.description,/omitted|absent/i);assert.match(owner.description,/empty|unowned/i);assert.match(owner.description,/exact|literal/i);
 assert.equal(params.some(p=>p.name==="environment"||p.name==="environment_id"),false);
 for(const path of ["/api/v1/tools","/api/v1/identities","/api/v1/runtimes"])assert.equal((doc.paths[path].get.parameters??[]).map(resolve).some(p=>p.name==="owner"),false);
});
