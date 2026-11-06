import {describe,it,expect,vi} from 'vitest';
import {createAPIClient} from '../../../apps/web/api/client';
import {createGatewayBootstrapAPI} from './api';
import {device,enrollment,bundle,status,issued,gatewayID,enrollmentID,scope} from './bootstrap-fixtures';
const response=(data:unknown,statusCode=200,headers:Record<string,string>={})=>new Response(JSON.stringify(data),{status:statusCode,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Pragma':'no-cache',...headers}});
const attempt={idempotencyKey:'gateway_test_123456789'};
describe('gateway bootstrap generated client connected flow',()=>{
 it('uses actual generated transport for create get issue revoke and metadata replay without secret',async()=>{
  const requests:Request[]=[];const answers=[response({device,replayed:false},201),response(status),response(issued,201),response({device,enrollment:{...enrollment,revoked_at:'2026-10-17T12:02:00Z'},replayed:false}),response({device,enrollment,replayed:true})];
  const fetch=vi.fn(async(request:Request)=>{requests.push(request);return answers.shift()!;});
  const api=createGatewayBootstrapAPI(createAPIClient({fetch,getCSRFToken:()=> 'c'.repeat(32)}),scope);
  expect(await api.createGatewayDevice({name:device.name},attempt)).toEqual({device,replayed:false});expect(await api.getGatewayDevice(gatewayID)).toEqual(status);expect(await api.issueGatewayEnrollment(gatewayID,{expected_version:1,ttl_seconds:3600},attempt)).toEqual(issued);await api.revokeGatewayEnrollment(gatewayID,enrollmentID,{expected_version:1},attempt);expect(await api.issueGatewayEnrollment(gatewayID,{expected_version:1,ttl_seconds:3600},attempt)).toEqual({device,enrollment,replayed:true});
  expect(requests.map(r=>new URL(r.url).pathname)).toEqual(['/api/v1/gateways',`/api/v1/gateways/${gatewayID}`,`/api/v1/gateways/${gatewayID}/enrollments`,`/api/v1/gateways/${gatewayID}/enrollments/${enrollmentID}/revoke`,`/api/v1/gateways/${gatewayID}/enrollments`]);
  for(const r of requests.filter(r=>r.method==='POST')){expect(r.headers.get('Idempotency-Key')).toBe(attempt.idempotencyKey);expect(r.headers.get('X-Zasp-Fresh-Auth')).toBe('confirmed');expect(r.headers.has('If-Match')).toBe(false);}expect(requests[1].headers.has('X-Zasp-Fresh-Auth')).toBe(false);expect(requests.every(r=>!r.url.includes(bundle.secret))).toBe(true);
 });
 it('rejects closed DTO cache scope device bundle and fresh versus replay status drift',async()=>{
  const invalid=[response({...issued,token_bundle:{...bundle,organization_id:gatewayID}},201),new Response(JSON.stringify(issued).replace('"replayed":false','"replayed":false,"replayed":false'),{status:201,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Pragma':'no-cache'}}),response(issued,200),response({...issued,replayed:true},201),response({...issued,token_bundle:{...bundle,device_id:enrollmentID}},201),response({...issued,token_bundle:{...bundle,secret:bundle.secret+'='}},201),response({...issued,unexpected:true},201),response(issued,201,{'Cache-Control':'public'}),response(issued,201,{'Pragma':''}),response({...issued,enrollment:{...enrollment,expires_at:'2026-02-30T00:00:00Z'}},201)];
  for(const reply of invalid){const api=createGatewayBootstrapAPI(createAPIClient({fetch:async()=>reply}),scope);await expect(api.issueGatewayEnrollment(gatewayID,{expected_version:1,ttl_seconds:3600},attempt)).rejects.toThrow();}
  const api=createGatewayBootstrapAPI(createAPIClient({fetch:async()=>response({...status,device:{...device,id:enrollmentID}})}),scope);await expect(api.getGatewayDevice(gatewayID)).rejects.toThrow();
  // Late source-review control: domain.ProductID is UUIDv4, not arbitrary UUID versions.
  const wrongVersion='pid_91000001-0000-1000-8000-000000000001';const oldID=createGatewayBootstrapAPI(createAPIClient({fetch:async()=>response({...status,device:{...device,id:wrongVersion}})}),scope);await expect(oldID.getGatewayDevice(wrongVersion)).rejects.toThrow();
  const zeroPayload='pid_00000000-0000-4000-8000-000000000000';const zeroID=createGatewayBootstrapAPI(createAPIClient({fetch:async()=>response({...status,device:{...device,id:zeroPayload}})}),scope);await expect(zeroID.getGatewayDevice(zeroPayload)).rejects.toThrow();
 });
});
