import {webcrypto} from 'node:crypto';
import {describe,it,expect,vi,beforeEach} from 'vitest';
import {createAPIClient} from '../../../../apps/web/api/client';
import {createAgentDeviceAssociationsAPI} from './api';
import {ids,scope,page,result,activated,revoked,challenge,item} from './fixtures';
const response=(value:unknown,status=200,headers:Record<string,string>={})=>new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Pragma':'no-cache',...headers}});
beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
const attempt={idempotencyKey:'association_test_123456789'};
describe('Agent device association generated client integration',()=>{
 it('uses actual generated list intent activate revoke routes with browser fresh mutation headers and exact replay metadata',async()=>{
  const requests:Request[]=[];const replies=[response(page),response(result,201),response(activated),response(revoked),response({...result,replayed:true})];const fetch=vi.fn(async(r:Request)=>{requests.push(r);return replies.shift()!;});
  const api=createAgentDeviceAssociationsAPI(createAPIClient({fetch,getCSRFToken:()=> 'c'.repeat(32)}),scope);
  expect(await api.listAgentDeviceAssociations(ids.agent_id,{limit:20})).toEqual(page);expect(await api.createAgentDeviceIntent(ids.agent_id,{device_id:ids.device_id,expected_association_version:0,ttl_seconds:300},attempt)).toEqual(result);expect(await api.activateAgentDeviceAssociation(ids.agent_id,ids.association_id,{challenge_id:ids.challenge_id,challenge_sha256:challenge.challenge_sha256,expected_association_version:0},attempt)).toEqual(activated);expect(await api.revokeAgentDeviceAssociation(ids.agent_id,ids.association_id,{expected_association_version:0},attempt)).toEqual(revoked);expect(await api.createAgentDeviceIntent(ids.agent_id,{device_id:ids.device_id,expected_association_version:0,ttl_seconds:300},attempt)).toEqual({...result,replayed:true});
  expect(requests.map(r=>new URL(r.url).pathname)).toEqual([`/api/v1/agents/${ids.agent_id}/device-associations`,`/api/v1/agents/${ids.agent_id}/device-association-intents`,`/api/v1/agents/${ids.agent_id}/device-associations/${ids.association_id}/activate`,`/api/v1/agents/${ids.agent_id}/device-associations/${ids.association_id}/revoke`,`/api/v1/agents/${ids.agent_id}/device-association-intents`]);
  for(const request of requests.slice(1)){expect(request.headers.get('X-Zasp-Fresh-Auth')).toBe('confirmed');expect(request.headers.get('Idempotency-Key')).toBe(attempt.idempotencyKey);expect(request.headers.has('If-Match')).toBe(false);}expect(requests[0].headers.has('X-Zasp-Fresh-Auth')).toBe(false);
 });
 it('rejects closed nested null scope Agent challenge hash canonical wire status and response cache drift',async()=>{
  for(const reply of [response({...result,replayed:true},201),response(result,200),response({...result,extra:true},201),response({...result,challenge:null},201),response({...result,challenge:{...challenge,challenge_sha256:'c'.repeat(64)}},201),response({...result,challenge:{...challenge,challenge_wire:challenge.challenge_wire+'='}},201),response(result,201,{'Cache-Control':'public'}),response(result,201,{'Pragma':''})]){const api=createAgentDeviceAssociationsAPI(createAPIClient({fetch:async()=>reply}),scope);await expect(api.createAgentDeviceIntent(ids.agent_id,{device_id:ids.device_id,expected_association_version:0,ttl_seconds:300},attempt)).rejects.toThrow();}
  for(const value of [{...page,items:[{...item,agent_id:ids.device_id}]},{...page,items:[{...item,source_identity:undefined}]},{...page,capabilities:{can_manage:true,environment_fallback:true}},{...page,items:[{...item,version:9007199254740992}]}]){const api=createAgentDeviceAssociationsAPI(createAPIClient({fetch:async()=>response(value)}),scope);await expect(api.listAgentDeviceAssociations(ids.agent_id)).rejects.toThrow();}
  // Late review successor after actual first7PASS: bounded manual pagination must advance.
  const repeated=createAgentDeviceAssociationsAPI(createAPIClient({fetch:async()=>response({...page,next_cursor:'abcd'})}),scope);await expect(repeated.listAgentDeviceAssociations(ids.agent_id,{limit:1,cursor:'abcd'})).rejects.toThrow('pagination did not advance');
 });
});
