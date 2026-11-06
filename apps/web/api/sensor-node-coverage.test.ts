import {describe,it,expect,vi} from "vitest";
import {createAPIClient} from "./client";
import {createSensorsAPI} from "../../../app/features/sensors/api";
import {decodeSensorNodeCoverage} from "./sensor-node-coverage";
const id="pid_91000001-0000-4000-8000-000000000001";
const legacy={sensor_id:id,supported:false,status:"pending",last_heartbeat:null,kernel:"unknown",btf:false,capabilities:[],event_rate:0,drops:0};
const target={namespace:"sensor",name:"agent",release:"zasp",release_namespace:"sensor",image:`example/sensor@sha256:${"b".repeat(64)}`,service_account:"agent",container:"agent"};
function fixture(state="source_current"){
 const observation={sequence:7,status:"degraded",capabilities:["process"],kernel:"unknown",btf:false,event_rate:0,drops:0,coverage_schema:"zasp-node-coverage-retained-v1",state_uid:"11111111-1111-4111-8111-111111111111",storage_epoch:1,selection:{source_profile:"tetragon-local-stream-v2",cluster_uid:"22222222-2222-4222-8222-222222222222",enrollment_binding:"a".repeat(64),match_labels:{group:"selected"},sensor:target,tetragon:{...target,name:"tetragon"}},target_digest:"c".repeat(64),inventory_observed_at:"2026-10-17T00:00:00Z",source_observed_at:"2026-10-17T00:00:00Z",ttl_seconds:30,sensor_daemonset_uid:"33333333-3333-4333-8333-333333333333",tetragon_daemonset_uid:"44444444-4444-4444-8444-444444444444",selected_nodes:[{node_name:"node-a",node_uid:"55555555-5555-4555-8555-555555555555",boot_id:"66666666-6666-4666-8666-666666666666"}],reports:[]};
 return {...legacy,node_observation:{schema:"zasp-node-observation-read-v1",state,receipt:state==="unavailable"?null:{sequence:7,request_digest:"d".repeat(64),received_at:"2026-10-17T00:00:00Z",source_observed_at:"2026-10-17T00:00:00Z",expires_at:"2026-10-17T00:00:30Z",observation}}};
}
const result=(value:unknown)=>new Response(JSON.stringify(value),{status:200,headers:{"Content-Type":"application/json","Cache-Control":"no-store"}});
describe("retained sensor observation typed transport",()=>{
 it("uses actual generated client with exact opt-in while legacy remains nine fields",async()=>{
  const fetch=vi.fn(async(request:Request)=>{expect(new URL(request.url).pathname).toBe(`/api/v1/sensors/${id}/coverage`);return result(request.headers.get("X-Zasp-Schema-Version")?fixture():legacy);});
  const api=createSensorsAPI(createAPIClient({fetch}));expect((await api.getSensorNodeCoverage(id)).node_observation.state).toBe("source_current");expect(await api.getSensorCoverage(id)).toEqual(legacy);expect(fetch).toHaveBeenCalledTimes(2);
 });
 it("retains expired/superseded/revoked testimony without inventing current Agent coverage",()=>{
  for(const state of ["unavailable","source_current","source_expired","source_superseded","enrollment_revoked"])expect(decodeSensorNodeCoverage(fixture(state),id).node_observation.state).toBe(state);
 });
 it("rejects header/body confusion, null or malformed nested authority and nanosecond mismatches",()=>{
  const mutations:((v:ReturnType<typeof fixture>)=>void)[]=[v=>{v.node_observation.schema="sensor-coverage-node-observation-v2";},v=>{v.sensor_id="pid_91000002-0000-4000-8000-000000000002";},v=>{v.node_observation.state="covered";},v=>{v.node_observation.receipt=null;},v=>{v.node_observation.receipt!.sequence++;},v=>{v.node_observation.receipt!.expires_at="2026-10-17T00:00:30.000000001Z";},v=>{v.node_observation.receipt!.observation.capabilities=[];},v=>{v.node_observation.receipt!.observation.selection.tetragon.name="agent";},v=>{v.node_observation.receipt!.observation.selected_nodes=[];},v=>{v.node_observation.receipt!.observation.status="healthy";},v=>{v.node_observation.receipt!.received_at="2026-02-30T00:00:00Z";},v=>{v.node_observation.receipt!.received_at="2026-10-17T24:00:00Z";},v=>{v.node_observation.receipt!.observation.kernel="界".repeat(60);}];
  for(const change of mutations){const value=structuredClone(fixture());change(value);expect(()=>decodeSensorNodeCoverage(value,id)).toThrow();}
  expect(()=>decodeSensorNodeCoverage(legacy,id)).toThrow();
 });
 it("allows bounded large versioned responses only on exact opted-in route and preserves smaller configured bound",async()=>{
  // Whitespace is legal JSON transport overhead; no fake large observation data.
  const payload=JSON.stringify(fixture())+" ".repeat(1024*1024);
  const fetch=async()=>new Response(payload,{status:200,headers:{"Content-Type":"application/json","Cache-Control":"no-store"}});
  await expect(createSensorsAPI(createAPIClient({fetch})).getSensorNodeCoverage(id)).resolves.toMatchObject({sensor_id:id});
  await expect(createSensorsAPI(createAPIClient({fetch})).getSensorCoverage(id)).rejects.toThrow();
  await expect(createSensorsAPI(createAPIClient({fetch,maximumResponseBytes:1024})).getSensorNodeCoverage(id)).rejects.toThrow();
 });
});
