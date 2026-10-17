import type { components } from "./generated";
import { APITransportError } from "./client";
import { decodeSensorCoverage } from "./decoders";
export type SensorNodeCoverage = components["schemas"]["SensorNodeCoverage"];
const bodySchema = "zasp-node-observation-read-v1";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const hash = /^[a-f0-9]{64}$/;
const name = /^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$/;
const heartbeatKeys = ["sequence","status","capabilities","kernel","btf","event_rate","drops"];
const envelopeKeys = [...heartbeatKeys,"coverage_schema","state_uid","storage_epoch","selection","target_digest","inventory_observed_at","source_observed_at","ttl_seconds","sensor_daemonset_uid","tetragon_daemonset_uid","selected_nodes","reports"];
const reportKeys = ["schema","enrollment_binding","cluster_uid","node_name","node_uid","boot_id","reporter_pod_name","reporter_pod_uid","tetragon_pod_name","tetragon_pod_uid","generation_id","source_profile","identity_observed_at","measured_at","status","capabilities","kernel","btf","event_rate","drops"];
export function decodeSensorNodeCoverage(value: unknown, expectedSensorID: string): SensorNodeCoverage {
 if(size(value)>16*1024*1024+65536)invalid();
 const top = object(value,["sensor_id","supported","status","last_heartbeat","kernel","btf","capabilities","event_rate","drops","node_observation"]);
 const {node_observation: observation,...legacy}=top; decodeSensorCoverage(legacy,expectedSensorID);
 const read=object(observation,["schema","state","receipt"]);
 if(read.schema!==bodySchema || !["unavailable","source_current","source_expired","source_superseded","enrollment_revoked"].includes(string(read.state))) invalid();
 if(read.state==="unavailable") {if(read.receipt!==null)invalid();return value as SensorNodeCoverage;}
 const receipt=object(read.receipt,["sequence","request_digest","received_at","source_observed_at","expires_at","observation"]); integer(receipt.sequence,1);pattern(receipt.request_digest,hash);
 const received=instant(receipt.received_at),source=instant(receipt.source_observed_at),expiry=instant(receipt.expires_at);
 const env=envelope(receipt.observation);
 if(receipt.sequence!==env.sequence || source!==instant(env.source_observed_at) || expiry!==source+BigInt(integer(env.ttl_seconds,6,300))*BigInt(1000000000) || received<source-BigInt(5000000000))invalid();
 // The stored request digest identifies the original raw request. Reserializing
 // an API JSON observation cannot reproduce or authenticate those original bytes.
 return value as SensorNodeCoverage;
}
function envelope(value:unknown):Record<string,unknown>{
 const e=object(value,envelopeKeys);integer(e.sequence,1);integer(e.storage_epoch,1);integer(e.ttl_seconds,6,300);
 if(e.coverage_schema!=="zasp-node-coverage-retained-v1")invalid();for(const k of ["state_uid","sensor_daemonset_uid","tetragon_daemonset_uid"])pattern(e[k],uuid);if(e.sensor_daemonset_uid===e.tetragon_daemonset_uid)invalid();pattern(e.target_digest,hash);
 const sel=object(e.selection,["source_profile","cluster_uid","enrollment_binding","match_labels","sensor","tetragon"]);pattern(sel.cluster_uid,uuid);pattern(sel.enrollment_binding,hash);if(!["tetragon-local-stream-v2","tetragon-local-stream-v3"].includes(string(sel.source_profile)))invalid();
 const labels=record(sel.match_labels);if(Object.keys(labels).length<1||Object.keys(labels).length>8)invalid();for(const [k,v]of Object.entries(labels)){text(k,1,253);const parts=k.split("/");if(parts.length>2||parts.length===2&&!name.test(parts[0]))invalid();pattern(parts[parts.length-1],/^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$/);pattern(v,/^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$/);}
 for(const k of ["sensor","tetragon"]){const target=object(sel[k],["namespace","name","release","release_namespace","image","service_account","container"]);for(const field of ["namespace","name","release","release_namespace","service_account","container"]){pattern(target[field],name);text(target[field],1,253);}text(target.image,1,512);pattern(target.image,/^[-A-Za-z0-9./:]+@sha256:[a-f0-9]{64}$/);if(target.release_namespace!==target.namespace)invalid();}
 if(size(sel)>65536 || record(sel.sensor).namespace===record(sel.tetragon).namespace&&record(sel.sensor).name===record(sel.tetragon).name)invalid();time(e.inventory_observed_at);time(e.source_observed_at);heartbeat(e,32);
 const selected=array(e.selected_nodes,1000);if(selected.length<1)invalid();const byID=new Map<string,Record<string,unknown>>(),names=new Set<string>(),uids=new Set<string>();let prior="";
 for(const value of selected){const n=object(value,["node_name","node_uid","boot_id"]);pattern(n.node_name,name);text(n.node_name,1,253);pattern(n.node_uid,uuid);pattern(n.boot_id,uuid);const key=`${string(n.node_uid)}/${string(n.boot_id)}`;if(key<=prior||names.has(string(n.node_name))||uids.has(string(n.node_uid))||size(n)>1024)invalid();prior=key;byID.set(key,n);names.add(string(n.node_name));uids.add(string(n.node_uid));}
 const reports=array(e.reports,1000);prior="";let source=instant(e.inventory_observed_at),kernel="unknown",rate=0,drops=0,allHealthy=reports.length===selected.length,allBTF=true;let caps=["file","network","process"];
 for(const value of reports){const v=object(value,reportKeys);if(v.schema!=="zasp-node-coverage-v2")invalid();for(const k of ["cluster_uid","node_uid","boot_id","reporter_pod_uid","tetragon_pod_uid","generation_id"])pattern(v[k],uuid);for(const k of ["node_name","reporter_pod_name","tetragon_pod_name"]){pattern(v[k],name);text(v[k],1,253);}const key=`${string(v.node_uid)}/${string(v.boot_id)}`;if(key<=prior||byID.get(key)?.node_name!==v.node_name||v.cluster_uid!==sel.cluster_uid||v.enrollment_binding!==sel.enrollment_binding||v.source_profile!==sel.source_profile||size(v)>8192)invalid();prior=key;
 const identity=instant(v.identity_observed_at),measured=instant(v.measured_at);if(identity>measured+BigInt(5000000000))invalid();source=identity<source?identity:source;source=measured<source?measured:source;heartbeat(v,3,false);const vc=array(v.capabilities,3).map(string);if(vc.some(c=>!["file","network","process"].includes(c)))invalid();
 kernel=kernel==="unknown"?string(v.kernel):kernel===v.kernel?kernel:"mixed";rate=Math.min(1e9,rate+integer(v.event_rate,0,1e9));drops=Math.min(1e9,drops+integer(v.drops,0,1e9));caps=caps.filter(c=>vc.includes(c));allBTF=allBTF&&v.btf===true;allHealthy=allHealthy&&v.status==="healthy"&&v.btf===true&&v.drops===0&&vc.length===3;
 }
 if(instant(e.source_observed_at)!==source||e.kernel!==kernel||e.event_rate!==rate||e.drops!==drops)invalid();const fallback=caps.length===0||reports.length===0;if(fallback)caps=["process"];
 if(JSON.stringify(caps)!==JSON.stringify(e.capabilities)||e.btf===true&&(!allBTF||!allHealthy)||e.status==="healthy"&&(!allHealthy||e.btf!==true||kernel==="mixed"||fallback)||fallback&&(e.status!=="degraded"||e.btf!==false))invalid();
 return e;
}
function heartbeat(v:Record<string,unknown>,max:number,ordered=true){if(v.status!=="healthy"&&v.status!=="degraded"||typeof v.btf!=="boolean")invalid();text(v.kernel,1,128);if(string(v.kernel).trim()!==v.kernel)invalid();integer(v.event_rate,0,1e9);integer(v.drops,0,1e9);const caps=array(v.capabilities,max).map(string);if(caps.length<1||new Set(caps).size!==caps.length||ordered&&caps.some((v,i)=>i>0&&caps[i-1]>=v))invalid();for(const c of caps)pattern(c,/^[a-z0-9][a-z0-9_.-]{0,95}$/);}
function record(v:unknown):Record<string,unknown>{if(!v||typeof v!=="object"||Array.isArray(v))return invalid();return v as Record<string,unknown>;}
function object(v:unknown,keys:readonly string[]):Record<string,unknown>{const r=record(v);if(Object.keys(r).length!==keys.length||keys.some(k=>!(k in r))||Object.keys(r).some(k=>!keys.includes(k)))invalid();return r;}
function array(v:unknown,max:number):unknown[]{if(!Array.isArray(v)||v.length>max)return invalid();return v;}
function string(v:unknown):string{if(typeof v!=="string")return invalid();return v;}
function text(v:unknown,min:number,max:number){const s=string(v);if(new TextEncoder().encode(s).byteLength<min||new TextEncoder().encode(s).byteLength>max||/\p{Cc}/u.test(s))invalid();}
function pattern(v:unknown,re:RegExp){if(!re.test(string(v)) || re===uuid&&v==="00000000-0000-0000-0000-000000000000")invalid();}
function integer(v:unknown,min:number,max=Number.MAX_SAFE_INTEGER):number{if(typeof v!=="number"||!Number.isSafeInteger(v)||v<min||v>max)return invalid();return v;}
function time(v:unknown):number{const s=string(v);if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(s)||s.startsWith("0000-")||!Number.isFinite(Date.parse(s))||new Date(Date.parse(s)).toISOString().slice(0,19)!==s.slice(0,19))return invalid();return Date.parse(s);}
function instant(v:unknown):bigint{const s=string(v);time(s);const match=/^(.*?)(?:\.(\d{1,9}))?Z$/.exec(s);if(!match)return invalid();return BigInt(Date.parse(`${match[1]}Z`))*BigInt(1000000)+BigInt((match[2]??"").padEnd(9,"0"));}
function size(v:unknown){const json=JSON.stringify(v,(_key,value:unknown)=>typeof value==="string"&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,9}Z$/.test(value)?value.replace(/(\.\d*?)0+Z$/,"$1Z").replace(/\.Z$/,"Z"):value);return new TextEncoder().encode(json.replace(/[<>&\u2028\u2029]/g,c=>`\\u${c.charCodeAt(0).toString(16).padStart(4,"0")}`)).byteLength;}
function invalid():never{throw new APITransportError("invalid_response","Invalid retained sensor observation response");}
