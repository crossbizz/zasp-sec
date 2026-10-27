"use client";
import {useEffect,useLayoutEffect,useMemo,useRef,useState} from 'react';
import type {GatewayDevice,GatewayDeviceStatus,GatewayEnrollmentTokenBundle} from '../../../apps/web/api/generated';
import {APIProductError} from '../../../apps/web/api/client';
import {useAPI} from '../../api/APIProvider';
import {useSession} from '../../auth/SessionProvider';
import {Button,Card,Field,Modal} from '../../components/ui';
import {createGatewayAttempt,createGatewayBootstrapAPI,type GatewayBootstrapAPI,type GatewayAttempt} from './api';
export type GatewayBootstrapAuthority=Readonly<{key:string,permitted:boolean,fresh:boolean,sessionValid:boolean,isCurrent():boolean}>;
export function ProductionGatewayBootstrapSurface(){
 const session=useSession();const context=useAPI();
 const organizationID=session.status==='authenticated'?session.organizationID:'',workspaceID=session.status==='authenticated'?session.workspaceID:'',environmentID=session.status==='authenticated'?session.environmentID:'';
 const scope=useMemo(()=>({organization_id:organizationID,workspace_id:workspaceID,environment_id:environmentID}),[organizationID,workspaceID,environmentID]);
 const api=useMemo(()=>createGatewayBootstrapAPI(context.client,scope),[context.client,scope]);
 const expiry=context.getSessionInvalidationGeneration(),stale=context.getScopeStaleGeneration();
 const authority:GatewayBootstrapAuthority={key:JSON.stringify([session.status==='authenticated'?session.principal.id:'',scope.organization_id,scope.workspace_id,scope.environment_id,context.queryGeneration,expiry,stale]),permitted:session.status==='authenticated'&&session.hasCapability('gateways.manage'),fresh:session.isFreshAuthenticated,sessionValid:session.status==='authenticated'&&context.queryScopeKey!==null,isCurrent:()=>expiry===context.getSessionInvalidationGeneration()&&stale===context.getScopeStaleGeneration()};
 return <ProductionGatewayBootstrapView api={api} authority={authority} onReauthenticate={session.reauthenticate}/>;
}
type GatewayViewProps={api:GatewayBootstrapAPI,authority:GatewayBootstrapAuthority,onReauthenticate():void};
export function ProductionGatewayBootstrapView(props:GatewayViewProps){return <GatewayBootstrapBody key={props.authority.key} {...props}/>;}
function GatewayBootstrapBody({api,authority,onReauthenticate}:GatewayViewProps){
 const [name,setName]=useState(''),[lookup,setLookup]=useState(''),[current,setCurrent]=useState<GatewayDeviceStatus|null>(null),[busy,setBusy]=useState(false),[message,setMessage]=useState(''),[revealed,setRevealed]=useState<Readonly<{key:string,value:GatewayEnrollmentTokenBundle}>|null>(null);
 const [pendingCreate,setPendingCreate]=useState<Readonly<{name:string,attempt:GatewayAttempt}>|null>(null);
 const [confirmedCreate,setConfirmedCreate]=useState<GatewayDevice|null>(null);
 const live=useRef(authority),mounted=useRef(true);
 useLayoutEffect(()=>{live.current=authority;},[authority]);
 useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;};},[]);
 useEffect(()=>{queueMicrotask(()=>{setRevealed(null);setCurrent(null);setLookup('');setName('');setMessage('');setBusy(false);});},[authority.key]);
 useEffect(()=>{if(!authority.fresh||!authority.permitted||!authority.sessionValid)queueMicrotask(()=>setRevealed(null));},[authority.fresh,authority.permitted,authority.sessionValid]);
 const active=(key:string,mutation=false)=>mounted.current&&live.current.key===key&&live.current.sessionValid&&live.current.permitted&&live.current.isCurrent()&&(!mutation||live.current.fresh);
 const refresh=async(id:string,key:string)=>{const value=await api.getGatewayDevice(id);if(active(key)){setCurrent(value);setLookup(id);}return value;};
 const create=async()=>{
  const key=authority.key;
  if(!active(key,true)||confirmedCreate||!validGatewayName(name))return;
  const intent=pendingCreate??{name,attempt:createGatewayAttempt()};
  setPendingCreate(intent);setBusy(true);setMessage('');setRevealed(null);
  let confirmed=false;
  try{
   const result=await api.createGatewayDevice({name:intent.name},intent.attempt);
   if(!active(key,true))return;
   // Once creation is confirmed, all recovery is a GET of this exact device.
   // Its idempotency attempt must never be confused with a failed metadata read.
   confirmed=true;setConfirmedCreate(result.device);setPendingCreate(null);setLookup(result.device.id);setCurrent(null);
   await refresh(result.device.id,key);
   if(active(key))setMessage('Gateway device created. Enrollment is a separate step.');
  }catch(cause){
   if(active(key)){
    if(confirmed)setMessage('Gateway creation is confirmed. Current metadata is unavailable; retry gateway status for this device.');
    else if(cause instanceof APIProductError&&cause.status===400){setPendingCreate(null);setMessage('Gateway input was rejected. Edit the name before submitting a new creation.');}
    else setMessage('Gateway creation may have committed. Recover this creation with the same metadata attempt before continuing; no enrollment was issued.');
   }
  }finally{if(active(key))setBusy(false);}
 };
 const retryConfirmed=async()=>{
  const key=authority.key;if(!confirmedCreate||!active(key))return;
  setBusy(true);setMessage('');
  try{await refresh(confirmedCreate.id,key);}catch{if(active(key))setMessage('Gateway creation is confirmed. Current metadata is unavailable; retry gateway status for this device.');}finally{if(active(key))setBusy(false);}
 };
 const startAnother=()=>{if(busy||!current)return;setConfirmedCreate(null);setPendingCreate(null);setCurrent(null);setLookup('');setName('');setMessage('');setRevealed(null);};

 const load=async()=>{const key=authority.key;if(!active(key))return;setBusy(true);setRevealed(null);setMessage('');try{await refresh(lookup,key);}catch{if(active(key)){setCurrent(null);setMessage('Current gateway metadata is unavailable. Retry the authoritative read.');}}finally{if(active(key))setBusy(false);}};
 const issue=async()=>{const key=authority.key;if(!current||!active(key,true)||current.issuance_state!=='available')return;const device=current.device;setBusy(true);setRevealed(null);setMessage('');try{const result=await api.issueGatewayEnrollment(device.id,{expected_version:device.version,ttl_seconds:3600},createGatewayAttempt());if(!active(key,true))return;if(!result.replayed)setRevealed({key,value:result.token_bundle});else setMessage('Enrollment metadata replayed without its one-time bundle. Read current status and deliberately revoke before issuing again.');}catch{if(active(key))setMessage('Enrollment may have committed, but its one-time bundle was not received. Read current status, deliberately revoke its enrollment, then issue with a new attempt.');}finally{if(active(key)){setCurrent(null);try{await refresh(device.id,key);}catch{if(active(key))setMessage('Enrollment may have committed. Current metadata is unavailable; retry the authoritative read before taking another action.');}if(active(key))setBusy(false);}}};
 const revoke=async()=>{const key=authority.key;if(!current?.latest_enrollment||!active(key,true))return;const device=current.device,token=current.latest_enrollment;setBusy(true);setMessage('');setRevealed(null);try{await api.revokeGatewayEnrollment(device.id,token.id,{expected_version:device.version},createGatewayAttempt());if(active(key))setMessage('Enrollment token revocation confirmed. Existing credentials are unaffected.');}catch{if(active(key))setMessage('Enrollment revocation was not confirmed. Refresh current metadata before another deliberate action.');}finally{if(active(key)){setCurrent(null);try{await refresh(device.id,key);}catch{if(active(key))setMessage('Current gateway metadata is unavailable. Retry the authoritative read.');}if(active(key))setBusy(false);}}};
 const visible=authority.permitted&&authority.fresh&&authority.sessionValid&&authority.isCurrent()&&revealed?.key===authority.key?revealed.value:null;
 if(!authority.permitted||!authority.sessionValid)return <section aria-label="Runtime gateways"><h2>Runtime gateways</h2><p>Gateway setup requires current environment identity permission and an available bootstrap profile.</p></section>;
 return <section aria-label="Runtime gateways"><Card title="Runtime gateways"><p>Create a device identity, then issue a one-time enrollment bundle. Device state and enrollment do not confirm installation or runtime coverage.</p>{message&&<p role="status">{message}</p>}
 {!authority.fresh?<Button onClick={onReauthenticate}>Reauthenticate for gateway setup</Button>:<><Field label="Gateway name" value={name} maxLength={128} disabled={busy||pendingCreate!==null||confirmedCreate!==null} onChange={event=>setName(event.target.value)}/>{!confirmedCreate&&<Button disabled={busy||!validGatewayName(name)} onClick={()=>void create()}>{pendingCreate?'Recover gateway creation':'Create gateway'}</Button>}{confirmedCreate&&current&&<Button disabled={busy} onClick={startAnother}>Create another gateway</Button>}</>}
 {confirmedCreate&&!current&&<div><p>{confirmedCreate.id}</p><Button disabled={busy} onClick={()=>void retryConfirmed()}>Retry gateway status</Button></div>}
 <Field label="Gateway device ID" value={lookup} disabled={busy} onChange={event=>setLookup(event.target.value)}/><Button disabled={busy||!/^pid_[0-9a-f-]{36}$/.test(lookup)} onClick={()=>void load()}>Load gateway</Button>
 {current&&<div><p>{current.device.id}</p><p>{current.device.name} · {current.device.state} · version {current.device.version}</p>{current.latest_enrollment&&<p>Enrollment {current.latest_enrollment.id} expires {current.latest_enrollment.expires_at}</p>}{current.issuance_state==='available'&&authority.fresh&&<Button disabled={busy} onClick={()=>void issue()}>Issue enrollment</Button>}{current.issuance_state==='existing_enrollment'&&<p>An existing enrollment blocks issuance until deliberately revoked, including after expiry.</p>}{current.issuance_state==='existing_credential'&&<p>An existing credential blocks enrollment. Revoking an enrollment token does not revoke a credential.</p>}{current.issuance_state==='device_unavailable'&&<p>This device cannot receive an enrollment.</p>}{current.latest_enrollment&&!current.latest_enrollment.revoked_at&&!current.latest_enrollment.consumed_at&&authority.fresh&&<Button disabled={busy} onClick={()=>void revoke()}>Revoke enrollment</Button>}</div>}
 </Card><Modal open={visible!==null} title="One-time gateway enrollment" onClose={()=>setRevealed(null)} footer={<Button onClick={()=>setRevealed(null)}>Done</Button>}><strong>Copy this enrollment bundle now</strong>{visible&&<><pre>{JSON.stringify(visible)}</pre><p>Pass this bundle through protected stdin to the gateway enrollment CLI. The CLI creates the private key locally. Never put this bundle in arguments, URLs, browser storage or Helm values.</p><p>After enrollment, create the Kubernetes credential Secret out of band and set runtimeGateway.credentialSecretName to its name. Authentic policy keys and proxy credentials require their separate existing Secret references.</p></>}</Modal></section>;
}

function validGatewayName(value:string):boolean{
 if(value!==value.trim())return false;
 const size=new TextEncoder().encode(value).length;
 if(size<1||size>128)return false;
 for(let i=0;i<value.length;i++){const unit=value.charCodeAt(i);if(unit<=0x1f||(unit>=0x7f&&unit<=0x9f))return false;if(unit>=0xd800&&unit<=0xdbff){const next=value.charCodeAt(++i);if(!(next>=0xdc00&&next<=0xdfff))return false;}else if(unit>=0xdc00&&unit<=0xdfff)return false;}
 return true;
}
