"use client";
import {useCallback,useEffect,useLayoutEffect,useMemo,useRef,useState} from 'react';
import type {AgentDeviceAssociation,AgentDeviceAssociationPage,AgentDeviceChallengeEnvelope,AgentDeviceIntentInput,AgentDeviceMutationResult} from '../../../../apps/web/api/generated';
import {APIProductError} from '../../../../apps/web/api/client';
import {challengeEnvelopeFromPending} from '../../../../apps/web/api/agent-device-association-decoders';
import {useAPI} from '../../../api/APIProvider';
import {Button,Field} from '../../../components/ui';
import {createAssociationAttempt,createAgentDeviceAssociationsAPI,type AgentDeviceAssociationsAPI,type AssociationAttempt,type AssociationScope} from './api';
export type AssociationAuthority=Readonly<{key:string,principalID:string,fresh:boolean,sessionValid:boolean,isCurrent():boolean}>;
export type AgentDeviceAssociationContext=Readonly<{authority:AssociationAuthority,scope:AssociationScope,onReauthenticate():void}>;
export function AgentDeviceAssociationsSurface({agentID,context}:{agentID:string,context:AgentDeviceAssociationContext}){
 const {client}=useAPI();const {organization_id,workspace_id,environment_id}=context.scope;
 const api=useMemo(()=>createAgentDeviceAssociationsAPI(client,{organization_id,workspace_id,environment_id}),[client,organization_id,workspace_id,environment_id]);
 return <AgentDeviceAssociationsPanel agentID={agentID} api={api} authority={context.authority} onReauthenticate={context.onReauthenticate}/>;
}
type Props={agentID:string,api:AgentDeviceAssociationsAPI,authority:AssociationAuthority,onReauthenticate():void};
export function AgentDeviceAssociationsPanel(props:Props){return <AssociationBody key={`${props.authority.key}/${props.agentID}`} {...props}/>;}
function AssociationBody({agentID,api,authority,onReauthenticate}:Props){
 const [page,setPage]=useState<AgentDeviceAssociationPage|null>(null),[ready,setReady]=useState(false),[loading,setLoading]=useState(false),[busy,setBusy]=useState(false),[message,setMessage]=useState(''),[deviceID,setDeviceID]=useState(''),[cursor,setCursor]=useState<string|undefined>(),[history,setHistory]=useState<(string|undefined)[]>([]);
 const [pendingCreate,setPendingCreate]=useState<Readonly<{body:AgentDeviceIntentInput,attempt:AssociationAttempt}>|null>(null),[confirmed,setConfirmed]=useState<AgentDeviceMutationResult|null>(null);
 const [clock,setClock]=useState<number|null>(null);
 const eventClock=useRef<number|null>(null);
 const mounted=useRef(true),live=useRef(authority),reader=useRef<AbortController|null>(null);
 useLayoutEffect(()=>{live.current=authority;},[authority]);
 useEffect(()=>{
  let cancelled=false;
  // Time changes through lifecycle/event work, never through rendering. Capture
  // click time before React handlers so an expired button cannot submit even
  // when browser timer throttling left its last rendered label behind.
  const tick=()=>{if(cancelled)return;const now=Date.now();eventClock.current=now;setClock(now);};
  queueMicrotask(tick);
  const timer=window.setInterval(tick,1000);
  window.addEventListener('click',tick,true);
  window.addEventListener('focus',tick);
  document.addEventListener('visibilitychange',tick);
  return()=>{cancelled=true;window.clearInterval(timer);window.removeEventListener('click',tick,true);window.removeEventListener('focus',tick);document.removeEventListener('visibilitychange',tick);};
 },[]);

 useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;reader.current?.abort();};},[]);
 const active=useCallback((key:string,write=false)=>mounted.current&&live.current.key===key&&live.current.sessionValid&&live.current.isCurrent()&&(!write||live.current.fresh),[]);
 const read=useCallback(async(next:string|undefined=undefined)=>{
  const key=authority.key;if(!active(key))return false;
  reader.current?.abort();const controller=new AbortController();reader.current=controller;setLoading(true);setReady(false);
  try{const data=await api.listAgentDeviceAssociations(agentID,{limit:20,...(next?{cursor:next}:{})},controller.signal);if(!active(key)||controller.signal.aborted)return false;setPage(data);setCursor(next);setReady(true);return true;}
  catch{if(active(key)&&!controller.signal.aborted)setMessage('Current administrative association metadata is unavailable. Retry the authoritative read.');return false;}
  finally{if(active(key)&&!controller.signal.aborted)setLoading(false);}
 },[api,agentID,authority.key,active]);
 useEffect(()=>{let cancelled=false;queueMicrotask(()=>{if(!cancelled)void read();});return()=>{cancelled=true;reader.current?.abort();};},[read]);
 useEffect(()=>{if(!authority.fresh||!authority.sessionValid)queueMicrotask(()=>{setPendingCreate(null);setConfirmed(null);});},[authority.fresh,authority.sessionValid]);
 const canManage=ready&&page?.capabilities.can_manage===true&&authority.fresh&&authority.sessionValid&&authority.isCurrent();
 const validID=/^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(deviceID)&&deviceID!=='pid_00000000-0000-4000-8000-000000000000';
 const create=async()=>{
  const key=authority.key;if(!canManage||!active(key,true)||!validID||confirmed)return;
  const intent=pendingCreate??{body:{device_id:deviceID,expected_association_version:page?.items.find(item=>item.device_id===deviceID)?.version??0,ttl_seconds:300},attempt:createAssociationAttempt()};
  setPendingCreate(intent);setConfirmed(null);setBusy(true);setMessage('');setReady(false);let receipt:AgentDeviceMutationResult|null=null;
  try{receipt=await api.createAgentDeviceIntent(agentID,intent.body,intent.attempt);if(!active(key,true))return;setConfirmed(receipt);setPendingCreate(null);}
  catch(cause){if(active(key)){if(cause instanceof APIProductError&&cause.status===400){setPendingCreate(null);setMessage('Association input was rejected. Edit the intended device before a new submission.');}else setMessage('Intent creation may have committed. Read current status or deliberately recover the original intent; no acceptance or approval was retried.');}}
  finally{if(active(key)){setHistory([]);const ok=await read();if(active(key)){if(receipt&&!ok)setMessage('Intent creation is confirmed. Retry association status; do not create another intent to recover this response.');setBusy(false);}}}
 };
 const mutation=async(item:AgentDeviceAssociation,kind:'activate'|'revoke')=>{
  const key=authority.key;if(!canManage||!active(key,true))return;
  const pending=item.pending_intent;
  if(kind==='activate'&&(!pending||pending.created_by!==authority.principalID||pending.state!=='pending_human'||!pending.acceptance||eventClock.current===null||Date.parse(pending.acceptance.expires_at)<=eventClock.current))return;
  setBusy(true);setMessage('');setReady(false);let succeeded=false;
  try{const attempt=createAssociationAttempt();const result=kind==='activate'?await api.activateAgentDeviceAssociation(agentID,item.association_id,{challenge_id:pending!.challenge_id,challenge_sha256:pending!.challenge_sha256,expected_association_version:item.version},attempt):await api.revokeAgentDeviceAssociation(agentID,item.association_id,{expected_association_version:item.version},attempt);if(!active(key,true))return;setConfirmed(result);succeeded=true;setMessage(kind==='activate'?'Administrative approval confirmed. Refresh current association metadata.':'Whole association revocation confirmed. Existing Device credentials are unaffected.');}
  catch{if(active(key))setMessage('The association change may have committed. Refresh current status before another deliberate action.');}
  finally{if(active(key)){setHistory([]);const ok=await read();if(active(key)){if(succeeded&&!ok)setMessage('Association change is confirmed. Retry association status for current metadata.');setBusy(false);}}}
 };
 const publicChallenge=(value:AgentDeviceChallengeEnvelope)=><div><strong>Copy this public challenge</strong><pre>{JSON.stringify(value)}</pre><p>This nonce grants no authority. Pass it through protected stdin to <code>agentsecctl gateway accept-agent --custody-file &lt;existing-custody-file&gt; --ca-bundle-file &lt;trusted-ca-file&gt;</code>. Device acceptance remains pending separate fresh human approval. No private key belongs in this browser.</p></div>;
 if(!authority.sessionValid||!authority.isCurrent())return <section aria-label="Administrative device associations"><h3>Administrative device associations</h3><p>Revalidate the current session and Agent scope before reading associations.</p></section>;
 const rows=page?.items??[],confirmedChallenge=confirmed?.challenge;
 const knownChallenge=confirmedChallenge&&!rows.some(item=>item.pending_intent?.challenge_sha256===confirmedChallenge.challenge_sha256)?confirmedChallenge:null;
 return <section aria-label="Administrative device associations"><h3>Administrative device associations</h3><p>Administrative admission is separate from observed workload routing, runtime health and policy coverage.</p>{message&&<p role="status">{message}</p>}{!ready&&<p>{loading?'Loading current association metadata…':'Current status is unavailable; retained metadata is not a current acceptance result.'}</p>}
 <Button disabled={busy||loading} onClick={()=>{setHistory([]);void read();}}>Refresh associations</Button>{confirmed&&!ready&&<Button disabled={busy||loading} onClick={()=>void read()}>Retry association status</Button>}
 {ready&&page?.capabilities.can_manage&&!authority.fresh&&<Button onClick={onReauthenticate}>Reauthenticate for association changes</Button>}
 {ready&&page?.capabilities.can_manage&&authority.fresh&&<div><Field label="Intended device ID" value={deviceID} disabled={busy||pendingCreate!==null||confirmed!==null} onChange={event=>setDeviceID(event.target.value)}/>{!confirmed&&<Button disabled={busy||!validID} onClick={()=>void create()}>{pendingCreate?'Recover intent':'Create association intent'}</Button>}{confirmed&&<Button disabled={busy} onClick={()=>{setConfirmed(null);setDeviceID('');setPendingCreate(null);setMessage('');}}>Prepare another intent</Button>}</div>}
 {knownChallenge&&authority.fresh&&publicChallenge(knownChallenge)}
 {ready&&rows.length===0&&<p>No administrative device associations were returned for this authorized Agent.</p>}
 {rows.map(item=><article key={item.association_id}><h4>{item.device_id}</h4><p>Association {item.association_id} · version {item.version}</p>{item.state!=='none'&&<p>Current administrative association: {item.state}{item.unavailable_reason!=='none'?` (${item.unavailable_reason})`:''}</p>}{item.pending_intent&&<div><p>Pending replacement or admission: {item.pending_intent.state}; expires {item.pending_intent.expires_at}</p>{ready&&authority.fresh&&publicChallenge(challengeEnvelopeFromPending(item.pending_intent))}{item.pending_intent.acceptance&&<p>Device accepted as {item.pending_intent.acceptance.credential.credential_id} generation {item.pending_intent.acceptance.credential.credential_generation}; acceptance expires {item.pending_intent.acceptance.expires_at}</p>}{canManage&&item.pending_intent.created_by===authority.principalID&&item.pending_intent.state==='pending_human'&&item.pending_intent.acceptance&&clock!==null&&Date.parse(item.pending_intent.acceptance.expires_at)>clock&&<Button disabled={busy} onClick={()=>void mutation(item,'activate')}>Approve association</Button>}</div>}{canManage&&<><p>Revoking this whole association invalidates its admitted configuration and every pending intent. Device credentials remain unchanged.</p><Button disabled={busy} onClick={()=>void mutation(item,'revoke')}>Revoke whole association</Button></>}</article>)}
 {ready&&<div><Button disabled={busy||history.length===0} onClick={()=>{const previous=history.at(-1);setHistory(value=>value.slice(0,-1));void read(previous);}}>Previous associations</Button><Button disabled={busy||!page?.next_cursor} onClick={()=>{if(page?.next_cursor){setHistory(value=>[...value,cursor].slice(-100));void read(page.next_cursor);}}}>Next associations</Button></div>}
 </section>;
}
