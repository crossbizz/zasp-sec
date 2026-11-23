"use client";
import {useCallback,useMemo,useState} from "react";
import {APIProductError} from "../../../apps/web/api/client";
import {useAPI} from "../../api/APIProvider";
import {useAPIQuery} from "../../api/query";
import {Button} from "../../components/ui";
import {purposeAPI,type PurposeAttempt} from "../policies/purpose-api";

export function ReviewedPurpose({agent,tools}:{agent:string;tools:readonly string[]}){
 const {client}=useAPI();
 const api=useMemo(()=>purposeAPI(client),[client]);
 const [opened,setOpened]=useState(false);
 const get=useCallback((signal?:AbortSignal)=>api.get(agent,signal),[api,agent]);
 const current=useAPIQuery(`reviewed-purpose:${agent}`,get,opened);
 const [pending,setPending]=useState<PurposeAttempt | null>(null);
 const [busy,setBusy]=useState(false);
 const [notice,setNotice]=useState("");
 const proposed=[...new Set(tools)].sort();
 const stored=current.status==="success"?current.data:undefined;
 const same=!!stored && stored.revision>0 && JSON.stringify([...stored.allowed_tool_ids].sort())===JSON.stringify(proposed);
 async function save(){
  if(busy||(!pending&&!stored))return;
  const attempt=pending??{agent,tools:proposed,revision:stored!.revision,key:crypto.randomUUID()};
  setPending(attempt);setBusy(true);setNotice("");
  try{const saved=await api.save(attempt);setPending(null);setNotice(`Saved purpose revision ${saved.revision}.`);await current.retry();}
  catch(e){if(e instanceof APIProductError && e.status>=400 && e.status<500 && e.status!==429){setPending(null);setNotice("The purpose or your access changed. Review the current declaration again.");await current.retry();}
   else setNotice("Save unconfirmed. Retry to retrieve the same decision.");}
  finally{setBusy(false);}
 }
 if(!opened)return <Button onClick={()=>setOpened(true)}>Review proposed declaration</Button>;
 return <section aria-label="Review proposed declaration"><h4>Review proposed declaration</h4>
  {current.status==="loading"&&<p role="status">Loading current declaration…</p>}
  {["error","stale","forbidden"].includes(current.status)&&<p role="alert">Current declaration unavailable. <Button onClick={()=>void current.retry()}>Refresh declaration</Button></p>}
  {stored&&<><dl><dt>Current tools · revision {stored.revision}</dt><dd>{stored.allowed_tool_ids.join(", ")||"None declared"}</dd>
    <dt>Proposed tools</dt><dd>{proposed.join(", ")||"No intended tools"}</dd></dl>
    {same?<p>This declaration already matches the draft.</p>:<Button disabled={busy} onClick={()=>void save()}>{pending?"Retry saving purpose":"Save reviewed purpose"}</Button>}</>}
  {notice&&<p role="status">{notice}</p>}
 </section>;
}
