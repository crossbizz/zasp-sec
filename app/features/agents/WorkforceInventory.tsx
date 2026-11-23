"use client";
import {useCallback,useState} from "react";
import type {workforceAPI} from "../../../apps/web/api/workforce-inventory";
import {useAPIQuery} from "../../api/query";
import {Button} from "../../components/ui";
import {Time} from "../../components/time";

export function WorkforceInventory({list}:{list:ReturnType<typeof workforceAPI>}){
 const [history,setHistory]=useState<string[]>([]);
 const cursor=history.at(-1);
 const load=useCallback((signal?:AbortSignal)=>list(cursor,signal),[list,cursor]);
 const query=useAPIQuery(`workforce:${cursor??""}`,load);
 return <section aria-label="Security workforce">
  {query.status==="loading" && <p role="status">Loading registered security agents…</p>}
  {["error","stale","forbidden"].includes(query.status) && <p role="alert">Workforce inventory is unavailable. <Button onClick={()=>void query.retry()}>Retry inventory</Button></p>}
  {query.status==="success" && query.data?.items.length===0 && <p>No registered security agents are visible in this environment.</p>}
  {query.status==="success" && query.data && query.data.items.length>0 && <table><thead><tr><th>Agent</th><th>Registration</th><th>Trigger</th><th>Locked purpose</th></tr></thead>
   <tbody>{query.data.items.map(a=><tr key={a.id+a.source}><td><strong>{a.name}</strong></td><td>{a.source==="studio"?"Custom Studio":"Built-in workflow"}<br/>Revision {a.revision}</td><td>{a.trigger.replaceAll("_"," ")}
    {a.source==="studio" && a.trigger==="finding_opened" && <p>{a.trigger_receipts} opening receipts</p>}</td>
    <td><details><summary>{a.mission}</summary><dl><dt>Read tools</dt><dd>{a.read_tools.map(t=>t.replaceAll("_"," ")).join(", ")||"None declared"}</dd>
    <dt>{a.source==="studio"?"Approval-gated proposal":"Registered actions"}</dt><dd>{a.actions.map(t=>t.replaceAll("_"," ")).join(", ")||"None"}</dd>
    <dt>Registered</dt><dd><Time value={a.updated_at}/></dd></dl></details></td></tr>)}</tbody></table>}
  {query.status==="empty" && <p>No registered security agents are visible in this environment.</p>}
  {(history.length>0 || query.data?.next_cursor) && <div className="page-actions">
   {history.length>0 && <Button onClick={()=>setHistory(h=>h.slice(0,-1))}>Previous agents</Button>}
   {query.data?.next_cursor && <Button onClick={()=>{const next=query.data?.next_cursor;if(next)setHistory(h=>[...h,next]);}}>Next agents</Button>}
  </div>}
 </section>;
}
