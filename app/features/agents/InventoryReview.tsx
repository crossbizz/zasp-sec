"use client";
import {useEffect,useRef,useState} from "react";
import type {InventoryReviewReceipt} from "../../../apps/web/api/generated";
import type {ReviewPurpose,reviewAPI} from "../../../apps/web/api/inventory-review";
import {APIProductError} from "../../../apps/web/api/client";
import {ReviewedPurpose} from "./ReviewedPurpose";
import {Button} from "../../components/ui";
import {useOptionalSession} from "../../auth/SessionProvider";

const actions = {
 agent_discovery_verify:"Verify discovery",
 agent_purpose_draft:"Draft intended tools",
 addon_semantic_audit:"Review static findings",
} as const;
function Result({receipt}:{receipt:InventoryReviewReceipt}) {
 const v=receipt.result;
 if(!v || receipt.coverage_degraded)return <p role="status">The optional model review is unavailable. Current evidence and approvals remain in effect.</p>;
 if("kind" in v)return <p><strong>{v.kind.replaceAll("_"," ")}</strong> · evidence {v.evidence_refs.join(", ")}</p>;
 if("allowed_tool_ids" in v)return <div><h4>Suggested purpose</h4><p>{v.allowed_tool_ids.length ? v.allowed_tool_ids.join(", ") : "No supported tools identified."}</p>{v.iam_mismatches.length>0 && <p>Access evidence to review · {v.iam_mismatches.join(", ")}</p>}<ReviewedPurpose agent={receipt.target_id} tools={v.allowed_tool_ids}/></div>;
 return <dl><dt>Estimated threat</dt><dd>{Math.round(v.threat_score*100)}%</dd><dt>Estimated impact</dt><dd>{Math.round(v.risk_score*100)}%</dd><dt>Static evidence</dt><dd>{v.citations.join(", ")}</dd>{v.tags.length>0 && <><dt>Framework references</dt><dd>{v.tags.join(", ")}</dd></>}</dl>;
}
export function InventoryReview({id,purposes,review}:{id:string;purposes:readonly ReviewPurpose[];review:ReturnType<typeof reviewAPI>}) {
 const session=useOptionalSession();
 const active=useRef<AbortController | null>(null);
 const [attempt,setAttempt]=useState<{purpose:ReviewPurpose;key:string} | null>(null);
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState("");
 const [receipt,setReceipt]=useState<InventoryReviewReceipt | null>(null);
 useEffect(()=>()=>active.current?.abort(),[]);
 if(session?.status!=="authenticated" || !session.hasCapability("policies.write"))return null;
 async function request(p:ReviewPurpose){
   if(active.current)return;
   const work=attempt??{purpose:p,key:crypto.randomUUID()};
   const controller=new AbortController();active.current=controller;
   setBusy(true);setError("");setReceipt(null);setAttempt(work);
   try {const value=await review(id,work.purpose,work.key,controller.signal);if(!controller.signal.aborted){setReceipt(value);setAttempt(null);}}
   catch(e){if(!controller.signal.aborted){
     const definitive=e instanceof APIProductError && e.status>=400 && e.status<500 && e.status!==429;
     if(definitive)setAttempt(null);
     setError(definitive?"Review unavailable for this item or session.":"The review could not be confirmed. Retry the same request.");}}
   finally{if(!controller.signal.aborted){active.current=null;setBusy(false);}}
 }
 return <section aria-label="Optional evidence review"><h3>Optional evidence review</h3>
   {session.isFreshAuthenticated?<div className="page-actions">{purposes.map(p=><Button key={p} disabled={busy || (!!attempt && attempt.purpose!==p)} onClick={()=>void request(p)}>{attempt?.purpose===p && !busy?"Retry review":actions[p]}</Button>)}</div>:<Button onClick={session.reauthenticate}>Verify identity to review evidence</Button>}
   {busy && <p role="status">Reviewing selected evidence…</p>}{error && <p role="alert">{error}</p>}{receipt && <Result receipt={receipt}/>}
 </section>;
}
