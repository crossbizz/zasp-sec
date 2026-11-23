"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport, type ChatTransport, type UIMessage } from "ai";
import { useAISDKRuntime } from "@assistant-ui/ai-sdk";
import { AssistantRuntimeProvider, ComposerPrimitive, MessagePrimitive, ThreadPrimitive } from "@assistant-ui/react";
import { useAPI } from "../../api/APIProvider";
import type { APIClient } from "../../../apps/web/api/client";
import {useOptionalSession} from "../../auth/SessionProvider";
import {Button} from "../../components/ui";
import type { AnalystThread } from "../../../apps/web/api/generated";

// One confirmation is consumed by the next outbound question, including an
// interrupted request. Retries require a new operator confirmation.
type ReadTool = "inspect_session" | "external_inventory_status";
class SingleQuestionApproval {
  private granted = new Set<ReadTool>();
  select(tool: ReadTool, value:boolean) { if (value) this.granted.add(tool); else this.granted.delete(tool); }
  take() { const approved=Array.from(this.granted).sort(); this.granted.clear(); return approved; }
}
function requiredReads(thread:AnalystThread):ReadTool[] {
  const tools:ReadTool[]=[];
  if(thread.requires_session_read_approval)tools.push("inspect_session");
  if(thread.requires_external_inventory_approval)tools.push("external_inventory_status");
  return tools;
}

export class InvestigationTransport extends DefaultChatTransport<UIMessage> {
  constructor(private readonly product: APIClient, private readonly thread: AnalystThread, private readonly consumeApproval: () => readonly ReadTool[] = () => []) { super({}); }
  override async sendMessages({ messages, chatId, trigger, abortSignal }: Parameters<ChatTransport<UIMessage>["sendMessages"]>[0]) {
    const last = messages.at(-1);
    if (chatId !== this.thread.id || trigger !== "submit-message" || last?.role !== "user" || last.parts.length !== 1 || last.parts[0].type !== "text") throw Error("A session question is required");
    const required = requiredReads(this.thread);
    const approved = required.length ? this.consumeApproval() : [];
    if (required.some(tool => !approved.includes(tool))) throw Error("Approve each required read for this question");
    const result = await this.product.openAuthorizedEventStream(this.thread.id, this.thread.session_id, last.parts[0].text, last.id, abortSignal, approved);
    if (!result.body) throw Error("Empty investigation response");
    return this.processResponseStream(result.body);
  }
  override async reconnectToStream() { return null; }
}

function UserMessage() {
  return <MessagePrimitive.Root className="analyst-message analyst-message--user"><strong>You</strong><MessagePrimitive.Parts /></MessagePrimitive.Root>;
}
function AssistantMessage() {
  return <MessagePrimitive.Root className="analyst-message"><strong>Session analyst</strong><MessagePrimitive.Parts /></MessagePrimitive.Root>;
}

export default function AnalystConversation({ thread, onCommitted }: { thread: AnalystThread; onCommitted?(): void }) {
  const { client } = useAPI();
  const session = useOptionalSession();
  const [approved, setApproved] = useState<ReadTool[]>([]);
  const required = requiredReads(thread);
  const [approval] = useState(() => new SingleQuestionApproval());
  const consumeApproval = useCallback(() => {
    const confirmed = approval.take();
    setApproved([]);
    return session?.status === "authenticated" && session.isFreshAuthenticated ? confirmed : [];
  }, [approval, session]);
  const transport = useMemo(() => new InvestigationTransport(client, thread, consumeApproval), [client, thread, consumeApproval]);
  const chat = useChat({
    id: thread.id, transport, onFinish: () => onCommitted?.(), generateId: () => "pid_" + crypto.randomUUID(),
    messages: thread.messages.map(m => ({ id: m.id, role: m.role, parts: [{ type: "text" as const, text: m.role === "assistant" && m.evidence_ids.length ? m.text+"\n\nEvidence: "+m.evidence_ids.join(", ") : m.text }] })),
  });
  const { stop } = chat;
  useEffect(() => () => { void stop(); }, [stop]);
  const runtime = useAISDKRuntime(chat);
  return <AssistantRuntimeProvider runtime={runtime}><ThreadPrimitive.Root className="analyst-conversation">
    <ThreadPrimitive.Messages components={{ UserMessage, AssistantMessage }} />
    {chat.error && <p role="alert">The analyst could not confirm an answer. Reopen this investigation to check its saved history.</p>}
    <ComposerPrimitive.Root>
      <ComposerPrimitive.Input aria-label="Question about this session" maxLength={1000} placeholder="Ask about blocked actions or missing evidence…" />
      {required.length > 0 && (session?.status === "authenticated" && session.isFreshAuthenticated
        ? required.map(tool => <label key={tool}><input type="checkbox" checked={approved.includes(tool)} onChange={e => {
          const selected=e.target.checked;
          approval.select(tool,selected);
          setApproved(current=>selected ? [...current,tool] : current.filter(value=>value!==tool));
        }}/>{tool === "inspect_session" ? " Approve reading this session’s evidence for this question" : " Approve a private connector read of this session’s agent inventory status for this question"}</label>)
        : session?.status === "authenticated" ? <Button onClick={session.reauthenticate}>Verify identity to approve these reads</Button> : <p>Sign in to approve these reads.</p>)}
      <div className="row-actions"><ComposerPrimitive.Send disabled={required.some(tool=>!approved.includes(tool))} className="button button--primary">Send question</ComposerPrimitive.Send>
        {chat.status === "streaming" && <ComposerPrimitive.Cancel className="button">Stop response</ComposerPrimitive.Cancel>}</div>
    </ComposerPrimitive.Root>
  </ThreadPrimitive.Root></AssistantRuntimeProvider>;
}
