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
class SingleQuestionApproval {
  private granted = false;
  select(value:boolean) { this.granted = value; }
  take() { const current=this.granted; this.granted=false; return current; }
}

export class InvestigationTransport extends DefaultChatTransport<UIMessage> {
  constructor(private readonly product: APIClient, private readonly thread: AnalystThread, private readonly consumeApproval: () => boolean = () => false) { super({}); }
  override async sendMessages({ messages, chatId, trigger, abortSignal }: Parameters<ChatTransport<UIMessage>["sendMessages"]>[0]) {
    const last = messages.at(-1);
    if (chatId !== this.thread.id || trigger !== "submit-message" || last?.role !== "user" || last.parts.length !== 1 || last.parts[0].type !== "text") throw Error("A session question is required");
    const approved = this.thread.requires_session_read_approval ? this.consumeApproval() : false;
    if (this.thread.requires_session_read_approval && !approved) throw Error("Approve the session read for this question");
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
  const [approved, setApproved] = useState(false);
  const [approval] = useState(() => new SingleQuestionApproval());
  const consumeApproval = useCallback(() => {
    const confirmed = approval.take();
    setApproved(false);
    return confirmed && session?.status === "authenticated" && session.isFreshAuthenticated;
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
      {thread.requires_session_read_approval && (session?.status === "authenticated" && session.isFreshAuthenticated
        ? <label><input type="checkbox" checked={approved} onChange={e => {approval.select(e.target.checked);setApproved(e.target.checked);}}/> Approve reading this session’s evidence for this question</label>
        : session?.status === "authenticated" ? <Button onClick={session.reauthenticate}>Verify identity to approve this read</Button> : <p>Sign in to approve this read.</p>)}
      <div className="row-actions"><ComposerPrimitive.Send disabled={Boolean(thread.requires_session_read_approval && !approved)} className="button button--primary">Send question</ComposerPrimitive.Send>
        {chat.status === "streaming" && <ComposerPrimitive.Cancel className="button">Stop response</ComposerPrimitive.Cancel>}</div>
    </ComposerPrimitive.Root>
  </ThreadPrimitive.Root></AssistantRuntimeProvider>;
}
