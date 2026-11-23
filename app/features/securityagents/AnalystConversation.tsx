"use client";

import { useEffect, useMemo } from "react";
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport, type ChatTransport, type UIMessage } from "ai";
import { useAISDKRuntime } from "@assistant-ui/ai-sdk";
import { AssistantRuntimeProvider, ComposerPrimitive, MessagePrimitive, ThreadPrimitive } from "@assistant-ui/react";
import { useAPI } from "../../api/APIProvider";
import type { APIClient } from "../../../apps/web/api/client";
import type { AnalystThread } from "../../../apps/web/api/generated";

export class InvestigationTransport extends DefaultChatTransport<UIMessage> {
  constructor(private readonly product: APIClient, private readonly thread: AnalystThread) { super({}); }
  override async sendMessages({ messages, chatId, trigger, abortSignal }: Parameters<ChatTransport<UIMessage>["sendMessages"]>[0]) {
    const last = messages.at(-1);
    if (chatId !== this.thread.id || trigger !== "submit-message" || last?.role !== "user" || last.parts.length !== 1 || last.parts[0].type !== "text") throw Error("A session question is required");
    const result = await this.product.openAuthorizedEventStream(this.thread.id, this.thread.session_id, last.parts[0].text, last.id, abortSignal);
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

export default function AnalystConversation({ thread }: { thread: AnalystThread }) {
  const { client } = useAPI();
  const transport = useMemo(() => new InvestigationTransport(client, thread), [client, thread]);
  const chat = useChat({
    id: thread.id, transport, generateId: () => "pid_" + crypto.randomUUID(),
    messages: thread.messages.map(m => ({ id: m.id, role: m.role, parts: [{ type: "text" as const, text: m.text }] })),
  });
  const { stop } = chat;
  useEffect(() => () => { void stop(); }, [stop]);
  const runtime = useAISDKRuntime(chat);
  return <AssistantRuntimeProvider runtime={runtime}><ThreadPrimitive.Root className="analyst-conversation">
    <ThreadPrimitive.Messages components={{ UserMessage, AssistantMessage }} />
    {chat.error && <p role="alert">The analyst could not confirm an answer. Reopen this investigation to check its saved history.</p>}
    <ComposerPrimitive.Root>
      <ComposerPrimitive.Input aria-label="Question about this session" maxLength={2048} placeholder="Ask about blocked actions or missing evidence…" />
      <div className="row-actions"><ComposerPrimitive.Send className="button button--primary">Send question</ComposerPrimitive.Send>
        {chat.status === "streaming" && <ComposerPrimitive.Cancel className="button">Stop response</ComposerPrimitive.Cancel>}</div>
    </ComposerPrimitive.Root>
  </ThreadPrimitive.Root></AssistantRuntimeProvider>;
}
