"use client";

import { useEffect, useState } from "react";

import { APIProductError, createAPIClient, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { decodeSessionCallbackResult } from "../../../apps/web/api/decoders";

const replaceBrowserLocation = (path: string) => window.location.replace(path);

type CallbackBody = { provider_token: string; state?: string; provider_token_type?: "oauth" | "multi_tenant_magic_links" };

// An invitation link is started by the identity provider, so it is the only
// redirect that arrives without the state this product issues at sign-in start.
// Every other redirect must carry that state.
export function callbackBody(providerToken: string, state: string, tokenType: string | null): CallbackBody | null {
  if (!providerToken) return null;
  const validState = state.length >= 32 && state.length <= 512;
  if (tokenType === "multi_tenant_magic_links") {
    if (state === "") return { provider_token: providerToken, provider_token_type: tokenType };
    return validState ? { provider_token: providerToken, state, provider_token_type: tokenType } : null;
  }
  if (tokenType !== null && tokenType !== "oauth") return null;
  return validState ? { provider_token: providerToken, state } : null;
}

export function CallbackCompletion({ suppliedClient, replaceLocation = replaceBrowserLocation }: { suppliedClient?: APIClient; replaceLocation?: (path: string) => void }) {
  const [client] = useState(() => suppliedClient ?? createAPIClient());
  const [failure, setFailure] = useState<{ message: string; correlation?: string } | null>(null);
  // An invitation token is single-use and arrives by email. Mail scanners
  // open links and run scripts, so it is exchanged only after a person clicks.
  const [accepted, setAccepted] = useState(false);
  const [invitation, setInvitation] = useState(false);
  useEffect(() => {
    let active = true;
    const complete = async () => {
      const query = new URLSearchParams(window.location.search);
      const providerToken = query.get("token") ?? "";
      const state = query.get("state") ?? "";
      const body = callbackBody(providerToken, state, query.get("stytch_token_type"));
      if (!body) {
        setFailure({ message: "The sign-in callback is invalid or expired." });
        return;
      }
      if (body.state === undefined && !accepted) {
        setInvitation(true);
        return;
      }
      try {
        const result = await client.POST("/api/v1/session/callback", { body });
        const completed = requireAPIData(result, decodeSessionCallbackResult);
        if (active) replaceLocation(completed.return_to);
      } catch (error) {
        if (!active) return;
        setFailure(error instanceof APIProductError ? { message: error.message, correlation: error.correlationID } : { message: "Sign-in could not be completed." });
      }
    };
    void complete();
    return () => { active = false; };
  }, [client, replaceLocation, accepted]);
  if (failure) return <main className="page auth-page"><h1>Sign-in failed</h1><p role="alert">{failure.message}</p>{failure.correlation && <p>Correlation: <code>{failure.correlation}</code></p>}</main>;
  if (invitation && !accepted) return <main className="page auth-page"><h1>Accept your invitation</h1><p>Continue to create your secure session.</p><button type="button" onClick={() => setAccepted(true)}>Accept invitation</button></main>;
  return <main className="page auth-page"><h1>Completing sign-in</h1><p role="status">Creating your secure session…</p></main>;
}

export default function CallbackPage() {
  return <CallbackCompletion />;
}
