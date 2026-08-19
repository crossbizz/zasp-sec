"use client";

import { useEffect, useState } from "react";

import { APIProductError, createAPIClient, requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { decodeSessionCallbackResult } from "../../../apps/web/api/decoders";

const replaceBrowserLocation = (path: string) => window.location.replace(path);

export function CallbackCompletion({ suppliedClient, replaceLocation = replaceBrowserLocation }: { suppliedClient?: APIClient; replaceLocation?: (path: string) => void }) {
  const [client] = useState(() => suppliedClient ?? createAPIClient());
  const [failure, setFailure] = useState<{ message: string; correlation?: string } | null>(null);
  useEffect(() => {
    let active = true;
    const complete = async () => {
      const query = new URLSearchParams(window.location.search);
      const authorizationCode = query.get("code") ?? "";
      const state = query.get("state") ?? "";
      if (!authorizationCode || state.length < 32 || state.length > 512) {
        setFailure({ message: "The sign-in callback is invalid or expired." });
        return;
      }
      try {
        const result = await client.POST("/api/v1/session/callback", { body: { authorization_code: authorizationCode, state } });
        const completed = requireAPIData(result, decodeSessionCallbackResult);
        if (active) replaceLocation(completed.return_to);
      } catch (error) {
        if (!active) return;
        setFailure(error instanceof APIProductError ? { message: error.message, correlation: error.correlationID } : { message: "Sign-in could not be completed." });
      }
    };
    void complete();
    return () => { active = false; };
  }, [client, replaceLocation]);
  if (failure) return <main className="page"><h1>Sign-in failed</h1><p role="alert">{failure.message}</p>{failure.correlation && <p>Correlation: <code>{failure.correlation}</code></p>}</main>;
  return <main className="page"><h1>Completing sign-in</h1><p role="status">Creating your secure session…</p></main>;
}

export default function CallbackPage() {
  return <CallbackCompletion />;
}
