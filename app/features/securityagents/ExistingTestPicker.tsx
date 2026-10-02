"use client";

import { useEffect, useMemo, useState } from "react";
import type { SecurityAgentExistingTestReference, TestDefinition } from "../../../apps/web/api/generated";
import { Button, Select } from "../../components/ui";
import type { SecurityAgentsAPI } from "./SecurityAgentsView";

export function ExistingTestPicker({ api, value, locked, onChange }: { api: Pick<SecurityAgentsAPI, "listExistingTests">; value: SecurityAgentExistingTestReference | null; locked: boolean; onChange(value: SecurityAgentExistingTestReference | null): void }) {
  const [revision, setRevision] = useState(0);
  const request = useMemo(() => ({ api, revision, onChange }), [api, revision, onChange]);
  const [result, setState] = useState<{ request: typeof request; status: "loading" | "ready" | "error"; tests: readonly TestDefinition[] }>({ request, status: "loading", tests: [] });
  const state = result.request === request ? result : { status: "loading", tests: [] };
  useEffect(() => {
    const controller = new AbortController();
    request.onChange(null);
    void request.api.listExistingTests(controller.signal).then(tests => {
      if (!controller.signal.aborted) setState({ request, status: "ready", tests: tests.filter(test => test.enabled) });
    }).catch(() => { if (!controller.signal.aborted) setState({ request, status: "error", tests: [] }); });
    return () => controller.abort();
  }, [request]);
  return <div className="form-stack">
    <Select label="Existing test definition" value={value?.definition_id ?? ""} disabled={locked || state.status !== "ready"} onChange={event => {
      const selected = state.tests.find(test => test.id === event.target.value);
      onChange(selected ? { definition_id: selected.id, definition_version: selected.version } : null);
    }}>
      <option value="">Select an enabled test</option>
      {state.tests.map(test => <option key={test.id} value={test.id}>{test.name} · version {test.version}</option>)}
    </Select>
    {state.status === "loading" && <p role="status">Loading existing tests…</p>}
    {state.status === "error" && <p role="alert">Existing tests could not be loaded. Retry the lookup before saving.</p>}
    {state.status === "ready" && state.tests.length === 0 && <p role="status">No enabled tests are available in this scope.</p>}
    <Button disabled={locked || state.status === "loading"} onClick={() => { onChange(null); setRevision(current => current + 1); }}>Reload existing tests</Button>
    <p>The selected version is pinned to this draft. Its target, prompts, credentials, and safety settings come from the existing test. The server rechecks scope and safety before accepting work.</p>
  </div>;
}
