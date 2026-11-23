"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { APIProductError, requireAPIData } from "../../../apps/web/api/client";
import type { CalibrationDownloadGrant, CalibrationExportJob } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useOptionalSession } from "../../auth/SessionProvider";
import { Button, Card } from "../../components/ui";
import { Time } from "../../components/time";
import { workflowIdempotencyKey } from "../workflows/api";

const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const digestOrGrant = /^[0-9a-f]{64}$/;

function readJob(value: unknown, environment: string, expectedID?: string): CalibrationExportJob {
  const job = value as Partial<CalibrationExportJob> | null;
  if (!job || !productID.test(job.id ?? "") || (expectedID && job.id !== expectedID)
    || job.environment_id !== environment || !["queued", "writing", "ready", "failed"].includes(job.status ?? "")
    || !Number.isInteger(job.samples) || job.samples! < 0 || job.samples! > 2048
    || !Number.isFinite(Date.parse(job.requested_at ?? "")) || !Number.isFinite(Date.parse(job.expires_at ?? ""))) {
    throw Error("Unexpected export status");
  }
  return job as CalibrationExportJob;
}

function ExportForm({ environment, scope, fresh, reauthenticate }: {
  environment: string; scope: string; fresh: boolean; reauthenticate(): void;
}) {
  const { client } = useAPI();
  const [job, setJob] = useState<CalibrationExportJob | null>(null);
  const [grant, setGrant] = useState<CalibrationDownloadGrant | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const request = useRef<AbortController | null>(null);
  const key = useRef<string | null>(null);
  useEffect(() => () => request.current?.abort(), []);

  const readStatus = useCallback(async (id: string, signal: AbortSignal) => {
    const result = await client.GET("/api/v1/calibration/exports/{id}", {
      params: { path: { id } }, headers: { "X-Zasp-Expected-Scope": scope }, signal,
    });
    const next = requireAPIData(result, raw => readJob(raw, environment, id));
    if (!signal.aborted) setJob(next);
  }, [client, environment, scope]);
  const queued = job?.status === "queued" || job?.status === "writing";
  const expired = job && now >= Date.parse(job.expires_at);
  useEffect(() => {
    if (!job) return;
    const expires = Math.min(Date.parse(job.expires_at), grant ? Date.parse(grant.expires_at) : Infinity);
    const delay = expires - Date.now();
    const timer = setTimeout(() => {
      setNow(Date.now());
      setGrant(null);
    }, Math.max(0, delay));
    return () => clearTimeout(timer);
  }, [job, grant]);
  useEffect(() => {
    if (!job || !queued || error || expired) return;
    const controller = new AbortController();
    const timer = setTimeout(() => {
      void readStatus(job.id, controller.signal).catch(() => {
        if (!controller.signal.aborted) setError("Could not refresh this export. Check its status again.");
      });
    }, 3000);
    return () => { controller.abort(); clearTimeout(timer); };
  }, [job, queued, error, expired, readStatus]);

  async function run(action: (signal: AbortSignal) => Promise<void>) {
    if (request.current) return;
    const controller = new AbortController();
    request.current = controller;
    setError("");
    setBusy(true);
    try {
      await action(controller.signal);
    } catch (cause) {
      if (!controller.signal.aborted) setError(cause instanceof APIProductError ? cause.product.message : "Could not confirm the export request. Retry to check it.");
    } finally {
      if (!controller.signal.aborted) setBusy(false);
      request.current = null;
    }
  }
  const headers = { "X-Zasp-Expected-Scope": scope };
  const freshHeaders = { "X-CSRF-Token": "", "X-Zasp-Fresh-Auth": "confirmed" as const };
  async function create(signal: AbortSignal) {
    key.current ??= workflowIdempotencyKey();
    const result = await client.POST("/api/v1/calibration/exports", {
      headers, params: { header: { ...freshHeaders, "Idempotency-Key": key.current } }, body: {}, signal,
    });
    const next = requireAPIData(result, value => readJob(value, environment));
    if (!signal.aborted) { key.current = null; setGrant(null); setJob(next); setNow(Date.now()); }
  }
  async function issueGrant(signal: AbortSignal) {
    if (!job) return;
    const result = await client.POST("/api/v1/calibration/exports/{id}/download-grants", {
      params: { path: { id: job.id }, header: freshHeaders }, headers, body: {}, signal,
    });
    const next = requireAPIData<CalibrationDownloadGrant>(result);
    if (!next || !digestOrGrant.test(next.grant) || !(Date.parse(next.expires_at) > Date.now())) throw Error("Invalid download grant");
    if (!signal.aborted) { setGrant(next); setNow(Date.now()); }
  }
  async function download(signal: AbortSignal) {
    if (!job || !grant) return;
    const result = await client.POST("/api/v1/calibration/exports/{id}/download", {
      params: { path: { id: job.id } }, headers, body: { grant: grant.grant }, signal,
    });
    if (signal.aborted) return;
    setGrant(null);
    const file = requireAPIData<import("../../../apps/web/api/generated").CalibrationExportFile>(result);
    if (file.environment_id !== environment || file.filename !== `calibration-${job.id}.jsonl` || typeof file.jsonl !== "string"
      || !digestOrGrant.test(file.sha256)) throw Error("Unexpected export file");
    const bytes = new TextEncoder().encode(file.jsonl);
    if (bytes.length === 0 || bytes.length > 1024 * 1024) throw Error("Invalid export size");
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), b => b.toString(16).padStart(2, "0")).join("");
    if (hash !== file.sha256) throw Error("Export digest mismatch");
    if (signal.aborted) return;
    const url = URL.createObjectURL(new Blob([bytes], { type: "application/x-ndjson" }));
    const link = document.createElement("a");
    link.href = url; link.download = file.filename;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <section id="calibration-exports"><Card title={<h2>Export calibration labels</h2>}>
    <p>Download up to 2,048 redacted samples from the past 30 days as JSON Lines.</p>
    {job && <p role="status">{expired ? "Expired" : job.status} · {job.samples} samples · Expires <Time value={job.expires_at} /></p>}
    {queued && error && <Button onClick={() => void run(signal => readStatus(job!.id, signal))}>Check export status</Button>}
    {!fresh && <Button onClick={reauthenticate}>Verify identity to export</Button>}
    {fresh && (!job || expired || job.status === "failed" || job.status === "ready") && <Button disabled={busy} onClick={() => void run(create)}>Create export</Button>}
    {fresh && job?.status === "ready" && !expired && !grant && <Button disabled={busy} onClick={() => void run(issueGrant)}>Get download grant</Button>}
    {grant && job && <div><Button disabled={busy} onClick={() => void run(download)}>Download JSONL</Button>
      <details><summary>Use this grant with zaspctl</summary>
        <p>Pass the grant to the CLI on standard input. It can be used once and expires <Time value={grant.expires_at} />.</p>
        <pre className="wrap-code">{`zaspctl calibration export --environment ${environment} --export-id ${job.id} --output calibration.jsonl`}</pre>
        <label>Single-use grant <input readOnly value={grant.grant} onFocus={e => e.currentTarget.select()} /></label>
      </details></div>}
    {error && <p role="alert">{error}</p>}
  </Card></section>;
}
export function CalibrationExports() {
  const session = useOptionalSession();
  const { queryGeneration } = useAPI();
  if (session?.status !== "authenticated" || !session.hasCapability("compliance.read")) return null;
  const scope = [session.organizationID, session.workspaceID, session.environmentID].join("/");
  return <ExportForm key={scope + ":" + queryGeneration} environment={session.environmentID} scope={scope} fresh={session.isFreshAuthenticated} reauthenticate={session.reauthenticate} />;
}
