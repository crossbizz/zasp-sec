"use client";

import { SkillRuleLabel } from "./SkillRuleLabel";

import { addonVersionLink, scanReceiptLink } from "../../domain/addon-links";

import { useEffect, useRef, useState } from "react";
import {
  APIProductError,
  requireAPIData,
  uploadPrivateAddonArchive,
  type APIClient,
} from "../../../apps/web/api/client";
import { decodeFindings } from "../../../apps/web/api/addon-reviews";
import { Button } from "../../components/ui";

type Retention = "memory_only" | "encrypted_24h";

type Grant = {
  retention: Retention;
  retain_until?: string;
  verification_key: string;
  id: string;
  upload_url: string;
  upload_grant: string;
  expires_at: string;
  result_delivery: "browser_only" | "registry";
};
const productID =
  /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function decodeGrant(value: unknown): Grant {
  if (!value || typeof value !== "object") throw Error();
  const g = value as Partial<Grant>;
  if (
    (g.retention !== "memory_only" && g.retention !== "encrypted_24h") ||
    typeof g.verification_key !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(g.verification_key) ||
    (g.result_delivery !== "browser_only" &&
      g.result_delivery !== "registry") ||
    !g.id ||
    !productID.test(g.id) ||
    typeof g.upload_url !== "string" ||
    typeof g.upload_grant !== "string" ||
    !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86}$/.test(g.upload_grant) ||
    g.upload_grant.length > 3072 ||
    typeof g.expires_at !== "string" ||
    !Number.isFinite(Date.parse(g.expires_at)) ||
    Date.parse(g.expires_at) <= Date.now() ||
    Date.parse(g.expires_at) > Date.now() + 360_000
  )
    throw Error();
  const url = new URL(g.upload_url);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.pathname !== "/v1/uploads/" + g.id ||
    url.search ||
    url.hash
  )
    throw Error();
  return {
    id: g.id,
    upload_url: url.href,
    upload_grant: g.upload_grant,
    expires_at: g.expires_at,
    result_delivery: g.result_delivery,
    verification_key: g.verification_key,
    retention: g.retention,
    retain_until: g.retain_until,
  };
}

function object(value: unknown): Record<string, unknown> | undefined {
  if (typeof value === "object" && value !== null && !Array.isArray(value))
    return value as Record<string, unknown>;
}

function decodeBase64URL(s: string) {
  return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
    c.charCodeAt(0),
  );
}

async function checkSignedGrant(
  g: Grant,
  choice: Retention,
  environment: string,
  digest: string,
  size: number,
) {
  if (g.retention !== choice) throw Error();
  const [encoded, signature] = g.upload_grant.split(".");
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase64URL(g.verification_key),
    "Ed25519",
    false,
    ["verify"],
  );
  const payload = decodeBase64URL(encoded);
  const domain = new TextEncoder().encode("zasp-private-addon-upload.v1\0");
  const signed = new Uint8Array(domain.length + payload.length);
  signed.set(domain);
  signed.set(payload, domain.length);
  if (
    !(await crypto.subtle.verify(
      "Ed25519",
      key,
      decodeBase64URL(signature),
      signed,
    ))
  )
    throw Error();
  const cap = object(JSON.parse(new TextDecoder().decode(payload)));
  const scope = typeof cap?.scope === "string" ? cap.scope.split("/") : [];
  if (
    !cap ||
    cap.id !== g.id ||
    cap.audience !== new URL(g.upload_url).origin ||
    scope.length !== 3 ||
    !scope.every((s) => productID.test(s)) ||
    scope[2] !== environment ||
    cap.sha256 !== digest ||
    cap.size !== size ||
    cap.expires !== Date.parse(g.expires_at) / 1000 ||
    (cap.registry === true) !== (g.result_delivery === "registry")
  )
    throw Error();
  if (choice === "memory_only") {
    if (
      cap.version !== "private-addon-upload.v1" ||
      cap.retain_until !== undefined ||
      g.retain_until !== undefined
    )
      throw Error();
  } else {
    const expiry =
      typeof g.retain_until === "string" ? Date.parse(g.retain_until) : NaN;
    if (
      cap.version !== "private-addon-upload-retained.v1" ||
      !Number.isFinite(expiry) ||
      expiry < Date.parse(g.expires_at) ||
      expiry > Date.now() + 86_460_000 ||
      cap.retain_until !== expiry / 1000 ||
      cap.retain_until !== Number(cap.expires) + 86_100
    )
      throw Error();
  }
}

export function PrivateAddonScan({
  client,
  environment,
  fresh,
  reauthenticate,
  allowRetention = true,
}: {
  client: APIClient;
  environment: string;
  fresh: boolean;
  reauthenticate: () => void;
  allowRetention?: boolean;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [retention, setRetention] = useState<Retention>("memory_only");
  const [grant, setGrant] = useState<Grant | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [findings, setFindings] = useState<ReturnType<typeof decodeFindings> | null>(null);
  const [dragging, setDragging] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const [review, setReview] = useState("");
  const [scanID, setScanID] = useState("");
  const current = useRef<AbortController | undefined>(undefined);
  useEffect(() => () => current.current?.abort(), []);
  function selectFile(next: File | null) {
    if (busy) return;
    setGrant(null);
    setReview("");
    setScanID("");
    setFindings(null);
    setRetention("memory_only");
    const valid = next && /\.zip$/i.test(next.name) && next.size > 0 && next.size <= 8 * 1024 * 1024;
    setFile(valid ? next : null);
    setMessage(next && !valid ? "Choose a .zip file between 1 byte and 8 MiB." : "");
  }
  async function prepare() {
    if (!file || busy) return;
    setGrant(null);
    setReview("");
    setScanID("");
    setFindings(null);
    current.current?.abort();
    const work = new AbortController();
    current.current = work;
    setBusy(true);
    setMessage("");
    try {
      const hash = new Uint8Array(
        await crypto.subtle.digest("SHA-256", await file.arrayBuffer()),
      );
      if (work.signal.aborted) return;
      const digest =
        "sha256:" +
        Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join("");
      const data = await client.POST("/api/v1/addon-scan-uploads", {
        params: {
          header: {
            "X-CSRF-Token": "",
            "Idempotency-Key": crypto.randomUUID(),
          },
        },
        body: {
          mode: "private_upload",
          retention,
          archive_bytes: file.size,
          archive_digest: digest,
        },
        signal: work.signal,
      });
      const approved = requireAPIData(data, decodeGrant);
      await checkSignedGrant(
        approved,
        retention,
        environment,
        digest,
        file.size,
      );
      if (!work.signal.aborted) setGrant(approved);
    } catch (error) {
      if (!work.signal.aborted) {
        if (error instanceof APIProductError && error.status === 403)
          setMessage("Upload authorization was denied. Verify your identity and check the Environment's data controls.");
        else if (error instanceof APIProductError && error.status === 503)
          setMessage(retention === "encrypted_24h"
            ? "Encrypted upload is unavailable. Try an in-memory scan or scan on this device."
            : "The private scan service is unavailable. Retry the upload review or scan on this device.");
        else
          setMessage("Could not verify the upload authorization. Retry the upload review or scan on this device.");
      }
    } finally {
      if (!work.signal.aborted) setBusy(false);
    }
  }
  async function upload() {
    if (!file || !grant || busy) return;
    if (Date.parse(grant.expires_at) <= Date.now()) {
      setGrant(null);
      setMessage("Upload authorization expired. Review the upload again.");
      return;
    }
    current.current?.abort();
    const work = new AbortController();
    current.current = work;
    setBusy(true);
    setMessage("");
    try {
      const data = object(
        await uploadPrivateAddonArchive(grant, file, work.signal),
      );
      const result = object(data?.result);
      const counts = object(result?.rule_counts);
      if (
        data?.grant_id !== grant.id ||
        result?.schema_version !== "zasp-private-scan.v1" ||
        (result.status !== "complete" && result.status !== "partial") ||
        !counts
      )
        throw Error();
      if (result.ruleset !== "zasp-static.v1" && result.ruleset !== "zasp-static.v2") throw Error();
      const rows = decodeFindings(Object.entries(counts).map(([rule_id, count]) => ({ rule_id, count })), result.ruleset);
      const total = rows.reduce((sum, row) => sum + row.count, 0);
      const skipped = object(result.skipped_counts);
      const partial = result.status !== "partial" ? ""
        : skipped?.missing_entry ? " The ZIP needs a readable SKILL.md at its root. No exact version is available."
        : " Some files could not be inspected. No exact version is available.";
      let storage = "";
      if (grant.retention === "encrypted_24h") {
        const saved = object(data.retention);
        if (
          !saved ||
          saved.mode !== "encrypted_24h" ||
          saved.state !== "retained" ||
          saved.grant_id !== grant.id ||
          typeof saved.expires_at !== "string" ||
          Date.parse(saved.expires_at) !== Date.parse(grant.retain_until!)
        )
          throw Error();
        storage =
          " Encrypted ZIP stored. Deletion is scheduled for " +
          grant.retain_until +
          ".";
      } else if (data.retention !== undefined) throw Error();
      let delivery = "";
      let reviewPath = "";
      let receiptID = "";
      if (
        grant.result_delivery === "registry" &&
        data.registry_status !== "queued" &&
        data.registry_status !== "recorded"
      )
        throw Error();
      if (
        grant.result_delivery === "browser_only" &&
        data.registry_status !== "transient"
      )
        throw Error();
      if (data.registry_status === "queued")
        delivery = " The worker queued the findings for the review registry.";
      else if (data.registry_status === "recorded") {
        const receipt = object(data.receipt);
        if (
          !receipt ||
          typeof receipt.scan_id !== "string" ||
          !productID.test(receipt.scan_id) ||
          receipt.completeness !== result.status
        )
          throw Error();
        if (result.status === "complete") {
          if (
            typeof result.manifest_digest !== "string" ||
            !/^sha256:[0-9a-f]{64}$/.test(result.manifest_digest) ||
            receipt.manifest_digest !== result.manifest_digest ||
            typeof receipt.version_id !== "string" ||
            !productID.test(receipt.version_id) ||
            receipt.review_path !==
              "/inventory/tools?addon=" + receipt.version_id
          )
            throw Error();
          reviewPath = addonVersionLink(receipt.version_id, environment);
        } else if (
          receipt.version_id !== null ||
          receipt.review_path !== null ||
          receipt.manifest_digest !== null
        )
          throw Error();
        receiptID = receipt.scan_id;
        delivery = " Findings recorded in the Environment registry.";
      }
      if (!work.signal.aborted) {
        setReview(reviewPath);
        setScanID(receiptID);
        setFindings(rows);
        setMessage(`Scan ${result.status}. ${total} static finding${total === 1 ? "" : "s"}.${partial}${delivery}${storage}`);
      }
    } catch {
      if (!work.signal.aborted)
        setMessage(
          grant.retention === "encrypted_24h"
            ? `The worker could not confirm this scan. The encrypted ZIP may already be stored. Ask the Environment administrator to check storage and deletion with grant ${grant.id} before retrying.`
            : `The worker could not confirm this scan. Contact the Environment administrator with grant ${grant.id} before retrying.`,
        );
    } finally {
      if (!work.signal.aborted) {
        setGrant(null);
        setRetention("memory_only");
        setBusy(false);
      }
    }
  }
  return (
    <div className="skill-scan">
      <p>Check a skill for risky instructions, scripts and dependencies. The worker inspects files without running them.</p>
      <div
        className={`skill-scan__drop${dragging ? " skill-scan__drop--active" : ""}`}
        onDragOver={event => { event.preventDefault(); if (!busy) setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={event => {
          event.preventDefault();
          setDragging(false);
          if (busy) return;
          const files = event.dataTransfer.files;
          if (files.length === 1) selectFile(files[0]);
          else { selectFile(null); setMessage("Choose one skill ZIP at a time."); }
        }}
      >
        <strong>{file ? file.name : "Drop a skill ZIP here"}</strong>
        <p id="skill-zip-hint">Up to 8 MiB, with SKILL.md at the root.</p>
        <input hidden ref={input} type="file" aria-label="Skill ZIP" accept=".zip,application/zip" disabled={busy}
          onChange={event => { selectFile(event.target.files?.[0] ?? null); event.target.value = ""; }}
        />
        <Button type="button" aria-describedby="skill-zip-hint" disabled={busy} onClick={() => input.current?.click()}>
          {file ? "Choose another ZIP" : "Choose ZIP"}
        </Button>
      </div>
      <p>The worker processes your ZIP in memory. You’ll review the recipient before sending the file.</p>
      {allowRetention && <label className="skill-scan__retention">
        <input type="checkbox" checked={retention === "encrypted_24h"} disabled={busy || !file} onChange={event => {
          setRetention(event.target.checked ? "encrypted_24h" : "memory_only");
          setGrant(null);
          setMessage("");
          setReview("");
          setScanID("");
          setFindings(null);
        }} /> Retain an encrypted copy of this ZIP for up to 24 hours
      </label>}
      {grant && <div className="skill-scan__recipient">
        <strong>Upload to {new URL(grant.upload_url).host}</strong>
        <p>{grant.result_delivery === "registry"
          ? "The worker records finding counts and the exact version, when available, in this Environment’s review registry."
          : "The worker returns findings to this browser only."}</p>
        {grant.retention === "encrypted_24h" && <p>Encrypted ZIP retained until <time dateTime={grant.retain_until}>{grant.retain_until}</time>.</p>}
      </div>}
      {!fresh ? (
        <Button variant="primary" onClick={reauthenticate}>Verify identity to scan</Button>
      ) : grant ? (
        <Button variant="primary" disabled={busy} onClick={() => void upload()}>Scan on {new URL(grant.upload_url).host}</Button>
      ) : (
        <Button variant="primary" disabled={busy || !file} onClick={() => void prepare()}>Review upload</Button>
      )}
      <div role="status" aria-live="polite">
        {busy ? (grant ? "Uploading and scanning the ZIP…" : "Checking the file and authorizing the upload…") : message}
      </div>
      {findings && findings.length > 0 && <ul aria-label="Findings by rule">{findings.map(row =>
        <li key={row.rule_id}><SkillRuleLabel rule={row.rule_id} /> · {row.count}</li>)}</ul>}
      {(scanID || review) && <div className="page-actions">
        {scanID && <a href={scanReceiptLink(scanID, environment)}>Open scan receipt</a>}
        {review && <a href={review}>Open version review</a>}
      </div>}
    </div>
  );
}
