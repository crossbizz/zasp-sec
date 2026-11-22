"use client";

import { useEffect, useRef, useState } from "react";
import {
  requireAPIData,
  uploadPrivateAddonArchive,
  type APIClient,
} from "../../../apps/web/api/client";
import { Button } from "../../components/ui";

type Grant = {
  id: string;
  upload_url: string;
  upload_grant: string;
  expires_at: string;
  result_delivery: "browser_only" | "registry";
};
const productID =
  /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const safeRule =
  /^(dependency\.unpinned|instruction\.hidden_text|mcp\.remote_endpoint|mcp\.unpinned_launcher|script\.network_access|script\.shell_execution)$/;

function decodeGrant(value: unknown): Grant {
  if (!value || typeof value !== "object") throw Error();
  const g = value as Partial<Grant> & { retention?: unknown };
  if (
    g.retention !== "memory_only" ||
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
    Date.parse(g.expires_at) <= Date.now()
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
  };
}

function object(value: unknown): Record<string, unknown> | undefined {
  if (typeof value === "object" && value !== null && !Array.isArray(value))
    return value as Record<string, unknown>;
}

export function PrivateAddonScan({
  client,
  environment,
  fresh,
  reauthenticate,
}: {
  client: APIClient;
  environment: string;
  fresh: boolean;
  reauthenticate: () => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [grant, setGrant] = useState<Grant | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [review, setReview] = useState("");
  const current = useRef<AbortController | undefined>(undefined);
  useEffect(() => () => current.current?.abort(), []);
  async function prepare() {
    if (!file || busy) return;
    setGrant(null);
    setReview("");
    if (file.size <= 0 || file.size > 8 * 1024 * 1024) {
      setMessage("Choose a ZIP between 1 byte and 8 MiB.");
      return;
    }
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
      const data = await client.POST("/api/v1/addon-scan-uploads", {
        params: {
          header: {
            "X-CSRF-Token": "",
            "Idempotency-Key": crypto.randomUUID(),
          },
        },
        body: {
          mode: "private_upload",
          retention: "memory_only",
          archive_bytes: file.size,
          archive_digest:
            "sha256:" +
            Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join(""),
        },
        signal: work.signal,
      });
      const approved = requireAPIData(data, decodeGrant);
      if (!work.signal.aborted) setGrant(approved);
    } catch {
      if (!work.signal.aborted)
        setMessage(
          "Could not prepare a grant. Verify extended collection, worker configuration, and fresh authorization.",
        );
    } finally {
      if (!work.signal.aborted) setBusy(false);
    }
  }
  async function upload() {
    if (!file || !grant || busy) return;
    if (Date.parse(grant.expires_at) <= Date.now()) {
      setGrant(null);
      setMessage("Grant expired. Prepare a new private scan.");
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
      const rows = Object.entries(counts);
      if (
        rows.some(
          ([rule, n]) =>
            !safeRule.test(rule) ||
            typeof n !== "number" ||
            !Number.isInteger(n) ||
            n < 1 ||
            n > 1024,
        )
      )
        throw Error();
      const text = rows.length
        ? rows.map(([rule, n]) => `${rule} (${n})`).join(", ") + "."
        : "No findings from this scan.";
      const partial =
        result.status === "partial"
          ? " Some members could not be inspected. No exact version is available."
          : "";
      let delivery = "";
      let reviewPath = "";
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
          reviewPath = "/inventory/tools?addon=" + receipt.version_id;
        } else if (
          receipt.version_id !== null ||
          receipt.review_path !== null ||
          receipt.manifest_digest !== null
        )
          throw Error();
        delivery = " Findings recorded under " + receipt.scan_id + ".";
      }
      if (!work.signal.aborted) {
        setReview(reviewPath);
        setMessage(`Scan ${result.status}. ${text}${partial}${delivery}`);
      }
    } catch {
      if (!work.signal.aborted)
        setMessage(
          "The worker could not confirm this scan. Prepare a new grant before retrying.",
        );
    } finally {
      if (!work.signal.aborted) {
        setGrant(null);
        setBusy(false);
      }
    }
  }
  return (
    <details className="card">
      <summary>Scan a private skill ZIP</summary>
      <p>
        Environment {environment}. The dedicated worker reads the archive in
        memory and returns static finding counts. Choose a ZIP up to 8 MiB with
        SKILL.md at its root.
      </p>
      <label>
        Skill ZIP{" "}
        <input
          type="file"
          accept=".zip,application/zip"
          disabled={busy}
          onChange={(e) => {
            setFile(e.target.files?.[0] ?? null);
            setGrant(null);
            setMessage("");
            setReview("");
          }}
        />
      </label>
      {grant && (
        <p>
          {grant.result_delivery === "registry"
            ? "This worker records finding counts and the exact version, when available, in the Environment’s review registry."
            : "This worker returns its findings to this browser only."}
        </p>
      )}
      {!fresh ? (
        <Button onClick={reauthenticate}>Verify identity</Button>
      ) : grant ? (
        <Button disabled={busy} onClick={() => void upload()}>
          Send ZIP to {new URL(grant.upload_url).host}
        </Button>
      ) : (
        <Button disabled={busy || !file} onClick={() => void prepare()}>
          Prepare private scan
        </Button>
      )}
      {message && <p role="status">{message}</p>}
      {review && <a href={review}>Open version review</a>}
    </details>
  );
}
