"use client";

import { useEffect, useRef, useState } from "react";
import {
  requireAPIData,
  uploadPrivateAddonArchive,
  type APIClient,
} from "../../../apps/web/api/client";
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
const safeRule =
  /^(dependency\.unpinned|instruction\.hidden_text|mcp\.remote_endpoint|mcp\.unpinned_launcher|script\.network_access|script\.shell_execution)$/;

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
      cap.retain_until !== expiry / 1000
    )
      throw Error();
  }
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
  const [retention, setRetention] = useState<Retention>("memory_only");
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
    } catch {
      if (!work.signal.aborted)
        setMessage(
          retention === "encrypted_24h"
            ? "Could not prepare a retained scan. Check that encrypted retention is enabled for this Environment, or choose a memory-only scan."
            : "Could not prepare a grant. Verify extended collection, worker configuration, and fresh authorization.",
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
        setMessage(
          `Scan ${result.status}. ${text}${partial}${delivery}${storage}`,
        );
      }
    } catch {
      if (!work.signal.aborted)
        setMessage(
          `The worker could not confirm this scan or its retention status. Contact the Environment administrator with grant ${grant.id} before retrying.`,
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
            setRetention("memory_only");
            setGrant(null);
            setMessage("");
            setReview("");
          }}
        />
      </label>
      <label>
        <input
          type="checkbox"
          checked={retention === "encrypted_24h"}
          disabled={busy || !file}
          onChange={(event) => {
            setRetention(
              event.target.checked ? "encrypted_24h" : "memory_only",
            );
            setGrant(null);
            setMessage("");
            setReview("");
          }}
        />{" "}
        Retain an encrypted copy of this ZIP for up to 24 hours
      </label>
      <p>
        Optional retention requires a configured private store. The default scan
        processes the ZIP in memory.
      </p>
      {grant?.retention === "encrypted_24h" && (
        <p>
          Approved encrypted archive retention through{" "}
          <time dateTime={grant.retain_until}>{grant.retain_until}</time>.
        </p>
      )}
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
