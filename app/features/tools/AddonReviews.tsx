"use client";
import { Time } from "../../components/time";

import { CLIReleaseDownloads } from "./CLIReleaseDownloads";
import { AddonScanReceipt } from "./AddonScanReceipt";
import type { ScanTarget } from "../../domain/addon-links";
import { InventoryReview } from "../agents/InventoryReview";
import { DeploymentReviews } from "./DeploymentReviews";
import { AddonInstallations } from "./AddonInstallations";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { APIProductError } from "../../../apps/web/api/client";
import {
  addonID,
  createAddonReviewAPI,
  type AddonReviewAPI,
  type AddonVersion,
  type ReviewDecision,
} from "../../../apps/web/api/addon-reviews";
import { catalogLink } from "../../domain/coverage-links";
import { frameworkNames, type CatalogFramework } from "../../../apps/web/api/framework-coverage";
import { useOptionalSession } from "../../auth/SessionProvider";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Button, Card } from "../../components/ui";

const originLabels: Record<AddonVersion["origin"], string> = {local: "local", ci: "CI", private_worker: "Private scanner"};

const staticRemediation: Readonly<Record<string, string>> = {
  "dependency.unpinned": "Pin the approved release and check the lockfile.",
  "instruction.override": "Inspect the directive in its surrounding instructions.",
  "script.credential_path_access": "Review the credential read and the permissions it needs.",
  "script.remote_exec_pipe": "Inspect and verify the fixed artifact before execution.",
  "mcp.unpinned_exec": "Check the launcher’s exact release and use an authenticated encrypted destination.",
};

export function addonFromSearch(search: string) {
  const ids = new URLSearchParams(search).getAll("addon");
  return ids.length === 1 && addonID.test(ids[0]) ? ids[0] : "";
}

export function LocalScanHelp() {
  const session = useOptionalSession();
  const environment = session?.status === "authenticated" ? session.environmentID : "ENV_ID";
  const cli = "cmd/zaspctl/zaspctl";
  return (
    <details>
      <summary>Scan this device</summary>
      <CLIReleaseDownloads />
      <p>
        From a Zasp source checkout, build the local scanner with Go 1.26. Scan
        a selected project or skill directory without signing in.
      </p>
      <pre>
        <code>
          {
            "go build -C cmd/zaspctl -o ./zaspctl .\ncmd/zaspctl/zaspctl addons inventory --local --project .\ncmd/zaspctl/zaspctl addons scan .claude/skills/ticket-helper --local --json > scan.json"
          }
        </code>
      </pre>
      <p>
        Local scans keep source and findings on this device. Preview the fields
        before sharing a report with an Environment.
      </p>
      <pre><code>{`${cli} addons submit scan.json --mode findings-only --environment ${environment} --dry-run`}</code></pre>
      <p>To share the previewed findings, set <code>ZASP_API_URL</code> to your deployment’s HTTPS origin. Sign in, confirm the Environment and terminal code in the browser, then submit.</p>
      <pre><code>{`${cli} auth login --environment ${environment}\n${cli} addons submit scan.json --mode findings-only --environment ${environment}`}</code></pre>
      <p>Open the link printed by the CLI, or enter its scan ID under Tools &amp; MCP → Add-ons → Find a scan receipt.</p>
    </details>
  );
}

export function AddonReviews({
  initialID = "",
  initialScan,
  environment = "",
  canReview,
  api: supplied,
}: {
  initialID?: string;
  initialScan?: ScanTarget;
  environment?: string;
  canReview: boolean;
  api?: AddonReviewAPI;
}) {
  const { client, queryScopeKey, queryGeneration } = useAPI();
  const api = useMemo(
    () => supplied ?? createAddonReviewAPI(client),
    [client, supplied],
  );
  return (
    <Registry
      key={JSON.stringify([queryScopeKey, queryGeneration, initialID, initialScan, environment])}
      api={api}
      initialID={initialID}
      initialScan={initialScan}
      environment={environment}
      canReview={canReview}
    />
  );
}

function Registry({
  api,
  initialID,
  initialScan,
  environment,
  canReview,
}: {
  api: AddonReviewAPI;
  initialID: string;
  initialScan?: ScanTarget;
  environment: string;
  canReview: boolean;
}) {
  const [id, select] = useState(initialID);
  const [pages, setPages] = useState<string[]>([]);
  const cursor = pages.at(-1);
  const load = useCallback(
    (signal?: AbortSignal) => api.list(cursor, signal),
    [api, cursor],
  );
  const query = useAPIQuery(`addon-versions:${cursor ?? ""}`, load, !id && !initialScan);
  if (initialScan) return <Card title="Add-on scan"><AddonScanReceipt api={api} initial={initialScan} environment={environment} /></Card>;
  if (id)
    return (
      <VersionReview
        key={id}
        api={api}
        id={id}
        canReview={canReview}
        onBack={() => select("")}
      />
    );
  return (
    <Card title="Add-on versions">
      <AddonScanReceipt api={api} environment={environment} />
      {!query.data &&
        (query.status === "idle" || query.status === "loading") && (
          <p role="status">Loading add-on versions…</p>
        )}
      {["error", "forbidden", "stale"].includes(query.status) && (
        <p role="alert">
          Version inventory could not be refreshed.{" "}
          <Button onClick={() => void query.retry()}>Retry</Button>
        </p>
      )}
      {query.data &&
        (query.data.items.length ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Version</th>
                <th>Reported source</th>
                <th>Review</th>
              </tr>
            </thead>
            <tbody>
              {query.data.items.map((row) => (
                <tr key={row.id}>
                  <td>
                    <Button onClick={() => select(row.id)}>
                      {row.manifest_digest.slice(0, 24)}…
                    </Button>
                  </td>
                  <td>{originLabels[row.origin]}</td>
                  <td>{row.review_state}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No submitted add-on versions in this Environment.</p>
        ))}
      {cursor && (
        <Button onClick={() => setPages((previous) => previous.slice(0, -1))}>
          Previous page
        </Button>
      )}
      {query.data?.next_cursor && (
        <Button
          onClick={() => {
            const next = query.data?.next_cursor;
            if (next) setPages((previous) => [...previous, next]);
          }}
        >
          Next page
        </Button>
      )}
      <LocalScanHelp />
    </Card>
  );
}

function VersionReview({
  api,
  id,
  canReview,
  onBack,
}: {
  api: AddonReviewAPI;
  id: string;
  canReview: boolean;
  onBack(): void;
}) {
  const load = useCallback(
    (signal?: AbortSignal) => api.get(id, signal),
    [api, id],
  );
  const query = useAPIQuery(`addon-version:${id}`, load);
  const originLoad = useCallback(
    (signal?: AbortSignal) => api.ciOrigin(id, signal),
    [api, id],
  );
  const origin = useAPIQuery(`addon-origin:${id}`, originLoad);
  const [intent, setIntent] = useState<{
    state: ReviewDecision;
    key: string;
    row: AddonVersion;
  } | null>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const mutation = useRef<AbortController | null>(null);
  useEffect(() => () => mutation.current?.abort(), []);
  const { invalidate } = useAPI();
  const session = useOptionalSession();
  const confirm = async () => {
    if (!intent || mutation.current || !canReview || (session?.status === "authenticated" && !session.isFreshAuthenticated)) return;
    const controller = new AbortController();
    mutation.current = controller;
    setBusy(true);
    setNotice("");
    try {
      await api.review(intent.row, intent.state, intent.key, controller.signal);
      if (controller.signal.aborted) return;
      setIntent(null);
      setNotice("Review decision recorded.");
      invalidate(["addon-versions:"]);
      await query.retry();
    } catch (error) {
      if (controller.signal.aborted) return;
      if (
        error instanceof APIProductError &&
        [401, 403, 409, 412].includes(error.status)
      ) {
        setIntent(null);
        setNotice(
          "Review was not accepted. Check your authentication and the latest revision.",
        );
        await query.retry();
      } else
        setNotice(
          "The result could not be confirmed. Retry this decision to recover its receipt.",
        );
    } finally {
      mutation.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  };
  const row = query.status === "forbidden" ? undefined : query.data;
  return (
    <Card
      title="Add-on version"
      action={
        <Button disabled={busy} onClick={onBack}>
          All versions
        </Button>
      }
    >
      {!row && (query.status === "loading" || query.status === "idle") && (
        <p role="status">Loading version…</p>
      )}
      {["error", "forbidden", "stale"].includes(query.status) && (
        <p role="alert">
          Version details are unavailable or stale.{" "}
          <Button onClick={() => void query.retry()}>Refresh version</Button>
        </p>
      )}
      {row && (
        <>
          <dl>
            <dt>Manifest</dt>
            <dd>
              <code>{row.manifest_digest}</code>
            </dd>
            <dt>Source</dt>
            <dd>{originLabels[row.origin]} · reported by submitter</dd>
            <dt>CI evidence</dt>
            <dd>
              {origin.data ? (
                <>
                  {origin.data.match === "direct"
                    ? "Verified repository submission"
                    : "Matches bytes in an attested repository version"}{" "}
                  · {origin.data.repository} at{" "}
                  <code>{origin.data.commit}</code>
                </>
              ) : origin.status === "loading" ? (
                "Checking…"
              ) : origin.status === "forbidden" ? (
                "CI evidence is unavailable in your current session."
              ) : origin.status === "error" || origin.status === "stale" ? (
                "Could not refresh evidence"
              ) : (
                "No verified repository origin"
              )}
            </dd>
            <dt>Review</dt>
            <dd>
              {row.review_state} · revision {row.revision}
            </dd>
            <dt>Observed usage</dt>
            <dd>Unknown</dd>
          </dl>
          {api.deployments && <DeploymentReviews key={row.id} api={api.deployments} versionID={row.id} versionRevision={row.revision} canReview={canReview && query.status === "success" && session?.status === "authenticated" && session.isFreshAuthenticated} />}
          <AddonInstallations key={row.id} api={api} version={row} />
          {api.reviewEvidence && canReview && <InventoryReview key={row.id} id={row.id} purposes={["addon_semantic_audit"]} review={api.reviewEvidence} />}
          <section aria-label="Offline scanner evidence">
            <h3>Offline scanner evidence</h3>
            {!row.offline_observations?.some(obs => obs.scanner === "gvisor_tetragon") && <p>No current signed sandbox observations for this version.</p>}
            {!!row.offline_observations?.length && <ul>{row.offline_observations.map(obs => <li key={obs.scanner}>
              <strong>{{gvisor_tetragon:"gVisor and Tetragon sandbox",cisco_skill_scanner:"Cisco Skill Scanner",nvidia_skillspector:"NVIDIA SkillSpector"}[obs.scanner]}</strong>
              <p>{obs.indicators.length ? obs.indicators.map(v => v.replaceAll("_"," ")).join(", ") : "The scanner reported no configured indicators."}</p>
              <small>Observed <Time value={obs.observed_at}/> · evidence <code>{obs.evidence_id}</code></small>
            </li>)}</ul>}
          </section>
          <h3>Static scan</h3>
          <p>{row.ruleset}</p>
          {row.findings.length === 0 ? (
            <p>No findings from this scan.</p>
          ) : (
            <ul>
              {row.findings.map((f) => (
                <li key={f.rule_id}>
                  <strong>{f.rule_id}</strong> · {f.count}
                  {staticRemediation[f.rule_id] && <p>{staticRemediation[f.rule_id]} The file and its digest are available in the submitter’s local scan.</p>}
                  {row.framework_evidence?.some((ref) => ref.rule_id === f.rule_id) && (
                    <ul aria-label={`Framework references for ${f.rule_id}`}>
                      {row.framework_evidence.filter((ref) => ref.rule_id === f.rule_id).map((ref) => (
                        <li key={`${ref.framework}/${ref.edition}/${ref.upstream_id}`}>
                          {session?.status === "authenticated" && session.hasCapability("compliance.read") && Object.hasOwn(frameworkNames, ref.framework)
                            ? <a href={catalogLink({ framework: ref.framework as CatalogFramework, edition: ref.edition, upstream_id: ref.upstream_id }, session)}>
                              {ref.framework} · {ref.edition} · {ref.upstream_id} · {ref.title} · Static scan</a>
                            : <>{ref.framework} · {ref.edition} · {ref.upstream_id} · {ref.title} · Static scan</>}
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              ))}
            </ul>
          )}
          {canReview && session?.status === "authenticated" && !session.isFreshAuthenticated && (
            <p>Fresh authentication is required to record a review. <Button onClick={session.reauthenticate}>Verify identity to review</Button></p>
          )}
          {canReview && (session?.status !== "authenticated" || session.isFreshAuthenticated) && query.status === "success" && !intent && (
            <div className="page-actions">
              {(["approved", "rejected", "revoked"] as const).map((state) => (
                <Button
                  key={state}
                  disabled={row.review_state === state}
                  onClick={() => {
                    setNotice("");
                    setIntent({ state, key: crypto.randomUUID(), row });
                  }}
                >
                  {
                    {
                      approved: "Approve version",
                      rejected: "Reject version",
                      revoked: "Revoke approval",
                    }[state]
                  }
                </Button>
              ))}
            </div>
          )}
          {canReview && (session?.status !== "authenticated" || session.isFreshAuthenticated) && intent && (
            <section aria-label="Confirm review">
              <p>
                Record <strong>{intent.state}</strong> for this digest and
                reported source in the current Environment?
              </p>
              <Button disabled={busy} onClick={() => void confirm()}>
                Confirm decision
              </Button>{" "}
              <Button disabled={busy} onClick={() => setIntent(null)}>
                Cancel
              </Button>
            </section>
          )}
        </>
      )}
      {notice && <p role="status">{notice}</p>}
    </Card>
  );
}
