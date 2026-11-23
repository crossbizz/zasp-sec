"use client";

import { FrameworkSurfaceReview } from "./FrameworkSurfaceReview";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { APIProductError, type APIClient } from "../../../apps/web/api/client";
import {
  evidenceNames, frameworkNames, frameworkCoverageAPI,
  type CatalogEdition, type CoverageEvidence, type CoverageRow, type CoverageSelector, type EvidenceKind,
  type EvidenceSelector, type SourceSelector,
} from "../../../apps/web/api/framework-coverage";
import { addonVersionLink } from "../../domain/addon-links";
import { activityLink, type ActivityScope } from "../../domain/activity-links";
import { catalogLink, type CatalogTarget } from "../../domain/coverage-links";
import { Badge, Button, Card } from "../../components/ui";
import { Time } from "../../components/time";
import type { ComplianceBoundary } from "./ComplianceEvidenceView";

const applicabilityNames = { applicable: "Applicable", out_of_scope: "Out of scope", unassessed: "Unassessed" };
const entryKinds = { risk: "Risk", technique: "Technique", subtechnique: "Sub-technique", mitigation: "Mitigation" };
type CoverageAPI = ReturnType<typeof frameworkCoverageAPI>;

function ProtectedRead<T>({ load, children }: { load: (signal: AbortSignal) => Promise<T>; children: (data: T) => ReactNode }) {
  const [attempt, setAttempt] = useState(0);
  const [read, setRead] = useState<{ request: typeof load; attempt: number; data: T } | { request: typeof load; attempt: number; error: string }>();
  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal).then(data => {
      if (!controller.signal.aborted) setRead({ request: load, attempt, data });
    }).catch(error => {
      if (controller.signal.aborted) return;
      const msg = error instanceof APIProductError && [401, 403, 404].includes(error.status)
        ? "This evidence is unavailable in your current session and Environment."
        : "Could not load framework coverage. Evidence counts are unknown.";
      setRead({ request: load, attempt, error: msg });
    });
    return () => controller.abort();
  }, [attempt, load]);
  if (!read || read.request !== load || read.attempt !== attempt) return <p role="status">Loading framework coverage…</p>;
  if ("error" in read) return <p role="alert">{read.error} <Button onClick={() => setAttempt(value => value + 1)}>Retry coverage</Button></p>;
  return children(read.data);
}

function PageControls({ pages, next, setPages }: { pages: string[]; next: string | null; setPages(v: string[]): void }) {
  if (!pages.length && !next) return null;
  return <div className="page-actions" aria-label="Pagination">
    <Button disabled={!pages.length} onClick={() => setPages(pages.slice(0, -1))}>Previous page</Button>
    <span>Page {pages.length + 1}</span>
    <Button disabled={!next || pages.includes(next)} onClick={() => next && setPages([...pages, next])}>Next page</Button>
  </div>;
}

function referenceLink(row: CoverageEvidence, scope: ActivityScope): { href: string; label: string } | undefined {
  if (row.source_kind === "addon_version") return { href: addonVersionLink(row.source_id, scope.environmentID), label: "Open add-on version" };
  if (row.source_kind === "finding") return { href: activityLink({ kind: "finding", id: row.source_id }, scope), label: "Open finding" };
  if (row.source_kind === "ticket_test") return { href: activityLink({ kind: "test_run", id: row.source_id }, scope), label: "Open test run" };
  if (row.session_id) return { href: activityLink({ kind: "session", id: row.session_id }, scope), label: "Open session" };
}

function EvidenceList({ api, selector, scope }: { api: CoverageAPI; selector: EvidenceSelector; scope: ActivityScope }) {
  const [pages, setPages] = useState<string[]>([]);
  const after = pages.at(-1);
  const load = useCallback((signal: AbortSignal) => api.evidence(selector, after, signal), [api, selector, after]);
  const fromSource = "source_kind" in selector;
  return <ProtectedRead load={load}>{page => <>
    {!page.items.length && <p>No mapped evidence is available for this selection in this Environment.</p>}
    {page.items.length > 0 && <ul aria-label="Mapped evidence">{page.items.map(row => {
      const target = referenceLink(row, scope);
      const key = [row.framework, row.edition, row.upstream_id, row.source_kind, row.source_id, row.rule, row.rule_version, row.evidence_kind, row.occurred_at].join("/");
      return <li key={key}>
        <strong>{evidenceNames[row.evidence_kind]}</strong> · {row.rule} ({row.rule_version}) · <Time value={row.occurred_at} />{" "}
        {fromSource ? <a className="evidence-reference-link" href={catalogLink(row, scope)}>{frameworkNames[row.framework]} {row.edition} · {row.upstream_id}</a> :
          target ? <a className="evidence-reference-link" href={target.href}>{target.label}</a> : <span>Decision <code>{row.source_id}</code> · linked product session unavailable</span>}
        {row.manifest_digest && <details><summary>Skill manifest digest</summary><code>{row.manifest_digest}</code></details>}
      </li>;
    })}</ul>}
    <PageControls pages={pages} setPages={setPages} next={page.next_after} />
  </>}</ProtectedRead>;
}

// Lookup is explicit: a reviewer can inspect a source without permission to read Compliance.
export function SourceFrameworkEvidence({ client, scope, kind, id }: {
  client: APIClient; scope: ActivityScope; kind: SourceSelector["source_kind"]; id: string;
}) {
  const [open, setOpen] = useState(false);
  const api = useMemo(() => frameworkCoverageAPI(client), [client]);
  const selector = useMemo(() => ({ source_kind: kind, source_id: id }), [kind, id]);
  return <section aria-label="Framework references"><Button aria-expanded={open} onClick={() => setOpen(!open)}>
    {open ? "Hide framework references" : "View framework references"}
  </Button>{open && <EvidenceList key={kind + id} api={api} selector={selector} scope={scope} />}</section>;
}

type Actions = { boundary: ComplianceBoundary; busy: boolean; create(input: CoverageSelector): void };
export function FrameworkCoverage({ client, initial, ...actions }: Actions & { client: APIClient; initial?: CatalogTarget }) {
  const api = useMemo(() => frameworkCoverageAPI(client), [client]);
  return <Card title="Framework coverage">
    <ProtectedRead load={api.editions}>{editions => editions.length ?
      <EditionPicker editions={editions} initial={initial} api={api} {...actions} /> :
      <p>No framework editions are available for this Environment.</p>}
    </ProtectedRead>
  </Card>;
}

function EditionPicker({ editions, initial, api, ...actions }: Actions & { editions: CatalogEdition[]; initial?: CatalogTarget; api: CoverageAPI }) {
  const [choice, setChoice] = useState(initial ?? editions.find(item => item.framework === "owasp_agentic_top10") ?? editions[0]);
  const selected = editions.find(item => item.framework === choice.framework && item.edition === choice.edition);
  const frameworks = [...new Set(editions.map(item => item.framework))];
  return <>
    <div className="form-grid framework-filters">
      <label className="field">Framework <select aria-label="Catalog framework" value={choice.framework} onChange={e => {
        const next = editions.filter(item => item.framework === e.target.value).at(-1);
        if (next) setChoice(next);
      }}>{frameworks.map(id => <option key={id} value={id}>{frameworkNames[id]}</option>)}</select></label>
      <label className="field">Edition <select aria-label="Edition" value={choice.edition} onChange={e => {
        const next = editions.find(item => item.framework === choice.framework && item.edition === e.target.value);
        if (next) setChoice(next);
      }}>{editions.filter(item => item.framework === choice.framework).map(item => <option key={item.edition}>{item.edition}</option>)}</select></label>
    </div>
    {selected ? <EditionCoverage key={selected.framework + "/" + selected.edition} edition={selected}
      initialID={initial?.framework === selected.framework && initial.edition === selected.edition ? initial.upstream_id : ""} api={api} {...actions} /> :
      <p role="alert">This linked edition is unavailable in the selected Environment.</p>}
  </>;
}

function EditionCoverage({ edition, initialID, api, ...actions }: Actions & { edition: CatalogEdition; initialID: string; api: CoverageAPI }) {
  const [kind, setKind] = useState<"" | EvidenceKind>("");
  const [id, setID] = useState(initialID), [draftID, setDraftID] = useState(initialID);
  const selector = useMemo(() => ({
    framework: edition.framework, edition: edition.edition,
    ...(id ? { upstream_id: id } : {}), ...(kind ? { evidence_kind: kind } : {}),
  }), [edition, id, kind]);
  return <>
    <div className="form-grid framework-filters">
      <label className="field">Evidence kind <select value={kind} onChange={e => setKind(e.target.value as typeof kind)}><option value="">All evidence kinds</option>
        {Object.entries(evidenceNames).map(([value, name]) => <option key={value} value={value}>{name}</option>)}
      </select></label>
      <form className="framework-control-filter" onSubmit={e => { e.preventDefault(); setID(draftID.trim()); }}>
        <label className="field">Control ID <input value={draftID} maxLength={64} placeholder="e.g. ASI04" onChange={e => setDraftID(e.target.value)} /></label>{" "}
        <Button type="submit">Apply control</Button>{id && <Button type="button" onClick={() => { setID(""); setDraftID(""); }}>Clear control</Button>}
      </form>
    </div>
    <CoveragePage key={id + "/" + kind} api={api} selector={selector} edition={edition} {...actions} />
  </>;
}

function CoveragePage({ api, selector, edition, boundary, busy, create }: Actions & { api: CoverageAPI; selector: CoverageSelector; edition: CatalogEdition }) {
  const [pages, setPages] = useState<string[]>([]);
  const after = pages.at(-1);
  const load = useCallback(async (signal: AbortSignal) => {
    const page = await api.coverage(selector, after, signal);
    if (page.source_digest !== edition.source_digest || page.total !== edition.total_controls) throw new Error("Edition changed");
    return page;
  }, [api, selector, after, edition]);
  return <ProtectedRead load={load}>{page => <>
    <p><strong>{page.matched} of {page.total} catalog entries</strong> match this selection. Evidence as of <Time value={page.collected_at} />.</p>
    <p>{page.summary.verified_applicable_controls} of {page.summary.applicable_controls} applicable entries have current verification (30-day window) · {page.summary.unassessed_controls} unassessed · {page.summary.out_of_scope_controls} out of scope</p>
    {page.summary.techniques + page.summary.subtechniques + page.summary.mitigations > 0 &&
      <p>{page.summary.techniques} techniques · {page.summary.subtechniques} sub-techniques · {page.summary.mitigations} mitigations</p>}
    <Button disabled={busy || !boundary.fresh} onClick={() => { if (boundary.fresh && boundary.isCurrent()) create(selector); }}>Export this selection</Button>
    {!boundary.fresh && <p>Fresh authentication required to export. <Button onClick={boundary.reauthenticate}>Reauthenticate to export</Button></p>}
    {page.items.length === 0 && <p>No catalog entries match these filters.</p>}
    {page.items.length > 0 && <div className="table-scroll"><table className="data-table framework-coverage-table" aria-label="Coverage by control"><thead><tr><th>Control</th><th>Applicability</th><th>Evidence in this Environment</th><th>Last verified</th></tr></thead>
      <tbody>{page.items.map(row => <ControlRow key={row.control.upstream_id} row={row} api={api} scope={boundary} selector={selector}
        asOf={page.collected_at} initialOpen={selector.upstream_id === row.control.upstream_id} exportable={boundary.fresh && !busy} create={input => { if (boundary.isCurrent()) create(input); }} />)}</tbody></table></div>}
    <PageControls pages={pages} setPages={setPages} next={page.next_after} />
  </>}</ProtectedRead>;
}

function ControlRow({ row, api, scope, selector, initialOpen, exportable, create, asOf }: {
  row: CoverageRow; api: CoverageAPI; scope: ActivityScope; selector: CoverageSelector; initialOpen: boolean; asOf: string; exportable: boolean; create(input: CoverageSelector): void;
}) {
  const [open, setOpen] = useState(initialOpen);
  const c = row.control;
  const target = useMemo(() => ({ ...selector, upstream_id: c.upstream_id }), [selector, c.upstream_id]);
  const counts = Object.entries(row.evidence_counts).filter(([, n]) => n > 0);
  return <><tr>
    <th scope="row"><Button variant="ghost" aria-expanded={open} onClick={() => setOpen(!open)}>{c.upstream_id} · {c.title}</Button></th>
    <td>{applicabilityNames[c.applicability]}</td>
    <td>{counts.length ? counts.map(([kind, count]) => <div key={kind}>{evidenceNames[kind as EvidenceKind]} · {count}</div>) : "Unknown — no mapped evidence"}</td>
    <td>{row.last_verified_at ? <>
      <Badge tone={Date.parse(asOf)-Date.parse(row.last_verified_at) <= 30*86400000 ? "success" : "warning"}>
        {Date.parse(asOf)-Date.parse(row.last_verified_at) <= 30*86400000 ? "Current" : "Stale"}</Badge>{" "}<Time value={row.last_verified_at} />
    </> : "No verification recorded"}</td>
  </tr>{open && <tr><td colSpan={4}><section aria-label={c.upstream_id + " details"}>
    <p><Badge>{entryKinds[c.kind]}</Badge> {c.status === "retired" && <Badge>Retired</Badge>} {c.parent_id && <>Parent {c.parent_id}</>}</p>
    <dl><dt>Owner</dt><dd>{c.owner}</dd><dt>Scope</dt><dd>{c.scope}</dd><dt>Applicability rationale</dt><dd>{c.rationale}</dd></dl>
    <FrameworkSurfaceReview scope={c.scope} applicability={c.applicability} />
    <a className="evidence-reference-link" href={c.source_url} target="_blank" rel="noreferrer">Upstream reference</a> · {c.attribution} · {c.license}
    <details><summary>Catalog source digest</summary><p>{c.digest_basis === "upstream_bytes" ? "Upstream source bytes" : "Reviewed catalog index"}</p><code>{c.source_digest}</code></details>
    <EvidenceList api={api} selector={target} scope={scope} />
    {!selector.upstream_id && <Button disabled={!exportable} onClick={() => create(target)}>Export {c.upstream_id} evidence</Button>}
  </section></td></tr>}</>;
}
