"use client";

import { useCallback, useMemo, useState } from "react";
import { createFleetAPI, type EndpointFleetAPI } from "../../../apps/web/api/endpoint-fleet";
import type { EndpointDetail } from "../../../apps/web/api/generated";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Button, Card, Select } from "../../components/ui";
import { SkillRuleLabel } from "./SkillRuleLabel";
import { deviceFleetLocation } from "../../domain/activity-links";
import { addonVersionLink } from "../../domain/addon-links";

function DeviceResults({ device, environment }: { device: EndpointDetail; environment: string }) {
  const partitions = device.partition_summaries;
  const rows = partitions.flatMap(p => p.observed_installations.map(installation => ({ partition: p.partition_id, installation })));
  const truncated = device.inventory_partitions > partitions.length || partitions.some(p => p.observed_count > p.observed_installations.length);
  return <>
    <p>Latest reported inventory from <a href={`/integrations/sensors?device=${device.id}`}>{device.cohort} · {device.id.slice(-12)}</a> ({device.connection.replaceAll("_", " ")}).</p>
    {!partitions.length ? <p>This device has not reported an inventory snapshot.</p> :
      !rows.length ? <p>No installations appear in these inventory snapshots.</p> :
      <div className="table-scroll"><table className="data-table">
        <thead><tr><th scope="col">Installation</th><th scope="col">Static scan</th><th scope="col">Findings</th><th scope="col">Review</th></tr></thead>
        <tbody>{rows.map(({ partition, installation }) => {
          const scan = installation.skill_scan;
          const findings = scan ? Object.entries(scan.rule_counts) : [];
          return <tr key={partition + installation.installation_id}>
            <td><code title={installation.installation_id}>{installation.installation_id.slice(0, 12)}</code></td>
            <td>{scan ? scan.skipped_count ? `Partial · ${scan.skipped_count} skipped` : "Complete" : "No scan reported"}</td>
            <td>{!scan ? "Unknown" : findings.length ? <ul>{findings.map(([rule, count]) => <li key={rule}><SkillRuleLabel rule={rule} /> · {count}</li>)}</ul> : "0 reported"}</td>
            <td>{installation.skill_version_id ? <a href={addonVersionLink(installation.skill_version_id, environment)}>Open version review</a> : "—"}</td>
          </tr>;
        })}</tbody>
      </table></div>}
    {partitions.some(p => !p.complete) && <p>Device discovery was incomplete for one or more inventory roots.</p>}
    {truncated && <p>This preview includes up to 8 inventory roots and 12 installations per root.</p>}
  </>;
}

function DeviceEvidence({ api, id, environment }: { api: EndpointFleetAPI; id: string; environment: string }) {
  const load = useCallback((signal?: AbortSignal) => api.get(id, signal), [api, id]);
  const result = useAPIQuery("scanner:device:" + id, load);
  if (result.status === "success" && result.data) return <DeviceResults device={result.data} environment={environment} />;
  if (result.status === "loading" || result.status === "idle") return <p role="status">Loading device scan results…</p>;
  return <p role="alert">Device scan results are unavailable. <Button onClick={() => void result.retry()}>Retry results</Button></p>;
}

export function AutomaticSkillScans({ environment }: { environment: string }) {
  const { client, invalidate } = useAPI();
  const api = useMemo(() => createFleetAPI(client), [client]);
  const [pages, setPages] = useState<string[]>([]);
  const [selected, select] = useState("");
  const cursor = pages.at(-1);
  const load = useCallback((signal?: AbortSignal) => api.list(cursor, signal), [api, cursor]);
  const fleetKey = "scanner:devices:" + (cursor ?? "");
  const query = useAPIQuery(fleetKey, load);
  const page = query.status === "success" || query.status === "empty" ? query.data : undefined;
  const device = page?.items.find(item => item.id === selected) ?? page?.items.find(item => item.state === "active") ?? page?.items[0];
  return <Card title="Automatic skill scans" action={page && <Button onClick={() => invalidate(device ? [fleetKey, "scanner:device:" + device.id] : [fleetKey])}>Refresh results</Button>}><div className="endpoint-skill-scans">
    <p>On devices with skill scanning enabled, the agent watches assigned skill folders and scans when files change. It reports installation IDs and findings. Skill contents and local paths stay on the device.</p>
    {page ? <>
      <p>{page.counts.enrolled} {page.counts.enrolled === 1 ? "device" : "devices"} enrolled · {page.counts.online} online</p>
      {device ? <>
        <Select label="Device" value={device.id} onChange={event => select(event.target.value)}>
          {page.items.map(item => <option key={item.id} value={item.id}>{item.cohort} · {item.id}</option>)}
        </Select>
        <DeviceEvidence api={api} id={device.id} environment={environment} />
      </> : <p>To start reporting scans, <a href={deviceFleetLocation}>enroll a device</a> in this Environment.</p>}
      {(cursor || page.next_after_id) && <div className="ai-actions">
        <Button disabled={!cursor} onClick={() => setPages(p => p.slice(0, -1))}>Previous devices</Button>
        <Button disabled={!page.next_after_id} onClick={() => { if (page.next_after_id) setPages([...pages, page.next_after_id]); }}>Next devices</Button>
      </div>}
    </> : query.status === "idle" || query.status === "loading" ? <p role="status">Loading device coverage…</p> :
      <p role="alert">Device coverage is unavailable. <Button onClick={() => void query.retry()}>Retry device coverage</Button></p>}
  </div></Card>;
}
