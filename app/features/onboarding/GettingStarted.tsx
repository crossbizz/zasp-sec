"use client";

import { useCallback } from "react";
import { Cable, RadioTower } from "lucide-react";
import { requireAPIData } from "../../../apps/web/api/client";
import { decodeInventoryPage, decodeSensorPage } from "../../../apps/web/api/decoders";
import { createIntegrationsAPI, isNangoIntegration } from "../workflows/api";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { Button } from "../../components/ui";
import { addSourceLocation, enrollSensorLocation } from "../../domain/activity-links";
import "./getting-started.css";

type SourceAccess = { read: boolean; write: boolean };
type Props = {
  environmentVisible: boolean;
  integrations: SourceAccess;
  sensors: SourceAccess;
  onNavigate(path: string): void;
};

export function GettingStarted({ environmentVisible, integrations, sensors, onNavigate }: Props) {
  const { client } = useAPI();
  const loadInventory = useCallback(async (signal?: AbortSignal) => {
    const options = { params: { query: { limit: 1 } }, signal };
    const pages = await Promise.all([
      client.GET("/api/v1/tools", options), client.GET("/api/v1/identities", options), client.GET("/api/v1/runtimes", options),
    ]);
    return pages.some(page => requireAPIData(page, decodeInventoryPage).items.length > 0);
  }, [client]);
  const inventory = useAPIQuery("home:other-inventory", loadInventory, environmentVisible);
  const inventoryEmpty = inventory.status === "success" && inventory.data === false;

  const loadIntegration = useCallback(async (signal?: AbortSignal) => {
    const records = await createIntegrationsAPI(client).listIntegrations(signal);
    return records.some(isNangoIntegration);
  }, [client]);
  const loadSensor = useCallback(async (signal?: AbortSignal) => {
    const result = await client.GET("/api/v1/sensors", { params: { query: { limit: 1 } }, signal });
    return requireAPIData(result, decodeSensorPage).items.length > 0;
  }, [client]);
  const connections = useAPIQuery("home:integration-present", loadIntegration, integrations.read && inventoryEmpty);
  const enrollments = useAPIQuery("home:sensor-present", loadSensor, sensors.read && inventoryEmpty);

  if (!environmentVisible || inventory.status === "forbidden") return <p className="setup-note">No agents are visible in your scope. Ask your administrator to check your environment access and discovery sources.</p>;
  if (inventory.status === "error" || inventory.status === "stale") return <p role="status">Inventory setup status is unavailable. <Button onClick={() => void inventory.retry()}>Retry setup status</Button></p>;
  if (!inventoryEmpty) return null;

  const hasSources = connections.data === true || enrollments.data === true;
  return <section className="setup-guide" aria-labelledby="setup-title">
    <header>
      <h2 id="setup-title">{hasSources ? "Check your data collection" : "Get started with discovery"}</h2>
      <p>{hasSources ? "This environment has a source configured. Check its connection and first results." : "Bring agents into this environment by connecting a source where they run."}</p>
    </header>
    <div className="setup-options">
      <article>
        <Cable aria-hidden="true" size={24} />
        <h3>SaaS integrations</h3>
        {integrations.read && connections.status === "success" ? <>
          <p>{connections.data ? "Open a configured integration to check authorization, run discovery, and review its latest sync." : integrations.write ? "Choose a provider, authorize read access, and check the first discovery sync. Discovered agents appear in Inventory." : "Ask your administrator to connect a provider and run its first discovery sync."}</p>
          {(connections.data || integrations.write) && <Button variant="primary" onClick={() => onNavigate(connections.data ? "/connectors" : addSourceLocation)}>{connections.data ? "View integrations" : "Connect an integration"}</Button>}
        </> : integrations.read ? <SourceStatus status={connections.status} retry={connections.retry} source="integrations" /> : <p>Ask your administrator to connect an enabled Nango provider and start discovery.</p>}
      </article>
      <article>
        <RadioTower aria-hidden="true" size={24} />
        <h3>Runtime sensors</h3>
        {sensors.read && enrollments.status === "success" ? <>
          <p>{enrollments.data ? "Open an enrolled sensor to check its status and confirm its first heartbeat." : sensors.write ? "For runtime coverage, enroll a collector, follow its installation instructions, and confirm the first heartbeat." : "Ask your administrator to enroll a sensor if your team needs runtime coverage."}</p>
          {(enrollments.data || sensors.write) && <Button onClick={() => onNavigate(enrollments.data ? "/integrations/sensors" : enrollSensorLocation)}>{enrollments.data ? "View sensors" : "Enroll a sensor"}</Button>}
        </> : sensors.read ? <SourceStatus status={enrollments.status} retry={enrollments.retry} source="sensors" /> : <p>Your administrator can enroll a sensor for runtime coverage and verify its first heartbeat.</p>}
      </article>
    </div>
  </section>;
}

function SourceStatus({ status, retry, source }: { status: string; retry(): Promise<void>; source: string }) {
  if (status === "loading" || status === "idle") return <p role="status">Checking {source}…</p>;
  return <><p role="status">The setup status for {source} is unavailable.</p><Button onClick={() => void retry()}>Retry {source}</Button></>;
}
