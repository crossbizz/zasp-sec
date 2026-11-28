"use client";

import { useCallback } from "react";
import { requireAPIData } from "../../../apps/web/api/client";
import { decodeDataControls } from "../../../apps/web/api/administration-decoders";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { useOptionalSession } from "../../auth/SessionProvider";
import { Button, Card } from "../../components/ui";
import { AutomaticSkillScans } from "./AutomaticSkillScans";
import { LocalScanHelp } from "./AddonReviews";
import { PrivateAddonScan } from "./PrivateAddonScan";

export function SkillScannerPanel() {
  const session = useOptionalSession();
  const { client, queryGeneration, queryScopeKey } = useAPI();
  const environment = session?.status === "authenticated" ? session.environmentID : "";
  const canUpload = !!environment && !!session?.hasCapability("data-controls.manage");
  // Grant issuance and settings reads have separate permissions. The worker
  // authorization still enforces collection policy when a settings read is unavailable.
  const canReadSettings = session?.status === "authenticated" && session.permissions.includes("view_compliance");
  const load = useCallback(async (signal?: AbortSignal) => {
    const response = await client.GET("/api/v1/settings/data-controls", { signal });
    const settings = requireAPIData(response, decodeDataControls);
    if (settings.environment_id !== environment) throw new Error("Environment changed");
    return { ...settings, worker: response.response.headers.get("X-Zasp-Private-Scan") };
  }, [client, environment]);
  const controls = useAPIQuery("scanner:data-controls", load, canUpload && canReadSettings);
  const settings = controls.status === "success" ? controls.data : undefined;
  let content;
  if (!canUpload) {
    content = <p>Private uploads require a data-controls administrator. You can scan a skill on this device with the local scanner.</p>;
  } else if (queryScopeKey === null || (canReadSettings && (controls.status === "loading" || controls.status === "idle"))) {
    content = <p role="status">Checking the Environment’s upload settings…</p>;
  } else if (canReadSettings && !settings) {
    content = <div role="alert"><p>Could not verify upload settings for this Environment.</p><Button onClick={() => void controls.retry()}>Retry settings check</Button></div>;
  } else if (settings?.collection_mode === "metadata_only") {
    content = <p>This Environment uses metadata-only collection. Scan the skill on this device to keep its contents local.</p>;
  } else if (settings?.environment_class === "production") {
    content = <p>Private uploads are restricted to development, test and staging. Scan production skills on this device.</p>;
  } else if (settings?.worker === "unconfigured") {
    content = <p>This Environment has no private scan worker configured. Scan on this device, or ask your administrator to connect a worker.</p>;
  } else if (session) {
    content = <PrivateAddonScan key={JSON.stringify([queryScopeKey, queryGeneration, environment])} client={client} environment={environment} allowRetention={settings?.worker === "encrypted_24h"} fresh={session.isFreshAuthenticated} reauthenticate={session.reauthenticate} />;
  }
  return <div className="skill-scanner-panels">
    {environment && <AutomaticSkillScans key={JSON.stringify([queryScopeKey, queryGeneration, environment])} environment={environment} />}
    <Card title="Scan a private ZIP">{content}<LocalScanHelp /></Card>
  </div>;
}
