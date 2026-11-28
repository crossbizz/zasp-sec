"use client";

import { useCallback } from "react";
import { requireAPIData } from "../../../apps/web/api/client";
import { decodeDataControls } from "../../../apps/web/api/administration-decoders";
import { useAPI } from "../../api/APIProvider";
import { useAPIQuery } from "../../api/query";
import { useOptionalSession } from "../../auth/SessionProvider";
import { Button, Card } from "../../components/ui";
import { LocalScanHelp } from "./AddonReviews";
import { PrivateAddonScan } from "./PrivateAddonScan";

export function SkillScannerPanel() {
  const session = useOptionalSession();
  const { client, queryGeneration, queryScopeKey } = useAPI();
  const environment = session?.status === "authenticated" ? session.environmentID : "";
  const canUpload = !!environment && !!session?.hasCapability("data-controls.manage");
  const load = useCallback(async (signal?: AbortSignal) => {
    const response = await client.GET("/api/v1/settings/data-controls", { signal });
    const settings = requireAPIData(response, decodeDataControls);
    if (settings.environment_id !== environment) throw new Error("Environment changed");
    return { ...settings, worker: response.response.headers.get("X-Zasp-Private-Scan") };
  }, [client, environment]);
  const controls = useAPIQuery("scanner:data-controls", load, canUpload);
  let content;
  if (!canUpload) {
    content = <p>Private uploads require a data-controls administrator. You can scan a skill on this device with the local scanner.</p>;
  } else if (controls.status === "loading" || controls.status === "idle") {
    content = <p role="status">Checking the Environment’s upload settings…</p>;
  } else if (controls.status !== "success" || !controls.data) {
    content = <div role="alert"><p>Could not verify upload settings for this Environment.</p><Button onClick={() => void controls.retry()}>Retry settings check</Button></div>;
  } else if (controls.data.collection_mode === "metadata_only") {
    content = <p>This Environment uses metadata-only collection. Scan the skill on this device to keep its contents local.</p>;
  } else if (controls.data.environment_class === "production") {
    content = <p>Private uploads are restricted to development, test and staging. Scan production skills on this device.</p>;
  } else if (controls.data.worker === "unconfigured") {
    content = <p>This Environment has no private scan worker configured. Scan on this device, or ask your administrator to connect a worker.</p>;
  } else if (session) {
    content = <PrivateAddonScan key={JSON.stringify([queryScopeKey, queryGeneration, environment])} client={client} environment={environment} allowRetention={controls.data.worker === "encrypted_24h"} fresh={session.isFreshAuthenticated} reauthenticate={session.reauthenticate} />;
  }
  return <Card title="Scan a skill">{content}<LocalScanHelp /></Card>;
}
