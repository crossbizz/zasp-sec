import { useMemo, type ComponentProps } from "react";
import { useAPI } from "../../../api/APIProvider";
import { createIntegrationsAPI } from "../api";
import { IntegrationsWorkspace } from "../ProductionWorkflowViews";

// Exercise the underlying workflows with recorded native API responses from
// older deployments. The public Integrations page supplies a Nango-only catalog.
export function LegacyIntegrationWorkflow(props: Omit<ComponentProps<typeof IntegrationsWorkspace>, "api">) {
  const { client } = useAPI();
  const api = useMemo(() => createIntegrationsAPI(client), [client]);
  return <IntegrationsWorkspace {...props} api={api} />;
}
