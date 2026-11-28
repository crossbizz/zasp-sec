import { Card, EmptyState, PageHeader } from "../../components/ui";

export function ConnectorView() {
  return <div className="page">
    <PageHeader title="Connections" />
    <Card>
      <EmptyState title="No Nango integrations configured" description="Sign in to a configured environment to connect a source." />
    </Card>
  </div>;
}
