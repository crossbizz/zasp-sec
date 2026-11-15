import type { InventorySummary } from "../../../apps/web/api/generated";
import { Time } from "../../components/time";
import { Button } from "../../components/ui";

type Attribution = NonNullable<InventorySummary["attribution"]>;
type Location = NonNullable<Attribution["location"]>;
type CreatorSource = NonNullable<Attribution["creator"]>["source"];

const locationKindLabels: Readonly<Record<Location["kind"], string>> = {
  aws_account: "AWS account", gcp_project: "Google Cloud project", gcp_scope: "Google Cloud scope", github_repository: "GitHub repository", github_organization: "GitHub organization",
  kubernetes_namespace: "Kubernetes namespace", kubernetes_cluster: "Kubernetes cluster", microsoft_subscription: "Azure subscription", power_platform_environment: "Power Platform environment",
  microsoft_tenant: "Microsoft tenant", okta_tenant: "Okta tenant", salesforce_org: "Salesforce org", saas_workspace: "Workspace",
};

// How the product knows who created an agent, in the words a person reads.
const creatorSourceLabels: Readonly<Record<CreatorSource, string>> = {
  cloudtrail: "from the AWS CloudTrail create event", audit_log: "from the provider's audit log", provider_record: "from the provider's record of the agent",
  codeowners: "from the repository's CODEOWNERS file", label: "from a label on the object", annotation: "from an annotation on the object",
};
// An audit log or the provider's record says who created the agent. A
// CODEOWNERS file, a label or an annotation names an owner, not a creator.
const namedOwnerSources: readonly CreatorSource[] = ["codeowners", "label", "annotation"];
const teamSourceLabels = { label: "from a label or annotation on the object", okta: "from the creator's department in Okta" } as const;

// "AWS account 123456789012", "GitHub repository org/repo". Empty when the
// provider names no location.
export function locationLabel(item: InventorySummary): string {
  const location = item.attribution?.location;
  return location ? `${locationKindLabels[location.kind]} ${location.label}` : "";
}

// The rows a detail-facts list shows about where an agent lives, who created
// it and whom to ask: Location, Found by integration, Created by and the
// suggested owner and team, each with how it is known.
export function AttributionFacts({ item }: { item: InventorySummary }) {
  const attribution = item.attribution;
  if (!attribution) return null;
  const { location, integration, creator, suggested_owner: owner, suggested_team: team } = attribution;
  return <>
    <div><dt>Location</dt><dd>{location ? <>{locationKindLabels[location.kind]} {location.label}{location.label !== location.id && <> (<code>{location.id}</code>)</>}</> : "Not reported by the provider"}</dd></div>
    <div><dt>Found by integration</dt><dd>{integration ? integration.name : "Unknown"}</dd></div>
    {item.kind === "agent" && <div><dt>{creator && namedOwnerSources.includes(creator.source) ? "Named owner" : "Created by"}</dt><dd>{creator ? <>{creator.identity}{creator.created_at && <> on <Time value={creator.created_at} /></>}, {creatorSourceLabels[creator.source]}</> : "Not reported by the provider"}</dd></div>}
    {owner && <div><dt>Suggested owner</dt><dd>{owner.value}, {creatorSourceLabels[owner.source]}. Not assigned yet.</dd></div>}
    {team && <div><dt>Suggested team</dt><dd>{team.value}, {teamSourceLabels[team.source]}. Not assigned yet.</dd></div>}
  </>;
}

// The same facts as a drawer section, with one button that copies the
// suggestion into the ownership fields. Nothing is saved until the person
// saves the ownership.
export function AttributionSection({ item, onAssign, disabled }: { item: InventorySummary; onAssign?: (owner: string, team: string | null) => void; disabled?: boolean }) {
  const attribution = item.attribution;
  if (!attribution) return null;
  const owner = attribution.suggested_owner; const team = attribution.suggested_team;
  return <section aria-label="Location and creator"><h3>Location and creator</h3><dl className="detail-facts"><AttributionFacts item={item} /></dl>
    {onAssign && owner && <div className="button-row"><Button disabled={disabled} onClick={() => onAssign(owner.value, team ? team.value : null)}>Assign suggested owner</Button><small>Fills the owner{team ? " and team" : ""} below. Save ownership to record it.</small></div>}
  </section>;
}
