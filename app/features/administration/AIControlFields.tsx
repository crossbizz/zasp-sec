import { Badge, Field, Select } from "../../components/ui";
import { bindingLabels, capabilityLabels, consentLabels, keysOf, modeLabels, residencyLabels, type AISettings, type EnvironmentInput, type Mode, type OrganizationInput } from "../../../apps/web/api/ai-controls";

type OptionProps = { label: string; checked: boolean; onChange(checked: boolean): void; locked?: string };
function Option({ label, checked, onChange, locked }: OptionProps) {
  return <label className="ai-option"><input type="checkbox" checked={checked} disabled={Boolean(locked)} onChange={event => onChange(event.target.checked)} /><span>{label}</span>{locked && <small>{locked}</small>}</label>;
}

export function OrganizationFields({ policy, change }: { policy: AISettings["organization"]; change(patch: OrganizationInput): void }) {
  return <>
    <Option label="Enable optional AI" checked={policy.ai_enabled} onChange={ai_enabled => change({ ai_enabled })} />
    <fieldset className="ai-options"><legend>Allowed hosting modes</legend>
      {keysOf(modeLabels).map(mode => <Option key={mode} label={modeLabels[mode]} checked={policy.allowed_modes.includes(mode)}
        locked={mode === "deterministic_only" ? "Always available" : undefined}
        onChange={value => change({ allowed_modes: value ? [...policy.allowed_modes, mode] : policy.allowed_modes.filter(m => m !== mode) })} />)}
    </fieldset>
    <Select label="Data residency" value={policy.allowed_residency} onChange={event => change({ allowed_residency: event.target.value as keyof typeof residencyLabels })}>
      {keysOf(residencyLabels).map(residency => <option key={residency} value={residency}>{residencyLabels[residency]}</option>)}
    </Select>
    <Option label="Allow environments to share approved private code" checked={policy.allow_private_code_egress} onChange={allow_private_code_egress => change({ allow_private_code_egress })} />
    <p className="ai-note">All providers must retain zero customer data.</p>
  </>;
}

function allowedModes(settings: AISettings) {
  const { organization, environment } = settings;
  return organization.allowed_modes.filter(mode => {
    if (mode === "deterministic_only") return true;
    if (!organization.ai_enabled) return false;
    if (mode === "dev_openrouter" && (!["development", "test"].includes(environment.environment_class) || organization.allowed_residency !== "us_eu")) return false;
    return organization.allowed_residency !== "customer_vpc_only" || mode === "byoc_self_hosted";
  });
}

const requiredJobs = {
  tier2_prompt_injection_enabled: ["indirect_injection_screen"],
  tier2_purpose_drift_enabled: ["purpose_alignment_check"],
  tier2_heuristic_fp_suppression_enabled: ["heuristic_fp_verify"],
  tier3_discovery_purpose_enabled: ["agent_discovery_verify", "agent_purpose_draft"],
  tier3_addon_audit_enabled: ["addon_semantic_audit"],
  tier3_security_agent_planner_enabled: ["security_agent_triage", "security_agent_remediate"],
} as const;

function qualificationLock(key: keyof typeof requiredJobs, env: AISettings["environment"], rows: AISettings["qualifications"]) {
  const tier2 = key.startsWith("tier2_");
  const modes = tier2 ? ["zasp_vpc_slm", "byoc_self_hosted", "dev_openrouter"] : ["privatelink_bedrock", "privatelink_vertex", "dev_openrouter"];
  if (!modes.includes(env.mode)) return "Requires another hosting mode";
  if (!tier2 && env.tier3_provider !== env.mode) return "Bind a matching reasoning provider";
  const model = tier2 ? env.tier2_profile : env.tier3_model_pin;
  if (!model) return tier2 ? "Choose a private model profile" : "Choose a pinned model";
  if (!requiredJobs[key].every(purpose => rows.some(r => r.qualified && r.provider === env.mode && r.model === model && r.purpose === purpose))) return "Requires model qualification";
}
export function EnvironmentFields({ settings, draft, change }: { settings: AISettings; draft: EnvironmentInput; change(patch: EnvironmentInput): void }) {
  const env = { ...settings.environment, ...draft };
  const choices = allowedModes(settings);
  const runtimeLock = !settings.organization.ai_enabled ? "Organization AI is off" : env.mode === "deterministic_only" || !choices.includes(env.mode) ? "Choose an allowed hosting mode" : undefined;
  const contentLock = env.collection_mode === "metadata_only" ? "Metadata-only collection" : !settings.organization.allow_private_code_egress ? "Organization policy" : undefined;
  function changeMode(mode: Mode) {
    const cleared = mode === "deterministic_only" ? Object.fromEntries([...keysOf(capabilityLabels), ...keysOf(consentLabels)].map(k => [k, false])) : {};
    change({ mode, ...cleared });
  }
  return <>
    <Select label="Environment hosting mode" value={env.mode} onChange={event => changeMode(event.target.value as Mode)}>
      {!choices.includes(env.mode) && <option value={env.mode} disabled>{modeLabels[env.mode]} (restricted)</option>}
      {choices.map(mode => <option key={mode} value={mode}>{modeLabels[mode]}</option>)}
    </Select>
    <fieldset className="ai-options"><legend>Model capabilities</legend>
      {keysOf(capabilityLabels).map(key => <Option key={key} label={capabilityLabels[key]} checked={env[key]} locked={env[key] ? undefined : runtimeLock ?? qualificationLock(key, env, settings.qualifications)} onChange={value => change({ [key]: value })} />)}
    </fieldset>
    <fieldset className="ai-options"><legend>Content permissions</legend>
      {keysOf(consentLabels).map(key => <Option key={key} label={consentLabels[key]} checked={env[key]} locked={env[key] ? undefined : key === "allow_redacted_summaries" ? runtimeLock : contentLock ?? runtimeLock} onChange={value => change({ [key]: value })} />)}
    </fieldset>
    <Field type="number" min={0} max={Number.MAX_SAFE_INTEGER} step={1} required label="Monthly budget (nano-credits)" value={Number.isNaN(env.monthly_budget_nano_credits) ? "" : env.monthly_budget_nano_credits}
      onChange={event => change({ monthly_budget_nano_credits: event.target.valueAsNumber })} />
    <details className="ai-bindings"><summary>Model and credential bindings</summary>
      <div className="ai-binding-fields">
        <Select label={bindingLabels.tier3_provider} value={env.tier3_provider} onChange={event => change({ tier3_provider: event.target.value })}>
          <option value="">Unbound</option>
          {(["privatelink_bedrock", "privatelink_vertex", "dev_openrouter"] as const).filter(mode => choices.includes(mode) || mode === env.tier3_provider).map(mode => <option value={mode} key={mode}>{modeLabels[mode]}</option>)}
        </Select>
        {(["tier2_profile", "tier3_model_pin"] as const).map(key => <Field label={bindingLabels[key]} key={key} autoComplete="off" maxLength={180} value={env[key]} onChange={event => change({ [key]: event.target.value })} />)}
        <Field label={bindingLabels.credential_reference} autoComplete="off" value={env.credential_reference} required={Boolean(env.credential_digest)} pattern="secret_ref_planner/.+" hint="Enter the scoped reference from your secret manager." onChange={event => change({ credential_reference: event.target.value })} />
        <Field label={bindingLabels.credential_digest} autoComplete="off" value={env.credential_digest} required={Boolean(env.credential_reference)} pattern="sha256:[a-f0-9]{64}" hint="Use sha256: followed by the 64-character lowercase digest." onChange={event => change({ credential_digest: event.target.value })} />
      </div>
    </details>
  </>;
}

export function Qualifications({ items }: { items: AISettings["qualifications"] }) {
  if (!items.length) return <p>No provider and model has qualified for a job in this scope. Model calls require a passing qualification.</p>;
  return <table className="data-table"><thead><tr><th scope="col">Job</th><th scope="col">Provider</th><th scope="col">Model</th><th scope="col">Qualification</th></tr></thead><tbody>
    {items.map(row => <tr key={JSON.stringify([row.provider, row.model, row.purpose])}><td>{row.purpose.replaceAll("_", " ")}</td><td>{row.provider}</td><td>{row.model}</td><td><Badge tone={row.qualified ? "success" : "warning"}>{row.qualified ? "Qualified" : "Unqualified"}</Badge></td></tr>)}
  </tbody></table>;
}
