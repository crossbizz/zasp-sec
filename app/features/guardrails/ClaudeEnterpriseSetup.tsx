"use client";

import { useState } from "react";

import { Button, Card, Field } from "../../components/ui";

const integrationProductID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const dnsLabel = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

function receiverHostname(value: string): boolean {
  const labels = value.split(".");
  const suffix = labels[labels.length - 1];
  return value.length <= 253 && labels.length >= 2 && labels.every(label => dnsLabel.test(label)) &&
    /^[a-z]/i.test(suffix) && !/\.(localhost|local|internal|home\.arpa)$/i.test(value);
}

export function ClaudeEnterpriseSetup({ openAPIAccess, openPolicies }: {
  openAPIAccess?: () => void;
  openPolicies?: () => void;
}) {
  const [host, setHost] = useState("");
  const [integrationID, setIntegrationID] = useState("");
  const hostValid = receiverHostname(host);
  const idValid = integrationProductID.test(integrationID);

  return <Card title={<h2>Claude Enterprise inference hooks</h2>}>
    <p>Claude can ask Zasp for a verdict before processing a prompt or tool frame. A Zasp deployment operator and a Claude Enterprise administrator configure the two ends.</p>
    <details>
      <summary>Set up Claude Enterprise</summary>
      <ol>
        <li><strong>Provision a dedicated credential.</strong> Ask a Zasp token administrator to create a token for this Environment with <code>decide_actions</code> as its only permission. Leave it unbound to any agent or runtime session. {openAPIAccess && <Button onClick={openAPIAccess}>Open API Access</Button>}</li>
        <li><strong>Prepare the receiver.</strong> Choose a stable integration product ID and a public HTTPS hostname for the Zasp API. Use these values to build the callback URL for the Claude administrator.
          <Field label="Public receiver hostname" value={host} onChange={event => setHost(event.target.value)} maxLength={253} placeholder="hooks.company.com" autoComplete="off" spellCheck={false} aria-invalid={!!host && !hostValid} error={host && !hostValid ? "Enter the public DNS hostname without a scheme, port or path." : undefined} />
          <Field label="Integration product ID" value={integrationID} onChange={event => setIntegrationID(event.target.value)} maxLength={100} placeholder="pid_…" autoComplete="off" spellCheck={false} aria-invalid={!!integrationID && !idValid} error={integrationID && !idValid ? "Enter the integration’s canonical pid_ UUID." : undefined} />
          {hostValid && idValid && <pre aria-label="Claude Enterprise callback URL">{`https://${host.toLowerCase()}/api/v1/runtime/provider-hooks/claude-enterprise/${integrationID}`}</pre>}
        </li>
        <li><strong>Configure the external provider.</strong> In Claude Enterprise inference-hook settings, enter the callback URL and start in shadow mode. Transfer the provider tenant ID and signing secret to the deployment operator through your secret manager. <a href="https://platform.claude.com/docs/en/manage-claude/inference-hooks-configuration" target="_blank" rel="noreferrer">Anthropic setup instructions</a></li>
        <li><strong>Mount the receiver configuration.</strong> The operator mounts an owner-controlled, read-only secret file containing the provider details, the Zasp scope and integration IDs, the credential ID and token, and an independent 32-byte reference key encoded in Base64. Set <code>ZASP_CLAUDE_ENTERPRISE_HOOK_FILE</code> to its absolute path, disable request-body capture and restart the API replicas. The file format is in <code>docs/operations/claude-enterprise-hooks.md</code>.</li>
        <li><strong>Verify before enforcement.</strong> Start the Environment’s runtime policy in monitor mode. Run Claude’s connection test, then send a harmless prompt and tool request from Claude. Compare the Zasp decision with the provider’s observation. In staging, exercise the organization’s timeout and failure policy. For an enforced test block, check the target independently and compare it with an allowed control before expanding the rollout. {openPolicies && <Button onClick={openPolicies}>Open runtime policies</Button>}</li>
      </ol>
    </details>
  </Card>;
}
