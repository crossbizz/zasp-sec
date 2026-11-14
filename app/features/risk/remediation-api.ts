import type { SecurityAgentsAPI } from "../securityagents/SecurityAgentsView";
import { createWorkflowMutationAttempt } from "../workflows/api";
import type { FindingRemediationAPI, RemediationAgent } from "./FindingRemediation";

type RemediationSecurityAgents = Pick<SecurityAgentsAPI, "listSecurityAgents" | "getSecurityAgentActivation" | "runSecurityAgent">;

// createFindingRemediationAPI starts a provider remediation through the
// existing Security Agent API: it lists the Security Agents whose only
// allowed action is the remediation's action, keeps those with supervised
// execution enabled, and starts a run on the chosen one with the finding as
// its trigger. It adds no endpoint of its own.
export function createFindingRemediationAPI(agents: RemediationSecurityAgents): FindingRemediationAPI {
  return {
    async listRemediationAgents(action, signal) {
      const page = await agents.listSecurityAgents({ limit: 100 }, signal);
      const result: RemediationAgent[] = [];
      // The first ten candidates are enough to offer a choice.
      for (const agent of page.items.filter((item) => item.enabled && item.allowed_actions.length === 1 && item.allowed_actions[0] === action).slice(0, 10)) {
        const activation = await agents.getSecurityAgentActivation(agent.id, signal);
        const environmentID = agent.environment_ids[0];
        if (activation.enabled && activation.activation === "supervised" && environmentID) result.push({ id: agent.id, name: agent.name, version: activation.version, environmentID });
      }
      return result;
    },
    async startRemediation(agent, findingID, remediation) {
      const receipt = await agents.runSecurityAgent(agent.id, agent.version, { environment_id: agent.environmentID, trigger_kind: "finding", trigger_id: findingID, remediation }, createWorkflowMutationAttempt());
      return { runID: receipt.value.id, state: receipt.value.state };
    },
  };
}
