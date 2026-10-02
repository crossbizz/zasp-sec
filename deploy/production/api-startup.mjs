import { isDeepStrictEqual } from "node:util";

// Startup loads are authority too: env entries alone cannot constrain a shell.
export function validateAPIStartup(container, auditExportsEnabled) {
  const reject = () => { throw new Error("release rejected: API startup"); };
  if (typeof auditExportsEnabled !== "boolean" || !isDeepStrictEqual(container?.command, ["/bin/sh", "-ec"]) || !Array.isArray(container.args) || container.args.length !== 1 || typeof container.args[0] !== "string") reject();
  const loads = [
    ["POSTGRES_DSN", "postgres-dsn"],
    ["SECURITY_AGENT_POSTGRES_DSN", "security-agent-postgres-dsn"],
    ["STYTCH_PROJECT_ID", "stytch-project-id"],
    ["STYTCH_SECRET", "stytch-secret"],
    ["STYTCH_WEBHOOK_SECRET", "stytch-webhook-secret"],
    ["STYTCH_PUBLIC_TOKEN", "stytch-public-token"],
    ["STYTCH_ORGANIZATION_ID", "stytch-organization-id"],
    ["WORKFLOW_SIGNING_KEY", "workflow-signing-key"],
    ["TOKEN_REVEAL_KEY", "token-reveal-key"],
  ];
  if (auditExportsEnabled) loads.push(["AUDIT_EXPORT_CURSOR_SIGNING_KEY", "audit-export-cursor-signing-key"]);
  const expected = [...loads.map(([env, file]) => `export ZASP_${env}="$(cat /var/run/secrets/zasp/${file})"`), "exec /app/agentsec-api"];
  if (!isDeepStrictEqual(container.args[0].split("\n").map(line => line.trim()).filter(Boolean), expected)) reject();
}
