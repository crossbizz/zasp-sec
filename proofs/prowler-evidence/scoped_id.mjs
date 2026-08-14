import { createHash } from "node:crypto";

const organizationIdPattern = /^org_[a-z0-9]{16}$/;
const namespacePattern = /^[a-z][a-z0-9_]{0,63}$/;

export function validateOrganizationId(value) {
  if (typeof value !== "string" || !organizationIdPattern.test(value)) {
    throw new TypeError("organization_id is invalid");
  }
  return value;
}

export function canonicalScopedSourceId(organizationId, provider, kind, sourceId) {
  const scope = validateOrganizationId(organizationId);
  if (typeof provider !== "string" || !namespacePattern.test(provider)) {
    throw new TypeError("provider is invalid");
  }
  if (typeof kind !== "string" || !namespacePattern.test(kind)) {
    throw new TypeError("kind is invalid");
  }
  if (
    typeof sourceId !== "string" ||
    sourceId.length === 0 ||
    Buffer.byteLength(sourceId, "utf8") > 4_096 ||
    hasControlCharacter(sourceId)
  ) {
    throw new TypeError("source_id is invalid");
  }

  const digest = createHash("sha256")
    .update(JSON.stringify([scope, provider, kind, sourceId]))
    .digest("hex");
  return `${scope}:${provider}:${kind}:${digest}`;
}

function hasControlCharacter(value) {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint <= 0x1f || codePoint === 0x7f) return true;
  }
  return false;
}
