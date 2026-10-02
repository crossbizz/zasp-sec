// Controlled comparison identity for component tests, never product authority.
import {createHash} from "node:crypto";
const hash=value=>createHash("sha256").update(value).digest("hex");
export function comparisonFixture(input) {
  return {schema_version:"red-team-target-comparison-v1",organization_id:input.organization_id,workspace_id:input.workspace_id,environment_id:input.environment_id,test_definition_id:input.definition_id,test_definition_version:input.definition_version,target_id:input.target_id,target_kind:input.target_kind,categories:[...input.categories],safety_digest:hash("controlled safety"),endpoint_digest:hash("controlled endpoint"),configuration_digest:hash("controlled configuration"),credential_binding_id:input.target_id,credential_binding_version:1,credential_binding_digest:hash("controlled credential binding")};
}
