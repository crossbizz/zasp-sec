package zasp.runtime

import rego.v1

default allow := false

allow if {
	input.organization_id == "org_aaaaaaaaaaaaaaaa"
	input.workspace_id == "wsp_aaaaaaaaaaaaaaaa"
	input.subject == "agent:demo"
	input.action == "tool:read"
	input.resource == "resource:approved"
	input.environment == "test"
}
