// Package evidencepacktest holds one captured evidence pack for tests of the
// packages that render and validate it.
package evidencepacktest

import "encoding/json"

const (
	Agent    = "pid_10000001-0000-4000-8000-000000000001"
	Finding  = "pid_30000001-0000-4000-8000-000000000001"
	Run      = "pid_40000001-0000-4000-8000-000000000001"
	Test     = "pid_60000001-0000-4000-8000-000000000001"
	TestRun  = "pid_70000001-0000-4000-8000-000000000001"
	Approver = "pid_50000002-0000-4000-8000-000000000002"
)

// Pack is the pack as the export capture builds it.
func Pack() json.RawMessage {
	return json.RawMessage(`{"schema_version":"agent-evidence-pack-v1",
"agent":{"summary":{"id":"` + Agent + `","name":"Support <agent>","kind":"agent","owner":"security","team":"platform","tags":[],"evidence_id":"pid_20000001-0000-4000-8000-000000000001","confidence_basis_points":9500,"first_seen":"2026-10-01T00:00:00Z","last_seen":"2026-11-10T00:00:00Z","observed_at":"2026-11-10T00:00:00Z","fresh_until":"2026-11-11T00:00:00Z","freshness_state":"fresh","version":1,"provider":"aws","source_kind":"aws_bedrock_agent","discovery":{"method":"provider_api","platform":"bedrock_agent","signals":["invoke:bedrock_model"]},"management_state":"managed","last_activity_at":"2026-11-09T00:00:00Z","activity_state":"active"},
 "sources":[{"integration_id":"pid_31000001-0000-4000-8000-000000000001","provider":"aws","source":"aws","source_identifier":"sha256:aa","snapshot_id":"pid_41000001-0000-4000-8000-000000000001","generation":1,"evidence_id":"pid_20000001-0000-4000-8000-000000000001","confidence_basis_points":9500,"observed_at":"2026-11-10T00:00:00Z","fresh_until":"2026-11-11T00:00:00Z","projection_version":1,"winning":true}],
 "evidence":[{"id":"pid_20000001-0000-4000-8000-000000000001","checksum":"sha256:bb","media_type":"application/json","schema_version":"raw_v1","parser_version":"parser_v1","tool_version":"tool_v1","collected_at":"2026-11-10T00:00:00Z","size_bytes":128}]},
"findings":{"status":"complete","items":[{"id":"` + Finding + `","source":"posture","rule":"ownerless_agent","title":"=Agent has no owner | review","severity":"high","status":"open","version":2,"created_at":"2026-11-01T00:00:00.000000Z","updated_at":"2026-11-02T00:00:00.000000Z","frameworks":[{"framework":"owasp_agentic_top10_2026","control":"ASI10","title":"Rogue Agents"}]}]},
"security_agent_runs":{"status":"partial","items":[{"id":"` + Run + `","security_agent_id":"pid_50000001-0000-4000-8000-000000000001","definition_version":1,"finding_id":"` + Finding + `","state":"remediated","requested_by":"pid_50000003-0000-4000-8000-000000000003","created_at":"2026-11-02T00:00:00.000000Z","updated_at":"2026-11-02T01:00:00.000000Z",
 "steps":[{"index":0,"action":"update_finding_response","authorization":"approval_required","state":"succeeded"}],
 "approvals":[{"id":"pid_42000001-0000-4000-8000-000000000001","step_id":"pid_41000002-0000-4000-8000-000000000002","state":"approved","requester_id":"pid_50000003-0000-4000-8000-000000000003","approver_id":"` + Approver + `","decided_at":"2026-11-02T00:30:00.000000Z","expires_at":"2026-11-03T00:00:00.000000Z"}]}]},
"red_team_tests":{"status":"complete","items":[{"id":"` + Test + `","version":1,"name":"Prompt injection sweep","target_kind":"agent_endpoint","categories":["prompt_injection","tool_abuse"],"enabled":true}]},
"red_team_runs":{"status":"complete","items":[{"id":"` + TestRun + `","definition_id":"` + Test + `","definition_version":1,"status":"complete","verdict":"fail","attempt":1,"queued_at":"2026-11-05T00:00:00.000000Z","completed_at":"2026-11-05T00:10:00.000000Z"}]}}`)
}
