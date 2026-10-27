package providercollection

import (
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"strings"
	"testing"
)

func TestNodePlacementClosedProviderSchema(t *testing.T) {
	const posture = `{"human_credential":false,"credential_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","untrusted_input":false,"production_write":false,"shell_execution":true,"production_credential":true,"unrestricted_egress":false,"sensitive_data_reach":false,"unapproved_remote_tool":false,"destructive_tool":false,"runtime_control":true,"production_agent":true,"runtime_policy_supported":true,"host_filesystem":false,"privileged":false,"cicd_write":false,"production_secret_reach":false,"credential_active":true}`
	const placement = `{"schema":"kubernetes-agent-placement-v1","cluster_uid":"10000000-0000-4000-8000-000000000099","controller_uid":"10000000-0000-4000-8000-000000000001","observed_at":"2026-10-17T12:00:00Z","placements":[{"replicaset_uid":"10000000-0000-4000-8000-000000000011","pod_uid":"10000000-0000-4000-8000-000000000021","node_uid":"10000000-0000-4000-8000-000000000031","boot_id":"10000000-0000-4000-8000-000000000041"}]}`
	for _, mode := range []string{"valid", "unknown_field", "duplicate_tuple", "null", "zero_uid"} {
		t.Run(mode, func(t *testing.T) {
			value := placement
			switch mode {
			case "unknown_field":
				value = strings.Replace(value, `"schema":`, `"covered":true,"schema":`, 1)
			case "duplicate_tuple":
				var obj map[string]json.RawMessage
				_ = json.Unmarshal([]byte(value), &obj)
				var rows []json.RawMessage
				_ = json.Unmarshal(obj["placements"], &rows)
				rows = append(rows, rows[0])
				obj["placements"], _ = json.Marshal(rows)
				raw, _ := json.Marshal(obj)
				value = string(raw)
			case "null":
				value = "null"
			case "zero_uid":
				value = strings.Replace(value, "10000000-0000-4000-8000-000000000031", "00000000-0000-0000-0000-000000000000", 1)
			}
			entity := json.RawMessage(`{"id":"pid_44600000-0000-4000-8000-000000000001","kind":"kubernetes_agent","source_native_id":"kubernetes:deployment:10000000-0000-4000-8000-000000000001","display_name":"default/agent","stable_fields":{"api_group":"apps","api_version":"v1","cluster":"api.example.com/production","name":"agent","namespace":"default","resource_kind":"Deployment","service_account":"agent"},"attributes":{"namespaced":true,"posture":` + posture + `,"placement":` + value + `}}`)
			cursor := collection.Cursor{Provider: collection.ProviderKubernetes, Version: "cursor_v1", Value: "complete"}
			_, err := NewPage(collection.ProviderKubernetes, collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "api.example.com/production"}, cursor, true, []json.RawMessage{entity}, nil)
			if (err == nil) != (mode == "valid") {
				t.Fatal("closed placement schema admission mismatch", mode, err)
			}
		})
	}
}
