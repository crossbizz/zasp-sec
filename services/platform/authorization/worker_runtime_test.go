package authorization

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Runtime source ancestry must add every source device to both current-user
// and task authorization, not reduce the existing test/target permissions.
func TestWorkerRuntimeTestExactCheckShape(t *testing.T) {
	for _, operation := range []WorkerOperation{"test74.planning.load", "test74.effect.reserve", "test74.adapter.start"} {
		for _, protocol := range []string{"retained74-session-latest", "configured77-event-occurrence"} {
			t.Run(string(operation)+"/"+protocol, func(t *testing.T) {
				spec, ok := workerOperation(operation)
				if !ok {
					t.Fatal("existing operation absent")
				}
				permission := "view"
				if spec.testExecution {
					permission = "run_tests"
				}
				checks := []map[string]string{
					{"kind": "security_agent", "id": "definition", "permission": "manage_workflows"},
					{"kind": "security_agent_run", "id": "run", "permission": "manage_workflows"},
					{"kind": "test", "id": "test", "permission": permission},
					{"kind": "agent", "id": "target", "permission": permission},
					{"kind": "session", "id": "source-session", "permission": "investigate_sessions"},
					{"kind": "agent", "id": "source-agent", "permission": "view"},
					{"kind": "gateway_device", "id": "device-a", "permission": "view"},
				}
				body := map[string]any{"definition_id": "definition", "run_id": "run", "test_id": "test", "target_id": "target", "target_kind": "agent", "trigger_kind": "runtime_decision", "trigger_id": "source-event-or-session", "runtime_protocol": protocol, "source_session_id": "source-session", "source_agent_id": "source-agent", "source_device_ids": []string{"device-a"}, "runtime_digest": strings.Repeat("d", 64), "checks": checks}
				if protocol == "retained74-session-latest" {
					body["trigger_id"] = "source-session"
				}
				decode := func(v map[string]any) workerFacts {
					raw, _ := json.Marshal(v)
					var f workerFacts
					if json.Unmarshal(raw, &f) != nil {
						t.Fatal("fixture encoding")
					}
					return f
				}
				if !workerCheckShape(spec, decode(body)) {
					t.Fatal("complete runtime source check set refused")
				}
				original, _ := json.Marshal(body)
				for _, mutate := range []func(map[string]any){
					func(v map[string]any) { delete(v, "source_device_ids") },
					func(v map[string]any) { v["source_device_ids"] = []string{"device-a", "device-a"} },
					func(v map[string]any) { v["source_session_id"] = "other-session" },
					func(v map[string]any) { v["source_agent_id"] = "other-agent" },
					func(v map[string]any) { v["runtime_protocol"] = "caller-selected" },
					func(v map[string]any) { v["runtime_digest"] = "" },
					func(v map[string]any) { v["checks"] = checks[:6] },
					func(v map[string]any) { v["checks"] = append(append([]map[string]string{}, checks...), checks[6]) },
				} {
					var changed map[string]any
					_ = json.Unmarshal(original, &changed)
					mutate(changed)
					if workerCheckShape(spec, decode(changed)) {
						t.Fatal("altered runtime ancestry accepted")
					}
				}
				if protocol == "configured77-event-occurrence" {
					devices := make([]string, 101)
					checks = checks[:6]
					for i := range devices {
						devices[i] = fmt.Sprintf("pid_00000001-0000-4000-8000-%012d", i+1)
						checks = append(checks, map[string]string{"kind": "gateway_device", "id": devices[i], "permission": "view"})
					}
					body["source_device_ids"], body["checks"] = devices, checks
					if !workerCheckShape(spec, decode(body)) {
						t.Fatal("native100-event plus independent-anchor device bound refused")
					}
					body["source_device_ids"], body["checks"] = devices[:100], checks[:106]
					if !workerCheckShape(spec, decode(body)) {
						t.Fatal("native100-device boundary refused")
					}
					body["source_device_ids"], body["checks"] = append(append([]string{}, devices...), "pid_00000001-0000-4000-8000-000000000102"), append(append([]map[string]string{}, checks...), map[string]string{"kind": "gateway_device", "id": "pid_00000001-0000-4000-8000-000000000102", "permission": "view"})
					if workerCheckShape(spec, decode(body)) {
						t.Fatal("more than count100 plus anchor accepted")
					}
					body["source_device_ids"], body["checks"] = devices, checks
					devices[99], devices[0] = devices[0], devices[99]
					if workerCheckShape(spec, decode(body)) {
						t.Fatal("noncanonical runtime device order accepted")
					}
				}
			})
		}
	}
}
