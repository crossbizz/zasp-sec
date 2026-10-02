package apiserver

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSecurityAgentExistingTestDisplayArguments(t *testing.T) {
	const target = "pid_89000012-0000-4000-8000-000000000002"
	for _, action := range []string{"run_test", "rerun_test"} {
		for _, version := range []string{"1", "1000000", "0", "1000001", "1.5", `"1"`, "null"} {
			t.Run(action+"/"+version, func(t *testing.T) {
				raw := json.RawMessage(fmt.Sprintf(`{"target_id":%q,"expected_version":%s}`, target, version))
				value, err := decodeSecurityAgentActionArguments(action, raw)
				valid := version == "1" || version == "1000000"
				if valid != (err == nil) || valid && (value == nil || value.TargetID != target) {
					t.Fatalf("value=%+v error=%v", value, err)
				}
			})
		}
		for _, raw := range []string{"null", `{"target_id":"` + target + `"}`, `{"target_id":"` + target + `","expected_version":1,"prompt":"override"}`, `{"target_id":"` + target + `","expected_version":1,"expected_version":2}`} {
			if _, err := decodeSecurityAgentActionArguments(action, json.RawMessage(raw)); err == nil {
				t.Fatalf("%s accepted unsafe arguments: %s", action, raw)
			}
		}
	}
}
