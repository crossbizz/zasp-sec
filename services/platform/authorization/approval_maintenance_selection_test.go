package authorization

import (
	"strings"
	"testing"
)

func TestApprovalMaintenanceProfileStateClosedGrammar(t *testing.T) {
	pin := strings.Repeat("a", 64)
	good := `{"active":false,"checksum":"` + pin + `","catalog_ready":true}`
	state, err := decodeApprovalMaintenanceProfileState([]byte(good))
	if err != nil || state.Active || !state.CatalogReady || state.Checksum != pin {
		t.Fatal("exact native metadata refused")
	}
	for _, bad := range []string{
		strings.Replace(good, `false`, `null`, 1), strings.Replace(good, `true`, `null`, 1),
		strings.Replace(good, `"active"`, `"Active"`, 1), strings.Replace(good, `"checksum"`, `"Checksum"`, 1),
		strings.Replace(good, `"active":false`, `"active":false,"active":true`, 1),
		strings.Replace(good, `"active":false,`, "", 1),
		strings.Replace(good, `"catalog_ready":true`, `"catalog_ready":1`, 1),
		strings.Replace(good, pin, strings.Repeat("A", 64), 1),
		strings.TrimSuffix(good, "}") + `,"extra":false}`, good + `{}`, `[]`,
	} {
		if _, err := decodeApprovalMaintenanceProfileState([]byte(bad)); err == nil {
			t.Fatal("malformed profile metadata admitted")
		}
	}
}
func TestApprovalOriginDispatchClosedOriginalOperations(t *testing.T) {
	want := map[WorkerOperation]string{
		"finding.planning.admit":   `SELECT zasp_approval_maintenance.admit_with_origin('finding78',$1::jsonb)`,
		"test74.planning.admit":    `SELECT zasp_approval_maintenance.admit_with_origin('test74',$1::jsonb)`,
		"ordered68.planning.admit": `SELECT zasp_approval_maintenance.admit_with_origin('ordered68',$1::jsonb)`,
		"ordered68.progress":       `SELECT zasp_approval_maintenance.admit_with_origin('ordered68_progress',$1::jsonb)`,
	}
	for op, sql := range want {
		spec, exists := workerOperation(op)
		got, ok := approvalOriginStatement(op)
		if !exists || spec.purpose != WorkerForward || !ok || got != sql {
			t.Fatal("original forward operation association changed", op)
		}
	}
	for _, op := range []WorkerOperation{FindingCleanup, "finding.planning.load", "ordered68.cleanup", "ordered68.progress ", "test74.planning.settle", "finding.planning.Admit"} {
		if sql, ok := approvalOriginStatement(op); ok || sql != "" {
			t.Fatal("unaffected or compensation operation redirected", op)
		}
	}
}
