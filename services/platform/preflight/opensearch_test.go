package preflight

import (
	"reflect"
	"strings"
	"testing"
)

func TestOpenSearchFootprintUsesActualContainerPhaseAndLiteralBindings(t *testing.T) {
	for _, mode := range []string{"legacy runtime", "current session", "inventory", "missing index", "indirect env", "envFrom", "foreign endpoint", "foreign image", "unsupported stage", "compatibility cannot v2", "unknown phase", "wrong pod UID", "wrong service account", "wrong purpose"} {
		t.Run(mode, func(t *testing.T) {
			c := OpenSearchConfig{Endpoint: "https://vpc-product.us-west-2.es.amazonaws.com", SessionSearchPhase: "compatibility", Container: "runtime-index", Image: "example/worker@sha256:" + strings.Repeat("a", 64)}
			selected := AWSSelectedWorkload{Purpose: `aws_iam_role.runtime["index"]`, PodName: "runtime-index-fixture", PodUID: "11111111-1111-4111-8111-111111111111"}
			o := openSearchWorkload{Namespace: "agentsec", PodName: selected.PodName, PodUID: selected.PodUID, ServiceAccount: "zasp-runtime-index", Purpose: `aws_iam_role.runtime["index"]`, Container: c.Container, Image: c.Image, Env: map[string]string{"ZASP_WORKER_MODE": "runtime-index", "ZASP_RUNTIME_STAGE_VERSION": "runtime-index-v1", "ZASP_OPENSEARCH_ENDPOINT": c.Endpoint, "ZASP_OPENSEARCH_INDEX": "zasp-runtime-events-v1", "ZASP_RUNTIME_SESSION_INDEX": "zasp-runtime-sessions-v1"}}
			want := []string{"zasp-runtime-events-v1", "zasp-runtime-sessions-v1"}
			valid := true
			switch mode {
			case "current session":
				c.SessionSearchPhase = "precision-intake"
				o.Env["ZASP_RUNTIME_STAGE_VERSION"] = "runtime-index-v2"
				o.Env["ZASP_RUNTIME_SESSION_INDEX"] = "zasp-runtime-sessions-v2"
				want[1] = "zasp-runtime-sessions-v2"
			case "inventory":
				o.Purpose = "aws_iam_role.projection_search"
				selected.Purpose = o.Purpose
				o.ServiceAccount = "zasp-projection-search"
				c.Container = "projection-search"
				o.Container = c.Container
				o.Env = map[string]string{"ZASP_WORKER_MODE": "projection-search", "ZASP_OPENSEARCH_ENDPOINT": c.Endpoint, "ZASP_OPENSEARCH_INDEX": "zasp-inventory-v1"}
				want = []string{"zasp-inventory-v1"}
			case "missing index":
				delete(o.Env, "ZASP_RUNTIME_SESSION_INDEX")
				valid = false
			case "indirect env":
				o.IndirectEnv = true
				valid = false
			case "envFrom":
				o.EnvFrom = true
				valid = false
			case "foreign endpoint":
				o.Env["ZASP_OPENSEARCH_ENDPOINT"] = "https://vpc-foreign.us-west-2.es.amazonaws.com"
				valid = false
			case "foreign image":
				o.Image = "example/worker@sha256:" + strings.Repeat("b", 64)
				valid = false
			case "unsupported stage":
				o.Env["ZASP_RUNTIME_STAGE_VERSION"] = "runtime-index-v999"
				valid = false
			case "compatibility cannot v2":
				o.Env["ZASP_RUNTIME_SESSION_INDEX"] = "zasp-runtime-sessions-v2"
				valid = false
			case "wrong pod UID":
				o.PodUID = "22222222-2222-4222-8222-222222222222"
				valid = false
			case "wrong service account":
				o.ServiceAccount = "foreign"
				valid = false
			case "wrong purpose":
				o.Purpose = "aws_iam_role.worker"
				valid = false
			case "unknown phase":
				c.SessionSearchPhase = "future"
				valid = false
			}
			got, e := deriveOpenSearchFootprint(c, selected, o)
			if valid {
				if e != nil || !reflect.DeepEqual(got, want) {
					t.Fatal("actual active footprint was not observed")
				}
			} else if e == nil || got != nil {
				t.Fatal("unobserved or unsupported container authority accepted")
			}
		})
	}
}
