package kubernetesdiscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// A workload's owner and team are read from its annotations and labels, the
// annotation first; its creation time is kept only beside an owner. A value
// that is not an identity is dropped, managed-by is not an owner, and the
// attributes stay canonical JSON.
func TestKubernetesCollectionAPIReadsOwnerAndTeamFromAnnotationsAndLabels(t *testing.T) {
	t.Parallel()
	body := `{"apiVersion":"apps/v1","kind":"DeploymentList","metadata":{"continue":""},"items":[` +
		`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"41000000-0000-4000-8000-000000000001","namespace":"support","name":"annotated","creationTimestamp":"2026-08-03T10:15:00Z","labels":{"zasp.ai/entity-kind":"agent","owner":"label-owner","team":"support-eng"},"annotations":{"zasp.ai/owner":"dana.reyes@example.com"}}},` +
		`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"41000000-0000-4000-8000-000000000002","namespace":"support","name":"labelled","creationTimestamp":"2026-08-04T11:00:00+02:00","labels":{"zasp.ai/entity-kind":"agent","owner":"platform-team","app.kubernetes.io/managed-by":"Helm"},"annotations":{"zasp.ai/team":"Platform Engineering"}}},` +
		`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"41000000-0000-4000-8000-000000000003","namespace":"support","name":"unattributed","creationTimestamp":"2026-08-05T12:00:00Z","labels":{"zasp.ai/entity-kind":"agent","app.kubernetes.io/managed-by":"Helm"},"annotations":{"owner":"Ask Dana in the platform channel","team":" padded "}}}]}`
	roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{{status: http.StatusOK, body: body}}}
	api, err := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}
	request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Cursor: nextKubernetesPageCursor(subject, "deployments", 7, "start"), Page: 7, RemainingItems: 8, RemainingRelationships: 64, RemainingBytes: 1 << 20}
	page, err := api.FetchCollectionPage(context.Background(), []byte("kubernetes-bearer-secret-value"), request)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{
		"support/annotated":    {"created_by": "dana.reyes@example.com", "created_by_source": "annotation", "created_at": "2026-08-03T10:15:00Z", "owning_team": "support-eng"},
		"support/labelled":     {"created_by": "platform-team", "created_by_source": "label", "created_at": "2026-08-04T09:00:00Z", "owning_team": "Platform Engineering"},
		"support/unattributed": {},
	}
	seen := 0
	for _, raw := range page.Entities {
		var entity struct {
			Kind        string          `json:"kind"`
			DisplayName string          `json:"display_name"`
			Attributes  json.RawMessage `json:"attributes"`
		}
		if json.Unmarshal(raw, &entity) != nil || entity.Kind != "kubernetes_agent" {
			t.Fatalf("entity = %s", raw)
		}
		expected, known := want[entity.DisplayName]
		if !known {
			t.Fatalf("unexpected agent %q", entity.DisplayName)
		}
		seen++
		var attributes map[string]any
		if err := json.Unmarshal(entity.Attributes, &attributes); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"created_by", "created_by_source", "created_at", "owning_team"} {
			value, present := attributes[name]
			if wanted, attributed := expected[name]; present != attributed || attributed && value != wanted {
				t.Fatalf("%s %s = %v (present %t), want %q", entity.DisplayName, name, value, present, wanted)
			}
		}
		// encoding/json writes a map with sorted keys: the collector's own
		// encoding must already be that.
		canonical, _ := json.Marshal(attributes)
		if !bytes.Equal(canonical, entity.Attributes) {
			t.Fatalf("%s attributes are not canonical: %s", entity.DisplayName, entity.Attributes)
		}
		if bytes.Contains(entity.Attributes, []byte("Helm")) || bytes.Contains(entity.Attributes, []byte("Ask Dana")) {
			t.Fatalf("%s kept a value that is not an identity: %s", entity.DisplayName, entity.Attributes)
		}
	}
	if seen != len(want) {
		t.Fatalf("agents = %d", seen)
	}
}
