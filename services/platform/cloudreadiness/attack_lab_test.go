package cloudreadiness

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func attackLabPrerequisiteDocuments(t *testing.T) AttackLabKubernetesDocuments {
	t.Helper()
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	raw, _ := json.Marshal(string(ca))
	return AttackLabKubernetesDocuments{
		Version:             []byte(`{"major":"1","minor":"34+"}`),
		Namespace:           []byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"zasp-attack-lab","uid":"223e4567-e89b-12d3-a456-426614174000","labels":{"kubernetes.io/metadata.name":"zasp-attack-lab","zasp.io/execution":"attack-lab"}},"status":{"phase":"Active"}}`),
		ServiceAccount:      []byte(`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"agentsec-attack-lab-runner","namespace":"zasp-attack-lab","uid":"323e4567-e89b-12d3-a456-426614174000","labels":{"zasp.io/execution":"attack-lab"},"annotations":{"eks.amazonaws.com/role-arn":"arn:aws:iam::123456789012:role/zasp-production-attack-lab-runner-test"}},"automountServiceAccountToken":false}`),
		ProxyCA:             []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"agentsec-attack-lab-proxy-ca","namespace":"zasp-attack-lab","uid":"423e4567-e89b-12d3-a456-426614174000"},"data":{"proxy-ca.crt":` + string(raw) + `}}`),
		SecurityGroupPolicy: []byte(`{"apiVersion":"vpcresources.k8s.aws/v1beta1","kind":"SecurityGroupPolicy","metadata":{"name":"agentsec-attack-lab-egress","namespace":"zasp-attack-lab","uid":"623e4567-e89b-12d3-a456-426614174000"},"spec":{"podSelector":{"matchLabels":{"zasp.io/execution":"attack-lab"}},"securityGroups":{"groupIds":["sg-1234abcd"]}}}`),
	}
}
func TestAttackLabOriginalFiveKubernetesPrerequisites(t *testing.T) {
	for _, mode := range []string{"observed", "numeric-version-existing-wrapper", "namespace-missing", "namespace-label", "namespace-inactive", "product-role", "automount", "product-secret", "pull-secret", "extra-annotation", "invalid-ca", "wrong-sgp-selector", "extra-sgp-group", "sgp-expression"} {
		t.Run(mode, func(t *testing.T) {
			docs := attackLabPrerequisiteDocuments(t)
			mutate := func(raw *[]byte, f func(map[string]any)) {
				var v map[string]any
				if json.Unmarshal(*raw, &v) != nil {
					t.Fatal("fixture invalid")
				}
				f(v)
				*raw, _ = json.Marshal(v)
			}
			switch mode {
			case "numeric-version-existing-wrapper":
				docs.Version = []byte(`{"major":"1","minor":"30"}`)
			case "namespace-missing":
				docs.Namespace = nil
			case "namespace-label":
				mutate(&docs.Namespace, func(v map[string]any) {
					v["metadata"].(map[string]any)["labels"] = map[string]string{"zasp.io/execution": "foreign"}
				})
			case "namespace-inactive":
				mutate(&docs.Namespace, func(v map[string]any) { v["status"].(map[string]any)["phase"] = "Terminating" })
			case "product-role":
				mutate(&docs.ServiceAccount, func(v map[string]any) {
					v["metadata"].(map[string]any)["annotations"] = map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/product-worker"}
				})
			case "automount":
				mutate(&docs.ServiceAccount, func(v map[string]any) { v["automountServiceAccountToken"] = true })
			case "product-secret":
				mutate(&docs.ServiceAccount, func(v map[string]any) { v["secrets"] = []any{map[string]string{"name": "product"}} })
			case "pull-secret":
				mutate(&docs.ServiceAccount, func(v map[string]any) { v["imagePullSecrets"] = []any{map[string]string{"name": "product"}} })
			case "extra-annotation":
				mutate(&docs.ServiceAccount, func(v map[string]any) {
					v["metadata"].(map[string]any)["annotations"].(map[string]any)["eks.amazonaws.com/audience"] = "other"
				})
			case "invalid-ca":
				mutate(&docs.ProxyCA, func(v map[string]any) { v["data"] = map[string]string{"proxy-ca.crt": "invalid"} })
			case "wrong-sgp-selector":
				mutate(&docs.SecurityGroupPolicy, func(v map[string]any) {
					v["spec"].(map[string]any)["podSelector"] = map[string]any{"matchLabels": map[string]string{"zasp.io/execution": "foreign"}}
				})
			case "extra-sgp-group":
				mutate(&docs.SecurityGroupPolicy, func(v map[string]any) {
					v["spec"].(map[string]any)["securityGroups"] = map[string]any{"groupIds": []string{"sg-1234abcd", "sg-foreign"}}
				})
			case "sgp-expression":
				mutate(&docs.SecurityGroupPolicy, func(v map[string]any) {
					v["spec"].(map[string]any)["podSelector"].(map[string]any)["matchExpressions"] = []any{map[string]any{"key": "foreign", "operator": "Exists"}}
				})
			}
			accepted := AttackLabKubernetesPrerequisites(docs, "sg-1234abcd", "arn:aws:iam::123456789012:role/zasp-production-attack-lab-runner-test")
			expected := mode == "observed" || mode == "numeric-version-existing-wrapper"
			if accepted != expected {
				t.Fatal("original complete prerequisite acceptance or refusal differs")
			}
		})
	}
}
