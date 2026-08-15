package main

import (
	"encoding/json"
	"testing"
)

func TestSecurityGroupPolicyManifestIsExact(t *testing.T) {
	resource := Resource{Kind: KindSecurityGroupPolicy, Namespace: "zasp-m019-" + string(make([]byte, 0)), Name: "canary",
		Labels:          map[string]string{ProofLabelKey: ProofLabelValue, RunLabelKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ProfileSelectorLabelKey: ProfileSelectorLabelValue},
		SecurityGroupID: "sg-0123456789abcdef0"}
	resource.Namespace = "zasp-m019-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	resource.SpecDigest = resourceDigest(resource)
	data, err := resourceManifest(resource)
	if err != nil {
		t.Fatalf("resourceManifest: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document["apiVersion"] != "vpcresources.k8s.aws/v1beta1" || document["kind"] != "SecurityGroupPolicy" {
		t.Fatalf("document=%v", document)
	}
	spec := document["spec"].(map[string]any)
	selector := spec["podSelector"].(map[string]any)["matchLabels"].(map[string]any)
	if selector[ProofLabelKey] != ProofLabelValue || selector[RunLabelKey] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || selector[ProfileSelectorLabelKey] != ProfileSelectorLabelValue {
		t.Fatalf("selector=%v", selector)
	}
	groups := spec["securityGroups"].(map[string]any)["groupIds"].([]any)
	if len(groups) != 1 || groups[0] != "sg-0123456789abcdef0" {
		t.Fatalf("groups=%v", groups)
	}
}

func TestJobManifestChecksDirectAndProxyPaths(t *testing.T) {
	_, _, options := happyProof()
	life := lifecycle{options: options, namespace: NamespacePrefix + options.Marker, labels: map[string]string{ProofLabelKey: ProofLabelValue, RunLabelKey: options.Marker, ProfileSelectorLabelKey: ProfileSelectorLabelValue}}
	job := life.resources()[4]
	data, err := resourceManifest(job)
	if err != nil {
		t.Fatalf("resourceManifest: %v", err)
	}
	text := string(data)
	for _, expected := range []string{"DIRECT_URL", "PROXY_URL", "direct=false proxy=true body=", "terminationGracePeriodSeconds", options.DirectURL, options.ProxyURL} {
		if !contains(text, expected) {
			t.Fatalf("manifest missing %q", expected)
		}
	}
}

func TestParsesExactSecurityGroupPolicyAndFargateENI(t *testing.T) {
	policy := []byte(`{"apiVersion":"vpcresources.k8s.aws/v1beta1","kind":"SecurityGroupPolicy","metadata":{"name":"canary","namespace":"zasp-m019-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","uid":"uid-policy","labels":{"zasp.agentsec.dev/proof":"m0-19"},"annotations":{"zasp.agentsec.dev/spec":"digest","zasp.agentsec.dev/image":"","zasp.agentsec.dev/fargate-profile":""}},"spec":{"podSelector":{"matchLabels":{"zasp.agentsec.dev/proof":"m0-19"}},"securityGroups":{"groupIds":["sg-0123456789abcdef0"]}}}`)
	state, err := parseKubernetesObject(policy)
	if err != nil || state.Kind != KindSecurityGroupPolicy {
		t.Fatalf("state=%#v err=%v", state, err)
	}

	pod := []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"canary-pod","namespace":"zasp-m019-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","uid":"uid-pod","labels":{"zasp.agentsec.dev/proof":"m0-19","eks.amazonaws.com/fargate-profile":"zasp-disposable-profile"},"annotations":{"zasp.agentsec.dev/image":"` + CanaryImage + `","zasp.agentsec.dev/fargate-profile":"zasp-disposable-profile","fargate.amazonaws.com/pod-sg":"{\"eniId\":\"eni-0123456789abcdef0\",\"securityGroups\":[\"sg-0123456789abcdef0\"]}"},"ownerReferences":[{"apiVersion":"batch/v1","kind":"Job","name":"canary","uid":"uid-job","controller":true,"blockOwnerDeletion":true}]},"spec":{"nodeName":"fargate-node","serviceAccountName":"canary","containers":[{"image":"` + CanaryImage + `"}]},"status":{"phase":"Succeeded","containerStatuses":[{"imageID":"` + CanaryRuntimeImageAMD64 + `","state":{"terminated":{"exitCode":0}}}]}}`)
	state, err = parseKubernetesObject(pod)
	if err != nil || state.ENIID != "eni-0123456789abcdef0" || len(state.SecurityGroupIDs) != 1 || state.SecurityGroupIDs[0] != "sg-0123456789abcdef0" {
		t.Fatalf("state=%#v err=%v", state, err)
	}
}

func contains(value, fragment string) bool {
	return len(fragment) <= len(value) && stringIndex(value, fragment) >= 0
}
func stringIndex(value, fragment string) int {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return i
		}
	}
	return -1
}
