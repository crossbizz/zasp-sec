package preflight

import (
	"context"
	"encoding/json"
	"strings"
)

type openSearchWorkloadReader interface {
	OpenSearchWorkload(context.Context, AWSSelectedWorkload, string) (openSearchWorkload, error)
}

func openSearchSubject(purpose string) (string, string) {
	for _, v := range compiledAWSRoleRequirements {
		if v.purpose == purpose && v.trustClass == "irsa" {
			parts := strings.Split(v.subject, ":")
			if len(parts) == 4 {
				return parts[2], parts[3]
			}
		}
	}
	return "", ""
}
func exactOpenSearchKeys(raw json.RawMessage, known ...string) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, false
	}
	for k := range object {
		for _, name := range known {
			if strings.EqualFold(k, name) && k != name {
				return nil, false
			}
		}
	}
	return object, true
}
func (r *awsKubernetesIdentityReader) OpenSearchWorkload(ctx context.Context, selected AWSSelectedWorkload, container string) (openSearchWorkload, error) {
	var result openSearchWorkload
	namespace, sa := openSearchSubject(selected.Purpose)
	if namespace == "" || !dnsPattern.MatchString(selected.PodName) || len(selected.PodUID) != 36 || !dnsPattern.MatchString(container) {
		return result, &awsKubernetesOutcomeError{outcome: "binding_mismatch"}
	}
	b, e := r.get(ctx, "/api/v1/namespaces/"+namespace+"/pods/"+selected.PodName)
	if e != nil {
		return result, e
	}
	defer clear(b)
	var pod kubernetesIdentityObject
	if json.Unmarshal(b, &pod) != nil {
		return result, &awsKubernetesOutcomeError{outcome: "malformed"}
	}
	if pod.APIVersion != "v1" || pod.Kind != "Pod" || pod.Metadata.Namespace != namespace || pod.Metadata.Name != selected.PodName || pod.Metadata.UID != selected.PodUID || pod.Metadata.DeletionTimestamp != nil || pod.Spec.ServiceAccountName != sa || pod.Status.Phase != "Running" {
		return result, &awsKubernetesOutcomeError{outcome: "binding_mismatch"}
	}
	top, ok := exactOpenSearchKeys(b, "apiVersion", "kind", "metadata", "spec", "status")
	if !ok {
		return result, &awsKubernetesOutcomeError{outcome: "malformed"}
	}
	spec, ok := exactOpenSearchKeys(top["spec"], "containers", "serviceAccountName", "volumes")
	if !ok {
		return result, &awsKubernetesOutcomeError{outcome: "malformed"}
	}
	var containers []json.RawMessage
	if json.Unmarshal(spec["containers"], &containers) != nil || len(containers) < 1 || len(containers) > 32 {
		return result, &awsKubernetesOutcomeError{outcome: "malformed"}
	}
	found := false
	for _, raw := range containers {
		c, ok := exactOpenSearchKeys(raw, "name", "image", "env", "envFrom")
		if !ok {
			return openSearchWorkload{}, &awsKubernetesOutcomeError{outcome: "malformed"}
		}
		var name string
		if json.Unmarshal(c["name"], &name) != nil {
			return openSearchWorkload{}, &awsKubernetesOutcomeError{outcome: "malformed"}
		}
		if name != container {
			continue
		}
		if found {
			return openSearchWorkload{}, &awsKubernetesOutcomeError{outcome: "malformed"}
		}
		found = true
		var image string
		if json.Unmarshal(c["image"], &image) != nil || len(image) > 512 {
			return openSearchWorkload{}, &awsKubernetesOutcomeError{outcome: "malformed"}
		}
		if raw, present := c["envFrom"]; present {
			var values []json.RawMessage
			if string(raw) == "null" || json.Unmarshal(raw, &values) != nil {
				return openSearchWorkload{}, &awsKubernetesOutcomeError{outcome: "malformed"}
			}
			if len(values) > 0 {
				return openSearchWorkload{}, &awsKubernetesOutcomeError{outcome: "binding_mismatch"}
			}
		}
		var env []json.RawMessage
		if json.Unmarshal(c["env"], &env) != nil || len(env) > 256 {
			return openSearchWorkload{}, &awsKubernetesOutcomeError{outcome: "malformed"}
		}
		result = openSearchWorkload{Namespace: namespace, PodName: pod.Metadata.Name, PodUID: pod.Metadata.UID, ServiceAccount: sa, Purpose: selected.Purpose, Container: name, Image: image, Env: map[string]string{}}
		allowed := map[string]bool{"ZASP_WORKER_MODE": true, "ZASP_RUNTIME_STAGE_VERSION": true, "ZASP_OPENSEARCH_ENDPOINT": true, "ZASP_OPENSEARCH_INDEX": true, "ZASP_RUNTIME_SESSION_INDEX": true}
		for _, raw := range env {
			field, ok := exactOpenSearchKeys(raw, "name", "value", "valueFrom")
			if !ok {
				return openSearchWorkload{}, &awsKubernetesOutcomeError{outcome: "malformed"}
			}
			var key string
			if json.Unmarshal(field["name"], &key) != nil {
				return openSearchWorkload{}, &awsKubernetesOutcomeError{outcome: "malformed"}
			}
			if !allowed[key] {
				continue
			}
			if _, duplicate := result.Env[key]; duplicate {
				return openSearchWorkload{}, &awsKubernetesOutcomeError{outcome: "malformed"}
			}
			if _, indirect := field["valueFrom"]; indirect {
				return openSearchWorkload{}, &awsKubernetesOutcomeError{outcome: "binding_mismatch"}
			}
			var value string
			if json.Unmarshal(field["value"], &value) != nil || value == "" || len(value) > 2048 {
				return openSearchWorkload{}, &awsKubernetesOutcomeError{outcome: "malformed"}
			}
			result.Env[key] = value
		}
	}
	if !found {
		return openSearchWorkload{}, &awsKubernetesOutcomeError{outcome: "binding_mismatch"}
	}
	return result, nil
}
