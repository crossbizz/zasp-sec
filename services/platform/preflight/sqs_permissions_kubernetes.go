package preflight

import (
	"context"
	"encoding/json"
	"strings"
)

type sqsPermissionWorkloadReader interface {
	SQSWorkload(context.Context, AWSSelectedWorkload) (sqsPermissionWorkload, error)
}

func (r *awsKubernetesIdentityReader) SQSWorkload(ctx context.Context, selected AWSSelectedWorkload) (sqsPermissionWorkload, error) {
	var result sqsPermissionWorkload
	requirement, known := sqsRequirement(selected.Purpose)
	if !known {
		return result, &awsKubernetesOutcomeError{outcome: "binding_mismatch"}
	}
	container := requirement.container
	namespace, sa := openSearchSubject(selected.Purpose)
	if namespace == "" || !dnsPattern.MatchString(selected.PodName) || len(selected.PodUID) != 36 || !dnsPattern.MatchString(container) {
		return result, &awsKubernetesOutcomeError{outcome: "binding_mismatch"}
	}
	b, attempted, e := r.getObserved(ctx, "/api/v1/namespaces/"+namespace+"/pods/"+selected.PodName)
	result.ReadAttempted = attempted
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
			return result, &awsKubernetesOutcomeError{outcome: "malformed"}
		}
		var name string
		if json.Unmarshal(c["name"], &name) != nil {
			return result, &awsKubernetesOutcomeError{outcome: "malformed"}
		}
		if name != container {
			continue
		}
		if found {
			return result, &awsKubernetesOutcomeError{outcome: "malformed"}
		}
		found = true
		var image string
		if json.Unmarshal(c["image"], &image) != nil || len(image) > 512 {
			return result, &awsKubernetesOutcomeError{outcome: "malformed"}
		}
		if raw, present := c["envFrom"]; present {
			var values []json.RawMessage
			if string(raw) == "null" || json.Unmarshal(raw, &values) != nil {
				return result, &awsKubernetesOutcomeError{outcome: "malformed"}
			}
			if len(values) > 0 {
				return result, &awsKubernetesOutcomeError{outcome: "binding_mismatch"}
			}
		}
		var env []json.RawMessage
		if json.Unmarshal(c["env"], &env) != nil || len(env) > 256 {
			return result, &awsKubernetesOutcomeError{outcome: "malformed"}
		}
		result = sqsPermissionWorkload{ReadAttempted: attempted, Namespace: namespace, PodName: pod.Metadata.Name, PodUID: pod.Metadata.UID, ServiceAccount: sa, Purpose: selected.Purpose, Container: name, Image: image, Env: map[string]string{}}
		allowed := map[string]bool{"ZASP_WORKER_MODE": true, requirement.queueEnv: true}
		if requirement.extraKey != "" {
			allowed[requirement.extraKey] = true
		}
		for _, raw := range env {
			field, ok := exactOpenSearchKeys(raw, "name", "value", "valueFrom")
			if !ok {
				return result, &awsKubernetesOutcomeError{outcome: "malformed"}
			}
			var key string
			if json.Unmarshal(field["name"], &key) != nil {
				return result, &awsKubernetesOutcomeError{outcome: "malformed"}
			}
			if !allowed[key] {
				for known := range allowed {
					if strings.EqualFold(key, known) {
						return result, &awsKubernetesOutcomeError{outcome: "malformed"}
					}
				}
				continue
			}
			if _, duplicate := result.Env[key]; duplicate {
				return result, &awsKubernetesOutcomeError{outcome: "malformed"}
			}
			if _, indirect := field["valueFrom"]; indirect {
				return result, &awsKubernetesOutcomeError{outcome: "binding_mismatch"}
			}
			var value string
			if json.Unmarshal(field["value"], &value) != nil || value == "" || len(value) > 2048 {
				return result, &awsKubernetesOutcomeError{outcome: "malformed"}
			}
			result.Env[key] = value
		}
	}
	if !found {
		return result, &awsKubernetesOutcomeError{outcome: "binding_mismatch"}
	}
	return result, nil
}
