package preflight

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/cloudreadiness"
)

// Unknown unrelated provider fields may be null, but spelling aliases of known
// authority keys may never enter encoding/json's case-insensitive typed binding.
func exactAttackLabAuthorityKeys(raw []byte, path string) bool {
	if string(raw) == "null" {
		return true
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return false
	}
	known := map[string][]string{"": {"apiVersion", "kind", "metadata", "status", "spec", "automountServiceAccountToken", "secrets", "imagePullSecrets", "data", "binaryData", "immutable", "major", "minor"}, "metadata": {"name", "namespace", "uid", "labels", "annotations", "ownerReferences", "deletionTimestamp"}, "status": {"phase"}, "spec": {"podSelector", "securityGroups"}, "podSelector": {"matchLabels", "matchExpressions"}, "securityGroups": {"groupIds"}}
	for key, value := range object {
		for _, name := range known[path] {
			if strings.EqualFold(key, name) && key != name {
				return false
			}
		}
		if path == "spec" || path == "podSelector" || path == "securityGroups" {
			allowed := false
			for _, name := range known[path] {
				allowed = allowed || key == name
			}
			if !allowed {
				return false
			}
		}
		next := ""
		recurse := false
		if path == "" && (key == "metadata" || key == "status" || key == "spec") {
			next = key
			recurse = true
		}
		if path == "spec" && (key == "podSelector" || key == "securityGroups") {
			next = key
			recurse = true
		}
		if recurse && !exactAttackLabAuthorityKeys(value, next) {
			return false
		}
	}
	return true
}

type attackLabReadMetadata struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	Labels            map[string]string `json:"labels"`
	Annotations       map[string]string `json:"annotations"`
	DeletionTimestamp json.RawMessage   `json:"deletionTimestamp"`
}

func (m attackLabReadMetadata) live() bool {
	return attackLabUUID.MatchString(m.UID) && (len(m.DeletionTimestamp) == 0 || string(m.DeletionTimestamp) == "null")
}
func exactProxyAttackLabSGP(raw []byte, group string) bool {
	var v struct {
		APIVersion string                `json:"apiVersion"`
		Kind       string                `json:"kind"`
		Metadata   attackLabReadMetadata `json:"metadata"`
		Spec       struct {
			PodSelector struct {
				MatchLabels      map[string]string `json:"matchLabels"`
				MatchExpressions []json.RawMessage `json:"matchExpressions"`
			} `json:"podSelector"`
			SecurityGroups struct {
				GroupIDs []string `json:"groupIds"`
			} `json:"securityGroups"`
		} `json:"spec"`
	}
	return json.Unmarshal(raw, &v) == nil && v.APIVersion == "vpcresources.k8s.aws/v1beta1" && v.Kind == "SecurityGroupPolicy" && v.Metadata.Name == "agentsec-attack-lab-proxy" && v.Metadata.Namespace == "agentsec" && v.Metadata.live() && len(v.Metadata.Annotations) == 0 && reflect.DeepEqual(v.Spec.PodSelector.MatchLabels, map[string]string{"app.kubernetes.io/name": "agentsec-attack-lab-proxy"}) && len(v.Spec.PodSelector.MatchExpressions) == 0 && reflect.DeepEqual(v.Spec.SecurityGroups.GroupIDs, []string{group})
}
func (r *Runner) observeAttackLabKubernetes(ctx context.Context, reader *awsKubernetesIdentityReader, authority *AWSAuthorityConfig, target *AWSAttackLabTarget, enabled bool) *attackLabEvidence {
	evidence := &attackLabEvidence{}
	if !enabled || ctx == nil || ctx.Err() != nil || reader == nil || authority == nil || target == nil {
		return evidence
	}
	// A private typed view shares exactly the existing transport, pinned CA and
	// credential loader. It adds no generic endpoint and does not mutate the B2
	// reader's capability map, including when that reader is used concurrently.
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	view := *reader
	view.paths = map[string]bool{}
	paths := []string{"/version", "/api/v1/namespaces/zasp-attack-lab", "/api/v1/namespaces/zasp-attack-lab/serviceaccounts/agentsec-attack-lab-runner", "/api/v1/namespaces/zasp-attack-lab/configmaps/agentsec-attack-lab-proxy-ca", "/apis/vpcresources.k8s.aws/v1beta1/namespaces/zasp-attack-lab/securitygrouppolicies/agentsec-attack-lab-egress", "/apis/vpcresources.k8s.aws/v1beta1/namespaces/agentsec/securitygrouppolicies/agentsec-attack-lab-proxy"}
	for _, path := range paths {
		view.paths[path] = true
	}
	documents := make([][]byte, len(paths))
	defer func() {
		for _, raw := range documents {
			clear(raw)
		}
	}()
	operations := []string{"kubernetes:GetVersion", "kubernetes:GetNamespace", "kubernetes:GetServiceAccount", "kubernetes:GetConfigMap", "kubernetes:GetSecurityGroupPolicy", "kubernetes:GetSecurityGroupPolicy"}
	failureOperation := "configuration:ValidateAttackLabKubernetes"
	failureTarget := "zasp-attack-lab"
	var failureErr error
	defer func() {
		if evidence.policyAttempted && !evidence.policy {
			evidence.failures = attackLabFailures(failureOperation, []string{failureTarget}, failureErr)
		}
	}()
	for i, path := range paths {
		raw, attempted, e := view.getObserved(bounded, path)
		if i == 1 {
			evidence.namespaceAttempted = attempted
		}
		if i != 1 && attempted {
			evidence.policyAttempted = true
		}
		failureOperation = operations[i]
		failureTarget = path
		failureErr = e
		if e != nil && !attempted {
			// A local credential prerequisite failed before this HTTP method. Earlier
			// completed reads do not fabricate an attempted later operation.
			evidence.policyAttempted = false
			clear(raw)
			return evidence
		}
		if e != nil || len(raw) > 64<<10 || !exactAttackLabAuthorityKeys(raw, "") {
			if e == nil {
				failureErr = errMalformedProviderObservation
			}
			clear(raw)
			return evidence
		}
		documents[i] = raw
		if i == 1 {
			evidence.namespace = exactAttackLabNamespace(raw)
		}
		if i > 0 {
			var metadata struct {
				Metadata attackLabReadMetadata `json:"metadata"`
			}
			if json.Unmarshal(raw, &metadata) != nil || !metadata.Metadata.live() {
				return evidence
			}
		}
	}
	failureOperation = "configuration:ValidateAttackLabKubernetes"
	failureTarget = "zasp-attack-lab"
	failureErr = nil

	role := ""
	for _, v := range authority.Roles {
		if v.Purpose == "aws_iam_role.attack_lab_runner_test" {
			role = v.RoleARN
		}
	}
	if !cloudreadiness.AttackLabKubernetesPrerequisites(cloudreadiness.AttackLabKubernetesDocuments{Version: documents[0], Namespace: documents[1], ServiceAccount: documents[2], ProxyCA: documents[3], SecurityGroupPolicy: documents[4]}, target.RunnerSecurityGroupID, role) {
		return evidence
	}
	var version struct {
		Major string `json:"major"`
		Minor string `json:"minor"`
	}
	if json.Unmarshal(documents[0], &version) != nil || version.Major != "1" || strings.TrimSuffix(version.Minor, "+") != "34" {
		return evidence
	}
	var ca struct {
		Immutable  *bool                      `json:"immutable"`
		Data       map[string]string          `json:"data"`
		BinaryData map[string]json.RawMessage `json:"binaryData"`
	}
	if json.Unmarshal(documents[3], &ca) != nil || ca.Immutable == nil || !*ca.Immutable || len(ca.BinaryData) != 0 {
		return evidence
	}
	digest := sha256.Sum256([]byte(ca.Data["proxy-ca.crt"]))
	evidence.policy = evidence.namespace && hex.EncodeToString(digest[:]) == target.ProxyCASHA256 && exactProxyAttackLabSGP(documents[5], target.ProxySecurityGroupID)
	return evidence
}

func exactAttackLabNamespace(raw []byte) bool {
	var namespace struct {
		APIVersion string                `json:"apiVersion"`
		Kind       string                `json:"kind"`
		Metadata   attackLabReadMetadata `json:"metadata"`
		Status     struct {
			Phase string `json:"phase"`
		} `json:"status"`
	}
	if json.Unmarshal(raw, &namespace) != nil {
		return false
	}
	return namespace.APIVersion == "v1" && namespace.Kind == "Namespace" && namespace.Metadata.Name == "zasp-attack-lab" && namespace.Metadata.live() && namespace.Status.Phase == "Active" && reflect.DeepEqual(namespace.Metadata.Labels, map[string]string{"kubernetes.io/metadata.name": "zasp-attack-lab", "zasp.io/execution": "attack-lab"})
}
