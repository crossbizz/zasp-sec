package main

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
)

func validAttackLabObservedPodIdentity(body []byte, role string) bool {
	var list struct {
		Items []struct {
			Spec json.RawMessage `json:"spec"`
		} `json:"items"`
	}
	if !decodeAttackLabKubernetesJSON(body, &list) || len(list.Items) != 1 {
		return false
	}
	spec, ok := attackLabKubernetesJSONObject(list.Items[0].Spec)
	if !ok || !attackLabKubernetesRequiredKeys(spec, "serviceAccountName", "automountServiceAccountToken", "containers", "volumes") {
		return false
	}
	var account string
	var automount bool
	if !decodeExactAttackLabKubernetesJSON(spec["serviceAccountName"], &account) || account != "agentsec-attack-lab-runner" || string(spec["automountServiceAccountToken"]) != "false" || !decodeExactAttackLabKubernetesJSON(spec["automountServiceAccountToken"], &automount) {
		return false
	}
	if raw, exists := spec["serviceAccount"]; exists {
		var alias string
		if !decodeExactAttackLabKubernetesJSON(raw, &alias) || alias != account {
			return false
		}
	}
	for _, name := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		if raw, exists := spec[name]; exists {
			var enabled bool
			if !decodeExactAttackLabKubernetesJSON(raw, &enabled) || enabled {
				return false
			}
		}
	}
	for _, name := range []string{"initContainers", "ephemeralContainers"} {
		if raw, exists := spec[name]; exists {
			var containers []json.RawMessage
			if !decodeExactAttackLabKubernetesJSON(raw, &containers) || len(containers) != 0 {
				return false
			}
		}
	}
	containers, ok := attackLabKubernetesJSONArray(spec["containers"])
	if !ok || len(containers) != 1 || !validAttackLabKubernetesContainerJSON(containers[0]) {
		return false
	}
	var container attackLabKubernetesContainer
	var volumes []attackLabKubernetesVolume
	if !decodeExactAttackLabKubernetesJSON(containers[0], &container) || !decodeExactAttackLabKubernetesJSON(spec["volumes"], &volumes) || !reflect.DeepEqual(volumes, attackLabRunnerVolumes()) || !reflect.DeepEqual(container.VolumeMounts, attackLabRunnerVolumeMounts()) {
		return false
	}
	image := strings.Split(container.Image, ".")
	if len(image) < 5 || !validAttackLabTestRole(role, image[0]) {
		return false
	}
	want := attackLabKubernetesJobEnvironment(attackLabKubernetesJob{Image: container.Image, TestRoleARN: role}, "")
	if len(container.Env) != len(want) {
		return false
	}
	allowed := make(map[string]string, len(want))
	for _, entry := range want {
		allowed[entry.Name] = entry.Value
	}
	for _, entry := range container.Env {
		value, exists := allowed[entry.Name]
		if !exists || strings.HasPrefix(entry.Name, "AWS_") && entry.Value != value {
			return false
		}
		delete(allowed, entry.Name)
	}
	return len(allowed) == 0
}

var attackLabTestRolePattern = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_-]+-attack-lab-runner-test$`)

func validAttackLabTestRole(role, account string) bool {
	match := attackLabTestRolePattern.FindStringSubmatch(role)
	return len(match) == 2 && match[1] == account
}

func attackLabRunnerVolumes() []attackLabKubernetesVolume {
	return []attackLabKubernetesVolume{
		{Name: "proxy-ca", ConfigMap: &attackLabKubernetesConfigMapVolume{Name: "agentsec-attack-lab-proxy-ca", DefaultMode: 0o444}},
		{Name: "aws-iam-token", Projected: &attackLabKubernetesProjectedVolume{DefaultMode: 0o440, Sources: []attackLabKubernetesTokenSource{{ServiceAccountToken: attackLabKubernetesTokenProjection{Audience: "sts.amazonaws.com", ExpirationSeconds: 600, Path: "token"}}}}},
	}
}

func attackLabRunnerVolumeMounts() []attackLabKubernetesVolumeMount {
	return []attackLabKubernetesVolumeMount{
		{Name: "proxy-ca", MountPath: "/var/run/secrets/zasp-attack-lab", ReadOnly: true},
		{Name: "aws-iam-token", MountPath: "/var/run/secrets/eks.amazonaws.com/serviceaccount", ReadOnly: true},
	}
}

// Supply the exact web-identity environment and projection ourselves. The EKS
// webhook sees the existing keys/volume and need not add ambient credentials.
func attackLabRunnerIdentityEnvironment(job attackLabKubernetesJob) []attackLabKubernetesEnv {
	return []attackLabKubernetesEnv{
		{Name: "AWS_ROLE_ARN", Value: job.TestRoleARN},
		{Name: "AWS_WEB_IDENTITY_TOKEN_FILE", Value: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"},
		{Name: "AWS_REGION", Value: strings.Split(job.Image, ".")[3]},
		{Name: "AWS_STS_REGIONAL_ENDPOINTS", Value: "regional"},
		{Name: "AWS_EC2_METADATA_DISABLED", Value: "true"},
	}
}

type attackLabKubernetesProjectedVolume struct {
	DefaultMode int32                            `json:"defaultMode"`
	Sources     []attackLabKubernetesTokenSource `json:"sources"`
}

type attackLabKubernetesTokenSource struct {
	ServiceAccountToken attackLabKubernetesTokenProjection `json:"serviceAccountToken"`
}

type attackLabKubernetesTokenProjection struct {
	Audience          string `json:"audience"`
	ExpirationSeconds int64  `json:"expirationSeconds"`
	Path              string `json:"path"`
}
