package cloudreadiness

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"reflect"
	"regexp"
)

// AttackLabKubernetesDocuments are transient actual GET response documents.
// This predicate confers no authority and does not observe packet enforcement.
type AttackLabKubernetesDocuments struct {
	Version, Namespace, ServiceAccount, ProxyCA, SecurityGroupPolicy []byte
}

var attackLabKubernetesUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var attackLabTestRolePattern = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_-]+-attack-lab-runner-test$`)

// AttackLabKubernetesPrerequisites retains the existing worker Ready predicate.
// EKS minor support, deletion/freshness and real networking are separate checks.
func AttackLabKubernetesPrerequisites(d AttackLabKubernetesDocuments, expectedGroup, expectedRole string) bool {
	version := &attackLabKubernetesVersion{}
	namespace := &attackLabKubernetesNamespace{}
	serviceAccount := &attackLabKubernetesServiceAccount{}
	configMap := &attackLabKubernetesConfigMap{}
	securityGroupPolicy := &attackLabKubernetesSecurityGroupPolicy{}
	documents := [][]byte{d.Version, d.Namespace, d.ServiceAccount, d.ProxyCA, d.SecurityGroupPolicy}
	objects := []any{version, namespace, serviceAccount, configMap, securityGroupPolicy}
	for i, raw := range documents {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		if decoder.Decode(objects[i]) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
			return false
		}
	}
	if version.Major != "1" || !regexp.MustCompile(`^[0-9]{1,3}[+]?$`).MatchString(version.Minor) || namespace.APIVersion != "v1" || namespace.Kind != "Namespace" || namespace.Metadata.Name != "zasp-attack-lab" || !attackLabKubernetesUIDPattern.MatchString(namespace.Metadata.UID) || !reflect.DeepEqual(namespace.Metadata.Labels, map[string]string{"kubernetes.io/metadata.name": "zasp-attack-lab", "zasp.io/execution": "attack-lab"}) || namespace.Status.Phase != "Active" || serviceAccount.APIVersion != "v1" || serviceAccount.Kind != "ServiceAccount" || serviceAccount.Metadata.Name != "agentsec-attack-lab-runner" || serviceAccount.Metadata.Namespace != "zasp-attack-lab" || !attackLabKubernetesUIDPattern.MatchString(serviceAccount.Metadata.UID) || !reflect.DeepEqual(serviceAccount.Metadata.Labels, map[string]string{"zasp.io/execution": "attack-lab"}) || !attackLabTestRolePattern.MatchString(expectedRole) || !reflect.DeepEqual(serviceAccount.Metadata.Annotations, map[string]string{"eks.amazonaws.com/role-arn": expectedRole}) || serviceAccount.AutomountServiceAccountToken == nil || *serviceAccount.AutomountServiceAccountToken || len(serviceAccount.Secrets) != 0 || len(serviceAccount.ImagePullSecrets) != 0 || configMap.APIVersion != "v1" || configMap.Kind != "ConfigMap" || configMap.Metadata.Name != "agentsec-attack-lab-proxy-ca" || configMap.Metadata.Namespace != "zasp-attack-lab" || !attackLabKubernetesUIDPattern.MatchString(configMap.Metadata.UID) || len(configMap.Data) != 1 || !validAttackLabCABundle([]byte(configMap.Data["proxy-ca.crt"])) || securityGroupPolicy.APIVersion != "vpcresources.k8s.aws/v1beta1" || securityGroupPolicy.Kind != "SecurityGroupPolicy" || securityGroupPolicy.Metadata.Name != "agentsec-attack-lab-egress" || securityGroupPolicy.Metadata.Namespace != "zasp-attack-lab" || !attackLabKubernetesUIDPattern.MatchString(securityGroupPolicy.Metadata.UID) || len(securityGroupPolicy.Metadata.Annotations) != 0 || !reflect.DeepEqual(securityGroupPolicy.Spec.PodSelector.MatchLabels, map[string]string{"zasp.io/execution": "attack-lab"}) || len(securityGroupPolicy.Spec.PodSelector.MatchExpressions) != 0 || !reflect.DeepEqual(securityGroupPolicy.Spec.SecurityGroups.GroupIDs, []string{expectedGroup}) {
		return false
	}
	return true
}

type attackLabKubernetesObjectMeta struct {
	Name            string                              `json:"name"`
	Namespace       string                              `json:"namespace,omitempty"`
	UID             string                              `json:"uid,omitempty"`
	Labels          map[string]string                   `json:"labels,omitempty"`
	Annotations     map[string]string                   `json:"annotations,omitempty"`
	OwnerReferences []attackLabKubernetesOwnerReference `json:"ownerReferences,omitempty"`
}

type attackLabKubernetesOwnerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller bool   `json:"controller"`
}

type attackLabKubernetesVersion struct {
	Major string `json:"major"`
	Minor string `json:"minor"`
}

type attackLabKubernetesNamespace struct {
	APIVersion string                        `json:"apiVersion"`
	Kind       string                        `json:"kind"`
	Metadata   attackLabKubernetesObjectMeta `json:"metadata"`
	Status     struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

type attackLabKubernetesServiceAccount struct {
	APIVersion                   string                              `json:"apiVersion"`
	Kind                         string                              `json:"kind"`
	Metadata                     attackLabKubernetesObjectMeta       `json:"metadata"`
	AutomountServiceAccountToken *bool                               `json:"automountServiceAccountToken"`
	Secrets                      []attackLabKubernetesLocalReference `json:"secrets"`
	ImagePullSecrets             []attackLabKubernetesLocalReference `json:"imagePullSecrets"`
}

type attackLabKubernetesLocalReference struct {
	Name string `json:"name"`
}

type attackLabKubernetesSecurityGroupPolicy struct {
	APIVersion string                        `json:"apiVersion"`
	Kind       string                        `json:"kind"`
	Metadata   attackLabKubernetesObjectMeta `json:"metadata"`
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

type attackLabKubernetesConfigMap struct {
	APIVersion string                        `json:"apiVersion"`
	Kind       string                        `json:"kind"`
	Metadata   attackLabKubernetesObjectMeta `json:"metadata"`
	Data       map[string]string             `json:"data"`
}

func validAttackLabCABundle(value []byte) bool {
	if len(value) < 64 || len(value) > 32<<10 {
		return false
	}
	rest := bytes.Clone(value)
	defer clear(rest)
	certificates := 0
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			clear(block.Bytes)
			return false
		}
		clear(block.Bytes)
		certificates++
		rest = remaining
	}
	return certificates >= 1 && certificates <= 32
}
