package kubernetesdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

const (
	kubernetesMaximumPageItems       = 500
	kubernetesMaximumResponseBytes   = int64(8 * 1024 * 1024)
	kubernetesMinimumCollectionBytes = int64(4096)
)

var (
	kubernetesPageCursorPattern = regexp.MustCompile(`^kubernetes:(namespaces|serviceaccounts|roles|clusterroles|rolebindings|clusterrolebindings|deployments|statefulsets|daemonsets|jobs|cronjobs):([1-9][0-9]{0,5}):([A-Za-z0-9_-]+|start):([0-9a-f]{16}):([0-9a-f]{16})$`)
	kubernetesDoneCursorPattern = regexp.MustCompile(`^kubernetes:complete:([0-9a-f]{16}):[0-9a-f]{16}$`)
	kubernetesNamePattern       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	kubernetesUIDPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)
)

type KubernetesCollectionAPIConfig struct {
	Endpoint    string
	CABundlePEM []byte
	Timeout     time.Duration
}

type KubernetesCollectionAPI struct {
	endpoint string
	host     string
	client   *http.Client
	timeout  time.Duration
}

var _ CollectionAPI = (*KubernetesCollectionAPI)(nil)

func NewKubernetesCollectionAPI(config KubernetesCollectionAPIConfig) (*KubernetesCollectionAPI, error) {
	parsed, ok := parseKubernetesCollectionEndpoint(config.Endpoint)
	if !ok || config.Timeout < 100*time.Millisecond || config.Timeout > 30*time.Second || len(config.CABundlePEM) < 1 || len(config.CABundlePEM) > 1<<20 {
		return nil, ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bytes.Clone(config.CABundlePEM)) {
		return nil, ErrInvalid
	}
	dialer := &net.Dialer{Timeout: config.Timeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: parsed.Hostname()}, TLSHandshakeTimeout: config.Timeout, ResponseHeaderTimeout: config.Timeout, MaxResponseHeaderBytes: 64 * 1024,
	}
	return newKubernetesCollectionAPI(config.Endpoint, transport, config.Timeout)
}

func newKubernetesCollectionAPI(endpoint string, roundTripper http.RoundTripper, timeout time.Duration) (*KubernetesCollectionAPI, error) {
	parsed, ok := parseKubernetesCollectionEndpoint(endpoint)
	if !ok || roundTripper == nil || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	return &KubernetesCollectionAPI{endpoint: "https://" + parsed.Host, host: strings.ToLower(parsed.Hostname()), client: &http.Client{Transport: roundTripper, Timeout: timeout, CheckRedirect: rejectKubernetesRedirect}, timeout: timeout}, nil
}

func (api *KubernetesCollectionAPI) FetchCollectionPage(ctx context.Context, credential []byte, request CollectionPageRequest) (CollectionPage, error) {
	phase, continuation, lineagePage, includeCluster, ok := api.validPageRequest(request)
	if ctx != nil && ctx.Err() != nil {
		return CollectionPage{}, providercollection.ClassifyProviderError(ctx, ctx.Err())
	}
	if api == nil || api.client == nil || ctx == nil || !validKubernetesCollectionCredential(credential) || !ok {
		return CollectionPage{}, ErrInvalid
	}
	pageLimit := request.RemainingItems
	if includeCluster {
		pageLimit--
	}
	if pageLimit < 1 {
		return CollectionPage{}, ErrInvalid
	}
	if pageLimit > kubernetesMaximumPageItems {
		pageLimit = kubernetesMaximumPageItems
	}
	if phase == "rolebindings" || phase == "clusterrolebindings" {
		pageLimit = 1
	}
	path, ok := kubernetesCollectionPhasePath(phase)
	if !ok {
		return CollectionPage{}, ErrInvalid
	}
	query := url.Values{}
	query.Set("limit", strconv.Itoa(pageLimit))
	if continuation != "" {
		query.Set("continue", continuation)
	}
	providerRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, api.endpoint+path+"?"+query.Encode(), nil)
	if err != nil {
		return CollectionPage{}, ErrInvalid
	}
	providerRequest.Close = true
	providerRequest.Header.Set("Accept", "application/json")
	providerRequest.Header.Set("Authorization", "Bearer "+string(credential))
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	providerRequest = providerRequest.WithContext(bounded)
	response, err := doKubernetesCollectionRequest(api.client, providerRequest)
	if err != nil || bounded.Err() != nil || response == nil {
		closeKubernetesResponse(response)
		return CollectionPage{}, providercollection.ClassifyProviderHTTPFailure(bounded, err, 0, "", time.Now().UTC())
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return CollectionPage{}, providercollection.ClassifyProviderHTTPFailure(bounded, nil, response.StatusCode, response.Header.Get("Retry-After"), time.Now().UTC())
	}
	responseLimit := request.RemainingBytes
	if responseLimit > kubernetesMaximumResponseBytes {
		responseLimit = kubernetesMaximumResponseBytes
	}
	body, ok := readKubernetesCollectionBody(response.Body, responseLimit)
	if !ok {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	var payload kubernetesCollectionList
	if !decodeKubernetesCollectionResponse(body, &payload) || len(payload.Items) > pageLimit {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	entities, relationships, ok := normalizeKubernetesCollectionPage(request.Subject, phase, includeCluster, payload)
	if !ok {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	if len(entities) > request.RemainingItems || len(relationships) > request.RemainingRelationships {
		return CollectionPage{}, providercollection.ErrPageCapacity
	}
	complete := false
	next := collection.Cursor{Provider: collection.ProviderKubernetes, Version: "cursor_v1"}
	if payload.Metadata.Continue != "" {
		if !validKubernetesContinuation(payload.Metadata.Continue) {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		next = nextKubernetesPageCursor(request.Subject, phase, lineagePage+1, base64.RawURLEncoding.EncodeToString([]byte(payload.Metadata.Continue)), request.Cursor)
	} else if nextPhase, hasNext := nextKubernetesCollectionPhase(phase); hasNext {
		next = nextKubernetesPageCursor(request.Subject, nextPhase, lineagePage+1, "start", request.Cursor)
	} else {
		complete = true
		next = nextKubernetesCompleteCursor(request.Cursor, request.Subject.ID)
	}
	page, err := NewCollectionPage(request.Subject, next, complete, entities, relationships)
	if err != nil || int64(len(page.Raw)) > request.RemainingBytes || bytes.Contains(page.Raw, credential) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	return page, nil
}

func (api *KubernetesCollectionAPI) CheckCollectionReadiness(ctx context.Context) error {
	if api == nil || api.client == nil || ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, api.endpoint+"/version", nil)
	if err != nil {
		return ErrDenied
	}
	request.Close = true
	request.Header.Set("Accept", "application/json")
	response, err := doKubernetesCollectionRequest(api.client, request)
	if err != nil || bounded.Err() != nil || response == nil {
		closeKubernetesResponse(response)
		return ErrDenied
	}
	defer response.Body.Close()
	body, ok := readKubernetesCollectionBody(response.Body, 64*1024)
	var version struct {
		GitVersion string `json:"gitVersion"`
	}
	if response.StatusCode != http.StatusOK || !ok || !decodeKubernetesCollectionResponse(body, &version) || !versionPattern.MatchString(version.GitVersion) {
		return ErrDenied
	}
	return nil
}

type kubernetesCollectionList struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []kubernetesCollectionItem `json:"items"`
}

type kubernetesCollectionItem struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		UID       string            `json:"uid"`
		Namespace string            `json:"namespace"`
		Name      string            `json:"name"`
		Labels    map[string]string `json:"labels,omitempty"`
	} `json:"metadata"`
	RoleRef struct {
		APIGroup string `json:"apiGroup"`
		Kind     string `json:"kind"`
		Name     string `json:"name"`
	} `json:"roleRef"`
	Subjects []struct {
		APIGroup  string `json:"apiGroup"`
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"subjects"`
	Rules []kubernetesPolicyRule   `json:"rules"`
	Spec  kubernetesCollectionSpec `json:"spec"`
}

type kubernetesPolicyRule struct {
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	Verbs           []string `json:"verbs"`
	ResourceNames   []string `json:"resourceNames"`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

type canonicalKubernetesPolicyRule struct {
	APIGroups       []string `json:"api_groups"`
	NonResourceURLs []string `json:"non_resource_urls"`
	ResourceNames   []string `json:"resource_names"`
	Resources       []string `json:"resources"`
	Verbs           []string `json:"verbs"`
}

type kubernetesCollectionSpec struct {
	Template struct {
		Spec kubernetesCollectionPodSpec `json:"spec"`
	} `json:"template"`
	JobTemplate struct {
		Spec struct {
			Template struct {
				Spec kubernetesCollectionPodSpec `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	} `json:"jobTemplate"`
}

type kubernetesCollectionPodSpec struct {
	ServiceAccountName string                          `json:"serviceAccountName"`
	HostNetwork        bool                            `json:"hostNetwork"`
	Containers         []kubernetesCollectionContainer `json:"containers"`
	Volumes            []kubernetesCollectionVolume    `json:"volumes"`
}

type kubernetesCollectionContainer struct {
	Name            string   `json:"name"`
	Command         []string `json:"command"`
	SecurityContext struct {
		Privileged bool `json:"privileged"`
	} `json:"securityContext"`
}

type kubernetesCollectionVolume struct {
	Name     string `json:"name"`
	HostPath *struct {
		Path string `json:"path"`
	} `json:"hostPath"`
}

type kubernetesAgentPosture struct {
	HumanCredential        bool   `json:"human_credential"`
	CredentialFingerprint  string `json:"credential_fingerprint"`
	UntrustedInput         bool   `json:"untrusted_input"`
	ProductionWrite        bool   `json:"production_write"`
	ShellExecution         bool   `json:"shell_execution"`
	ProductionCredential   bool   `json:"production_credential"`
	UnrestrictedEgress     bool   `json:"unrestricted_egress"`
	SensitiveDataReach     bool   `json:"sensitive_data_reach"`
	UnapprovedRemoteTool   bool   `json:"unapproved_remote_tool"`
	DestructiveTool        bool   `json:"destructive_tool"`
	RuntimeControl         bool   `json:"runtime_control"`
	ProductionAgent        bool   `json:"production_agent"`
	RuntimePolicySupported bool   `json:"runtime_policy_supported"`
	HostFilesystem         bool   `json:"host_filesystem"`
	Privileged             bool   `json:"privileged"`
	CICDWrite              bool   `json:"cicd_write"`
	ProductionSecretReach  bool   `json:"production_secret_reach"`
	CredentialActive       bool   `json:"credential_active"`
}

func normalizeKubernetesCollectionPage(subject collection.SubjectBinding, phase string, includeCluster bool, payload kubernetesCollectionList) ([]json.RawMessage, []json.RawMessage, bool) {
	expectedAPIVersion, expectedKind, ok := kubernetesCollectionPhaseType(phase)
	if !ok || payload.APIVersion != expectedAPIVersion || payload.Kind != expectedKind {
		return nil, nil, false
	}
	clusterEntityID := deterministicKubernetesInventoryID(subject, "kubernetes_cluster", subject.ID)
	entities := make([]json.RawMessage, 0, len(payload.Items)+1)
	relationships := make([]json.RawMessage, 0, len(payload.Items))
	parts := strings.SplitN(subject.ID, "/", 2)
	if len(parts) != 2 {
		return nil, nil, false
	}
	if includeCluster {
		stable, _ := json.Marshal(struct {
			Cluster string `json:"cluster"`
			Name    string `json:"name"`
		}{subject.ID, parts[1]})
		entity, err := marshalKubernetesEntity(clusterEntityID, "kubernetes_cluster", "kubernetes:cluster:"+subject.ID, subject.ID, stable, json.RawMessage(`{}`))
		if err != nil {
			return nil, nil, false
		}
		entities = append(entities, entity)
	}
	seen := make(map[string]struct{}, len(payload.Items))
	for _, item := range payload.Items {
		if !kubernetesUIDPattern.MatchString(item.Metadata.UID) || !kubernetesNamePattern.MatchString(item.Metadata.Name) {
			return nil, nil, false
		}
		if _, duplicate := seen[item.Metadata.UID]; duplicate {
			return nil, nil, false
		}
		seen[item.Metadata.UID] = struct{}{}
		switch phase {
		case "namespaces":
			if item.APIVersion != "v1" || item.Kind != "Namespace" || item.Metadata.Namespace != "" {
				return nil, nil, false
			}
			entityID := deterministicKubernetesInventoryID(subject, "kubernetes_namespace", "namespace:"+item.Metadata.Name)
			stable, _ := json.Marshal(struct {
				Cluster   string `json:"cluster"`
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
			}{subject.ID, item.Metadata.Name, item.Metadata.Name})
			entity, err := marshalKubernetesEntity(entityID, "kubernetes_namespace", "kubernetes:namespace:"+item.Metadata.UID, item.Metadata.Name, stable, json.RawMessage(`{}`))
			if err != nil {
				return nil, nil, false
			}
			entities = append(entities, entity)
			relationship, err := marshalKubernetesRelationship(deterministicKubernetesInventoryID(subject, "contains", "cluster:"+item.Metadata.UID), "contains", "kubernetes:cluster:"+subject.ID+":namespace:"+item.Metadata.UID, clusterEntityID, entityID, "cluster_namespace")
			if err != nil {
				return nil, nil, false
			}
			relationships = append(relationships, relationship)
		case "serviceaccounts":
			entity, relationship, valid := normalizeKubernetesNamespacedResource(subject, item, "v1", "ServiceAccount", "kubernetes_service_account", "core", "contains", "namespace_service_account")
			if !valid {
				return nil, nil, false
			}
			entities = append(entities, entity)
			relationships = append(relationships, relationship)
		case "roles":
			entity, relationship, valid := normalizeKubernetesRole(subject, item, false)
			if !valid {
				return nil, nil, false
			}
			entities = append(entities, entity)
			relationships = append(relationships, relationship)
		case "clusterroles":
			entity, relationship, valid := normalizeKubernetesRole(subject, item, true)
			if !valid {
				return nil, nil, false
			}
			entities = append(entities, entity)
			relationships = append(relationships, relationship)
		case "rolebindings", "clusterrolebindings":
			bindingEntities, bindingRelationships, valid := normalizeKubernetesRoleBinding(subject, item, phase == "clusterrolebindings")
			if !valid {
				return nil, nil, false
			}
			entities = append(entities, bindingEntities...)
			relationships = append(relationships, bindingRelationships...)
		case "deployments", "statefulsets", "daemonsets", "jobs", "cronjobs":
			entity, workloadRelationships, valid := normalizeKubernetesWorkload(subject, phase, item)
			if !valid {
				return nil, nil, false
			}
			entities = append(entities, entity)
			relationships = append(relationships, workloadRelationships...)
		default:
			return nil, nil, false
		}
	}
	entities, ok = coalesceKubernetesEntities(entities)
	return entities, relationships, ok
}

func normalizeKubernetesNamespacedResource(subject collection.SubjectBinding, item kubernetesCollectionItem, apiVersion, resourceKind, entityKind, apiGroup, relationshipKind, relationshipType string) (json.RawMessage, json.RawMessage, bool) {
	if item.APIVersion != apiVersion || item.Kind != resourceKind || !kubernetesNamePattern.MatchString(item.Metadata.Namespace) {
		return nil, nil, false
	}
	entityID := deterministicKubernetesInventoryID(subject, entityKind, item.Metadata.Namespace+"/"+item.Metadata.Name)
	stable, _ := json.Marshal(struct {
		APIGroup     string `json:"api_group"`
		APIVersion   string `json:"api_version"`
		Cluster      string `json:"cluster"`
		Name         string `json:"name"`
		Namespace    string `json:"namespace"`
		ResourceKind string `json:"resource_kind"`
	}{apiGroup, "v1", subject.ID, item.Metadata.Name, item.Metadata.Namespace, resourceKind})
	sourceNativeID := "kubernetes:" + strings.ToLower(resourceKind) + ":" + item.Metadata.UID
	if resourceKind == "ServiceAccount" {
		sourceNativeID = "kubernetes:serviceaccount:" + item.Metadata.Namespace + "/" + item.Metadata.Name
	}
	entity, err := marshalKubernetesEntity(entityID, entityKind, sourceNativeID, item.Metadata.Namespace+"/"+item.Metadata.Name, stable, json.RawMessage(`{"namespaced":true}`))
	if err != nil {
		return nil, nil, false
	}
	namespaceEntityID := deterministicKubernetesInventoryID(subject, "kubernetes_namespace", "namespace:"+item.Metadata.Namespace)
	relationship, err := marshalKubernetesRelationship(deterministicKubernetesInventoryID(subject, relationshipKind, resourceKind+":"+item.Metadata.UID), relationshipKind, "kubernetes:"+strings.ToLower(resourceKind)+":"+item.Metadata.UID+":namespace:"+item.Metadata.Namespace, namespaceEntityID, entityID, relationshipType)
	return entity, relationship, err == nil
}

func normalizeKubernetesRole(subject collection.SubjectBinding, item kubernetesCollectionItem, clusterScoped bool) (json.RawMessage, json.RawMessage, bool) {
	resourceKind, entityKind, scope := "Role", "kubernetes_role", "namespace"
	if clusterScoped {
		resourceKind, entityKind, scope = "ClusterRole", "kubernetes_cluster_role", "cluster"
	}
	if item.APIVersion != "rbac.authorization.k8s.io/v1" || item.Kind != resourceKind || clusterScoped && item.Metadata.Namespace != "" || !clusterScoped && !kubernetesNamePattern.MatchString(item.Metadata.Namespace) {
		return nil, nil, false
	}
	nativeKey := item.Metadata.Name
	if !clusterScoped {
		nativeKey = item.Metadata.Namespace + "/" + item.Metadata.Name
	}
	entityID := deterministicKubernetesInventoryID(subject, entityKind, nativeKey)
	stableFields := map[string]string{"api_group": "rbac.authorization.k8s.io", "api_version": "v1", "cluster": subject.ID, "name": item.Metadata.Name, "resource_kind": resourceKind, "scope": scope}
	if !clusterScoped {
		stableFields["namespace"] = item.Metadata.Namespace
	}
	stable, _ := json.Marshal(stableFields)
	rules, rulesOK := canonicalKubernetesPolicyRules(item.Rules)
	if !rulesOK {
		return nil, nil, false
	}
	attributes, _ := json.Marshal(struct {
		Namespaced bool                            `json:"namespaced"`
		Rules      []canonicalKubernetesPolicyRule `json:"rules"`
	}{!clusterScoped, rules})
	entity, err := marshalKubernetesEntity(entityID, entityKind, "kubernetes:"+strings.ToLower(resourceKind)+":"+item.Metadata.UID, nativeKey, stable, attributes)
	if err != nil {
		return nil, nil, false
	}
	ownerID, relationshipType := deterministicKubernetesInventoryID(subject, "kubernetes_cluster", subject.ID), "cluster_role"
	if !clusterScoped {
		ownerID, relationshipType = deterministicKubernetesInventoryID(subject, "kubernetes_namespace", "namespace:"+item.Metadata.Namespace), "namespace_role"
	}
	relationship, err := marshalKubernetesRelationship(deterministicKubernetesInventoryID(subject, "contains", resourceKind+":"+item.Metadata.UID), "contains", "kubernetes:"+strings.ToLower(resourceKind)+":"+item.Metadata.UID+":owner", ownerID, entityID, relationshipType)
	return entity, relationship, err == nil
}

func canonicalKubernetesPolicyRules(input []kubernetesPolicyRule) ([]canonicalKubernetesPolicyRule, bool) {
	if len(input) > 64 {
		return nil, false
	}
	encoded := make(map[string]canonicalKubernetesPolicyRule, len(input))
	for _, rule := range input {
		apiGroups, ok := canonicalKubernetesRuleValues(rule.APIGroups, 32, true)
		if !ok {
			return nil, false
		}
		resources, ok := canonicalKubernetesRuleValues(rule.Resources, 32, false)
		if !ok {
			return nil, false
		}
		verbs, ok := canonicalKubernetesRuleValues(rule.Verbs, 32, false)
		if !ok || len(verbs) == 0 {
			return nil, false
		}
		resourceNames, ok := canonicalKubernetesRuleValues(rule.ResourceNames, 32, false)
		if !ok {
			return nil, false
		}
		nonResourceURLs, ok := canonicalKubernetesRuleValues(rule.NonResourceURLs, 32, false)
		if !ok || len(resources) == 0 && len(nonResourceURLs) == 0 || len(nonResourceURLs) > 0 && (len(resources) > 0 || len(resourceNames) > 0 || len(apiGroups) > 0) {
			return nil, false
		}
		canonical := canonicalKubernetesPolicyRule{APIGroups: apiGroups, NonResourceURLs: nonResourceURLs, ResourceNames: resourceNames, Resources: resources, Verbs: verbs}
		body, err := json.Marshal(canonical)
		if err != nil {
			return nil, false
		}
		encoded[string(body)] = canonical
	}
	keys := make([]string, 0, len(encoded))
	for key := range encoded {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]canonicalKubernetesPolicyRule, 0, len(keys))
	for _, key := range keys {
		result = append(result, encoded[key])
	}
	return result, true
}

func canonicalKubernetesRuleValues(input []string, maximum int, allowEmpty bool) ([]string, bool) {
	if len(input) > maximum {
		return nil, false
	}
	values := make(map[string]struct{}, len(input))
	for _, value := range input {
		if value == "" && allowEmpty {
			values[value] = struct{}{}
			continue
		}
		if !validKubernetesRuleText(value) {
			return nil, false
		}
		values[value] = struct{}{}
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, true
}

func validKubernetesRuleText(value string) bool {
	if len(value) < 1 || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func normalizeKubernetesRoleBinding(subject collection.SubjectBinding, item kubernetesCollectionItem, clusterScoped bool) ([]json.RawMessage, []json.RawMessage, bool) {
	resourceKind, entityKind, scope := "RoleBinding", "kubernetes_role_binding", "namespace"
	if clusterScoped {
		resourceKind, entityKind, scope = "ClusterRoleBinding", "kubernetes_cluster_role_binding", "cluster"
	}
	if item.APIVersion != "rbac.authorization.k8s.io/v1" || item.Kind != resourceKind || item.RoleRef.APIGroup != "rbac.authorization.k8s.io" || !kubernetesNamePattern.MatchString(item.RoleRef.Name) || len(item.Subjects) > 64 || clusterScoped && (item.Metadata.Namespace != "" || item.RoleRef.Kind != "ClusterRole") || !clusterScoped && (!kubernetesNamePattern.MatchString(item.Metadata.Namespace) || item.RoleRef.Kind != "Role" && item.RoleRef.Kind != "ClusterRole") {
		return nil, nil, false
	}
	nativeKey := item.Metadata.Name
	if !clusterScoped {
		nativeKey = item.Metadata.Namespace + "/" + item.Metadata.Name
	}
	bindingID := deterministicKubernetesInventoryID(subject, entityKind, nativeKey)
	stableFields := map[string]string{"api_group": "rbac.authorization.k8s.io", "api_version": "v1", "cluster": subject.ID, "name": item.Metadata.Name, "resource_kind": resourceKind, "role": item.RoleRef.Kind + "/" + item.RoleRef.Name, "scope": scope}
	if !clusterScoped {
		stableFields["namespace"] = item.Metadata.Namespace
	}
	stable, _ := json.Marshal(stableFields)
	attributes, _ := json.Marshal(struct {
		Namespaced bool `json:"namespaced"`
	}{!clusterScoped})
	binding, err := marshalKubernetesEntity(bindingID, entityKind, "kubernetes:"+strings.ToLower(resourceKind)+":"+item.Metadata.UID, nativeKey, stable, attributes)
	if err != nil {
		return nil, nil, false
	}
	entities := []json.RawMessage{binding}
	ownerID := deterministicKubernetesInventoryID(subject, "kubernetes_cluster", subject.ID)
	ownerType := "cluster_binding"
	if !clusterScoped {
		ownerID = deterministicKubernetesInventoryID(subject, "kubernetes_namespace", "namespace:"+item.Metadata.Namespace)
		ownerType = "namespace_binding"
	}
	contains, err := marshalKubernetesRelationship(deterministicKubernetesInventoryID(subject, "contains", resourceKind+":"+item.Metadata.UID), "contains", "kubernetes:"+strings.ToLower(resourceKind)+":"+item.Metadata.UID+":owner", ownerID, bindingID, ownerType)
	if err != nil {
		return nil, nil, false
	}
	roleKind := "kubernetes_role"
	roleKey := item.Metadata.Namespace + "/" + item.RoleRef.Name
	if item.RoleRef.Kind == "ClusterRole" {
		roleKind, roleKey = "kubernetes_cluster_role", item.RoleRef.Name
	}
	roleID := deterministicKubernetesInventoryID(subject, roleKind, roleKey)
	binds, err := marshalKubernetesRelationship(deterministicKubernetesInventoryID(subject, "binds", item.Metadata.UID+":"+item.RoleRef.Kind+":"+item.RoleRef.Name), "binds", "kubernetes:"+strings.ToLower(resourceKind)+":"+item.Metadata.UID+":role:"+item.RoleRef.Name, bindingID, roleID, "binding_role")
	if err != nil {
		return nil, nil, false
	}
	relationships := []json.RawMessage{contains, binds}
	seenSubjects := map[string]struct{}{}
	for _, bindingSubject := range item.Subjects {
		subjectKey := bindingSubject.Kind + "/" + bindingSubject.Namespace + "/" + bindingSubject.Name
		if _, duplicate := seenSubjects[subjectKey]; duplicate || !validKubernetesSubjectName(bindingSubject.Name) {
			return nil, nil, false
		}
		seenSubjects[subjectKey] = struct{}{}
		var principalID string
		switch bindingSubject.Kind {
		case "ServiceAccount":
			if bindingSubject.APIGroup != "" || !kubernetesNamePattern.MatchString(bindingSubject.Namespace) || !kubernetesNamePattern.MatchString(bindingSubject.Name) {
				return nil, nil, false
			}
			principalID = deterministicKubernetesInventoryID(subject, "kubernetes_service_account", bindingSubject.Namespace+"/"+bindingSubject.Name)
			principal, marshalErr := marshalKubernetesServiceAccountReference(subject, bindingSubject.Namespace, bindingSubject.Name)
			if marshalErr != nil {
				return nil, nil, false
			}
			entities = append(entities, principal)
		case "User", "Group":
			if bindingSubject.APIGroup != "rbac.authorization.k8s.io" || bindingSubject.Namespace != "" {
				return nil, nil, false
			}
			principalKind := "kubernetes_" + strings.ToLower(bindingSubject.Kind)
			principalID = deterministicKubernetesInventoryID(subject, principalKind, bindingSubject.Name)
			principalStable, _ := json.Marshal(struct {
				Cluster     string `json:"cluster"`
				Name        string `json:"name"`
				Scope       string `json:"scope"`
				SubjectType string `json:"subject_type"`
			}{subject.ID, bindingSubject.Name, "cluster", bindingSubject.Kind})
			principal, marshalErr := marshalKubernetesEntity(principalID, principalKind, "kubernetes:subject:"+bindingSubject.Kind+":"+bindingSubject.Name, bindingSubject.Name, principalStable, json.RawMessage(`{}`))
			if marshalErr != nil {
				return nil, nil, false
			}
			entities = append(entities, principal)
		default:
			return nil, nil, false
		}
		assignment, marshalErr := marshalKubernetesRelationship(deterministicKubernetesInventoryID(subject, "assigned_to", item.Metadata.UID+":"+subjectKey), "assigned_to", "kubernetes:"+strings.ToLower(resourceKind)+":"+item.Metadata.UID+":subject:"+subjectKey, principalID, bindingID, "principal_binding")
		if marshalErr != nil {
			return nil, nil, false
		}
		relationships = append(relationships, assignment)
	}
	return entities, relationships, true
}

func marshalKubernetesServiceAccountReference(subject collection.SubjectBinding, namespace, name string) (json.RawMessage, error) {
	stable, _ := json.Marshal(struct {
		APIGroup     string `json:"api_group"`
		APIVersion   string `json:"api_version"`
		Cluster      string `json:"cluster"`
		Name         string `json:"name"`
		Namespace    string `json:"namespace"`
		ResourceKind string `json:"resource_kind"`
	}{"core", "v1", subject.ID, name, namespace, "ServiceAccount"})
	entityID := deterministicKubernetesInventoryID(subject, "kubernetes_service_account", namespace+"/"+name)
	return marshalKubernetesEntity(entityID, "kubernetes_service_account", "kubernetes:serviceaccount:"+namespace+"/"+name, namespace+"/"+name, stable, json.RawMessage(`{"namespaced":true}`))
}

func coalesceKubernetesEntities(values []json.RawMessage) ([]json.RawMessage, bool) {
	type identity struct {
		ID             string `json:"id"`
		SourceNativeID string `json:"source_native_id"`
	}
	result := make([]json.RawMessage, 0, len(values))
	byID := make(map[string]json.RawMessage, len(values))
	bySource := make(map[string]string, len(values))
	for _, value := range values {
		var item identity
		if json.Unmarshal(value, &item) != nil || item.ID == "" || item.SourceNativeID == "" {
			return nil, false
		}
		if prior, exists := byID[item.ID]; exists {
			if !bytes.Equal(prior, value) || bySource[item.SourceNativeID] != item.ID {
				return nil, false
			}
			continue
		}
		if _, exists := bySource[item.SourceNativeID]; exists {
			return nil, false
		}
		byID[item.ID] = value
		bySource[item.SourceNativeID] = item.ID
		result = append(result, value)
	}
	return result, true
}

func normalizeKubernetesWorkload(subject collection.SubjectBinding, phase string, item kubernetesCollectionItem) (json.RawMessage, []json.RawMessage, bool) {
	definitions := map[string][3]string{
		"deployments":  {"apps/v1", "Deployment", "apps"},
		"statefulsets": {"apps/v1", "StatefulSet", "apps"},
		"daemonsets":   {"apps/v1", "DaemonSet", "apps"},
		"jobs":         {"batch/v1", "Job", "batch"},
		"cronjobs":     {"batch/v1", "CronJob", "batch"},
	}
	definition, ok := definitions[phase]
	if !ok || item.APIVersion != definition[0] || item.Kind != definition[1] || !kubernetesNamePattern.MatchString(item.Metadata.Namespace) {
		return nil, nil, false
	}
	podSpec := item.Spec.Template.Spec
	if phase == "cronjobs" {
		podSpec = item.Spec.JobTemplate.Spec.Template.Spec
	}
	serviceAccount := podSpec.ServiceAccountName
	if serviceAccount == "" {
		serviceAccount = "default"
	}
	if !kubernetesNamePattern.MatchString(serviceAccount) || !validKubernetesAgentPodSpec(podSpec) {
		return nil, nil, false
	}
	entityKind := "kubernetes_workload"
	if phase == "deployments" && item.Metadata.Labels["zasp.ai/entity-kind"] == "agent" {
		entityKind = "kubernetes_agent"
	}
	entityID := deterministicKubernetesInventoryID(subject, entityKind, item.Metadata.UID)
	stable, _ := json.Marshal(struct {
		APIGroup       string `json:"api_group"`
		APIVersion     string `json:"api_version"`
		Cluster        string `json:"cluster"`
		Name           string `json:"name"`
		Namespace      string `json:"namespace"`
		ResourceKind   string `json:"resource_kind"`
		ServiceAccount string `json:"service_account"`
	}{definition[2], "v1", subject.ID, item.Metadata.Name, item.Metadata.Namespace, definition[1], serviceAccount})
	attributes := json.RawMessage(`{"namespaced":true}`)
	if entityKind == "kubernetes_agent" {
		posture := deriveKubernetesAgentPosture(subject, item.Metadata.Namespace, serviceAccount, item.Metadata.Labels, podSpec)
		attributes, _ = json.Marshal(struct {
			Namespaced bool                   `json:"namespaced"`
			Posture    kubernetesAgentPosture `json:"posture"`
		}{true, posture})
	}
	entity, err := marshalKubernetesEntity(entityID, entityKind, "kubernetes:"+strings.ToLower(definition[1])+":"+item.Metadata.UID, item.Metadata.Namespace+"/"+item.Metadata.Name, stable, attributes)
	if err != nil {
		return nil, nil, false
	}
	namespaceID := deterministicKubernetesInventoryID(subject, "kubernetes_namespace", "namespace:"+item.Metadata.Namespace)
	attached, err := marshalKubernetesRelationship(deterministicKubernetesInventoryID(subject, "attached_to", definition[1]+":"+item.Metadata.UID), "attached_to", "kubernetes:"+strings.ToLower(definition[1])+":"+item.Metadata.UID+":namespace:"+item.Metadata.Namespace, namespaceID, entityID, "namespace_workload")
	if err != nil {
		return nil, nil, false
	}
	serviceAccountID := deterministicKubernetesInventoryID(subject, "kubernetes_service_account", item.Metadata.Namespace+"/"+serviceAccount)
	usesIdentity, err := marshalKubernetesRelationship(deterministicKubernetesInventoryID(subject, "uses_identity", definition[1]+":"+item.Metadata.UID), "uses_identity", "kubernetes:"+strings.ToLower(definition[1])+":"+item.Metadata.UID+":serviceaccount:"+serviceAccount, entityID, serviceAccountID, "workload_service_account")
	if err != nil {
		return nil, nil, false
	}
	return entity, []json.RawMessage{attached, usesIdentity}, true
}

func validKubernetesAgentPodSpec(spec kubernetesCollectionPodSpec) bool {
	if len(spec.Containers) > 256 || len(spec.Volumes) > 256 {
		return false
	}
	for _, container := range spec.Containers {
		if !kubernetesNamePattern.MatchString(container.Name) || len(container.Command) > 64 {
			return false
		}
		for _, command := range container.Command {
			if len(command) < 1 || len(command) > 1024 || !validKubernetesRuleText(command) {
				return false
			}
		}
	}
	for _, volume := range spec.Volumes {
		if !kubernetesNamePattern.MatchString(volume.Name) {
			return false
		}
		if volume.HostPath != nil && !validKubernetesHostPath(volume.HostPath.Path) {
			return false
		}
	}
	return true
}

func validKubernetesHostPath(value string) bool {
	if len(value) < 1 || len(value) > 4096 || !utf8.ValidString(value) || !strings.HasPrefix(value, "/") || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func deriveKubernetesAgentPosture(subject collection.SubjectBinding, namespace, serviceAccount string, labels map[string]string, spec kubernetesCollectionPodSpec) kubernetesAgentPosture {
	credentialDigest := sha256.Sum256([]byte("kubernetes-service-account-v1\x1f" + subject.ID + "\x1f" + namespace + "\x1f" + serviceAccount))
	production := namespace == "prod" || namespace == "production"
	runtimeSupported := labels["zasp.ai/runtime-policy"] == "supported"
	posture := kubernetesAgentPosture{
		CredentialFingerprint:  fmt.Sprintf("sha256:%x", credentialDigest),
		ProductionCredential:   production,
		UnrestrictedEgress:     spec.HostNetwork,
		RuntimeControl:         runtimeSupported,
		ProductionAgent:        production,
		RuntimePolicySupported: runtimeSupported,
		CredentialActive:       true,
	}
	for _, container := range spec.Containers {
		posture.Privileged = posture.Privileged || container.SecurityContext.Privileged
		if len(container.Command) > 0 && kubernetesShellCommand(container.Command[0]) {
			posture.ShellExecution = true
		}
	}
	for _, volume := range spec.Volumes {
		posture.HostFilesystem = posture.HostFilesystem || volume.HostPath != nil
	}
	return posture
}

func kubernetesShellCommand(value string) bool {
	switch value {
	case "sh", "bash", "dash", "zsh", "/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/zsh":
		return true
	default:
		return false
	}
}

func validKubernetesSubjectName(value string) bool {
	if len(value) < 1 || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func marshalKubernetesEntity(id, kind, sourceNativeID, displayName string, stable, attributes json.RawMessage) (json.RawMessage, error) {
	return json.Marshal(struct {
		ID             string          `json:"id"`
		Kind           string          `json:"kind"`
		SourceNativeID string          `json:"source_native_id"`
		DisplayName    string          `json:"display_name"`
		StableFields   json.RawMessage `json:"stable_fields"`
		Attributes     json.RawMessage `json:"attributes"`
	}{id, kind, sourceNativeID, displayName, stable, attributes})
}

func marshalKubernetesRelationship(id, kind, sourceNativeID, from, to, relationshipType string) (json.RawMessage, error) {
	attributes, _ := json.Marshal(struct {
		Type string `json:"type"`
	}{relationshipType})
	return json.Marshal(struct {
		ID             string          `json:"id"`
		Kind           string          `json:"kind"`
		SourceNativeID string          `json:"source_native_id"`
		FromEntityID   string          `json:"from_entity_id"`
		ToEntityID     string          `json:"to_entity_id"`
		Attributes     json.RawMessage `json:"attributes"`
	}{id, kind, sourceNativeID, from, to, attributes})
}

func (api *KubernetesCollectionAPI) validPageRequest(request CollectionPageRequest) (string, string, int, bool, bool) {
	initialCursor := request.Cursor == (collection.Cursor{})
	if api == nil || request.Provider != collection.ProviderKubernetes || request.Subject.Kind != "kubernetes_cluster" || (!initialCursor && (request.Cursor.Provider != collection.ProviderKubernetes || request.Cursor.Version != "cursor_v1")) || request.RemainingItems < 1 || request.RemainingBytes < kubernetesMinimumCollectionBytes {
		return "", "", 0, false, false
	}
	parts := strings.SplitN(request.Subject.ID, "/", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != api.host || !kubernetesNamePattern.MatchString(parts[1]) {
		return "", "", 0, false, false
	}
	if initialCursor || request.Cursor.Value == "initial" {
		return "namespaces", "", 1, true, request.Page == 1
	}
	if match := kubernetesDoneCursorPattern.FindStringSubmatch(request.Cursor.Value); len(match) == 2 {
		return "namespaces", "", 1, true, request.Page == 1 && match[1] == providercollection.CompleteCursorBinding(collection.ProviderKubernetes, request.Subject)
	}
	match := kubernetesPageCursorPattern.FindStringSubmatch(request.Cursor.Value)
	if len(match) != 6 || request.Page < 1 || len(match[3]) > 2048 {
		return "", "", 0, false, false
	}
	page, err := strconv.Atoi(match[2])
	if err != nil || page != request.Page || match[5] != providercollection.CursorBinding(collection.ProviderKubernetes, request.Subject, match[1], page, match[3]+":"+match[4]) {
		return "", "", 0, false, false
	}
	if match[3] == "start" {
		_, ok := kubernetesCollectionPhasePath(match[1])
		return match[1], "", page, false, ok
	}
	decoded, err := base64.RawURLEncoding.DecodeString(match[3])
	if err != nil || !validKubernetesContinuation(string(decoded)) {
		return "", "", 0, false, false
	}
	return match[1], string(decoded), page, false, true
}

func kubernetesCollectionPhasePath(phase string) (string, bool) {
	paths := map[string]string{
		"namespaces":          "/api/v1/namespaces",
		"serviceaccounts":     "/api/v1/serviceaccounts",
		"roles":               "/apis/rbac.authorization.k8s.io/v1/roles",
		"clusterroles":        "/apis/rbac.authorization.k8s.io/v1/clusterroles",
		"rolebindings":        "/apis/rbac.authorization.k8s.io/v1/rolebindings",
		"clusterrolebindings": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
		"deployments":         "/apis/apps/v1/deployments",
		"statefulsets":        "/apis/apps/v1/statefulsets",
		"daemonsets":          "/apis/apps/v1/daemonsets",
		"jobs":                "/apis/batch/v1/jobs",
		"cronjobs":            "/apis/batch/v1/cronjobs",
	}
	path, ok := paths[phase]
	return path, ok
}

func nextKubernetesCollectionPhase(phase string) (string, bool) {
	phases := []string{"namespaces", "serviceaccounts", "roles", "clusterroles", "rolebindings", "clusterrolebindings", "deployments", "statefulsets", "daemonsets", "jobs", "cronjobs"}
	for index := 0; index+1 < len(phases); index++ {
		if phases[index] == phase {
			return phases[index+1], true
		}
	}
	return "", false
}

func kubernetesCollectionPhaseType(phase string) (string, string, bool) {
	types := map[string][2]string{
		"namespaces":          {"v1", "NamespaceList"},
		"serviceaccounts":     {"v1", "ServiceAccountList"},
		"roles":               {"rbac.authorization.k8s.io/v1", "RoleList"},
		"clusterroles":        {"rbac.authorization.k8s.io/v1", "ClusterRoleList"},
		"rolebindings":        {"rbac.authorization.k8s.io/v1", "RoleBindingList"},
		"clusterrolebindings": {"rbac.authorization.k8s.io/v1", "ClusterRoleBindingList"},
		"deployments":         {"apps/v1", "DeploymentList"},
		"statefulsets":        {"apps/v1", "StatefulSetList"},
		"daemonsets":          {"apps/v1", "DaemonSetList"},
		"jobs":                {"batch/v1", "JobList"},
		"cronjobs":            {"batch/v1", "CronJobList"},
	}
	value, ok := types[phase]
	return value[0], value[1], ok
}

func parseKubernetesCollectionEndpoint(value string) (*url.URL, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() != "" && parsed.Port() != "443" {
		return nil, false
	}
	host := strings.ToLower(parsed.Hostname())
	if net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return nil, false
	}
	return parsed, true
}

func validKubernetesCollectionCredential(value []byte) bool {
	if len(value) < 16 || len(value) > 16_384 || !utf8.Valid(value) {
		return false
	}
	for _, character := range string(value) {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validKubernetesContinuation(value string) bool {
	if len(value) < 1 || len(value) > 1536 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func deterministicKubernetesInventoryID(subject collection.SubjectBinding, kind, nativeID string) string {
	digest := sha256.Sum256([]byte("kubernetes\x1f" + subject.Kind + "\x1f" + subject.ID + "\x1f" + kind + "\x1f" + nativeID))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	return fmt.Sprintf("pid_%x-%x-%x-%x-%x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func nextKubernetesCompleteCursor(prior collection.Cursor, subjectID string) collection.Cursor {
	digest := sha256.Sum256([]byte(prior.Value + "\x1f" + subjectID + "\x1fcomplete"))
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: subjectID}
	return collection.Cursor{Provider: collection.ProviderKubernetes, Version: "cursor_v1", Value: fmt.Sprintf("kubernetes:complete:%s:%x", providercollection.CompleteCursorBinding(collection.ProviderKubernetes, subject), digest[:8])}
}

func nextKubernetesPageCursor(subject collection.SubjectBinding, phase string, page int, continuation string, prior ...collection.Cursor) collection.Cursor {
	previous := collection.Cursor{}
	if len(prior) == 1 {
		previous = prior[0]
	}
	priorBinding := kubernetesCursorPredecessorBinding(previous)
	return collection.Cursor{Provider: collection.ProviderKubernetes, Version: "cursor_v1", Value: fmt.Sprintf("kubernetes:%s:%d:%s:%s:%s", phase, page, continuation, priorBinding, providercollection.CursorBinding(collection.ProviderKubernetes, subject, phase, page, continuation+":"+priorBinding))}
}

func kubernetesCursorPredecessorBinding(cursor collection.Cursor) string {
	value := cursor.Value
	if cursor == (collection.Cursor{}) || value == "initial" {
		value = "initial"
	}
	digest := sha256.Sum256([]byte("kubernetes-cursor-chain-v1\x1f" + value))
	return fmt.Sprintf("%x", digest[:8])
}

func decodeKubernetesCollectionResponse(body []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(destination) != nil {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}

func readKubernetesCollectionBody(body io.Reader, maximum int64) ([]byte, bool) {
	if maximum < 1 {
		return nil, false
	}
	value, err := io.ReadAll(io.LimitReader(body, maximum+1))
	return value, err == nil && len(value) > 0 && int64(len(value)) <= maximum
}

func doKubernetesCollectionRequest(client *http.Client, request *http.Request) (response *http.Response, resultErr error) {
	defer func() {
		if recover() != nil {
			response = nil
			resultErr = ErrDenied
		}
	}()
	return client.Do(request)
}

func closeKubernetesResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

func rejectKubernetesRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
