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
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

const (
	kubernetesMaximumPageItems       = 500
	kubernetesMaximumResponseBytes   = int64(8 * 1024 * 1024)
	kubernetesMinimumCollectionBytes = int64(4096)
)

var (
	kubernetesPageCursorPattern = regexp.MustCompile(`^kubernetes:(namespaces|deployments):([A-Za-z0-9_-]+|start)$`)
	kubernetesDoneCursorPattern = regexp.MustCompile(`^kubernetes:complete:[0-9a-f]{16}$`)
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
	phase, continuation, includeCluster, ok := api.validPageRequest(request)
	if api == nil || api.client == nil || ctx == nil || ctx.Err() != nil || !validKubernetesCollectionCredential(credential) || !ok {
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
	path := "/api/v1/namespaces"
	if phase == "deployments" {
		path = "/apis/apps/v1/deployments"
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
		return CollectionPage{}, ErrDenied
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return CollectionPage{}, ErrDenied
	}
	responseLimit := request.RemainingBytes
	if responseLimit > kubernetesMaximumResponseBytes {
		responseLimit = kubernetesMaximumResponseBytes
	}
	body, ok := readKubernetesCollectionBody(response.Body, responseLimit)
	if !ok {
		return CollectionPage{}, ErrDenied
	}
	var payload kubernetesCollectionList
	if !decodeKubernetesCollectionResponse(body, &payload) || len(payload.Items) > pageLimit {
		return CollectionPage{}, ErrDenied
	}
	entities, relationships, ok := normalizeKubernetesCollectionPage(request.Subject, phase, includeCluster, payload)
	if !ok {
		return CollectionPage{}, ErrDenied
	}
	complete := false
	next := collection.Cursor{Provider: collection.ProviderKubernetes, Version: "cursor_v1"}
	if payload.Metadata.Continue != "" {
		if !validKubernetesContinuation(payload.Metadata.Continue) {
			return CollectionPage{}, ErrDenied
		}
		next.Value = "kubernetes:" + phase + ":" + base64.RawURLEncoding.EncodeToString([]byte(payload.Metadata.Continue))
	} else if phase == "namespaces" {
		next.Value = "kubernetes:deployments:start"
	} else {
		complete = true
		next = nextKubernetesCompleteCursor(request.Cursor, request.Subject.ID)
	}
	page, err := NewCollectionPage(request.Subject, next, complete, entities, relationships)
	if err != nil || int64(len(page.Raw)) > request.RemainingBytes || bytes.Contains(page.Raw, credential) {
		return CollectionPage{}, ErrDenied
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
	Items []struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			UID       string `json:"uid"`
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"metadata"`
	} `json:"items"`
}

func normalizeKubernetesCollectionPage(subject collection.SubjectBinding, phase string, includeCluster bool, payload kubernetesCollectionList) ([]json.RawMessage, []json.RawMessage, bool) {
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
			if payload.APIVersion != "v1" || payload.Kind != "NamespaceList" || item.APIVersion != "v1" || item.Kind != "Namespace" || item.Metadata.Namespace != "" {
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
		case "deployments":
			if payload.APIVersion != "apps/v1" || payload.Kind != "DeploymentList" || item.APIVersion != "apps/v1" || item.Kind != "Deployment" || !kubernetesNamePattern.MatchString(item.Metadata.Namespace) {
				return nil, nil, false
			}
			entityID := deterministicKubernetesInventoryID(subject, "kubernetes_workload", item.Metadata.UID)
			stable, _ := json.Marshal(struct {
				Cluster      string `json:"cluster"`
				Namespace    string `json:"namespace"`
				APIGroup     string `json:"api_group"`
				APIVersion   string `json:"api_version"`
				ResourceKind string `json:"resource_kind"`
				Name         string `json:"name"`
			}{subject.ID, item.Metadata.Namespace, "apps", "v1", "Deployment", item.Metadata.Name})
			entity, err := marshalKubernetesEntity(entityID, "kubernetes_workload", "kubernetes:deployment:"+item.Metadata.UID, item.Metadata.Namespace+"/"+item.Metadata.Name, stable, json.RawMessage(`{"namespaced":true}`))
			if err != nil {
				return nil, nil, false
			}
			entities = append(entities, entity)
			namespaceEntityID := deterministicKubernetesInventoryID(subject, "kubernetes_namespace", "namespace:"+item.Metadata.Namespace)
			relationship, err := marshalKubernetesRelationship(deterministicKubernetesInventoryID(subject, "attached_to", item.Metadata.UID), "attached_to", "kubernetes:deployment:"+item.Metadata.UID+":namespace:"+item.Metadata.Namespace, namespaceEntityID, entityID, "namespace_workload")
			if err != nil {
				return nil, nil, false
			}
			relationships = append(relationships, relationship)
		default:
			return nil, nil, false
		}
	}
	return entities, relationships, true
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

func (api *KubernetesCollectionAPI) validPageRequest(request CollectionPageRequest) (string, string, bool, bool) {
	initialCursor := request.Cursor == (collection.Cursor{})
	if api == nil || request.Provider != collection.ProviderKubernetes || request.Subject.Kind != "kubernetes_cluster" || (!initialCursor && (request.Cursor.Provider != collection.ProviderKubernetes || request.Cursor.Version != "cursor_v1")) || request.RemainingItems < 1 || request.RemainingBytes < kubernetesMinimumCollectionBytes {
		return "", "", false, false
	}
	parts := strings.SplitN(request.Subject.ID, "/", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != api.host || !kubernetesNamePattern.MatchString(parts[1]) {
		return "", "", false, false
	}
	if initialCursor || request.Cursor.Value == "initial" || kubernetesDoneCursorPattern.MatchString(request.Cursor.Value) {
		return "namespaces", "", true, request.Page == 1
	}
	match := kubernetesPageCursorPattern.FindStringSubmatch(request.Cursor.Value)
	if len(match) != 3 || request.Page < 1 || len(match[2]) > 2048 {
		return "", "", false, false
	}
	if match[2] == "start" {
		return match[1], "", false, match[1] == "deployments"
	}
	decoded, err := base64.RawURLEncoding.DecodeString(match[2])
	if err != nil || !validKubernetesContinuation(string(decoded)) {
		return "", "", false, false
	}
	return match[1], string(decoded), false, true
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
	return collection.Cursor{Provider: collection.ProviderKubernetes, Version: "cursor_v1", Value: fmt.Sprintf("kubernetes:complete:%x", digest[:8])}
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
