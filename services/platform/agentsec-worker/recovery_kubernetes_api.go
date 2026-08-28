package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

const recoveryKubernetesResponseLimit = 1 << 20

var recoveryKubernetesUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type recoveryKubernetesTransport interface {
	Request(context.Context, string, string, []byte) ([]byte, int, error)
}

type recoveryKubernetesHTTPConfig struct {
	Endpoint  string
	TokenFile string
	RootCAs   *x509.CertPool
	Timeout   time.Duration
}

type recoveryKubernetesHTTPTransport struct {
	endpoint  string
	tokenFile string
	client    *http.Client
	transport *http.Transport
	closeOnce sync.Once
}

func newRecoveryKubernetesHTTPTransport(config recoveryKubernetesHTTPConfig) (*recoveryKubernetesHTTPTransport, error) {
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || parsed.String() != config.Endpoint || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || config.TokenFile == "" || config.RootCAs == nil || config.Timeout < time.Millisecond || config.Timeout > 30*time.Second {
		return nil, errRuntimeUnavailable
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: config.Timeout, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: config.RootCAs, ServerName: parsed.Hostname()}, TLSHandshakeTimeout: config.Timeout, ResponseHeaderTimeout: config.Timeout, MaxResponseHeaderBytes: 64 << 10,
	}
	client := &http.Client{Transport: transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }}
	return &recoveryKubernetesHTTPTransport{endpoint: config.Endpoint, tokenFile: config.TokenFile, client: client, transport: transport}, nil
}

func newProductionRecoveryKubernetesHTTPTransport(endpoint, tokenFile, caFile string, timeout time.Duration) (*recoveryKubernetesHTTPTransport, error) {
	if endpoint != "https://kubernetes.default.svc" || tokenFile != "/var/run/secrets/kubernetes.io/serviceaccount/token" || caFile != "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" {
		return nil, errRuntimeUnavailable
	}
	caBundle, err := os.ReadFile(caFile)
	if err != nil || !validDiscoveryCABundle(caBundle) {
		clear(caBundle)
		return nil, errRuntimeUnavailable
	}
	defer clear(caBundle)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBundle) {
		return nil, errRuntimeUnavailable
	}
	return newRecoveryKubernetesHTTPTransport(recoveryKubernetesHTTPConfig{Endpoint: endpoint, TokenFile: tokenFile, RootCAs: roots, Timeout: timeout})
}

func (transport *recoveryKubernetesHTTPTransport) Request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	if transport == nil || transport.client == nil || ctx == nil || ctx.Err() != nil || !strings.HasPrefix(path, "/") || strings.Contains(path, "//") || len(body) > 64<<10 {
		return nil, 0, errWorkerExecution
	}
	token, err := os.ReadFile(transport.tokenFile)
	if err != nil || !validDiscoveryOpaqueSecret(token, 16, 16<<10) {
		clear(token)
		return nil, 0, errWorkerExecution
	}
	defer clear(token)
	request, err := http.NewRequestWithContext(ctx, method, transport.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, errWorkerExecution
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(token))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := transport.client.Do(request)
	if err != nil {
		return nil, 0, errWorkerExecution
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		return nil, response.StatusCode, errWorkerExecution
	}
	encoded, readErr := io.ReadAll(io.LimitReader(response.Body, recoveryKubernetesResponseLimit+1))
	if readErr != nil || len(encoded) > recoveryKubernetesResponseLimit || len(encoded) == 0 || !json.Valid(encoded) {
		return nil, response.StatusCode, errWorkerExecution
	}
	return encoded, response.StatusCode, nil
}

func (transport *recoveryKubernetesHTTPTransport) Close() error {
	if transport != nil {
		transport.closeOnce.Do(func() {
			if transport.transport != nil {
				transport.transport.CloseIdleConnections()
			}
		})
	}
	return nil
}

type recoveryKubernetesAPIConfig struct {
	Transport         recoveryKubernetesTransport
	Store             artifactstore.ObjectReferencingArtifactStore
	RunnerImage       string
	ServiceAccount    string
	SourcePostgresDSN string
	NeonCIDRs         []string
	PollInterval      time.Duration
	Resolve           func(context.Context, string) ([]net.IP, error)
}

type productionRecoveryKubernetesAPI struct{ config recoveryKubernetesAPIConfig }

type recoveryKubernetesMetadata struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace,omitempty"`
	UID         string            `json:"uid,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type recoveryKubernetesResource struct {
	APIVersion string                     `json:"apiVersion"`
	Kind       string                     `json:"kind"`
	Metadata   recoveryKubernetesMetadata `json:"metadata"`
	Spec       json.RawMessage            `json:"spec,omitempty"`
	Data       map[string]string          `json:"data,omitempty"`
	Type       string                     `json:"type,omitempty"`
	Status     json.RawMessage            `json:"status,omitempty"`
}

type recoveryKubernetesJobStatus struct {
	Succeeded  int `json:"succeeded"`
	Failed     int `json:"failed"`
	Conditions []struct {
		Type   string `json:"type"`
		Status string `json:"status"`
	} `json:"conditions"`
}

type recoveryKubernetesPodList struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []struct {
		APIVersion string                     `json:"apiVersion"`
		Kind       string                     `json:"kind"`
		Metadata   recoveryKubernetesMetadata `json:"metadata"`
		Status     struct {
			Phase             string `json:"phase"`
			ContainerStatuses []struct {
				Name         string `json:"name"`
				Ready        bool   `json:"ready"`
				RestartCount int    `json:"restartCount"`
				State        struct {
					Terminated *struct {
						ExitCode int    `json:"exitCode"`
						Reason   string `json:"reason"`
						Message  string `json:"message"`
					} `json:"terminated"`
				} `json:"state"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

func newRecoveryKubernetesAPI(config recoveryKubernetesAPIConfig) (*productionRecoveryKubernetesAPI, error) {
	parsed, err := url.Parse(config.SourcePostgresDSN)
	image := regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr\.[a-z]{2}(?:-gov)?-[a-z]+-[0-9]\.amazonaws\.com/zasp/agentsec-worker@sha256:[a-f0-9]{64}$`).MatchString(config.RunnerImage)
	if config.Transport == nil || config.Store == nil || !image || config.ServiceAccount != "agentsec-recovery-runner" || err != nil || parsed.String() != config.SourcePostgresDSN || parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" || parsed.User == nil || !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.neon\.tech$`).MatchString(parsed.Hostname()) || parsed.Path == "" || parsed.Query().Get("sslmode") != "verify-full" || !validRecoveryNeonCIDRs(config.NeonCIDRs) || config.PollInterval < time.Millisecond || config.PollInterval > time.Second || config.Resolve == nil {
		return nil, errRuntimeUnavailable
	}
	config.NeonCIDRs = append([]string(nil), config.NeonCIDRs...)
	return &productionRecoveryKubernetesAPI{config: config}, nil
}

func (api *productionRecoveryKubernetesAPI) Ready(ctx context.Context) error {
	body, status, err := api.request(ctx, http.MethodGet, "/version", nil)
	var version struct {
		Major      string `json:"major"`
		Minor      string `json:"minor"`
		GitVersion string `json:"gitVersion,omitempty"`
	}
	if err != nil || status != http.StatusOK || json.Unmarshal(body, &version) != nil || version.Major != "1" || !regexp.MustCompile(`^[0-9]{1,3}[+]?$`).MatchString(version.Minor) {
		return errRuntimeUnavailable
	}
	checks := [][4]string{
		{"create", "", "namespaces", ""}, {"get", "", "namespaces", ""}, {"delete", "", "namespaces", ""},
		{"create", "networking.k8s.io", "networkpolicies", "zasp-recovery-authority-check"}, {"get", "networking.k8s.io", "networkpolicies", "zasp-recovery-authority-check"},
		{"create", "", "secrets", "zasp-recovery-authority-check"}, {"get", "", "secrets", "zasp-recovery-authority-check"},
		{"create", "batch", "jobs", "zasp-recovery-authority-check"}, {"get", "batch", "jobs", "zasp-recovery-authority-check"},
		{"list", "", "pods", "zasp-recovery-authority-check"},
	}
	for _, check := range checks {
		request := map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview", "spec": map[string]any{"resourceAttributes": map[string]string{"group": check[1], "namespace": check[3], "resource": check[2], "verb": check[0]}}}
		encoded, _ := json.Marshal(request)
		response, reviewStatus, reviewErr := api.request(ctx, http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", encoded)
		var review struct {
			Status struct {
				Allowed bool `json:"allowed"`
				Denied  bool `json:"denied"`
			} `json:"status"`
		}
		if reviewErr != nil || reviewStatus != http.StatusCreated || json.Unmarshal(response, &review) != nil || !review.Status.Allowed || review.Status.Denied {
			return errRuntimeUnavailable
		}
	}
	return nil
}

func (api *productionRecoveryKubernetesAPI) Provision(ctx context.Context, plan recoveryKubernetesPlan) (string, error) {
	if !validRecoveryKubernetesAPIPlan(plan, api.config.NeonCIDRs) {
		return "", errWorkerExecution
	}
	namespace := map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": plan.Namespace, "labels": plan.Labels}}
	created, err := api.createOrReconcile(ctx, "/api/v1/namespaces", "/api/v1/namespaces/"+plan.Namespace, namespace, "v1", "Namespace", plan.Namespace, "", plan.Labels)
	if err != nil || !recoveryKubernetesUIDPattern.MatchString(created.Metadata.UID) {
		return "", errWorkerExecution
	}
	policy := recoveryKubernetesNetworkPolicyManifest(plan, api.config.NeonCIDRs)
	if _, err := api.createOrReconcile(ctx, "/apis/networking.k8s.io/v1/namespaces/"+plan.Namespace+"/networkpolicies", "/apis/networking.k8s.io/v1/namespaces/"+plan.Namespace+"/networkpolicies/"+plan.NetworkPolicy.Name, policy, "networking.k8s.io/v1", "NetworkPolicy", plan.NetworkPolicy.Name, plan.Namespace, plan.Labels); err != nil {
		return created.Metadata.UID, errWorkerExecution
	}
	dsn, err := recoveryBranchDSN(api.config.SourcePostgresDSN, plan.BranchHost)
	if err != nil {
		return created.Metadata.UID, errWorkerExecution
	}
	branchIP, err := api.resolveBranch(ctx, plan.BranchHost)
	if err != nil {
		return created.Metadata.UID, errWorkerExecution
	}
	secret := map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "recovery-database", "namespace": plan.Namespace, "labels": plan.Labels}, "type": "Opaque", "stringData": map[string]string{"branch_ip": branchIP, "dsn": dsn}}
	if _, err := api.createOrReconcile(ctx, "/api/v1/namespaces/"+plan.Namespace+"/secrets", "/api/v1/namespaces/"+plan.Namespace+"/secrets/recovery-database", secret, "v1", "Secret", "recovery-database", plan.Namespace, plan.Labels); err != nil {
		return created.Metadata.UID, errWorkerExecution
	}
	return created.Metadata.UID, nil
}

func (api *productionRecoveryKubernetesAPI) Validate(ctx context.Context, plan recoveryKubernetesPlan, namespaceUID string) (apiserver.RecoveryCounts, apiserver.RecoveryArtifactLocator, error) {
	message, err := api.runJob(ctx, plan, namespaceUID, plan.Jobs[0])
	var result struct {
		SchemaVersion        string                   `json:"schema_version"`
		Counts               apiserver.RecoveryCounts `json:"counts"`
		EvidenceSampleSHA256 string                   `json:"evidence_sample_sha256"`
	}
	if err != nil || decodeStrictWorkerJSON([]byte(message), &result) != nil || result.SchemaVersion != "recovery_validation_job_v1" || !validRecoveryCounts(result.Counts) || result.Counts != plan.ExpectedCounts || result.EvidenceSampleSHA256 != hex.EncodeToString(plan.EvidenceSampleDigest[:]) {
		return apiserver.RecoveryCounts{}, apiserver.RecoveryArtifactLocator{}, errWorkerExecution
	}
	body, _ := json.Marshal(map[string]any{"counts": result.Counts, "evidence_sample_sha256": result.EvidenceSampleSHA256, "namespace_uid": namespaceUID, "scope_digest": plan.Labels["zasp.io/recovery-scope"], "state": "validated"})
	evidence, err := api.putEvidence(ctx, plan, "validation", "recovery_validation_v1", body)
	return result.Counts, evidence, err
}

func (api *productionRecoveryKubernetesAPI) Rebuild(ctx context.Context, plan recoveryKubernetesPlan, namespaceUID string) ([sha256.Size]byte, error) {
	for index, wantKind := range []string{"graph", "search"} {
		message, err := api.runJob(ctx, plan, namespaceUID, plan.Jobs[index+1])
		var result struct {
			SchemaVersion        string `json:"schema_version"`
			Kind                 string `json:"kind"`
			ProjectionSHA256     string `json:"projection_sha256"`
			EvidenceSampleSHA256 string `json:"evidence_sample_sha256"`
		}
		if err != nil || decodeStrictWorkerJSON([]byte(message), &result) != nil || result.SchemaVersion != "recovery_projection_job_v1" || result.Kind != wantKind || result.ProjectionSHA256 != hex.EncodeToString(plan.ProjectionDigest[:]) || result.EvidenceSampleSHA256 != hex.EncodeToString(plan.EvidenceSampleDigest[:]) {
			return [sha256.Size]byte{}, errWorkerExecution
		}
	}
	return plan.ProjectionDigest, nil
}

func (api *productionRecoveryKubernetesAPI) Cleanup(ctx context.Context, plan recoveryKubernetesPlan, namespaceUID string) (apiserver.RecoveryCleanupEvidence, error) {
	if !validRecoveryKubernetesAPIPlan(plan, api.config.NeonCIDRs) || namespaceUID != "" && !recoveryKubernetesUIDPattern.MatchString(namespaceUID) {
		return apiserver.RecoveryCleanupEvidence{}, errWorkerExecution
	}
	path := "/api/v1/namespaces/" + plan.Namespace
	body, status, err := api.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return api.failedCleanupEvidence(ctx, plan, namespaceUID)
	}
	if status != http.StatusNotFound {
		var namespace recoveryKubernetesResource
		if status != http.StatusOK || json.Unmarshal(body, &namespace) != nil || !exactRecoveryKubernetesResource(namespace, "v1", "Namespace", plan.Namespace, "", namespaceUID, plan.Labels) {
			return api.failedCleanupEvidence(ctx, plan, namespaceUID)
		}
		if namespaceUID == "" {
			namespaceUID = namespace.Metadata.UID
		}
		options := map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "gracePeriodSeconds": 0, "propagationPolicy": "Foreground", "preconditions": map[string]string{"uid": namespaceUID}}
		encoded, _ := json.Marshal(options)
		if _, status, err = api.request(ctx, http.MethodDelete, path, encoded); err != nil || status != http.StatusOK && status != http.StatusAccepted {
			return api.failedCleanupEvidence(ctx, plan, namespaceUID)
		}
	}
	for {
		_, status, err = api.request(ctx, http.MethodGet, path, nil)
		if err == nil && status == http.StatusNotFound {
			break
		}
		if err != nil || status != http.StatusOK || !waitRecoveryKubernetes(ctx, api.config.PollInterval) {
			return api.failedCleanupEvidence(ctx, plan, namespaceUID)
		}
	}
	evidenceBody, _ := json.Marshal(map[string]string{"namespace_uid": namespaceUID, "scope_digest": plan.Labels["zasp.io/recovery-scope"], "state": "deleted"})
	evidence, err := api.putEvidence(ctx, plan, "cleanup", "recovery_cleanup_v1", evidenceBody)
	if err != nil {
		return apiserver.RecoveryCleanupEvidence{}, errWorkerExecution
	}
	return apiserver.RecoveryCleanupEvidence{State: "deleted", Evidence: evidence}, nil
}

func (api *productionRecoveryKubernetesAPI) failedCleanupEvidence(ctx context.Context, plan recoveryKubernetesPlan, namespaceUID string) (apiserver.RecoveryCleanupEvidence, error) {
	body, _ := json.Marshal(map[string]string{"namespace_uid": namespaceUID, "scope_digest": plan.Labels["zasp.io/recovery-scope"], "state": "failed"})
	evidence, err := api.putEvidence(ctx, plan, "cleanup", "recovery_cleanup_v1", body)
	if err != nil {
		return apiserver.RecoveryCleanupEvidence{}, errWorkerExecution
	}
	return apiserver.RecoveryCleanupEvidence{State: "failed", Evidence: evidence}, errWorkerExecution
}

func (api *productionRecoveryKubernetesAPI) runJob(ctx context.Context, plan recoveryKubernetesPlan, namespaceUID string, job recoveryKubernetesJob) (string, error) {
	if !recoveryKubernetesUIDPattern.MatchString(namespaceUID) || job.Namespace != plan.Namespace {
		return "", errWorkerExecution
	}
	manifest := recoveryKubernetesJobManifest(job, plan, api.config.RunnerImage, api.config.ServiceAccount)
	created, err := api.createOrReconcile(ctx, "/apis/batch/v1/namespaces/"+plan.Namespace+"/jobs", "/apis/batch/v1/namespaces/"+plan.Namespace+"/jobs/"+job.Name, manifest, "batch/v1", "Job", job.Name, plan.Namespace, plan.Labels)
	if err != nil || !recoveryKubernetesUIDPattern.MatchString(created.Metadata.UID) {
		return "", errWorkerExecution
	}
	jobPath := "/apis/batch/v1/namespaces/" + plan.Namespace + "/jobs/" + job.Name
	for {
		body, status, requestErr := api.request(ctx, http.MethodGet, jobPath, nil)
		var value recoveryKubernetesResource
		var jobStatus recoveryKubernetesJobStatus
		if requestErr != nil || status != http.StatusOK || json.Unmarshal(body, &value) != nil || json.Unmarshal(value.Status, &jobStatus) != nil || !exactRecoveryKubernetesResource(value, "batch/v1", "Job", job.Name, plan.Namespace, created.Metadata.UID, plan.Labels) || jobStatus.Failed > 0 {
			return "", errWorkerExecution
		}
		complete := false
		for _, condition := range jobStatus.Conditions {
			if condition.Type == "Complete" && condition.Status == "True" {
				complete = true
			}
			if condition.Type == "Failed" && condition.Status == "True" {
				return "", errWorkerExecution
			}
		}
		if complete && jobStatus.Succeeded == 1 && jobStatus.Failed == 0 {
			break
		}
		if !waitRecoveryKubernetes(ctx, api.config.PollInterval) {
			return "", errWorkerExecution
		}
	}
	query := url.Values{"labelSelector": {"job-name=" + job.Name}}.Encode()
	body, status, err := api.request(ctx, http.MethodGet, "/api/v1/namespaces/"+plan.Namespace+"/pods?"+query, nil)
	var pods recoveryKubernetesPodList
	if err != nil || status != http.StatusOK || json.Unmarshal(body, &pods) != nil || pods.APIVersion != "v1" || pods.Kind != "PodList" || pods.Metadata.Continue != "" || len(pods.Items) != 1 {
		return "", errWorkerExecution
	}
	pod := pods.Items[0]
	if pod.APIVersion != "v1" || pod.Kind != "Pod" || !recoveryKubernetesUIDPattern.MatchString(pod.Metadata.UID) || pod.Metadata.Namespace != plan.Namespace || pod.Metadata.Labels["app.kubernetes.io/managed-by"] != plan.Labels["app.kubernetes.io/managed-by"] || pod.Metadata.Labels["zasp.io/recovery-id"] != plan.RestoreID || pod.Metadata.Labels["zasp.io/recovery-scope"] != plan.Labels["zasp.io/recovery-scope"] || pod.Metadata.Labels["job-name"] != job.Name || pod.Status.Phase != "Succeeded" || len(pod.Status.ContainerStatuses) != 1 {
		return "", errWorkerExecution
	}
	container := pod.Status.ContainerStatuses[0]
	if container.Name != "runner" || container.Ready || container.RestartCount != 0 || container.State.Terminated == nil || container.State.Terminated.ExitCode != 0 || container.State.Terminated.Reason != "Completed" || len(container.State.Terminated.Message) < 2 || len(container.State.Terminated.Message) > 4096 {
		return "", errWorkerExecution
	}
	return container.State.Terminated.Message, nil
}

func (api *productionRecoveryKubernetesAPI) createOrReconcile(ctx context.Context, collectionPath, itemPath string, manifest any, apiVersion, kind, name, namespace string, labels map[string]string) (recoveryKubernetesResource, error) {
	encoded, err := json.Marshal(manifest)
	if err != nil || len(encoded) > 64<<10 {
		return recoveryKubernetesResource{}, errWorkerExecution
	}
	body, status, err := api.request(ctx, http.MethodPost, collectionPath, encoded)
	if err != nil || status != http.StatusCreated {
		body, status, err = api.request(ctx, http.MethodGet, itemPath, nil)
	}
	var value recoveryKubernetesResource
	if err != nil || status != http.StatusCreated && status != http.StatusOK || json.Unmarshal(body, &value) != nil || !exactRecoveryKubernetesResource(value, apiVersion, kind, name, namespace, "", labels) || !exactRecoveryKubernetesCreatedBody(value, encoded) {
		return recoveryKubernetesResource{}, errWorkerExecution
	}
	return value, nil
}

func (api *productionRecoveryKubernetesAPI) putEvidence(ctx context.Context, plan recoveryKubernetesPlan, section, schema string, body []byte) (apiserver.RecoveryArtifactLocator, error) {
	reference, err := recoverySectionReference(plan.Scope, plan.RestoreID, section)
	if err != nil || len(body) < 2 || len(body) > 64<<10 {
		return apiserver.RecoveryArtifactLocator{}, errWorkerExecution
	}
	artifact, err := api.config.Store.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: plan.Scope, Reference: reference}, MediaType: "application/json", Body: append([]byte(nil), body...)})
	if err != nil || artifact.Scope != plan.Scope || artifact.Reference != reference || artifact.VersionID == "" || artifact.MediaType != "application/json" || artifact.Size != int64(len(body)) || artifact.SHA256 != sha256.Sum256(body) || !bytes.Equal(artifact.Body, body) {
		return apiserver.RecoveryArtifactLocator{}, errWorkerExecution
	}
	objectReference, err := api.config.Store.ObjectReference(artifact.Locator)
	if err != nil {
		return apiserver.RecoveryArtifactLocator{}, errWorkerExecution
	}
	return apiserver.RecoveryArtifactLocator{Reference: objectReference, VersionID: artifact.VersionID, SHA256: hex.EncodeToString(artifact.SHA256[:]), SizeBytes: artifact.Size, MediaType: artifact.MediaType, Schema: schema}, nil
}

func (api *productionRecoveryKubernetesAPI) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	if api == nil || api.config.Transport == nil || ctx == nil || ctx.Err() != nil {
		return nil, 0, errWorkerExecution
	}
	return api.config.Transport.Request(ctx, method, path, body)
}

func validRecoveryKubernetesAPIPlan(plan recoveryKubernetesPlan, cidrs []string) bool {
	if !regexp.MustCompile(`^zasp-recovery-[a-f0-9]{32}$`).MatchString(plan.Namespace) || plan.RestoreID == "" || plan.Scope.Validate() != nil || !validRecoveryTargetEnvironment(plan.TargetEnvironment, plan.Scope) || !strings.HasPrefix(plan.BranchID, "br-") || !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.neon\.tech$`).MatchString(plan.BranchHost) || !validRecoveryCounts(plan.ExpectedCounts) || plan.ProjectionDigest == ([sha256.Size]byte{}) || plan.EvidenceSampleDigest == ([sha256.Size]byte{}) || plan.NetworkPolicy.Name != "recovery-deny-by-default" || len(plan.Jobs) != 3 || !validRecoveryNeonCIDRs(cidrs) {
		return false
	}
	wantLabels := map[string]string{"app.kubernetes.io/managed-by": "agentsec-recovery", "zasp.io/recovery-id": plan.RestoreID, "zasp.io/recovery-scope": plan.Labels["zasp.io/recovery-scope"]}
	if len(plan.Labels["zasp.io/recovery-scope"]) != 16 || !reflect.DeepEqual(plan.Labels, wantLabels) || !reflect.DeepEqual(plan.NetworkPolicy.Labels, wantLabels) {
		return false
	}
	for index, kind := range []string{"postgres-validation", "graph-projection", "search-projection"} {
		job := plan.Jobs[index]
		if job.Kind != kind || job.Namespace != plan.Namespace || job.Scope != plan.Scope || job.TargetEnvironment != plan.TargetEnvironment || job.BranchHost != plan.BranchHost || !reflect.DeepEqual(job.Labels, wantLabels) {
			return false
		}
	}
	return true
}

func exactRecoveryKubernetesResource(value recoveryKubernetesResource, apiVersion, kind, name, namespace, uid string, labels map[string]string) bool {
	return value.APIVersion == apiVersion && value.Kind == kind && value.Metadata.Name == name && value.Metadata.Namespace == namespace && (uid == "" || value.Metadata.UID == uid) && recoveryKubernetesUIDPattern.MatchString(value.Metadata.UID) && reflect.DeepEqual(value.Metadata.Labels, labels)
}

func exactRecoveryKubernetesCreatedBody(actual recoveryKubernetesResource, requested []byte) bool {
	var expected struct {
		Spec       json.RawMessage   `json:"spec"`
		StringData map[string]string `json:"stringData"`
		Type       string            `json:"type"`
	}
	if json.Unmarshal(requested, &expected) != nil {
		return false
	}
	if len(expected.Spec) > 0 {
		var expectedSpec, actualSpec any
		if len(actual.Spec) == 0 || json.Unmarshal(expected.Spec, &expectedSpec) != nil || json.Unmarshal(actual.Spec, &actualSpec) != nil || !reflect.DeepEqual(expectedSpec, actualSpec) {
			return false
		}
	}
	if expected.Type != "" && actual.Type != expected.Type {
		return false
	}
	if expected.StringData != nil {
		if len(actual.Data) != len(expected.StringData) {
			return false
		}
		for key, value := range expected.StringData {
			decoded, err := base64.StdEncoding.Strict().DecodeString(actual.Data[key])
			if err != nil || string(decoded) != value {
				clear(decoded)
				return false
			}
			clear(decoded)
		}
	}
	return true
}

func recoveryKubernetesNetworkPolicyManifest(plan recoveryKubernetesPlan, cidrs []string) map[string]any {
	egress := make([]map[string]any, len(cidrs))
	for index, cidr := range cidrs {
		egress[index] = map[string]any{"to": []map[string]any{{"ipBlock": map[string]string{"cidr": cidr}}}, "ports": []map[string]any{{"port": 5432, "protocol": "TCP"}}}
	}
	return map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": map[string]any{"name": plan.NetworkPolicy.Name, "namespace": plan.Namespace, "labels": plan.Labels}, "spec": map[string]any{"podSelector": map[string]any{}, "policyTypes": []string{"Ingress", "Egress"}, "ingress": []any{}, "egress": egress}}
}

func recoveryKubernetesJobManifest(job recoveryKubernetesJob, plan recoveryKubernetesPlan, image, serviceAccount string) map[string]any {
	environment := []map[string]any{
		{"name": "ZASP_WORKER_MODE", "value": "recovery-" + job.Kind}, {"name": "ZASP_RECOVERY_ORGANIZATION_ID", "value": job.Scope.OrganizationID().String()}, {"name": "ZASP_RECOVERY_WORKSPACE_ID", "value": job.Scope.WorkspaceID().String()}, {"name": "ZASP_RECOVERY_ENVIRONMENT_ID", "value": job.Scope.EnvironmentID().String()}, {"name": "ZASP_RECOVERY_TARGET_ENVIRONMENT", "value": job.TargetEnvironment}, {"name": "ZASP_RECOVERY_PROJECTION_SHA256", "value": hex.EncodeToString(plan.ProjectionDigest[:])}, {"name": "ZASP_RECOVERY_EVIDENCE_SAMPLE_SHA256", "value": hex.EncodeToString(plan.EvidenceSampleDigest[:])}, {"name": "ZASP_RECOVERY_TARGET_DIRECTORY", "value": "/var/lib/zasp-recovery"},
		{"name": "ZASP_POSTGRES_DSN", "valueFrom": map[string]any{"secretKeyRef": map[string]string{"name": "recovery-database", "key": "dsn"}}},
		{"name": "ZASP_RECOVERY_BRANCH_IP", "valueFrom": map[string]any{"secretKeyRef": map[string]string{"name": "recovery-database", "key": "branch_ip"}}},
	}
	containerSecurity := map[string]any{"allowPrivilegeEscalation": false, "capabilities": map[string]any{"drop": []string{"ALL"}}, "readOnlyRootFilesystem": true, "runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532}
	resources := map[string]any{"requests": map[string]string{"cpu": "250m", "memory": "256Mi", "ephemeral-storage": "512Mi"}, "limits": map[string]string{"cpu": "1", "memory": "1Gi", "ephemeral-storage": "2Gi"}}
	return map[string]any{"apiVersion": "batch/v1", "kind": "Job", "metadata": map[string]any{"name": job.Name, "namespace": job.Namespace, "labels": job.Labels}, "spec": map[string]any{"activeDeadlineSeconds": 300, "backoffLimit": 0, "completions": 1, "parallelism": 1, "ttlSecondsAfterFinished": 300, "template": map[string]any{"metadata": map[string]any{"labels": job.Labels}, "spec": map[string]any{"automountServiceAccountToken": false, "enableServiceLinks": false, "restartPolicy": "Never", "serviceAccountName": serviceAccount, "terminationGracePeriodSeconds": 10, "securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532, "seccompProfile": map[string]string{"type": "RuntimeDefault"}}, "volumes": []map[string]any{{"name": "recovery-target", "emptyDir": map[string]any{"sizeLimit": "256Mi"}}}, "containers": []map[string]any{{"name": "runner", "image": image, "imagePullPolicy": "IfNotPresent", "command": []string{"/app/agentsec-worker"}, "env": environment, "resources": resources, "securityContext": containerSecurity, "volumeMounts": []map[string]any{{"name": "recovery-target", "mountPath": "/var/lib/zasp-recovery"}}, "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File"}}}}}}
}

func recoveryBranchDSN(source, branchHost string) (string, error) {
	parsed, err := url.Parse(source)
	if err != nil || parsed.User == nil || parsed.Path == "" || parsed.Query().Get("sslmode") != "verify-full" || !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.neon\.tech$`).MatchString(branchHost) {
		return "", errWorkerExecution
	}
	parsed.Host = net.JoinHostPort(branchHost, "5432")
	return parsed.String(), nil
}

func (api *productionRecoveryKubernetesAPI) resolveBranch(ctx context.Context, host string) (string, error) {
	if api == nil || api.config.Resolve == nil || ctx == nil || ctx.Err() != nil {
		return "", errWorkerExecution
	}
	addresses, err := api.config.Resolve(ctx, host)
	if err != nil || len(addresses) < 1 || len(addresses) > 8 {
		return "", errWorkerExecution
	}
	allowed := make([]*net.IPNet, len(api.config.NeonCIDRs))
	for index, cidr := range api.config.NeonCIDRs {
		_, network, parseErr := net.ParseCIDR(cidr)
		if parseErr != nil {
			return "", errWorkerExecution
		}
		allowed[index] = network
	}
	values := make([]string, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		if address == nil {
			return "", errWorkerExecution
		}
		permitted := false
		for _, network := range allowed {
			if network.Contains(address) {
				permitted = true
				break
			}
		}
		value := address.String()
		if !permitted || value == "" {
			return "", errWorkerExecution
		}
		if _, duplicate := seen[value]; !duplicate {
			seen[value] = struct{}{}
			values = append(values, value)
		}
	}
	sort.Strings(values)
	return values[0], nil
}

func waitRecoveryKubernetes(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

var _ recoveryKubernetesTransport = (*recoveryKubernetesHTTPTransport)(nil)
var _ recoveryKubernetesAPI = (*productionRecoveryKubernetesAPI)(nil)
