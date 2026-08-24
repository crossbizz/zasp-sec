package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const attackLabKubernetesResponseLimit = 64 << 10

var attackLabKubernetesLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9_.]{0,61}[a-z0-9])?$`)

type productionAttackLabKubernetesAPI struct {
	endpoint  string
	tokenFile string
	client    *http.Client
	transport *http.Transport
}

func newProductionAttackLabKubernetesAPI(endpoint, tokenFile, caFile string, timeout time.Duration) (*productionAttackLabKubernetesAPI, error) {
	if endpoint != "https://kubernetes.default.svc" || tokenFile != "/var/run/secrets/kubernetes.io/serviceaccount/token" || caFile != "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" || timeout < time.Second || timeout > 30*time.Second {
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
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "kubernetes.default.svc"}, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 64 << 10,
	}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }}
	return &productionAttackLabKubernetesAPI{endpoint: endpoint, tokenFile: tokenFile, client: client, transport: transport}, nil
}

func (api *productionAttackLabKubernetesAPI) Close() error {
	if api != nil && api.transport != nil {
		api.transport.CloseIdleConnections()
	}
	return nil
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

type attackLabKubernetesJobManifest struct {
	APIVersion string                        `json:"apiVersion"`
	Kind       string                        `json:"kind"`
	Metadata   attackLabKubernetesObjectMeta `json:"metadata"`
	Spec       attackLabKubernetesJobSpec    `json:"spec"`
}

type attackLabKubernetesJobSpec struct {
	ActiveDeadlineSeconds   int64                          `json:"activeDeadlineSeconds"`
	BackoffLimit            int32                          `json:"backoffLimit"`
	Completions             int32                          `json:"completions"`
	Parallelism             int32                          `json:"parallelism"`
	TTLSecondsAfterFinished int32                          `json:"ttlSecondsAfterFinished"`
	Template                attackLabKubernetesPodTemplate `json:"template"`
}

type attackLabKubernetesPodTemplate struct {
	Metadata attackLabKubernetesObjectMeta `json:"metadata"`
	Spec     attackLabKubernetesPodSpec    `json:"spec"`
}

type attackLabKubernetesPodSpec struct {
	ServiceAccountName            string                         `json:"serviceAccountName"`
	AutomountServiceAccountToken  bool                           `json:"automountServiceAccountToken"`
	RestartPolicy                 string                         `json:"restartPolicy"`
	EnableServiceLinks            bool                           `json:"enableServiceLinks"`
	TerminationGracePeriodSeconds int64                          `json:"terminationGracePeriodSeconds"`
	HostNetwork                   bool                           `json:"hostNetwork"`
	HostPID                       bool                           `json:"hostPID"`
	HostIPC                       bool                           `json:"hostIPC"`
	Containers                    []attackLabKubernetesContainer `json:"containers"`
	Volumes                       []attackLabKubernetesVolume    `json:"volumes"`
}

type attackLabKubernetesContainer struct {
	Name                     string                             `json:"name"`
	Image                    string                             `json:"image"`
	ImagePullPolicy          string                             `json:"imagePullPolicy"`
	Command                  []string                           `json:"command"`
	Args                     []string                           `json:"args"`
	Env                      []attackLabKubernetesEnv           `json:"env"`
	SecurityContext          attackLabKubernetesSecurityContext `json:"securityContext"`
	Resources                attackLabKubernetesResources       `json:"resources"`
	VolumeMounts             []attackLabKubernetesVolumeMount   `json:"volumeMounts"`
	TerminationMessagePath   string                             `json:"terminationMessagePath"`
	TerminationMessagePolicy string                             `json:"terminationMessagePolicy"`
}

type attackLabKubernetesEnv struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type attackLabKubernetesSecurityContext struct {
	AllowPrivilegeEscalation bool                            `json:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   bool                            `json:"readOnlyRootFilesystem"`
	RunAsNonRoot             bool                            `json:"runAsNonRoot"`
	RunAsUser                int64                           `json:"runAsUser"`
	RunAsGroup               int64                           `json:"runAsGroup"`
	Capabilities             attackLabKubernetesCapabilities `json:"capabilities"`
}

type attackLabKubernetesCapabilities struct {
	Drop []string `json:"drop"`
}

type attackLabKubernetesResources struct {
	Requests map[string]string `json:"requests"`
	Limits   map[string]string `json:"limits"`
}

type attackLabKubernetesVolume struct {
	Name      string                              `json:"name"`
	ConfigMap *attackLabKubernetesConfigMapVolume `json:"configMap,omitempty"`
}

type attackLabKubernetesConfigMapVolume struct {
	Name        string `json:"name"`
	DefaultMode int32  `json:"defaultMode"`
}

type attackLabKubernetesVolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly"`
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
	APIVersion                   string                        `json:"apiVersion"`
	Kind                         string                        `json:"kind"`
	Metadata                     attackLabKubernetesObjectMeta `json:"metadata"`
	AutomountServiceAccountToken *bool                         `json:"automountServiceAccountToken"`
}

type attackLabKubernetesConfigMap struct {
	APIVersion string                        `json:"apiVersion"`
	Kind       string                        `json:"kind"`
	Metadata   attackLabKubernetesObjectMeta `json:"metadata"`
	Data       map[string]string             `json:"data"`
}

type attackLabKubernetesJobRead struct {
	APIVersion string                        `json:"apiVersion"`
	Kind       string                        `json:"kind"`
	Metadata   attackLabKubernetesObjectMeta `json:"metadata"`
	Status     struct {
		Succeeded  int32 `json:"succeeded"`
		Failed     int32 `json:"failed"`
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
	} `json:"status"`
}

type attackLabKubernetesPodList struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []attackLabKubernetesPod `json:"items"`
}

type attackLabKubernetesPod struct {
	APIVersion string                        `json:"apiVersion"`
	Kind       string                        `json:"kind"`
	Metadata   attackLabKubernetesObjectMeta `json:"metadata"`
	Spec       struct {
		NodeName   string `json:"nodeName"`
		Containers []struct {
			Name  string `json:"name"`
			Image string `json:"image"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase             string `json:"phase"`
		ContainerStatuses []struct {
			Name         string `json:"name"`
			Image        string `json:"image"`
			ImageID      string `json:"imageID"`
			Ready        bool   `json:"ready"`
			RestartCount int32  `json:"restartCount"`
			State        struct {
				Terminated *struct {
					ExitCode int32  `json:"exitCode"`
					Reason   string `json:"reason"`
					Message  string `json:"message"`
				} `json:"terminated"`
			} `json:"state"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

type attackLabKubernetesRunnerOutcome struct {
	SchemaVersion     string `json:"schema_version"`
	CriterionObserved bool   `json:"criterion_observed"`
	CanaryTouched     bool   `json:"canary_touched"`
	GatewayEvidence   string `json:"gateway_evidence"`
	EgressEvidence    string `json:"egress_evidence"`
	CloudEvidence     string `json:"cloud_evidence"`
}

type attackLabKubernetesDeleteOptions struct {
	APIVersion         string `json:"apiVersion"`
	Kind               string `json:"kind"`
	GracePeriodSeconds int64  `json:"gracePeriodSeconds"`
	PropagationPolicy  string `json:"propagationPolicy"`
	Preconditions      struct {
		UID string `json:"uid"`
	} `json:"preconditions"`
}

func (api *productionAttackLabKubernetesAPI) Ready(ctx context.Context) error {
	if api == nil || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	checks := []struct {
		path string
		out  any
	}{
		{path: "/version", out: &attackLabKubernetesVersion{}},
		{path: "/api/v1/namespaces/zasp-attack-lab", out: &attackLabKubernetesNamespace{}},
		{path: "/api/v1/namespaces/zasp-attack-lab/serviceaccounts/agentsec-attack-lab-runner", out: &attackLabKubernetesServiceAccount{}},
		{path: "/api/v1/namespaces/zasp-attack-lab/configmaps/agentsec-attack-lab-proxy-ca", out: &attackLabKubernetesConfigMap{}},
	}
	for _, check := range checks {
		body, status, err := api.do(ctx, http.MethodGet, check.path, nil)
		if err != nil || status != http.StatusOK || !decodeAttackLabKubernetesJSON(body, check.out) {
			return errRuntimeUnavailable
		}
	}
	version := checks[0].out.(*attackLabKubernetesVersion)
	namespace := checks[1].out.(*attackLabKubernetesNamespace)
	serviceAccount := checks[2].out.(*attackLabKubernetesServiceAccount)
	configMap := checks[3].out.(*attackLabKubernetesConfigMap)
	if version.Major != "1" || !regexp.MustCompile(`^[0-9]{1,3}[+]?$`).MatchString(version.Minor) || namespace.APIVersion != "v1" || namespace.Kind != "Namespace" || namespace.Metadata.Name != "zasp-attack-lab" || !attackLabKubernetesUIDPattern.MatchString(namespace.Metadata.UID) || namespace.Metadata.Labels["zasp.io/execution"] != "attack-lab" || namespace.Status.Phase != "Active" || serviceAccount.APIVersion != "v1" || serviceAccount.Kind != "ServiceAccount" || serviceAccount.Metadata.Name != "agentsec-attack-lab-runner" || serviceAccount.Metadata.Namespace != "zasp-attack-lab" || !attackLabKubernetesUIDPattern.MatchString(serviceAccount.Metadata.UID) || serviceAccount.AutomountServiceAccountToken == nil || *serviceAccount.AutomountServiceAccountToken || configMap.APIVersion != "v1" || configMap.Kind != "ConfigMap" || configMap.Metadata.Name != "agentsec-attack-lab-proxy-ca" || configMap.Metadata.Namespace != "zasp-attack-lab" || !attackLabKubernetesUIDPattern.MatchString(configMap.Metadata.UID) || len(configMap.Data) != 1 || !validDiscoveryCABundle([]byte(configMap.Data["proxy-ca.crt"])) {
		return errRuntimeUnavailable
	}
	return nil
}

func (api *productionAttackLabKubernetesAPI) Collect(ctx context.Context, namespace, name, uid string, timeout time.Duration) (attackLabClusterOutcome, error) {
	if api == nil || ctx == nil || ctx.Err() != nil || namespace != "zasp-attack-lab" || !regexp.MustCompile(`^zasp-attack-lab-[a-f0-9]{32}$`).MatchString(name) || !attackLabKubernetesUIDPattern.MatchString(uid) || timeout < time.Second || timeout > 5*time.Minute {
		return attackLabClusterOutcome{}, &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	jobPath := fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs/%s", namespace, name)
	for {
		body, status, err := api.do(bounded, http.MethodGet, jobPath, nil)
		if err != nil {
			return attackLabClusterOutcome{}, err
		}
		if status != http.StatusOK {
			return attackLabClusterOutcome{}, attackLabKubernetesStatusError(status, "outcome_unknown")
		}
		var job attackLabKubernetesJobRead
		if !decodeAttackLabKubernetesJSON(body, &job) || job.APIVersion != "batch/v1" || job.Kind != "Job" || job.Metadata.Name != name || job.Metadata.Namespace != namespace || job.Metadata.UID != uid {
			return attackLabClusterOutcome{}, &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
		}
		complete, failed := attackLabKubernetesJobCompletion(job)
		if failed {
			return attackLabClusterOutcome{}, &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
		}
		if complete {
			return api.collectCompletedPod(bounded, namespace, name, uid)
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-bounded.Done():
			timer.Stop()
			return attackLabClusterOutcome{}, &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
		case <-timer.C:
		}
	}
}

func (api *productionAttackLabKubernetesAPI) collectCompletedPod(ctx context.Context, namespace, name, uid string) (attackLabClusterOutcome, error) {
	query := url.Values{"labelSelector": []string{"job-name=" + name}}.Encode()
	body, status, err := api.do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/pods?%s", namespace, query), nil)
	if err != nil {
		return attackLabClusterOutcome{}, err
	}
	var list attackLabKubernetesPodList
	if status != http.StatusOK || !decodeAttackLabKubernetesJSON(body, &list) || list.APIVersion != "v1" || list.Kind != "PodList" || list.Metadata.Continue != "" || len(list.Items) != 1 {
		return attackLabClusterOutcome{}, &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	pod := list.Items[0]
	if pod.APIVersion != "v1" || pod.Kind != "Pod" || pod.Metadata.Namespace != namespace || !attackLabKubernetesUIDPattern.MatchString(pod.Metadata.UID) || pod.Metadata.Labels["job-name"] != name || pod.Metadata.Labels["zasp.io/execution"] != "attack-lab" || pod.Metadata.Labels["eks.amazonaws.com/fargate-profile"] != "agentsec-attack-lab" || !strings.HasPrefix(pod.Spec.NodeName, "fargate-") || len(pod.Metadata.OwnerReferences) != 1 || pod.Metadata.OwnerReferences[0] != (attackLabKubernetesOwnerReference{APIVersion: "batch/v1", Kind: "Job", Name: name, UID: uid, Controller: true}) || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != "runner" || len(pod.Status.ContainerStatuses) != 1 {
		return attackLabClusterOutcome{}, &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	container := pod.Status.ContainerStatuses[0]
	wantImage := pod.Spec.Containers[0].Image
	if pod.Status.Phase != "Succeeded" || container.Name != "runner" || container.Image != wantImage || container.ImageID != wantImage || container.Ready || container.RestartCount != 0 || container.State.Terminated == nil || container.State.Terminated.ExitCode != 0 || container.State.Terminated.Reason != "Completed" || !regexp.MustCompile(`@sha256:[a-f0-9]{64}$`).MatchString(wantImage) {
		return attackLabClusterOutcome{}, &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	var runner attackLabKubernetesRunnerOutcome
	if len(container.State.Terminated.Message) > 4096 || !decodeExactAttackLabKubernetesJSON([]byte(container.State.Terminated.Message), &runner) || runner.SchemaVersion != "attack-lab-outcome-v1" || !validAttackLabProviderText(runner.GatewayEvidence, 256) || !validAttackLabProviderText(runner.EgressEvidence, 256) || !validAttackLabProviderText(runner.CloudEvidence, 256) {
		return attackLabClusterOutcome{}, &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	return attackLabClusterOutcome{CriterionObserved: runner.CriterionObserved, CanaryTouched: runner.CanaryTouched, GatewayEvidence: runner.GatewayEvidence, EgressEvidence: runner.EgressEvidence, KubernetesEvidence: "job completed on EKS Fargate with the exact runner image", CloudEvidence: runner.CloudEvidence}, nil
}

func (api *productionAttackLabKubernetesAPI) Destroy(ctx context.Context, namespace, name, uid string) error {
	if api == nil || ctx == nil || ctx.Err() != nil || namespace != "zasp-attack-lab" || !regexp.MustCompile(`^zasp-attack-lab-[a-f0-9]{32}$`).MatchString(name) || !attackLabKubernetesUIDPattern.MatchString(uid) {
		return &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	path := fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs/%s", namespace, name)
	body, status, err := api.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	var job attackLabKubernetesJobRead
	if status != http.StatusOK || !decodeAttackLabKubernetesJSON(body, &job) || job.APIVersion != "batch/v1" || job.Kind != "Job" || job.Metadata.Name != name || job.Metadata.Namespace != namespace || job.Metadata.UID != uid {
		return &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	options := attackLabKubernetesDeleteOptions{APIVersion: "v1", Kind: "DeleteOptions", GracePeriodSeconds: 0, PropagationPolicy: "Background"}
	options.Preconditions.UID = uid
	requestBody, marshalErr := json.Marshal(options)
	if marshalErr != nil {
		return &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	_, status, err = api.do(ctx, http.MethodDelete, path, requestBody)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusAccepted {
		return attackLabKubernetesStatusError(status, "outcome_unknown")
	}
	for {
		_, status, err = api.do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		if status == http.StatusNotFound {
			return nil
		}
		if status != http.StatusOK {
			return attackLabKubernetesStatusError(status, "outcome_unknown")
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
		case <-timer.C:
		}
	}
}

func attackLabKubernetesJobCompletion(job attackLabKubernetesJobRead) (bool, bool) {
	complete, failed := false, job.Status.Failed > 0
	for _, condition := range job.Status.Conditions {
		if condition.Type == "Complete" && condition.Status == "True" {
			complete = true
		}
		if condition.Type == "Failed" && condition.Status == "True" {
			failed = true
		}
	}
	return complete && job.Status.Succeeded == 1 && !failed, failed
}

func (api *productionAttackLabKubernetesAPI) Create(ctx context.Context, job attackLabKubernetesJob) (string, error) {
	if api == nil || ctx == nil || ctx.Err() != nil || !validAttackLabKubernetesAPIJob(job) {
		return "", &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	expectedSideEffects, err := json.Marshal(job.ExpectedSideEffects)
	if err != nil || len(expectedSideEffects) > 4096 {
		return "", &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	manifest := attackLabKubernetesJobManifest{
		APIVersion: "batch/v1",
		Kind:       "Job",
		Metadata:   attackLabKubernetesObjectMeta{Name: job.Name, Namespace: job.Namespace, Labels: cloneAttackLabLabels(job.Labels), Annotations: attackLabKubernetesJobAnnotations(job)},
		Spec: attackLabKubernetesJobSpec{
			ActiveDeadlineSeconds:   int64(job.ActiveDeadlineSeconds),
			BackoffLimit:            0,
			Completions:             1,
			Parallelism:             1,
			TTLSecondsAfterFinished: 60,
			Template: attackLabKubernetesPodTemplate{
				Metadata: attackLabKubernetesObjectMeta{Labels: cloneAttackLabLabels(job.Labels)},
				Spec: attackLabKubernetesPodSpec{
					ServiceAccountName:            job.ServiceAccount,
					AutomountServiceAccountToken:  false,
					RestartPolicy:                 "Never",
					EnableServiceLinks:            false,
					TerminationGracePeriodSeconds: 5,
					Containers: []attackLabKubernetesContainer{{
						Name: "runner", Image: job.Image, ImagePullPolicy: "IfNotPresent", Command: []string{"/app/agentsec-attack-lab-runner"}, Args: []string{"run"},
						Env:             attackLabKubernetesJobEnvironment(job, string(expectedSideEffects)),
						SecurityContext: attackLabKubernetesSecurityContext{AllowPrivilegeEscalation: false, ReadOnlyRootFilesystem: true, RunAsNonRoot: true, RunAsUser: 65532, RunAsGroup: 65532, Capabilities: attackLabKubernetesCapabilities{Drop: []string{"ALL"}}},
						Resources:       attackLabKubernetesResources{Requests: attackLabKubernetesResourceValues(job), Limits: attackLabKubernetesResourceValues(job)},
						VolumeMounts:    []attackLabKubernetesVolumeMount{{Name: "proxy-ca", MountPath: "/var/run/secrets/zasp-attack-lab", ReadOnly: true}}, TerminationMessagePath: "/dev/termination-log", TerminationMessagePolicy: "File",
					}},
					Volumes: []attackLabKubernetesVolume{{Name: "proxy-ca", ConfigMap: &attackLabKubernetesConfigMapVolume{Name: "agentsec-attack-lab-proxy-ca", DefaultMode: 0o444}}},
				},
			},
		},
	}
	requestBody, err := json.Marshal(manifest)
	if err != nil || len(requestBody) > 32<<10 {
		return "", &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	path := fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs", job.Namespace)
	responseBody, status, err := api.do(ctx, http.MethodPost, path, requestBody)
	if err != nil {
		if uid, reconcileErr := api.reconcileCreatedJob(ctx, job); reconcileErr == nil {
			return uid, nil
		}
		return "", err
	}
	if status == http.StatusConflict {
		return api.reconcileCreatedJob(ctx, job)
	}
	if status != http.StatusCreated {
		return "", attackLabKubernetesStatusError(status, "outcome_unknown")
	}
	var created attackLabKubernetesJobManifest
	if !decodeAttackLabKubernetesJSON(responseBody, &created) || created.APIVersion != "batch/v1" || created.Kind != "Job" || created.Metadata.Name != job.Name || created.Metadata.Namespace != job.Namespace || !attackLabKubernetesUIDPattern.MatchString(created.Metadata.UID) {
		return "", &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	return created.Metadata.UID, nil
}

func (api *productionAttackLabKubernetesAPI) reconcileCreatedJob(ctx context.Context, job attackLabKubernetesJob) (string, error) {
	path := fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs/%s", job.Namespace, job.Name)
	body, status, err := api.do(ctx, http.MethodGet, path, nil)
	if err != nil || status != http.StatusOK {
		return "", &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	var existing attackLabKubernetesJobRead
	wantAnnotations := attackLabKubernetesJobAnnotations(job)
	if !decodeAttackLabKubernetesJSON(body, &existing) || existing.APIVersion != "batch/v1" || existing.Kind != "Job" || existing.Metadata.Name != job.Name || existing.Metadata.Namespace != job.Namespace || !attackLabKubernetesUIDPattern.MatchString(existing.Metadata.UID) || len(existing.Metadata.Annotations) != len(wantAnnotations) {
		return "", &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
	}
	for key, value := range wantAnnotations {
		if existing.Metadata.Annotations[key] != value {
			return "", &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
		}
	}
	return existing.Metadata.UID, nil
}

func (api *productionAttackLabKubernetesAPI) do(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	if api == nil || api.client == nil || api.endpoint != "https://kubernetes.default.svc" || api.tokenFile == "" || !strings.HasPrefix(path, "/") {
		return nil, 0, &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	token, err := os.ReadFile(api.tokenFile)
	if err != nil || !validDiscoveryOpaqueSecret(token, 16, 16<<10) {
		clear(token)
		return nil, 0, &attackLabProviderFailure{code: "retryable", retryAfter: 30 * time.Second}
	}
	defer clear(token)
	request, err := http.NewRequestWithContext(ctx, method, api.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(token))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := api.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, &attackLabProviderFailure{code: "outcome_unknown", retryAfter: 30 * time.Second}
		}
		return nil, 0, &attackLabProviderFailure{code: "retryable", retryAfter: 30 * time.Second}
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		return nil, response.StatusCode, &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	limited := io.LimitReader(response.Body, attackLabKubernetesResponseLimit+1)
	responseBody, readErr := io.ReadAll(limited)
	if readErr != nil || len(responseBody) > attackLabKubernetesResponseLimit {
		return nil, response.StatusCode, &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	return responseBody, response.StatusCode, nil
}

func attackLabKubernetesStatusError(status int, ambiguous string) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return &attackLabProviderFailure{code: "denied", retryAfter: 30 * time.Second}
	case status == http.StatusTooManyRequests || status >= 500:
		return &attackLabProviderFailure{code: "retryable", retryAfter: 30 * time.Second}
	case status >= 400 && status < 500:
		return &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	default:
		return &attackLabProviderFailure{code: ambiguous, retryAfter: 30 * time.Second}
	}
}

func validAttackLabKubernetesAPIJob(job attackLabKubernetesJob) bool {
	if job.Namespace != "zasp-attack-lab" || job.ServiceAccount != "agentsec-attack-lab-runner" || job.ProxyEndpoint != "https://agentsec-attack-lab-proxy.zasp.svc.cluster.local/v1/egress" || job.ProxyCAFile != "/var/run/secrets/zasp-attack-lab/proxy-ca.crt" || job.AllowsDirectEgress || job.ActiveDeadlineSeconds != 300 || job.ActiveDeadlineSeconds != job.Limits.TimeoutSeconds || job.Limits.CPU != "500m" || job.Limits.Memory != "1Gi" || job.Limits.EphemeralStorage != "2Gi" || !regexp.MustCompile(`^zasp-attack-lab-[a-f0-9]{32}$`).MatchString(job.Name) || !regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr\.[a-z]{2}(?:-gov)?-[a-z]+-[0-9]\.amazonaws\.com/zasp/attack-lab-runner@sha256:[a-f0-9]{64}$`).MatchString(job.Image) || !validDiscoveryOpaqueSecret([]byte(job.EgressToken), 16, 4096) || !validAttackLabWorkerDestination(job.Destination) || len(job.InputDigest) != 64 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(job.InputDigest) || !validAttackLabProviderText(job.SuccessCriterion, 512) || len(job.ExpectedSideEffects) < 1 || len(job.ExpectedSideEffects) > 16 || len(job.Labels) != 2 || job.Labels["zasp.io/execution"] != "attack-lab" || job.Labels["zasp.io/run-id"] != job.RunID {
		return false
	}
	for key, value := range job.Labels {
		if !strings.HasPrefix(key, "zasp.io/") || !attackLabKubernetesLabelPattern.MatchString(value) {
			return false
		}
	}
	for _, value := range []string{job.OrganizationID, job.WorkspaceID, job.EnvironmentID, job.RunID} {
		if !regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(value) {
			return false
		}
	}
	for _, value := range job.ExpectedSideEffects {
		if !validAttackLabProviderText(value, 256) {
			return false
		}
	}
	return true
}

func attackLabKubernetesJobEnvironment(job attackLabKubernetesJob, sideEffects string) []attackLabKubernetesEnv {
	return []attackLabKubernetesEnv{
		{Name: "ZASP_ATTACK_LAB_ORGANIZATION_ID", Value: job.OrganizationID},
		{Name: "ZASP_ATTACK_LAB_WORKSPACE_ID", Value: job.WorkspaceID},
		{Name: "ZASP_ATTACK_LAB_ENVIRONMENT_ID", Value: job.EnvironmentID},
		{Name: "ZASP_ATTACK_LAB_RUN_ID", Value: job.RunID},
		{Name: "ZASP_ATTACK_LAB_DESTINATION", Value: job.Destination},
		{Name: "ZASP_ATTACK_LAB_SUCCESS_CRITERION", Value: job.SuccessCriterion},
		{Name: "ZASP_ATTACK_LAB_EXPECTED_SIDE_EFFECTS", Value: sideEffects},
		{Name: "ZASP_ATTACK_LAB_INPUT_DIGEST", Value: job.InputDigest},
		{Name: "ZASP_ATTACK_LAB_EGRESS_PROXY", Value: job.ProxyEndpoint},
		{Name: "ZASP_ATTACK_LAB_EGRESS_PROXY_CA_FILE", Value: job.ProxyCAFile},
		{Name: "ZASP_ATTACK_LAB_EGRESS_TOKEN", Value: job.EgressToken},
	}
}

func attackLabKubernetesResourceValues(job attackLabKubernetesJob) map[string]string {
	return map[string]string{"cpu": job.Limits.CPU, "memory": job.Limits.Memory, "ephemeral-storage": job.Limits.EphemeralStorage}
}

func attackLabKubernetesJobAnnotations(job attackLabKubernetesJob) map[string]string {
	return map[string]string{
		"zasp.io/organization-id": job.OrganizationID,
		"zasp.io/workspace-id":    job.WorkspaceID,
		"zasp.io/environment-id":  job.EnvironmentID,
		"zasp.io/run-id":          job.RunID,
		"zasp.io/input-digest":    job.InputDigest,
		"zasp.io/runner-image":    job.Image,
	}
}

func cloneAttackLabLabels(labels map[string]string) map[string]string {
	cloned := make(map[string]string, len(labels))
	for key, value := range labels {
		cloned[key] = value
	}
	return cloned
}

func decodeExactAttackLabKubernetesJSON(raw []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination) == nil && errors.Is(decoder.Decode(new(any)), io.EOF)
}

func decodeAttackLabKubernetesJSON(raw []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	return decoder.Decode(destination) == nil && errors.Is(decoder.Decode(new(any)), io.EOF)
}

var _ attackLabClusterAPI = (*productionAttackLabKubernetesAPI)(nil)
