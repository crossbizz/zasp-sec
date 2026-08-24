package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func TestProductionAttackLabKubernetesAPICreatesExactHardenedJob(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("header.payload.signature-with-bounded-production-length-1234567890"), 0o600); err != nil {
		t.Fatal(err)
	}
	transport := &recordingAttackLabKubernetesTransport{responses: []*http.Response{{
		StatusCode: http.StatusCreated, Header: http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"zasp-attack-lab-7e300001000040008000000000000001","namespace":"zasp-attack-lab","uid":"123e4567-e89b-12d3-a456-426614174000","resourceVersion":"12345","creationTimestamp":"2026-08-24T00:00:00Z"}}`)),
	}}}
	api := &productionAttackLabKubernetesAPI{endpoint: "https://kubernetes.default.svc", tokenFile: tokenPath, client: &http.Client{Transport: transport}}
	job := attackLabKubernetesJob{
		Namespace: "zasp-attack-lab", Name: "zasp-attack-lab-7e300001000040008000000000000001", ServiceAccount: "agentsec-attack-lab-runner",
		Image: "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64), ProxyEndpoint: "https://agentsec-attack-lab-proxy.zasp.svc.cluster.local/v1/egress", ProxyCAFile: "/var/run/secrets/zasp-attack-lab/proxy-ca.crt", EgressToken: "signed.capability",
		OrganizationID: "pid_7d100010-0000-4000-8000-000000000010", WorkspaceID: "pid_7d100011-0000-4000-8000-000000000011", EnvironmentID: "pid_7d100012-0000-4000-8000-000000000012", RunID: "pid_7e300001-0000-4000-8000-000000000001", Destination: "adapter.customer.example",
		SuccessCriterion: "Observe exact canary touch", ExpectedSideEffects: []string{"one bounded canary mutation"}, InputDigest: strings.Repeat("b", 64), Labels: map[string]string{"zasp.io/execution": "attack-lab", "zasp.io/run-id": "pid_7e300001-0000-4000-8000-000000000001"},
		Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, ActiveDeadlineSeconds: 300,
	}
	uid, err := api.Create(context.Background(), job)
	if err != nil || uid != "123e4567-e89b-12d3-a456-426614174000" {
		t.Fatalf("uid=%q err=%v", uid, err)
	}
	if len(transport.requests) != 1 || transport.requests[0].Method != http.MethodPost || transport.requests[0].URL.String() != "https://kubernetes.default.svc/apis/batch/v1/namespaces/zasp-attack-lab/jobs" || transport.requests[0].Header.Get("Authorization") != "Bearer header.payload.signature-with-bounded-production-length-1234567890" {
		t.Fatal("Kubernetes request authority drifted")
	}
	var manifest struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name, Namespace string
			Labels          map[string]string
		} `json:"metadata"`
		Spec struct {
			ActiveDeadlineSeconds, BackoffLimit, Completions, Parallelism int
			TTLSecondsAfterFinished                                       int `json:"ttlSecondsAfterFinished"`
			Template                                                      struct {
				Metadata struct{ Labels map[string]string } `json:"metadata"`
				Spec     struct {
					ServiceAccountName            string
					AutomountServiceAccountToken  *bool
					RestartPolicy                 string
					EnableServiceLinks            *bool
					TerminationGracePeriodSeconds int
					HostNetwork, HostPID, HostIPC bool
					Containers                    []struct {
						Name, Image, ImagePullPolicy string
						Command, Args                []string
						SecurityContext              struct {
							AllowPrivilegeEscalation *bool
							ReadOnlyRootFilesystem   *bool
							RunAsNonRoot             *bool
							RunAsUser, RunAsGroup    int64
							Capabilities             struct{ Drop []string }
						}
						Resources struct{ Requests, Limits map[string]string }
						Env       []struct{ Name, Value string }
					}
				}
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.NewDecoder(bytes.NewReader(transport.requests[0].body)).Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	container := manifest.Spec.Template.Spec.Containers
	if manifest.APIVersion != "batch/v1" || manifest.Kind != "Job" || manifest.Metadata.Name != job.Name || manifest.Metadata.Namespace != job.Namespace || manifest.Spec.ActiveDeadlineSeconds != 300 || manifest.Spec.BackoffLimit != 0 || manifest.Spec.Completions != 1 || manifest.Spec.Parallelism != 1 || manifest.Spec.TTLSecondsAfterFinished != 60 || len(container) != 1 {
		t.Fatal("Job lifecycle authority drifted")
	}
	pod := manifest.Spec.Template.Spec
	runner := container[0]
	if pod.ServiceAccountName != job.ServiceAccount || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || pod.RestartPolicy != "Never" || pod.EnableServiceLinks == nil || *pod.EnableServiceLinks || pod.TerminationGracePeriodSeconds != 5 || pod.HostNetwork || pod.HostPID || pod.HostIPC || runner.Name != "runner" || runner.Image != job.Image || runner.ImagePullPolicy != "IfNotPresent" || strings.Join(runner.Command, " ") != "/app/agentsec-attack-lab-runner" || strings.Join(runner.Args, " ") != "run" {
		t.Fatal("Pod execution authority drifted")
	}
	security := runner.SecurityContext
	if security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation || security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem || security.RunAsNonRoot == nil || !*security.RunAsNonRoot || security.RunAsUser != 65532 || security.RunAsGroup != 65532 || len(security.Capabilities.Drop) != 1 || security.Capabilities.Drop[0] != "ALL" {
		t.Fatal("Pod security authority drifted")
	}
	if runner.Resources.Requests["cpu"] != "500m" || runner.Resources.Requests["memory"] != "1Gi" || runner.Resources.Requests["ephemeral-storage"] != "2Gi" || len(runner.Resources.Requests) != 3 || len(runner.Resources.Limits) != 3 {
		t.Fatal("Pod resources drifted")
	}
}

func TestProductionAttackLabKubernetesAPIReadinessCollectsAndUIDFencesCleanup(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("header.payload.signature-with-bounded-production-length-1234567890"), 0o600); err != nil {
		t.Fatal(err)
	}
	name := "zasp-attack-lab-7e300001000040008000000000000001"
	uid := "123e4567-e89b-12d3-a456-426614174000"
	image := "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64)
	termination := `{"schema_version":"attack-lab-outcome-v1","criterion_observed":true,"canary_touched":true,"gateway_evidence":"proxy authorized one POST","egress_evidence":"destination exact","cloud_evidence":"canary changed"}`
	transport := &recordingAttackLabKubernetesTransport{responses: []*http.Response{
		attackLabKubernetesTestResponse(http.StatusOK, `{"major":"1","minor":"30"}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"zasp-attack-lab","uid":"223e4567-e89b-12d3-a456-426614174000","labels":{"zasp.io/execution":"attack-lab"}},"status":{"phase":"Active"}}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"agentsec-attack-lab-runner","namespace":"zasp-attack-lab","uid":"323e4567-e89b-12d3-a456-426614174000"},"automountServiceAccountToken":false}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"agentsec-attack-lab-proxy-ca","namespace":"zasp-attack-lab","uid":"423e4567-e89b-12d3-a456-426614174000"},"data":{"proxy-ca.crt":`+strconv.Quote(testDiscoveryCACertificatePEM)+`}}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"`+name+`","namespace":"zasp-attack-lab","uid":"`+uid+`"},"status":{"succeeded":1,"failed":0,"conditions":[{"type":"Complete","status":"True"}]}}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"PodList","metadata":{"continue":""},"items":[{"apiVersion":"v1","kind":"Pod","metadata":{"name":"`+name+`-abcde","namespace":"zasp-attack-lab","uid":"523e4567-e89b-12d3-a456-426614174000","labels":{"job-name":"`+name+`","zasp.io/execution":"attack-lab","eks.amazonaws.com/fargate-profile":"agentsec-attack-lab"},"ownerReferences":[{"apiVersion":"batch/v1","kind":"Job","name":"`+name+`","uid":"`+uid+`","controller":true}]},"spec":{"nodeName":"fargate-ip-10-0-1-10","containers":[{"name":"runner","image":"`+image+`"}]},"status":{"phase":"Succeeded","containerStatuses":[{"name":"runner","image":"`+image+`","imageID":"`+image+`","ready":false,"restartCount":0,"state":{"terminated":{"exitCode":0,"reason":"Completed","message":`+strconv.Quote(termination)+`}}}]}}]}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"`+name+`","namespace":"zasp-attack-lab","uid":"`+uid+`"}}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"Status","status":"Success","reason":"Deleted","code":200}`),
		attackLabKubernetesTestResponse(http.StatusNotFound, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}`),
	}}
	api := &productionAttackLabKubernetesAPI{endpoint: "https://kubernetes.default.svc", tokenFile: tokenPath, client: &http.Client{Transport: transport}}
	if err := api.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	outcome, err := api.Collect(context.Background(), "zasp-attack-lab", name, uid, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.CriterionObserved || !outcome.CanaryTouched || outcome.GatewayEvidence != "proxy authorized one POST" || outcome.EgressEvidence != "destination exact" || outcome.KubernetesEvidence != "job completed on EKS Fargate with the exact runner image" || outcome.CloudEvidence != "canary changed" {
		t.Fatalf("unexpected outcome: %#v", outcome)
	}
	if err := api.Destroy(context.Background(), "zasp-attack-lab", name, uid); err != nil {
		t.Fatal(err)
	}
	if len(transport.requests) != 9 {
		t.Fatalf("requests=%d", len(transport.requests))
	}
	deleteRequest := transport.requests[7]
	if deleteRequest.Method != http.MethodDelete || deleteRequest.URL.Path != "/apis/batch/v1/namespaces/zasp-attack-lab/jobs/"+name {
		t.Fatal("cleanup path drifted")
	}
	var options struct {
		APIVersion, Kind, PropagationPolicy string
		GracePeriodSeconds                  int64
		Preconditions                       struct{ UID string }
	}
	if !decodeExactAttackLabKubernetesJSON(deleteRequest.body, &options) || options.APIVersion != "v1" || options.Kind != "DeleteOptions" || options.PropagationPolicy != "Background" || options.GracePeriodSeconds != 0 || options.Preconditions.UID != uid {
		t.Fatal("cleanup UID fence drifted")
	}
}

func TestProductionAttackLabKubernetesAPIReconcilesExactCreateConflictWithoutDuplicate(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("header.payload.signature-with-bounded-production-length-1234567890"), 0o600); err != nil {
		t.Fatal(err)
	}
	job := attackLabKubernetesJob{
		Namespace: "zasp-attack-lab", Name: "zasp-attack-lab-7e300001000040008000000000000001", ServiceAccount: "agentsec-attack-lab-runner",
		Image: "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64), ProxyEndpoint: "https://agentsec-attack-lab-proxy.zasp.svc.cluster.local/v1/egress", ProxyCAFile: "/var/run/secrets/zasp-attack-lab/proxy-ca.crt", EgressToken: "signed.capability.production",
		OrganizationID: "pid_7d100010-0000-4000-8000-000000000010", WorkspaceID: "pid_7d100011-0000-4000-8000-000000000011", EnvironmentID: "pid_7d100012-0000-4000-8000-000000000012", RunID: "pid_7e300001-0000-4000-8000-000000000001", Destination: "adapter.customer.example",
		SuccessCriterion: "Observe exact canary touch", ExpectedSideEffects: []string{"one bounded canary mutation"}, InputDigest: strings.Repeat("b", 64), Labels: map[string]string{"zasp.io/execution": "attack-lab", "zasp.io/run-id": "pid_7e300001-0000-4000-8000-000000000001"},
		Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, ActiveDeadlineSeconds: 300,
	}
	annotations, err := json.Marshal(attackLabKubernetesJobAnnotations(job))
	if err != nil {
		t.Fatal(err)
	}
	uid := "123e4567-e89b-12d3-a456-426614174000"
	transport := &recordingAttackLabKubernetesTransport{responses: []*http.Response{
		attackLabKubernetesTestResponse(http.StatusConflict, `{"apiVersion":"v1","kind":"Status","reason":"AlreadyExists","code":409}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"`+job.Name+`","namespace":"zasp-attack-lab","uid":"`+uid+`","annotations":`+string(annotations)+`}}`),
	}}
	api := &productionAttackLabKubernetesAPI{endpoint: "https://kubernetes.default.svc", tokenFile: tokenPath, client: &http.Client{Transport: transport}}
	got, err := api.Create(context.Background(), job)
	if err != nil || got != uid || len(transport.requests) != 2 || transport.requests[0].Method != http.MethodPost || transport.requests[1].Method != http.MethodGet {
		t.Fatalf("uid=%q requests=%d err=%v", got, len(transport.requests), err)
	}
}

func attackLabKubernetesTestResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

type recordedAttackLabKubernetesRequest struct {
	Method string
	URL    *url.URL
	Header http.Header
	body   []byte
}

type recordingAttackLabKubernetesTransport struct {
	requests  []recordedAttackLabKubernetesRequest
	responses []*http.Response
}

func (transport *recordingAttackLabKubernetesTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	transport.requests = append(transport.requests, recordedAttackLabKubernetesRequest{Method: request.Method, URL: request.URL, Header: request.Header.Clone(), body: body})
	if len(transport.responses) == 0 {
		return nil, errors.New("unexpected Kubernetes request")
	}
	response := transport.responses[0]
	transport.responses = transport.responses[1:]
	response.Request = request
	return response, nil
}
