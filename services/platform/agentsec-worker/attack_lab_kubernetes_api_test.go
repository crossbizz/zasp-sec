package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	job := attackLabKubernetesJob{
		Namespace: "zasp-attack-lab", Name: "zasp-attack-lab-7e300001000040008000000000000001", ServiceAccount: "agentsec-attack-lab-runner",
		Image: "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64), ProxyEndpoint: "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress", ProxyCAFile: "/var/run/secrets/zasp-attack-lab/proxy-ca.crt", EgressToken: "signed.capability",
		OrganizationID: "pid_7d100010-0000-4000-8000-000000000010", WorkspaceID: "pid_7d100011-0000-4000-8000-000000000011", EnvironmentID: "pid_7d100012-0000-4000-8000-000000000012", RunID: "pid_7e300001-0000-4000-8000-000000000001", Destination: "adapter.customer.example",
		SuccessCriterion: "Observe exact canary touch", ExpectedSideEffects: []string{"one bounded canary mutation"}, InputDigest: strings.Repeat("b", 64), Labels: map[string]string{"zasp.io/execution": "attack-lab", "zasp.io/run-id": "pid_7e300001-0000-4000-8000-000000000001"},
		Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, ActiveDeadlineSeconds: 300,
	}
	uid := "123e4567-e89b-12d3-a456-426614174000"
	transport := &recordingAttackLabKubernetesTransport{responses: []*http.Response{
		attackLabKubernetesTestResponse(http.StatusCreated, attackLabKubernetesExactJobResponse(t, job, uid)),
	}}
	api := &productionAttackLabKubernetesAPI{endpoint: "https://kubernetes.default.svc", tokenFile: tokenPath, securityGroupID: "sg-1234abcd", client: &http.Client{Transport: transport}}
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
					SecurityContext struct {
						RunAsNonRoot          *bool
						RunAsUser, RunAsGroup int64
						FSGroup               int64 `json:"fsGroup"`
						SeccompProfile        struct{ Type string }
					}
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
	if pod.ServiceAccountName != job.ServiceAccount || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || pod.RestartPolicy != "Never" || pod.EnableServiceLinks == nil || *pod.EnableServiceLinks || pod.TerminationGracePeriodSeconds != 5 || pod.HostNetwork || pod.HostPID || pod.HostIPC || pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot || pod.SecurityContext.RunAsUser != 65532 || pod.SecurityContext.RunAsGroup != 65532 || pod.SecurityContext.FSGroup != 65532 || pod.SecurityContext.SeccompProfile.Type != "RuntimeDefault" || runner.Name != "runner" || runner.Image != job.Image || runner.ImagePullPolicy != "IfNotPresent" || strings.Join(runner.Command, " ") != "/app/agentsec-attack-lab-runner" || strings.Join(runner.Args, " ") != "run" {
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

func TestProductionAttackLabProviderCancellationUsesUIDFenceAndIdempotentCleanup(t *testing.T) {
	const name = "zasp-attack-lab-7e300001000040008000000000000001"
	const uid = "123e4567-e89b-12d3-a456-426614174000"
	job := func(value string) string {
		return `{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"` + name + `","namespace":"zasp-attack-lab","uid":"` + value + `"}}`
	}
	notFound := func() *http.Response {
		return attackLabKubernetesTestResponse(http.StatusNotFound, `{"kind":"Status","reason":"NotFound","code":404}`)
	}
	absentPods := func() *http.Response {
		return attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"PodList","items":[]}`)
	}
	for _, tc := range []struct {
		name         string
		responses    []*http.Response
		wantErr      bool
		wantRequests int
	}{
		{"owned", []*http.Response{attackLabKubernetesTestResponse(http.StatusOK, job(uid)), attackLabKubernetesTestResponse(http.StatusOK, `{"kind":"Status","status":"Success","code":200}`), notFound(), absentPods(), notFound(), absentPods()}, false, 6},
		{"already absent", []*http.Response{notFound(), absentPods(), notFound(), absentPods()}, false, 4},
		{"foreign UID", []*http.Response{attackLabKubernetesTestResponse(http.StatusOK, job("123e4567-e89b-12d3-a456-426614174001"))}, true, 1},
		{"uncertain termination", []*http.Response{attackLabKubernetesTestResponse(http.StatusOK, job(uid)), attackLabKubernetesTestResponse(http.StatusServiceUnavailable, `{"kind":"Status","reason":"Unavailable","code":503}`)}, true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokenPath := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(tokenPath, []byte("header.payload.signature-with-bounded-production-length-1234567890"), 0o600); err != nil {
				t.Fatal(err)
			}
			transport := &recordingAttackLabKubernetesTransport{responses: tc.responses}
			api := &productionAttackLabKubernetesAPI{endpoint: "https://kubernetes.default.svc", tokenFile: tokenPath, securityGroupID: "sg-1234abcd", client: &http.Client{Transport: transport}}
			provider := &productionAttackLabKubernetesProvider{config: productionAttackLabKubernetesProviderConfig{Cluster: api, Namespace: "zasp-attack-lab", OperationTimeout: time.Second}}
			sandbox := attackLabSandbox{Reference: "k8s://attack-lab/jobs/" + name + "@" + uid}
			if err := provider.Cancel(context.Background(), sandbox); (err != nil) != tc.wantErr {
				t.Fatalf("cancellation err=%v", err)
			}
			if !tc.wantErr {
				if err := provider.Destroy(context.Background(), sandbox); err != nil {
					t.Fatal(err)
				}
			}
			if len(transport.requests) != tc.wantRequests {
				t.Fatalf("requests=%d", len(transport.requests))
			}
			for _, request := range transport.requests {
				if request.URL.Path == "/api/v1/namespaces/zasp-attack-lab/pods" {
					if request.Method != http.MethodGet || request.URL.Query().Get("labelSelector") != "job-name="+name {
						t.Fatal("cleanup dependent scope drifted")
					}
					continue
				}
				if request.URL.Path != "/apis/batch/v1/namespaces/zasp-attack-lab/jobs/"+name {
					t.Fatal("cleanup target drifted")
				}
				if request.Method == http.MethodDelete {
					var options attackLabKubernetesDeleteOptions
					if !decodeExactAttackLabKubernetesJSON(request.body, &options) || options.Preconditions.UID != uid || options.PropagationPolicy != "Foreground" {
						t.Fatal("cancellation lost UID precondition")
					}
				}
			}
		})
	}
}

func TestAttackLabCleanupWaitsForOwnedPodsAfterJobIsAbsent(t *testing.T) {
	const name = "zasp-attack-lab-7e300001000040008000000000000001"
	const uid = "123e4567-e89b-12d3-a456-426614174000"
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("header.payload.signature-with-bounded-production-length-1234567890"), 0o600); err != nil {
		t.Fatal(err)
	}
	owned := `{"apiVersion":"v1","kind":"PodList","items":[{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"zasp-attack-lab","name":"owned-pod","uid":"123e4567-e89b-12d3-a456-426614174002","labels":{"job-name":"` + name + `"},"ownerReferences":[{"apiVersion":"batch/v1","kind":"Job","name":"` + name + `","uid":"` + uid + `","controller":true}]},"status":{"phase":"Running"}}]}`
	for _, tc := range []struct{ name, body string }{
		{"owned pod remains", owned},
		{"foreign owner", strings.Replace(owned, uid, "123e4567-e89b-12d3-a456-426614174009", 1)},
		{"missing list", `{"apiVersion":"v1","kind":"PodList"}`},
		{"null list", `{"apiVersion":"v1","kind":"PodList","items":null}`},
		{"truncated page", `{"apiVersion":"v1","kind":"PodList","metadata":{"continue":"next-page"},"items":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &recordingAttackLabKubernetesTransport{responses: []*http.Response{attackLabKubernetesTestResponse(http.StatusNotFound, `{"kind":"Status","reason":"NotFound"}`), attackLabKubernetesTestResponse(http.StatusOK, tc.body)}}
			api := &productionAttackLabKubernetesAPI{endpoint: "https://kubernetes.default.svc", tokenFile: tokenPath, securityGroupID: "sg-1234abcd", client: &http.Client{Transport: transport}}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			started := time.Now()
			if err := api.Destroy(ctx, "zasp-attack-lab", name, uid); err == nil {
				t.Fatal("job absence falsely established dependent cleanup")
			}
			if time.Since(started) > time.Second || len(transport.requests) != 2 {
				t.Fatal("cleanup was not bounded or never inspected dependents")
			}
			request := transport.requests[1]
			if request.Method != http.MethodGet || request.URL.Path != "/api/v1/namespaces/zasp-attack-lab/pods" || request.URL.Query().Get("labelSelector") != "job-name="+name {
				t.Fatal("dependent inspection scope drifted")
			}
		})
	}
}

func testAttackLabControllerWaitsForActualPodCleanup(t *testing.T, config attackLabProcessorConfig, authority *recordingAttackLabAuthority, provider *contractCancellationProvider, steps *[]string) {
	t.Helper()
	const name = "zasp-attack-lab-7e300001000040008000000000000001"
	const uid = "123e4567-e89b-12d3-a456-426614174000"
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("header.payload.signature-with-bounded-production-length-1234567890"), 0o600); err != nil {
		t.Fatal(err)
	}
	owned := `{"apiVersion":"v1","kind":"PodList","items":[{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"zasp-attack-lab","name":"owned-pod","uid":"123e4567-e89b-12d3-a456-426614174002","labels":{"job-name":"` + name + `"},"ownerReferences":[{"apiVersion":"batch/v1","kind":"Job","name":"` + name + `","uid":"` + uid + `","controller":true}]},"status":{"phase":"Running"}}]}`
	transport := &recordingAttackLabKubernetesTransport{responses: []*http.Response{attackLabKubernetesTestResponse(http.StatusNotFound, `{"kind":"Status","reason":"NotFound"}`), attackLabKubernetesTestResponse(http.StatusOK, owned)}}
	api := &productionAttackLabKubernetesAPI{endpoint: "https://kubernetes.default.svc", tokenFile: tokenPath, securityGroupID: "sg-1234abcd", client: &http.Client{Transport: transport}}
	*steps = nil
	authority.claim.Disposition, authority.claim.Run.Status, authority.cleanupErr = "cleanup", "cleanup", nil
	provider.sandbox.Reference = "k8s://attack-lab/jobs/" + name + "@" + uid
	authority.claim.Checkpoint.SandboxReference = provider.sandbox.Reference
	provider.cancel = func(ctx context.Context, sandbox attackLabSandbox) error {
		bounded, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		return api.Destroy(bounded, "zasp-attack-lab", name, uid)
	}
	processor, err := newAttackLabProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if processor.RunOnce(context.Background()) == nil || fmt.Sprint(*steps) != "[consume claim cancel]" || len(transport.requests) != 2 {
		t.Fatalf("live owned Pod permitted Finish/ACK: %v", *steps)
	}
	*steps = nil
	transport.responses = []*http.Response{attackLabKubernetesTestResponse(http.StatusNotFound, `{"kind":"Status","reason":"NotFound"}`), attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"PodList","items":[]}`)}
	resumed, err := newAttackLabProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := resumed.RunOnce(context.Background()); err != nil || fmt.Sprint(*steps) != "[consume claim cancel destroy finish-cleanup ack]" {
		t.Fatalf("confirmed pod cleanup did not finish: err=%v steps=%v", err, *steps)
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
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"zasp-attack-lab","uid":"223e4567-e89b-12d3-a456-426614174000","labels":{"kubernetes.io/metadata.name":"zasp-attack-lab","zasp.io/execution":"attack-lab"}},"status":{"phase":"Active"}}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"agentsec-attack-lab-runner","namespace":"zasp-attack-lab","uid":"323e4567-e89b-12d3-a456-426614174000","labels":{"zasp.io/execution":"attack-lab"}},"automountServiceAccountToken":false,"secrets":[],"imagePullSecrets":[]}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"agentsec-attack-lab-proxy-ca","namespace":"zasp-attack-lab","uid":"423e4567-e89b-12d3-a456-426614174000"},"data":{"proxy-ca.crt":`+strconv.Quote(testDiscoveryCACertificatePEM)+`}}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"vpcresources.k8s.aws/v1beta1","kind":"SecurityGroupPolicy","metadata":{"name":"agentsec-attack-lab-egress","namespace":"zasp-attack-lab","uid":"623e4567-e89b-12d3-a456-426614174000"},"spec":{"podSelector":{"matchLabels":{"zasp.io/execution":"attack-lab"}},"securityGroups":{"groupIds":["sg-1234abcd"]}}}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"`+name+`","namespace":"zasp-attack-lab","uid":"`+uid+`"},"status":{"succeeded":1,"failed":0,"conditions":[{"type":"Complete","status":"True"}]}}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"PodList","metadata":{"continue":""},"items":[{"apiVersion":"v1","kind":"Pod","metadata":{"name":"`+name+`-abcde","namespace":"zasp-attack-lab","uid":"523e4567-e89b-12d3-a456-426614174000","labels":{"job-name":"`+name+`","zasp.io/execution":"attack-lab","eks.amazonaws.com/fargate-profile":"agentsec-attack-lab"},"ownerReferences":[{"apiVersion":"batch/v1","kind":"Job","name":"`+name+`","uid":"`+uid+`","controller":true}]},"spec":{"nodeName":"fargate-ip-10-0-1-10","containers":[{"name":"runner","image":"`+image+`"}]},"status":{"phase":"Succeeded","containerStatuses":[{"name":"runner","image":"`+image+`","imageID":"`+image+`","ready":false,"restartCount":0,"state":{"terminated":{"exitCode":0,"reason":"Completed","message":`+strconv.Quote(termination)+`}}}]}}]}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"`+name+`","namespace":"zasp-attack-lab","uid":"`+uid+`"}}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"Status","status":"Success","reason":"Deleted","code":200}`),
		attackLabKubernetesTestResponse(http.StatusNotFound, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}`),
		attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"PodList","items":[]}`),
	}}
	api := &productionAttackLabKubernetesAPI{endpoint: "https://kubernetes.default.svc", tokenFile: tokenPath, securityGroupID: "sg-1234abcd", client: &http.Client{Transport: transport}}
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
	if len(transport.requests) != 11 {
		t.Fatalf("requests=%d", len(transport.requests))
	}
	deleteRequest := transport.requests[8]
	if deleteRequest.Method != http.MethodDelete || deleteRequest.URL.Path != "/apis/batch/v1/namespaces/zasp-attack-lab/jobs/"+name {
		t.Fatal("cleanup path drifted")
	}
	var options struct {
		APIVersion, Kind, PropagationPolicy string
		GracePeriodSeconds                  int64
		Preconditions                       struct{ UID string }
	}
	if !decodeExactAttackLabKubernetesJSON(deleteRequest.body, &options) || options.APIVersion != "v1" || options.Kind != "DeleteOptions" || options.PropagationPolicy != "Foreground" || options.GracePeriodSeconds != 0 || options.Preconditions.UID != uid {
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
		Image: "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64), ProxyEndpoint: "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress", ProxyCAFile: "/var/run/secrets/zasp-attack-lab/proxy-ca.crt", EgressToken: "signed.capability.production",
		OrganizationID: "pid_7d100010-0000-4000-8000-000000000010", WorkspaceID: "pid_7d100011-0000-4000-8000-000000000011", EnvironmentID: "pid_7d100012-0000-4000-8000-000000000012", RunID: "pid_7e300001-0000-4000-8000-000000000001", Destination: "adapter.customer.example",
		SuccessCriterion: "Observe exact canary touch", ExpectedSideEffects: []string{"one bounded canary mutation"}, InputDigest: strings.Repeat("b", 64), Labels: map[string]string{"zasp.io/execution": "attack-lab", "zasp.io/run-id": "pid_7e300001-0000-4000-8000-000000000001"},
		Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, ActiveDeadlineSeconds: 300,
	}
	uid := "123e4567-e89b-12d3-a456-426614174000"
	transport := &recordingAttackLabKubernetesTransport{responses: []*http.Response{
		attackLabKubernetesTestResponse(http.StatusConflict, `{"apiVersion":"v1","kind":"Status","reason":"AlreadyExists","code":409}`),
		attackLabKubernetesTestResponse(http.StatusOK, attackLabKubernetesExactJobResponse(t, job, uid)),
	}}
	api := &productionAttackLabKubernetesAPI{endpoint: "https://kubernetes.default.svc", tokenFile: tokenPath, securityGroupID: "sg-1234abcd", client: &http.Client{Transport: transport}}
	got, err := api.Create(context.Background(), job)
	if err != nil || got != uid || len(transport.requests) != 2 || transport.requests[0].Method != http.MethodPost || transport.requests[1].Method != http.MethodGet {
		t.Fatalf("uid=%q requests=%d err=%v", got, len(transport.requests), err)
	}
}

func TestProductionAttackLabKubernetesAPICreateWrongContentTypeWithDelayedVisibilityIsOutcomeUnknown(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("header.payload.signature-with-bounded-production-length-1234567890"), 0o600); err != nil {
		t.Fatal(err)
	}
	created := attackLabKubernetesTestResponse(http.StatusCreated, `created`)
	created.Header.Set("Content-Type", "text/plain")
	transport := &recordingAttackLabKubernetesTransport{responses: []*http.Response{
		created,
		attackLabKubernetesTestResponse(http.StatusNotFound, `{"apiVersion":"v1","kind":"Status","reason":"NotFound","code":404}`),
	}}
	api := &productionAttackLabKubernetesAPI{endpoint: "https://kubernetes.default.svc", tokenFile: tokenPath, securityGroupID: "sg-1234abcd", client: &http.Client{Transport: transport}}
	uid, err := api.Create(context.Background(), attackLabKubernetesTestJob())
	var failure *attackLabProviderFailure
	if uid != "" || !errors.As(err, &failure) || failure.code != "outcome_unknown" {
		t.Fatalf("uid=%q failure=%#v err=%v", uid, failure, err)
	}
	if len(transport.requests) != 2 || transport.requests[0].Method != http.MethodPost || transport.requests[1].Method != http.MethodGet {
		t.Fatalf("requests=%#v", transport.requests)
	}
}

func TestProductionAttackLabKubernetesAPIRejectsCreateConflictWithDriftedJobSpec(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("header.payload.signature-with-bounded-production-length-1234567890"), 0o600); err != nil {
		t.Fatal(err)
	}
	job := attackLabKubernetesTestJob()
	drifted := attackLabKubernetesExactJobManifest(job, "123e4567-e89b-12d3-a456-426614174000")
	drifted.Spec.Template.Spec.ServiceAccountName = "production-admin"
	drifted.Spec.Template.Spec.Containers = append(drifted.Spec.Template.Spec.Containers, drifted.Spec.Template.Spec.Containers[0])
	raw, err := json.Marshal(drifted)
	if err != nil {
		t.Fatal(err)
	}
	transport := &recordingAttackLabKubernetesTransport{responses: []*http.Response{
		attackLabKubernetesTestResponse(http.StatusConflict, `{"apiVersion":"v1","kind":"Status","reason":"AlreadyExists","code":409}`),
		attackLabKubernetesTestResponse(http.StatusOK, string(raw)),
	}}
	api := &productionAttackLabKubernetesAPI{endpoint: "https://kubernetes.default.svc", tokenFile: tokenPath, securityGroupID: "sg-1234abcd", client: &http.Client{Transport: transport}}
	if uid, err := api.Create(context.Background(), job); err == nil || uid != "" {
		t.Fatalf("drifted existing job adopted: uid=%q err=%v", uid, err)
	}
}

func TestProductionAttackLabKubernetesAPIReadinessRejectsPrivilegeAndEgressDrift(t *testing.T) {
	for name, fixture := range map[string]struct {
		namespace      string
		serviceAccount string
		policy         string
	}{
		"service account role": {
			namespace:      `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"zasp-attack-lab","uid":"223e4567-e89b-12d3-a456-426614174000","labels":{"kubernetes.io/metadata.name":"zasp-attack-lab","zasp.io/execution":"attack-lab"}},"status":{"phase":"Active"}}`,
			serviceAccount: `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"agentsec-attack-lab-runner","namespace":"zasp-attack-lab","uid":"323e4567-e89b-12d3-a456-426614174000","labels":{"zasp.io/execution":"attack-lab"},"annotations":{"eks.amazonaws.com/role-arn":"arn:aws:iam::123456789012:role/production-admin"}},"automountServiceAccountToken":false,"secrets":[],"imagePullSecrets":[]}`,
			policy:         `{"apiVersion":"vpcresources.k8s.aws/v1beta1","kind":"SecurityGroupPolicy","metadata":{"name":"agentsec-attack-lab-egress","namespace":"zasp-attack-lab","uid":"623e4567-e89b-12d3-a456-426614174000"},"spec":{"podSelector":{"matchLabels":{"zasp.io/execution":"attack-lab"}},"securityGroups":{"groupIds":["sg-1234abcd"]}}}`,
		},
		"foreign security group": {
			namespace:      `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"zasp-attack-lab","uid":"223e4567-e89b-12d3-a456-426614174000","labels":{"kubernetes.io/metadata.name":"zasp-attack-lab","zasp.io/execution":"attack-lab"}},"status":{"phase":"Active"}}`,
			serviceAccount: `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"agentsec-attack-lab-runner","namespace":"zasp-attack-lab","uid":"323e4567-e89b-12d3-a456-426614174000","labels":{"zasp.io/execution":"attack-lab"}},"automountServiceAccountToken":false,"secrets":[],"imagePullSecrets":[]}`,
			policy:         `{"apiVersion":"vpcresources.k8s.aws/v1beta1","kind":"SecurityGroupPolicy","metadata":{"name":"agentsec-attack-lab-egress","namespace":"zasp-attack-lab","uid":"623e4567-e89b-12d3-a456-426614174000"},"spec":{"podSelector":{"matchLabels":{"zasp.io/execution":"attack-lab"}},"securityGroups":{"groupIds":["sg-deadbeef"]}}}`,
		},
		"foreign namespace label": {
			namespace:      `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"zasp-attack-lab","uid":"223e4567-e89b-12d3-a456-426614174000","labels":{"kubernetes.io/metadata.name":"zasp-attack-lab","zasp.io/execution":"attack-lab","example.com/admin":"true"}},"status":{"phase":"Active"}}`,
			serviceAccount: `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"agentsec-attack-lab-runner","namespace":"zasp-attack-lab","uid":"323e4567-e89b-12d3-a456-426614174000","labels":{"zasp.io/execution":"attack-lab"}},"automountServiceAccountToken":false,"secrets":[],"imagePullSecrets":[]}`,
			policy:         `{"apiVersion":"vpcresources.k8s.aws/v1beta1","kind":"SecurityGroupPolicy","metadata":{"name":"agentsec-attack-lab-egress","namespace":"zasp-attack-lab","uid":"623e4567-e89b-12d3-a456-426614174000"},"spec":{"podSelector":{"matchLabels":{"zasp.io/execution":"attack-lab"}},"securityGroups":{"groupIds":["sg-1234abcd"]}}}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			tokenPath := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(tokenPath, []byte("header.payload.signature-with-bounded-production-length-1234567890"), 0o600); err != nil {
				t.Fatal(err)
			}
			transport := &recordingAttackLabKubernetesTransport{responses: []*http.Response{
				attackLabKubernetesTestResponse(http.StatusOK, `{"major":"1","minor":"30"}`),
				attackLabKubernetesTestResponse(http.StatusOK, fixture.namespace),
				attackLabKubernetesTestResponse(http.StatusOK, fixture.serviceAccount),
				attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"agentsec-attack-lab-proxy-ca","namespace":"zasp-attack-lab","uid":"423e4567-e89b-12d3-a456-426614174000"},"data":{"proxy-ca.crt":`+strconv.Quote(testDiscoveryCACertificatePEM)+`}}`),
				attackLabKubernetesTestResponse(http.StatusOK, fixture.policy),
			}}
			api := &productionAttackLabKubernetesAPI{endpoint: "https://kubernetes.default.svc", tokenFile: tokenPath, securityGroupID: "sg-1234abcd", client: &http.Client{Transport: transport}}
			if err := api.Ready(context.Background()); err == nil {
				t.Fatal("privilege or egress drift accepted")
			}
		})
	}
}

func attackLabKubernetesTestJob() attackLabKubernetesJob {
	return attackLabKubernetesJob{
		Namespace: "zasp-attack-lab", Name: "zasp-attack-lab-7e300001000040008000000000000001", ServiceAccount: "agentsec-attack-lab-runner",
		Image: "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/attack-lab-runner@sha256:" + strings.Repeat("a", 64), ProxyEndpoint: "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress", ProxyCAFile: "/var/run/secrets/zasp-attack-lab/proxy-ca.crt", EgressToken: "signed.capability.production",
		OrganizationID: "pid_7d100010-0000-4000-8000-000000000010", WorkspaceID: "pid_7d100011-0000-4000-8000-000000000011", EnvironmentID: "pid_7d100012-0000-4000-8000-000000000012", RunID: "pid_7e300001-0000-4000-8000-000000000001", Destination: "adapter.customer.example",
		SuccessCriterion: "Observe exact canary touch", ExpectedSideEffects: []string{"one bounded canary mutation"}, InputDigest: strings.Repeat("b", 64), Labels: map[string]string{"zasp.io/execution": "attack-lab", "zasp.io/run-id": "pid_7e300001-0000-4000-8000-000000000001"},
		Limits: apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}, ActiveDeadlineSeconds: 300,
	}
}

func attackLabKubernetesExactJobResponse(t *testing.T, job attackLabKubernetesJob, uid string) string {
	t.Helper()
	raw, err := json.Marshal(attackLabKubernetesExactJobManifest(job, uid))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func attackLabKubernetesExactJobManifest(job attackLabKubernetesJob, uid string) attackLabKubernetesJobManifest {
	expectedSideEffects, _ := json.Marshal(job.ExpectedSideEffects)
	manifest := attackLabKubernetesJobManifest{
		APIVersion: "batch/v1", Kind: "Job", Metadata: attackLabKubernetesObjectMeta{Name: job.Name, Namespace: job.Namespace, UID: uid, Labels: cloneAttackLabLabels(job.Labels), Annotations: attackLabKubernetesJobAnnotations(job)},
		Spec: attackLabKubernetesJobSpec{ActiveDeadlineSeconds: int64(job.ActiveDeadlineSeconds), BackoffLimit: 0, Completions: 1, Parallelism: 1, TTLSecondsAfterFinished: 60,
			Template: attackLabKubernetesPodTemplate{Metadata: attackLabKubernetesObjectMeta{Labels: cloneAttackLabLabels(job.Labels)}, Spec: attackLabKubernetesPodSpec{
				ServiceAccountName: job.ServiceAccount, AutomountServiceAccountToken: false, RestartPolicy: "Never", EnableServiceLinks: false, TerminationGracePeriodSeconds: 5,
				SecurityContext: attackLabKubernetesPodSecurityContext{RunAsNonRoot: true, RunAsUser: 65532, RunAsGroup: 65532, FSGroup: 65532, SeccompProfile: attackLabKubernetesSeccompProfile{Type: "RuntimeDefault"}},
				Containers:      []attackLabKubernetesContainer{{Name: "runner", Image: job.Image, ImagePullPolicy: "IfNotPresent", Command: []string{"/app/agentsec-attack-lab-runner"}, Args: []string{"run"}, Env: attackLabKubernetesJobEnvironment(job, string(expectedSideEffects)), SecurityContext: attackLabKubernetesSecurityContext{AllowPrivilegeEscalation: false, ReadOnlyRootFilesystem: true, RunAsNonRoot: true, RunAsUser: 65532, RunAsGroup: 65532, Capabilities: attackLabKubernetesCapabilities{Drop: []string{"ALL"}}}, Resources: attackLabKubernetesResources{Requests: attackLabKubernetesResourceValues(job), Limits: attackLabKubernetesResourceValues(job)}, VolumeMounts: []attackLabKubernetesVolumeMount{{Name: "proxy-ca", MountPath: "/var/run/secrets/zasp-attack-lab", ReadOnly: true}}, TerminationMessagePath: "/dev/termination-log", TerminationMessagePolicy: "File"}},
				Volumes:         []attackLabKubernetesVolume{{Name: "proxy-ca", ConfigMap: &attackLabKubernetesConfigMapVolume{Name: "agentsec-attack-lab-proxy-ca", DefaultMode: 0o444}}},
			}},
		},
	}
	return manifest
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
