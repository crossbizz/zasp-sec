package main

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

const attackLabIdentityTestRole = "arn:aws:iam::123456789012:role/zasp-production-attack-lab-runner-test"

func TestAttackLabServiceAccountTestRoleFencesReadiness(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"exact role":   func(map[string]any) {},
		"missing role": func(s map[string]any) { delete(s["metadata"].(map[string]any), "annotations") },
		"product role": func(s map[string]any) {
			s["metadata"].(map[string]any)["annotations"] = map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/zasp-production-discovery-worker"}
		},
		"foreign account": func(s map[string]any) {
			s["metadata"].(map[string]any)["annotations"] = map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::210987654321:role/zasp-production-attack-lab-runner-test"}
		},
		"other test role": func(s map[string]any) {
			s["metadata"].(map[string]any)["annotations"] = map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/other-attack-lab-runner-test"}
		},
		"extra annotation": func(s map[string]any) {
			s["metadata"].(map[string]any)["annotations"].(map[string]string)["eks.amazonaws.com/audience"] = "other"
		},
		"token mount":    func(s map[string]any) { s["automountServiceAccountToken"] = true },
		"product secret": func(s map[string]any) { s["secrets"] = []any{map[string]any{"name": "product-worker"}} },
	} {
		t.Run(name, func(t *testing.T) {
			sa := map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": "agentsec-attack-lab-runner", "namespace": "zasp-attack-lab", "uid": "323e4567-e89b-12d3-a456-426614174000", "labels": map[string]string{"zasp.io/execution": "attack-lab"}, "annotations": map[string]string{"eks.amazonaws.com/role-arn": attackLabIdentityTestRole}}, "automountServiceAccountToken": false, "secrets": []any{}, "imagePullSecrets": []any{}}
			mutate(sa)
			body, err := json.Marshal(sa)
			if err != nil {
				t.Fatal(err)
			}
			ca, _ := json.Marshal(testDiscoveryCACertificatePEM)
			transport := &recordingAttackLabKubernetesTransport{responses: []*http.Response{
				attackLabKubernetesTestResponse(http.StatusOK, `{"major":"1","minor":"30"}`),
				attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"zasp-attack-lab","uid":"223e4567-e89b-12d3-a456-426614174000","labels":{"kubernetes.io/metadata.name":"zasp-attack-lab","zasp.io/execution":"attack-lab"}},"status":{"phase":"Active"}}`),
				attackLabKubernetesTestResponse(http.StatusOK, string(body)),
				attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"agentsec-attack-lab-proxy-ca","namespace":"zasp-attack-lab","uid":"423e4567-e89b-12d3-a456-426614174000"},"data":{"proxy-ca.crt":`+string(ca)+`}}`),
				attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"vpcresources.k8s.aws/v1beta1","kind":"SecurityGroupPolicy","metadata":{"name":"agentsec-attack-lab-egress","namespace":"zasp-attack-lab","uid":"623e4567-e89b-12d3-a456-426614174000"},"spec":{"podSelector":{"matchLabels":{"zasp.io/execution":"attack-lab"}},"securityGroups":{"groupIds":["sg-1234abcd"]}}}`),
			}}
			api := timeoutTestKubernetesAPI(t, transport)
			api.runnerTestRoleARN = attackLabIdentityTestRole
			if err := api.Ready(context.Background()); (err == nil) != (name == "exact role") {
				t.Fatalf("readiness identity acceptance: %v", err)
			}
		})
	}
}

func TestAttackLabCreateCannotSelectAnotherTestIdentity(t *testing.T) {
	transport := &recordingAttackLabKubernetesTransport{}
	api := timeoutTestKubernetesAPI(t, transport)
	api.runnerTestRoleARN = attackLabIdentityTestRole
	job := attackLabKubernetesTestJob()
	job.TestRoleARN = "arn:aws:iam::123456789012:role/other-attack-lab-runner-test"
	if _, err := api.Create(context.Background(), job); err == nil {
		t.Fatal("foreign test role accepted")
	}
	if _, _, err := api.Reconcile(context.Background(), job); err == nil {
		t.Fatal("foreign test role reconciled")
	}
	if len(transport.requests) != 0 {
		t.Fatal("foreign identity performed I/O")
	}
}

func TestAttackLabIdentityManifestRejectsProductCredentials(t *testing.T) {
	job := attackLabKubernetesTestJob()
	manifest := attackLabKubernetesExactJobManifest(job, "123e4567-e89b-12d3-a456-426614174000")
	if !validExactAttackLabKubernetesJob(manifest, job) {
		t.Fatal("valid test identity rejected")
	}
	pod := manifest.Spec.Template.Spec
	if pod.ServiceAccountName != "agentsec-attack-lab-runner" || pod.AutomountServiceAccountToken {
		t.Fatal("ambient Kubernetes identity")
	}
	identity := pod.Volumes[1]
	if identity.Name != "aws-iam-token" || identity.Projected.DefaultMode != 0o440 || len(identity.Projected.Sources) != 1 || identity.Projected.Sources[0].ServiceAccountToken != (attackLabKubernetesTokenProjection{Audience: "sts.amazonaws.com", ExpirationSeconds: 600, Path: "token"}) {
		t.Fatal("token authority drift")
	}
	wantAWS := map[string]string{"AWS_ROLE_ARN": attackLabIdentityTestRole, "AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", "AWS_REGION": "us-west-2", "AWS_STS_REGIONAL_ENDPOINTS": "regional", "AWS_EC2_METADATA_DISABLED": "true"}
	gotAWS := map[string]string{}
	for _, entry := range pod.Containers[0].Env {
		if strings.HasPrefix(entry.Name, "AWS_") {
			gotAWS[entry.Name] = entry.Value
		}
	}
	if !reflect.DeepEqual(gotAWS, wantAWS) {
		t.Fatal("AWS authority does not match dedicated test role")
	}
	for name, mutate := range map[string]func(*attackLabKubernetesPodSpec){
		"product service account": func(p *attackLabKubernetesPodSpec) { p.ServiceAccountName = "zasp-discovery-worker" },
		"automount":               func(p *attackLabKubernetesPodSpec) { p.AutomountServiceAccountToken = true },
		"product role": func(p *attackLabKubernetesPodSpec) {
			for i := range p.Containers[0].Env {
				if p.Containers[0].Env[i].Name == "AWS_ROLE_ARN" {
					p.Containers[0].Env[i].Value = "arn:aws:iam::123456789012:role/zasp-production-discovery-worker"
				}
			}
		},
		"static key": func(p *attackLabKubernetesPodSpec) {
			p.Containers[0].Env = append(p.Containers[0].Env, attackLabKubernetesEnv{Name: "AWS_ACCESS_KEY_ID", Value: "fixture-not-a-key"})
		},
		"kube audience": func(p *attackLabKubernetesPodSpec) {
			p.Volumes[1].Projected.Sources[0].ServiceAccountToken.Audience = "https://kubernetes.default.svc"
		},
		"unbounded token": func(p *attackLabKubernetesPodSpec) {
			p.Volumes[1].Projected.Sources[0].ServiceAccountToken.ExpirationSeconds = 86400
		},
		"token path": func(p *attackLabKubernetesPodSpec) {
			p.Volumes[1].Projected.Sources[0].ServiceAccountToken.Path = "other"
		},
		"readable by others": func(p *attackLabKubernetesPodSpec) { p.Volumes[1].Projected.DefaultMode = 0o444 },
		"extra volume": func(p *attackLabKubernetesPodSpec) {
			p.Volumes = append(p.Volumes, attackLabKubernetesVolume{Name: "product-secret"})
		},
		"writable token": func(p *attackLabKubernetesPodSpec) { p.Containers[0].VolumeMounts[1].ReadOnly = false },
	} {
		t.Run(name, func(t *testing.T) {
			drift := attackLabKubernetesExactJobManifest(job, manifest.Metadata.UID)
			mutate(&drift.Spec.Template.Spec)
			if validExactAttackLabKubernetesJob(drift, job) {
				t.Fatal("identity drift accepted")
			}
		})
	}
}

func TestAttackLabObservedPodCannotInheritWorkerIdentity(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"exact identity":          func(map[string]any) {},
		"product service account": func(p map[string]any) { p["serviceAccountName"] = "zasp-discovery-worker" },
		"automount":               func(p map[string]any) { p["automountServiceAccountToken"] = true },
		"injected credentials": func(p map[string]any) {
			c := p["containers"].([]any)[0].(map[string]any)
			c["envFrom"] = []any{map[string]any{"secretRef": map[string]any{"name": "product-worker"}}}
		},
		"product role": func(p map[string]any) {
			for _, entry := range p["containers"].([]any)[0].(map[string]any)["env"].([]any) {
				e := entry.(map[string]any)
				if e["name"] == "AWS_ROLE_ARN" {
					e["value"] = "arn:aws:iam::123456789012:role/zasp-production-discovery-worker"
				}
			}
		},
		"static key": func(p map[string]any) {
			c := p["containers"].([]any)[0].(map[string]any)
			c["env"] = append(c["env"].([]any), map[string]any{"name": "AWS_ACCESS_KEY_ID", "value": "fixture-not-a-key"})
		},
		"kube token": func(p map[string]any) {
			v := p["volumes"].([]any)[1].(map[string]any)["projected"].(map[string]any)
			v["sources"].([]any)[0].(map[string]any)["serviceAccountToken"].(map[string]any)["audience"] = "https://kubernetes.default.svc"
		},
		"init container": func(p map[string]any) { p["initContainers"] = []any{map[string]any{"name": "credential-copy"}} },
	} {
		t.Run(name, func(t *testing.T) {
			const uid = "123e4567-e89b-12d3-a456-426614174000"
			job := attackLabKubernetesTestJob()
			transport := &recordingAttackLabKubernetesTransport{responses: []*http.Response{
				attackLabKubernetesTestResponse(http.StatusOK, `{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"`+job.Name+`","namespace":"zasp-attack-lab","uid":"`+uid+`"},"status":{"succeeded":1,"conditions":[{"type":"Complete","status":"True"}]}}`),
				attackLabKubernetesTestResponse(http.StatusOK, attackLabIdentityPodList(t, mutate)),
			}}
			api := timeoutTestKubernetesAPI(t, transport)
			api.runnerTestRoleARN = attackLabIdentityTestRole
			_, err := api.Collect(context.Background(), job.Namespace, job.Name, uid, time.Second)
			if (err == nil) != (name == "exact identity") {
				t.Fatalf("identity acceptance mismatch: %v", err)
			}
		})
	}
}

func attackLabIdentityPodList(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	job := attackLabKubernetesTestJob()
	const uid = "123e4567-e89b-12d3-a456-426614174000"
	encoded, err := json.Marshal(attackLabKubernetesExactJobManifest(job, uid).Spec.Template.Spec)
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if json.Unmarshal(encoded, &spec) != nil {
		t.Fatal("fixture decode")
	}
	spec["nodeName"] = "fargate-fixture"
	mutate(spec)
	termination := `{"schema_version":"attack-lab-outcome-v1","criterion_observed":true,"canary_touched":true,"gateway_evidence":"proxy authorized one POST","egress_evidence":"destination exact","cloud_evidence":"canary changed"}`
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": job.Name + "-fixture", "namespace": job.Namespace, "uid": "523e4567-e89b-12d3-a456-426614174000", "labels": map[string]string{"job-name": job.Name, "zasp.io/execution": "attack-lab", "eks.amazonaws.com/fargate-profile": "attack-lab"}, "ownerReferences": []attackLabKubernetesOwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: uid, Controller: true}}}, "spec": spec, "status": map[string]any{"phase": "Succeeded", "containerStatuses": []any{map[string]any{"name": "runner", "image": job.Image, "imageID": job.Image, "ready": false, "restartCount": 0, "state": map[string]any{"terminated": map[string]any{"exitCode": 0, "reason": "Completed", "message": termination}}}}}}
	body, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "PodList", "items": []any{pod}})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
