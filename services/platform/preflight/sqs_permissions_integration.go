package preflight

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"net/http"
	"time"
)

func sqsReportDiagnostic(report *Report) *SQSPermissionDiagnostic {
	if report != nil {
		for i := range report.Checks {
			if report.Checks[i].Name == "sqs" {
				return report.Checks[i].PermissionDiagnostic
			}
		}
	}
	return nil
}
func (r *Runner) observeSQSQueuePermissions(ctx context.Context, report *Report, authority *awsAuthorityEvidence, proof *awsWebIdentityProof, reader KubernetesIdentityReader) {
	diagnostic := sqsReportDiagnostic(report)
	if r == nil || ctx == nil || ctx.Err() != nil || r.config.SQSPermissions == nil || diagnostic == nil || r.config.AWSAuthority == nil || r.config.AWSAuthority.Selected == nil {
		return
	}
	// Earlier genuine evidence is never overwritten by a later prerequisite gap.
	if diagnostic.Observation.ObservedAt != nil || len(diagnostic.Observation.Failures) != 0 {
		return
	}
	selected := *r.config.AWSAuthority.Selected
	row, supported := sqsRequirement(selected.Purpose)
	if !supported || row.topic == "attack-lab-jobs" && r.config.Features.AttackLab != "enabled" {
		return
	}
	if authority == nil || !authority.clusterVerified || !authority.selectedExchangeVerified || !authority.selectedSpecVerified || authority.inspectionSDK == nil || proof == nil || !proof.expires.After(time.Now().Add(time.Minute)) || r.config.Credentials.Kind != "workload_web_identity" {
		return
	}
	namespace, sa := openSearchSubject(selected.Purpose)
	roles, ok := authorityRoles(r.config.AWSAuthority, requiredAWSRoleInventory(r.config.Features.AttackLab == "enabled"), r.config.Deployment)
	if !ok || roles[selected.Purpose] == "" || roles[selected.Purpose] != r.config.Credentials.ExpectedRoleARN || proof.requestedRoleARN != roles[selected.Purpose] || proof.subject != "system:serviceaccount:"+namespace+":"+sa || proof.audience != "sts.amazonaws.com" || proof.provider != r.config.AWSAuthority.Cluster.Issuer {
		return
	}
	kubeIdentity := "none"
	if r.config.Kubernetes != nil {
		switch r.config.Kubernetes.Credentials.Kind {
		case "existing_service_account":
			kubeIdentity = "workload-kubernetes"
		case "explicit_bearer_file":
			kubeIdentity = "operator-kubernetes"
		}
	}
	if kubeIdentity == "none" {
		return
	}
	actual, ok := reader.(sqsPermissionWorkloadReader)
	if !ok {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	workload, e := actual.SQSWorkload(bounded, selected)
	if !workload.ReadAttempted {
		diagnostic.Observation.Code = "selected_pod_not_observed"
		return
	}
	now := time.Now().UTC()
	// This is a real Pod read, separate from a simulation that may never be sent.
	diagnostic.AuthorityObservation = &Observation{Name: "selected_queue_workload", Status: "fail", Kind: "provider-read", Code: "selected_queue_binding_unavailable", ObservedAt: &now, TargetDigest: singleTargetDigest(selected), IdentityKind: kubeIdentity}
	if e != nil {
		outcome := openSearchOutcome(e)
		diagnostic.AuthorityObservation.Failures = []Failure{{Operation: "kubernetes:GetSelectedSQSPod", TargetDigest: singleTargetDigest(selected), Outcome: outcome, Hint: "verify the exact selected Pod and literal queue binding"}}
		return
	}
	footprint, e := deriveSQSPermissionFootprint(r.config, *r.config.SQSPermissions, selected, workload)
	if e != nil {
		diagnostic.AuthorityObservation.Failures = []Failure{{Operation: "kubernetes:GetSelectedSQSPod", TargetDigest: singleTargetDigest(selected), Outcome: "binding_mismatch", Hint: "verify the exact selected workload image, mode and literal queue binding"}}
		return
	}
	diagnostic.AuthorityObservation.Status = "pass"
	diagnostic.AuthorityObservation.Code = "observed_selected_queue_binding"
	if bounded.Err() != nil || !proof.expires.After(time.Now().Add(time.Minute)) {
		return
	}
	sdk := *authority.inspectionSDK
	capture := &sqsSimulationAttempt{client: sdk.HTTPClient}
	sdk.HTTPClient = capture
	evaluation, e := simulateSQSQueuePermissions(bounded, sdk, footprint)
	if !capture.attempted {
		diagnostic.Observation.Code = "simulation_not_dispatched"
		return
	}
	now = time.Now().UTC()
	observation := Observation{Name: "sqs_identity_policy_simulation", Status: "fail", Kind: "provider-read", Code: "simulation_indeterminate", ObservedAt: &now, TargetDigest: singleTargetDigest(footprint), IdentityKind: "operator"}
	if e != nil {
		if !errors.Is(e, ErrRejected) {
			observation.Failures = []Failure{{Operation: "iam:SimulatePrincipalPolicy", TargetDigest: singleTargetDigest(footprint), Outcome: failureOutcome(e), Hint: "verify inspector simulation access and exact selected role policy"}}
		}
		diagnostic.Observation = observation
		return
	}
	if bounded.Err() != nil || !proof.expires.After(time.Now().Add(time.Minute)) {
		diagnostic.Observation = observation
		return
	}
	diagnostic.Decisions = append([]SQSPermissionDecision(nil), evaluation.Decisions...)
	observation.Status = "pass"
	observation.Code = "simulated_identity_policy_only"
	for _, decision := range evaluation.Decisions {
		if decision.Decision != "allowed" {
			observation.Status = "fail"
			observation.Code = "simulated_action_denied"
			observation.Failures = append(observation.Failures, Failure{Operation: decision.Action, TargetDigest: singleTargetDigest(footprint), Outcome: "denied", Hint: "review the selected role policy for this exact queue action; simulation is not exercised workload authority"})
		}
	}
	diagnostic.Observation = observation
	// queue_permissions is deliberately untouched; no queue service mutation,
	// workload-network origin, resource/KMS/SCP/session authority is established.
}

// Only a real SDK HTTP dispatch creates simulation attempt metadata. This
// borrows the same client and owns neither its transport nor its credentials.
type sqsSimulationAttempt struct {
	client    aws.HTTPClient
	attempted bool
}

func (c *sqsSimulationAttempt) Do(req *http.Request) (*http.Response, error) {
	c.attempted = true
	return c.client.Do(req)
}
