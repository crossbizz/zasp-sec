package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/recovery/neondriver"
)

type recoveryNeonFake struct {
	createRequest  neondriver.CreateBranchRequest
	deletedProject string
	deletedBranch  string
	calls          []string
	getBranch      neondriver.Branch
	getErr         error
}

func (fake *recoveryNeonFake) CreateBranch(_ context.Context, request neondriver.CreateBranchRequest) (neondriver.Branch, error) {
	fake.calls = append(fake.calls, "create")
	fake.createRequest = request
	return neondriver.Branch{ID: "br-recovery-123456", ProjectID: "silent-river-123456", ParentID: "br-falling-sun-123456", ParentLSN: request.ParentLSN, Name: request.Name, Endpoints: []neondriver.Endpoint{{ID: "ep-recovery-123456", BranchID: "br-recovery-123456", Type: "read_write", Host: "ep-recovery.internal"}}}, nil
}
func (fake *recoveryNeonFake) GetBranchByName(_ context.Context, project, name string) (neondriver.Branch, error) {
	fake.calls = append(fake.calls, "get:"+project+":"+name)
	if fake.getErr != nil {
		return neondriver.Branch{}, fake.getErr
	}
	if fake.getBranch.ID == "" {
		return neondriver.Branch{}, neondriver.ErrNotFound
	}
	return fake.getBranch, nil
}
func (fake *recoveryNeonFake) DeleteBranch(_ context.Context, project, branch string) error {
	fake.calls = append(fake.calls, "delete")
	fake.deletedProject, fake.deletedBranch = project, branch
	return nil
}
func (*recoveryNeonFake) Ready(context.Context) error { return nil }

type recoveryKubernetesFake struct {
	plan         recoveryKubernetesPlan
	uid          string
	calls        []string
	provisionErr error
	cleanup      apiserver.RecoveryCleanupEvidence
	cleanupPlan  recoveryKubernetesCleanupPlan
}

func (*recoveryKubernetesFake) Ready(context.Context) error { return nil }
func (fake *recoveryKubernetesFake) Provision(_ context.Context, plan recoveryKubernetesPlan) (string, error) {
	fake.calls = append(fake.calls, "provision")
	fake.plan = plan
	return fake.uid, fake.provisionErr
}
func (fake *recoveryKubernetesFake) Validate(_ context.Context, plan recoveryKubernetesPlan, uid string) (apiserver.RecoveryCounts, apiserver.RecoveryArtifactLocator, error) {
	fake.calls = append(fake.calls, "validate")
	if !reflect.DeepEqual(plan, fake.plan) || uid != fake.uid {
		return apiserver.RecoveryCounts{}, apiserver.RecoveryArtifactLocator{}, errors.New("authority drift")
	}
	return plan.ExpectedCounts, recoveryEvidenceLocator(plan.Scope, "pid_71000008-0000-4000-8000-000000000008", "recovery_validation_v1"), nil
}
func (fake *recoveryKubernetesFake) Rebuild(_ context.Context, plan recoveryKubernetesPlan, uid string) ([sha256.Size]byte, error) {
	fake.calls = append(fake.calls, "rebuild")
	if !reflect.DeepEqual(plan, fake.plan) || uid != fake.uid {
		return [sha256.Size]byte{}, errors.New("authority drift")
	}
	return plan.ProjectionDigest, nil
}
func (fake *recoveryKubernetesFake) Cleanup(_ context.Context, plan recoveryKubernetesPlan, uid string) (apiserver.RecoveryCleanupEvidence, error) {
	fake.calls = append(fake.calls, "cleanup")
	if !reflect.DeepEqual(plan, fake.plan) || uid != fake.uid {
		return apiserver.RecoveryCleanupEvidence{}, errors.New("authority drift")
	}
	return fake.cleanup, nil
}

func (fake *recoveryKubernetesFake) CleanupNamespace(_ context.Context, plan recoveryKubernetesCleanupPlan, uid string) (string, error) {
	fake.calls = append(fake.calls, "cleanup-namespace")
	if fake.plan.RestoreID != "" && (plan.Scope != fake.plan.Scope || plan.RestoreID != fake.plan.RestoreID || plan.Namespace != fake.plan.Namespace || !reflect.DeepEqual(plan.Labels, fake.plan.Labels)) || uid != fake.uid {
		return uid, errors.New("authority drift")
	}
	fake.cleanupPlan = plan
	return uid, nil
}

func (fake *recoveryKubernetesFake) RecordCleanup(_ context.Context, plan recoveryKubernetesCleanupPlan, uid, state string) (apiserver.RecoveryCleanupEvidence, error) {
	fake.calls = append(fake.calls, "record-cleanup")
	wantPlan := fake.cleanupPlan
	if fake.plan.RestoreID != "" {
		wantPlan = recoveryCleanupPlan(fake.plan.Scope, fake.plan.RestoreID, fake.plan.Namespace, fake.plan.Labels["zasp.io/recovery-scope"])
	}
	if !reflect.DeepEqual(plan, wantPlan) || uid != fake.uid || fake.cleanup.State != state {
		return apiserver.RecoveryCleanupEvidence{}, errors.New("authority drift")
	}
	return fake.cleanup, nil
}

func TestRecoveryKubernetesPlansOneOwnedNamespaceNetworkPolicyAndThreeJobs(t *testing.T) {
	scope := recoveryWorkerScope(t)
	manifest := recoveryRestoreManifest(t, scope)
	claim := recoveryRestoreClaim(scope)
	neon := &recoveryNeonFake{}
	kubernetes := &recoveryKubernetesFake{uid: "11111111-2222-4333-8444-555555555555", cleanup: apiserver.RecoveryCleanupEvidence{State: "deleted", Evidence: recoveryEvidenceLocator(scope, "pid_71000009-0000-4000-8000-000000000009", "recovery_cleanup_v1")}}
	infrastructure, err := newProductionRecoveryRestoreInfrastructure(productionRecoveryRestoreInfrastructureConfig{Neon: neon, Kubernetes: kubernetes, ProjectID: manifest.NeonProjectID, ParentBranchID: manifest.NeonBranchID})
	if err != nil {
		t.Fatal(err)
	}
	evidenceDigest := sha256.Sum256([]byte("[]"))
	target, err := infrastructure.Provision(context.Background(), recoveryRestoreProvisionRequest{Scope: claim, TargetEnvironment: claim.TargetEnvironment, Manifest: manifest, EvidenceSampleDigest: evidenceDigest})
	if err != nil {
		t.Fatal(err)
	}
	expectedName, _, err := recoveryRestoreNames(claim)
	if err != nil {
		t.Fatal(err)
	}
	if neon.createRequest.Name != expectedName || neon.createRequest.ParentLSN != manifest.PostgresLSN || target.Namespace != neon.createRequest.Name || target.NamespaceUID != kubernetes.uid || target.BranchID != "br-recovery-123456" {
		t.Fatalf("request=%#v target=%#v", neon.createRequest, target)
	}
	plan := kubernetes.plan
	wantLabels := map[string]string{"app.kubernetes.io/managed-by": "agentsec-recovery", "zasp.io/recovery-id": claim.OperationID, "zasp.io/recovery-scope": target.ScopeDigest}
	if plan.Namespace != target.Namespace || !reflect.DeepEqual(plan.Labels, wantLabels) || plan.NetworkPolicy.Name != "recovery-deny-by-default" || !reflect.DeepEqual(plan.NetworkPolicy.Labels, wantLabels) || len(plan.Jobs) != 3 || plan.Jobs[0].Kind != "postgres-validation" || plan.Jobs[1].Kind != "graph-projection" || plan.Jobs[2].Kind != "search-projection" {
		t.Fatalf("plan=%#v", plan)
	}
	for _, job := range plan.Jobs {
		if job.Namespace != plan.Namespace || !reflect.DeepEqual(job.Labels, wantLabels) || job.Scope != scope || job.TargetEnvironment != claim.TargetEnvironment || job.BranchHost != "ep-recovery.internal" {
			t.Fatalf("job=%#v", job)
		}
	}
	counts, _, err := infrastructure.Validate(context.Background(), target, manifest)
	if err != nil || counts != (apiserver.RecoveryCounts{Assets: 3, Findings: 2, Policies: 1}) {
		t.Fatalf("counts=%#v err=%v", counts, err)
	}
	digest, err := infrastructure.Rebuild(context.Background(), target, manifest)
	if err != nil || digest != manifest.Projection.SHA256 {
		t.Fatalf("digest=%x err=%v", digest, err)
	}
	cleanup, err := infrastructure.Cleanup(context.Background(), target)
	if err != nil || cleanup.State != "deleted" || neon.deletedProject != manifest.NeonProjectID || neon.deletedBranch != target.BranchID || !reflect.DeepEqual(neon.calls, []string{"create", "delete"}) || !reflect.DeepEqual(kubernetes.calls, []string{"provision", "validate", "rebuild", "cleanup-namespace", "record-cleanup"}) {
		t.Fatalf("cleanup=%#v neon=%v kubernetes=%v err=%v", cleanup, neon.calls, kubernetes.calls, err)
	}
}

func TestRecoveryKubernetesRejectsManifestAuthorityBeforeProviders(t *testing.T) {
	scope := recoveryWorkerScope(t)
	manifest := recoveryRestoreManifest(t, scope)
	claim := recoveryRestoreClaim(scope)
	neon := &recoveryNeonFake{}
	kubernetes := &recoveryKubernetesFake{}
	infrastructure, err := newProductionRecoveryRestoreInfrastructure(productionRecoveryRestoreInfrastructureConfig{Neon: neon, Kubernetes: kubernetes, ProjectID: manifest.NeonProjectID, ParentBranchID: manifest.NeonBranchID})
	if err != nil {
		t.Fatal(err)
	}
	manifest.NeonBranchID = "br-foreign-parent-123456"
	evidenceDigest := sha256.Sum256([]byte("[]"))
	if _, err := infrastructure.Provision(context.Background(), recoveryRestoreProvisionRequest{Scope: claim, TargetEnvironment: claim.TargetEnvironment, Manifest: manifest, EvidenceSampleDigest: evidenceDigest}); err == nil || len(neon.calls) != 0 || len(kubernetes.calls) != 0 {
		t.Fatalf("neon=%v kubernetes=%v err=%v", neon.calls, kubernetes.calls, err)
	}
}

func TestRecoveryKubernetesReturnsPartialTargetForCleanupAfterNamespaceFailure(t *testing.T) {
	scope := recoveryWorkerScope(t)
	manifest := recoveryRestoreManifest(t, scope)
	claim := recoveryRestoreClaim(scope)
	neon := &recoveryNeonFake{}
	kubernetes := &recoveryKubernetesFake{provisionErr: errors.New("create response unknown"), cleanup: apiserver.RecoveryCleanupEvidence{State: "deleted", Evidence: recoveryEvidenceLocator(scope, "pid_71000009-0000-4000-8000-000000000009", "recovery_cleanup_v1")}}
	infrastructure, _ := newProductionRecoveryRestoreInfrastructure(productionRecoveryRestoreInfrastructureConfig{Neon: neon, Kubernetes: kubernetes, ProjectID: manifest.NeonProjectID, ParentBranchID: manifest.NeonBranchID})
	evidenceDigest := sha256.Sum256([]byte("[]"))
	target, err := infrastructure.Provision(context.Background(), recoveryRestoreProvisionRequest{Scope: claim, TargetEnvironment: claim.TargetEnvironment, Manifest: manifest, EvidenceSampleDigest: evidenceDigest})
	if err == nil || target.BranchID == "" || target.Namespace == "" {
		t.Fatalf("target=%#v err=%v", target, err)
	}
	// Cleanup retains the exact plan even if namespace creation was uncertain.
	kubernetes.uid = target.NamespaceUID
	if _, err := infrastructure.Cleanup(context.Background(), target); err != nil || neon.deletedBranch != target.BranchID {
		t.Fatalf("cleanup err=%v neon=%#v", err, neon)
	}
}

func TestRecoveryKubernetesReconcilesAttempt100CleanupByDeterministicIdentityWithoutCreate(t *testing.T) {
	scope := recoveryWorkerScope(t)
	manifest := recoveryRestoreManifest(t, scope)
	claim := recoveryRestoreClaim(scope)
	claim.Attempt = 100
	claim.CleanupOnly = true
	name, scopeDigest, err := recoveryRestoreNames(claim)
	if err != nil {
		t.Fatal(err)
	}
	neon := &recoveryNeonFake{getBranch: neondriver.Branch{ID: "br-recovery-123456", ProjectID: manifest.NeonProjectID, ParentID: manifest.NeonBranchID, Name: name}}
	kubernetes := &recoveryKubernetesFake{cleanup: apiserver.RecoveryCleanupEvidence{State: "deleted", Evidence: recoveryEvidenceLocator(scope, "pid_71000009-0000-4000-8000-000000000009", "recovery_cleanup_v1")}}
	infrastructure, err := newProductionRecoveryRestoreInfrastructure(productionRecoveryRestoreInfrastructureConfig{Neon: neon, Kubernetes: kubernetes, ProjectID: manifest.NeonProjectID, ParentBranchID: manifest.NeonBranchID})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := infrastructure.ReconcileCleanup(context.Background(), claim)
	if err != nil || evidence.State != "deleted" || !reflect.DeepEqual(neon.calls, []string{"get:" + manifest.NeonProjectID + ":" + name, "delete"}) || !reflect.DeepEqual(kubernetes.calls, []string{"cleanup-namespace", "record-cleanup"}) || kubernetes.cleanupPlan.Namespace != name || kubernetes.cleanupPlan.Labels["zasp.io/recovery-scope"] != scopeDigest {
		t.Fatalf("evidence=%#v neon=%v kubernetes=%v plan=%#v err=%v", evidence, neon.calls, kubernetes.calls, kubernetes.cleanupPlan, err)
	}
}

func TestRecoveryKubernetesScopesDeterministicIdentityAndNeverDeletesForeignBranch(t *testing.T) {
	scope := recoveryWorkerScope(t)
	foreignOrganization, _ := domain.ParseProductID("pid_72000001-0000-4000-8000-000000000001")
	foreignScope, err := domain.NewScope(foreignOrganization, scope.WorkspaceID(), scope.EnvironmentID())
	if err != nil {
		t.Fatal(err)
	}
	restoreID := "pid_71000004-0000-4000-8000-000000000004"
	name, _, err := recoveryRestoreIdentity(scope, restoreID)
	if err != nil {
		t.Fatal(err)
	}
	foreignName, _, err := recoveryRestoreIdentity(foreignScope, restoreID)
	if err != nil {
		t.Fatal(err)
	}
	if name == foreignName || !neondriver.ValidRecoveryBranchName(name) || !neondriver.ValidRecoveryBranchName(foreignName) || len(name) > 63 || len(foreignName) > 63 {
		t.Fatalf("scoped names=%q/%q", name, foreignName)
	}
	manifest := recoveryRestoreManifest(t, scope)
	claim := recoveryRestoreClaim(scope)
	claim.Attempt, claim.CleanupOnly = 100, true
	neon := &recoveryNeonFake{getBranch: neondriver.Branch{ID: "br-foreign-123456", ProjectID: manifest.NeonProjectID, ParentID: manifest.NeonBranchID, Name: foreignName}}
	kubernetes := &recoveryKubernetesFake{cleanup: apiserver.RecoveryCleanupEvidence{State: "failed", Evidence: recoveryEvidenceLocator(scope, "pid_71000009-0000-4000-8000-000000000009", "recovery_cleanup_v1")}}
	infrastructure, err := newProductionRecoveryRestoreInfrastructure(productionRecoveryRestoreInfrastructureConfig{Neon: neon, Kubernetes: kubernetes, ProjectID: manifest.NeonProjectID, ParentBranchID: manifest.NeonBranchID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := infrastructure.ReconcileCleanup(context.Background(), claim); err == nil || reflect.DeepEqual(neon.calls, []string{"get:" + manifest.NeonProjectID + ":" + name, "delete"}) {
		t.Fatalf("foreign branch calls=%v err=%v", neon.calls, err)
	}
	for _, call := range neon.calls {
		if call == "delete" {
			t.Fatalf("foreign branch was deleted: %v", neon.calls)
		}
	}
}
