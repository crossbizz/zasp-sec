package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/recovery"
	"github.com/zasp-ai/zasp-sec/services/platform/recovery/neondriver"
)

type recoveryKubernetesNetworkPolicy struct {
	Name   string
	Labels map[string]string
}

type recoveryKubernetesJob struct {
	Kind              string
	Name              string
	Namespace         string
	Labels            map[string]string
	Scope             domain.Scope
	TargetEnvironment string
	BranchHost        string
}

type recoveryKubernetesPlan struct {
	Namespace            string
	Labels               map[string]string
	Scope                domain.Scope
	RestoreID            string
	TargetEnvironment    string
	BranchID             string
	BranchHost           string
	ExpectedCounts       apiserver.RecoveryCounts
	ProjectionDigest     [sha256.Size]byte
	EvidenceSampleDigest [sha256.Size]byte
	NetworkPolicy        recoveryKubernetesNetworkPolicy
	Jobs                 []recoveryKubernetesJob
}

type recoveryKubernetesCleanupPlan struct {
	Namespace string
	Labels    map[string]string
	Scope     domain.Scope
	RestoreID string
}

type recoveryKubernetesAPI interface {
	Ready(context.Context) error
	Provision(context.Context, recoveryKubernetesPlan) (string, error)
	Validate(context.Context, recoveryKubernetesPlan, string) (apiserver.RecoveryCounts, apiserver.RecoveryArtifactLocator, error)
	Rebuild(context.Context, recoveryKubernetesPlan, string) ([sha256.Size]byte, error)
	CleanupNamespace(context.Context, recoveryKubernetesCleanupPlan, string) (string, error)
	RecordCleanup(context.Context, recoveryKubernetesCleanupPlan, string, string) (apiserver.RecoveryCleanupEvidence, error)
}

type productionRecoveryRestoreInfrastructureConfig struct {
	Neon           neondriver.Client
	Kubernetes     recoveryKubernetesAPI
	ProjectID      string
	ParentBranchID string
}

type productionRecoveryRestoreInfrastructure struct {
	config productionRecoveryRestoreInfrastructureConfig
}

func newProductionRecoveryRestoreInfrastructure(config productionRecoveryRestoreInfrastructureConfig) (*productionRecoveryRestoreInfrastructure, error) {
	if config.Neon == nil || config.Kubernetes == nil || config.ProjectID == "" || config.ParentBranchID == "" {
		return nil, errRuntimeUnavailable
	}
	return &productionRecoveryRestoreInfrastructure{config: config}, nil
}

func (infrastructure *productionRecoveryRestoreInfrastructure) Ready(ctx context.Context) error {
	if infrastructure == nil || ctx == nil || ctx.Err() != nil || infrastructure.config.Neon.Ready(ctx) != nil || infrastructure.config.Kubernetes.Ready(ctx) != nil {
		return errRuntimeUnavailable
	}
	return nil
}

func (infrastructure *productionRecoveryRestoreInfrastructure) Provision(ctx context.Context, input recoveryRestoreProvisionRequest) (recoveryRestoreTarget, error) {
	if infrastructure == nil || ctx == nil || ctx.Err() != nil || !validRecoveryOperationClaim(input.Scope) || input.Scope.Kind != "restore" || input.TargetEnvironment != input.Scope.TargetEnvironment || !validLoadedRecoveryManifest(input.Manifest, input.Scope.Scope) || input.EvidenceSampleDigest == ([sha256.Size]byte{}) || input.Manifest.NeonProjectID != infrastructure.config.ProjectID || input.Manifest.NeonBranchID != infrastructure.config.ParentBranchID {
		return recoveryRestoreTarget{}, errWorkerExecution
	}
	name, scopeDigest, err := recoveryRestoreNames(input.Scope)
	if err != nil {
		return recoveryRestoreTarget{}, errWorkerExecution
	}
	branch, err := infrastructure.config.Neon.CreateBranch(ctx, neondriver.CreateBranchRequest{Name: name, ParentLSN: input.Manifest.PostgresLSN})
	if err != nil {
		return recoveryRestoreTarget{}, errWorkerExecution
	}
	if branch.ProjectID != infrastructure.config.ProjectID || branch.ParentID != infrastructure.config.ParentBranchID || branch.ParentLSN != input.Manifest.PostgresLSN || branch.Name != name || len(branch.Endpoints) != 1 || branch.Endpoints[0].BranchID != branch.ID || branch.Endpoints[0].Type != "read_write" || branch.Endpoints[0].Host == "" {
		return recoveryRestoreTarget{BranchID: branch.ID, BranchName: name, Namespace: name, ScopeDigest: scopeDigest}, errWorkerExecution
	}
	plan := newRecoveryKubernetesPlan(input, branch, name, scopeDigest)
	target := recoveryRestoreTarget{BranchID: branch.ID, BranchName: name, Namespace: name, ScopeDigest: scopeDigest, plan: plan}
	uid, err := infrastructure.config.Kubernetes.Provision(ctx, plan)
	target.NamespaceUID = uid
	if err != nil {
		return target, errWorkerExecution
	}
	if uid == "" || len(uid) > 64 {
		return target, errWorkerExecution
	}
	return target, nil
}

func (infrastructure *productionRecoveryRestoreInfrastructure) Validate(ctx context.Context, target recoveryRestoreTarget, manifest recovery.Manifest) (apiserver.RecoveryCounts, apiserver.RecoveryArtifactLocator, error) {
	if !infrastructure.validTarget(ctx, target, manifest) {
		return apiserver.RecoveryCounts{}, apiserver.RecoveryArtifactLocator{}, errWorkerExecution
	}
	return infrastructure.config.Kubernetes.Validate(ctx, target.plan, target.NamespaceUID)
}

func (infrastructure *productionRecoveryRestoreInfrastructure) Rebuild(ctx context.Context, target recoveryRestoreTarget, manifest recovery.Manifest) ([sha256.Size]byte, error) {
	if !infrastructure.validTarget(ctx, target, manifest) {
		return [sha256.Size]byte{}, errWorkerExecution
	}
	return infrastructure.config.Kubernetes.Rebuild(ctx, target.plan, target.NamespaceUID)
}

func (infrastructure *productionRecoveryRestoreInfrastructure) Cleanup(ctx context.Context, target recoveryRestoreTarget) (apiserver.RecoveryCleanupEvidence, error) {
	if infrastructure == nil || ctx == nil || ctx.Err() != nil || target.BranchID == "" || target.BranchName == "" || target.Namespace == "" || len(target.ScopeDigest) != 16 || target.plan.Namespace != target.Namespace || target.plan.BranchID != target.BranchID {
		return apiserver.RecoveryCleanupEvidence{}, errWorkerExecution
	}
	plan := recoveryCleanupPlan(target.plan.Scope, target.plan.RestoreID, target.Namespace, target.ScopeDigest)
	return infrastructure.cleanupResources(ctx, plan, target.NamespaceUID, target.BranchID, nil)
}

func (infrastructure *productionRecoveryRestoreInfrastructure) ReconcileCleanup(ctx context.Context, claim recoveryOperationClaim) (apiserver.RecoveryCleanupEvidence, error) {
	if infrastructure == nil || ctx == nil || ctx.Err() != nil || !validRecoveryOperationClaim(claim) || claim.Kind != "restore" || !claim.CleanupOnly {
		return apiserver.RecoveryCleanupEvidence{}, errWorkerExecution
	}
	name, scopeDigest, err := recoveryRestoreNames(claim)
	if err != nil {
		return apiserver.RecoveryCleanupEvidence{}, errWorkerExecution
	}
	plan := recoveryCleanupPlan(claim.Scope, claim.OperationID, name, scopeDigest)
	branch, branchErr := infrastructure.config.Neon.GetBranchByName(ctx, infrastructure.config.ProjectID, name)
	branchID := ""
	if errors.Is(branchErr, neondriver.ErrNotFound) {
		branchErr = nil
	} else if branchErr == nil {
		if branch.ProjectID != infrastructure.config.ProjectID || branch.ParentID != infrastructure.config.ParentBranchID || branch.Name != name || branch.ID == "" {
			branchErr = errWorkerExecution
		} else {
			branchID = branch.ID
		}
	}
	return infrastructure.cleanupResources(ctx, plan, "", branchID, branchErr)
}

func (infrastructure *productionRecoveryRestoreInfrastructure) cleanupResources(ctx context.Context, plan recoveryKubernetesCleanupPlan, namespaceUID, branchID string, priorNeonErr error) (apiserver.RecoveryCleanupEvidence, error) {
	resolvedUID, kubernetesErr := infrastructure.config.Kubernetes.CleanupNamespace(ctx, plan, namespaceUID)
	neonErr := priorNeonErr
	if neonErr == nil && branchID != "" {
		neonErr = infrastructure.config.Neon.DeleteBranch(ctx, infrastructure.config.ProjectID, branchID)
	}
	state := "deleted"
	if kubernetesErr != nil || neonErr != nil {
		state = "failed"
	}
	evidence, evidenceErr := infrastructure.config.Kubernetes.RecordCleanup(ctx, plan, resolvedUID, state)
	if evidenceErr != nil || evidence.State != state {
		return apiserver.RecoveryCleanupEvidence{}, errWorkerExecution
	}
	if state == "failed" {
		return evidence, errWorkerExecution
	}
	return evidence, nil
}

func (infrastructure *productionRecoveryRestoreInfrastructure) validTarget(ctx context.Context, target recoveryRestoreTarget, manifest recovery.Manifest) bool {
	return infrastructure != nil && ctx != nil && ctx.Err() == nil && target.BranchID != "" && target.NamespaceUID != "" && target.plan.Namespace == target.Namespace && target.plan.BranchID == target.BranchID && target.plan.ProjectionDigest == manifest.Projection.SHA256 && target.plan.ExpectedCounts == recoveryManifestCounts(manifest)
}

func newRecoveryKubernetesPlan(input recoveryRestoreProvisionRequest, branch neondriver.Branch, name, scopeDigest string) recoveryKubernetesPlan {
	labels := map[string]string{"app.kubernetes.io/managed-by": "agentsec-recovery", "zasp.io/recovery-id": input.Scope.OperationID, "zasp.io/recovery-scope": scopeDigest}
	job := func(kind string) recoveryKubernetesJob {
		return recoveryKubernetesJob{Kind: kind, Name: name + "-" + strings.TrimSuffix(kind, "-projection"), Namespace: name, Labels: cloneRecoveryLabels(labels), Scope: input.Scope.Scope, TargetEnvironment: input.TargetEnvironment, BranchHost: branch.Endpoints[0].Host}
	}
	return recoveryKubernetesPlan{
		Namespace: name, Labels: labels, Scope: input.Scope.Scope, RestoreID: input.Scope.OperationID, TargetEnvironment: input.TargetEnvironment, BranchID: branch.ID, BranchHost: branch.Endpoints[0].Host,
		ExpectedCounts: recoveryManifestCounts(input.Manifest), ProjectionDigest: input.Manifest.Projection.SHA256, EvidenceSampleDigest: input.EvidenceSampleDigest,
		NetworkPolicy: recoveryKubernetesNetworkPolicy{Name: "recovery-deny-by-default", Labels: cloneRecoveryLabels(labels)},
		Jobs:          []recoveryKubernetesJob{job("postgres-validation"), job("graph-projection"), job("search-projection")},
	}
}

func recoveryRestoreNames(claim recoveryOperationClaim) (string, string, error) {
	if !validRecoveryOperationClaim(claim) || claim.Kind != "restore" {
		return "", "", errWorkerExecution
	}
	return recoveryRestoreIdentity(claim.Scope, claim.OperationID)
}

func recoveryRestoreIdentity(scope domain.Scope, restoreID string) (string, string, error) {
	parsed, err := domain.ParseProductID(restoreID)
	if scope.Validate() != nil || err != nil || parsed.IsZero() {
		return "", "", errWorkerExecution
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), restoreID}, "\x1f")))
	scopeDigest := hex.EncodeToString(digest[:8])
	name := "zasp-recovery-" + hex.EncodeToString(digest[:16])
	if !neondriver.ValidRecoveryBranchName(name) {
		return "", "", errWorkerExecution
	}
	return name, scopeDigest, nil
}

func recoveryCleanupPlan(scope domain.Scope, restoreID, namespace, scopeDigest string) recoveryKubernetesCleanupPlan {
	return recoveryKubernetesCleanupPlan{Namespace: namespace, Scope: scope, RestoreID: restoreID, Labels: map[string]string{"app.kubernetes.io/managed-by": "agentsec-recovery", "zasp.io/recovery-id": restoreID, "zasp.io/recovery-scope": scopeDigest}}
}

func cloneRecoveryLabels(value map[string]string) map[string]string {
	clone := make(map[string]string, len(value))
	for key, item := range value {
		clone[key] = item
	}
	return clone
}

var _ recoveryRestoreInfrastructure = (*productionRecoveryRestoreInfrastructure)(nil)
