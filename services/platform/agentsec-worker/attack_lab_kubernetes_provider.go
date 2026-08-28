package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/attacklab"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var attackLabKubernetesUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type attackLabClusterAPI interface {
	Ready(context.Context) error
	Create(context.Context, attackLabKubernetesJob) (string, error)
	Reconcile(context.Context, attackLabKubernetesJob) (string, bool, error)
	Collect(context.Context, string, string, string, time.Duration) (attackLabClusterOutcome, error)
	Destroy(context.Context, string, string, string) error
}

type attackLabKubernetesJob struct {
	Namespace, Name, ServiceAccount, Image  string
	ProxyEndpoint, ProxyCAFile, EgressToken string
	OrganizationID, WorkspaceID             string
	EnvironmentID, RunID, Destination       string
	SuccessCriterion                        string
	ExpectedSideEffects                     []string
	InputDigest                             string
	Labels                                  map[string]string
	Limits                                  apiserver.AttackLabSandboxLimits
	ActiveDeadlineSeconds                   int
	AllowsDirectEgress                      bool
}

type attackLabClusterOutcome struct {
	CriterionObserved, CanaryTouched                    bool
	GatewayEvidence, EgressEvidence, KubernetesEvidence string
	CloudEvidence                                       string
}

type productionAttackLabKubernetesProviderConfig struct {
	Cluster                    attackLabClusterAPI
	Namespace, ServiceAccount  string
	RunnerImage                string
	ProxyEndpoint, ProxyCAFile string
	SigningKey                 []byte
	OperationTimeout           time.Duration
	Now                        func() time.Time
}

type productionAttackLabKubernetesProvider struct {
	config productionAttackLabKubernetesProviderConfig
}

func newProductionAttackLabKubernetesProvider(config productionAttackLabKubernetesProviderConfig) (*productionAttackLabKubernetesProvider, error) {
	if !validProductionAttackLabKubernetesProviderConfig(config) {
		return nil, errRuntimeUnavailable
	}
	config.SigningKey = append([]byte(nil), config.SigningKey...)
	return &productionAttackLabKubernetesProvider{config: config}, nil
}

func validProductionAttackLabKubernetesProviderConfig(config productionAttackLabKubernetesProviderConfig) bool {
	if config.Cluster == nil || config.Namespace != "zasp-attack-lab" || config.ServiceAccount != "agentsec-attack-lab-runner" || config.ProxyEndpoint != "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress" || config.ProxyCAFile != "/var/run/secrets/zasp-attack-lab/proxy-ca.crt" || len(config.SigningKey) < 32 || len(config.SigningKey) > 64 || config.OperationTimeout < time.Second || config.OperationTimeout > 30*time.Second || config.Now == nil {
		return false
	}
	if !regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr\.[a-z]{2}(?:-gov)?-[a-z]+-[0-9]\.amazonaws\.com/zasp/attack-lab-runner@sha256:[a-f0-9]{64}$`).MatchString(config.RunnerImage) {
		return false
	}
	now := config.Now()
	return !now.IsZero() && now.Location() == time.UTC
}

func (provider *productionAttackLabKubernetesProvider) Ready(ctx context.Context) error {
	if provider == nil || !validProductionAttackLabKubernetesProviderConfig(provider.config) || ctx == nil || ctx.Err() != nil || provider.config.Cluster.Ready(ctx) != nil {
		return errRuntimeUnavailable
	}
	return nil
}

func (provider *productionAttackLabKubernetesProvider) Create(ctx context.Context, request attackLabSandboxRequest) (attackLabSandbox, error) {
	if provider == nil || ctx == nil || ctx.Err() != nil || !validProductionAttackLabSandboxRequest(request, provider.config.Now()) {
		return attackLabSandbox{}, &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	job, err := provider.jobForRequest(request)
	if err != nil {
		return attackLabSandbox{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, provider.config.OperationTimeout)
	defer cancel()
	uid, createErr := provider.config.Cluster.Create(bounded, job)
	if createErr != nil || !attackLabKubernetesUIDPattern.MatchString(uid) {
		return attackLabSandbox{}, productionAttackLabProviderError(createErr, "outcome_unknown")
	}
	return attackLabSandbox{Reference: "k8s://attack-lab/jobs/" + job.Name + "@" + uid}, nil
}

func (provider *productionAttackLabKubernetesProvider) Reconcile(ctx context.Context, request attackLabSandboxRequest) (attackLabSandbox, bool, error) {
	if provider == nil || ctx == nil || ctx.Err() != nil || !validProductionAttackLabSandboxReconcileRequest(request) {
		return attackLabSandbox{}, false, &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	job, err := provider.jobForRequest(request)
	if err != nil {
		return attackLabSandbox{}, false, err
	}
	bounded, cancel := context.WithTimeout(ctx, provider.config.OperationTimeout)
	defer cancel()
	uid, reconcileErr := provider.config.Cluster.Create(bounded, job)
	if reconcileErr != nil || !attackLabKubernetesUIDPattern.MatchString(uid) {
		return attackLabSandbox{}, false, productionAttackLabProviderError(reconcileErr, "outcome_unknown")
	}
	return attackLabSandbox{Reference: "k8s://attack-lab/jobs/" + job.Name + "@" + uid}, true, nil
}

func (provider *productionAttackLabKubernetesProvider) jobForRequest(request attackLabSandboxRequest) (attackLabKubernetesJob, error) {
	name, ok := attackLabJobName(request.Scope, request.Run.ID)
	if !ok || request.Run.AttemptStartedAt == nil {
		return attackLabKubernetesJob{}, &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	expires := request.Run.AttemptStartedAt.Add(time.Duration(request.Run.Limits.TimeoutSeconds) * time.Second)
	token, err := signAttackLabEgressToken(provider.config.SigningKey, request, *request.Run.AttemptStartedAt, expires)
	if err != nil {
		return attackLabKubernetesJob{}, &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	return attackLabKubernetesJob{
		Namespace: provider.config.Namespace, Name: name, ServiceAccount: provider.config.ServiceAccount, Image: provider.config.RunnerImage,
		ProxyEndpoint: provider.config.ProxyEndpoint, ProxyCAFile: provider.config.ProxyCAFile, EgressToken: token,
		OrganizationID: request.Scope.OrganizationID().String(), WorkspaceID: request.Scope.WorkspaceID().String(), EnvironmentID: request.Scope.EnvironmentID().String(), RunID: request.Run.ID, Destination: request.Run.Destination,
		SuccessCriterion: request.Preflight.SuccessCriterion, ExpectedSideEffects: append([]string(nil), request.Preflight.ExpectedSideEffects...), InputDigest: hex.EncodeToString(request.InputDigest[:]),
		Labels: map[string]string{"zasp.io/execution": "attack-lab", "zasp.io/run-id": request.Run.ID}, Limits: request.Run.Limits, ActiveDeadlineSeconds: request.Run.Limits.TimeoutSeconds, AllowsDirectEgress: false,
	}, nil
}

func (provider *productionAttackLabKubernetesProvider) Collect(ctx context.Context, request attackLabSandboxRequest, sandbox attackLabSandbox) (attackLabSandboxResult, error) {
	if provider == nil || ctx == nil || ctx.Err() != nil || !validProductionAttackLabSandboxRequest(request, provider.config.Now()) {
		return attackLabSandboxResult{}, &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	name, uid, ok := attackLabSandboxIdentity(sandbox.Reference)
	wantName, nameOK := attackLabJobName(request.Scope, request.Run.ID)
	if !ok || !nameOK || name != wantName {
		return attackLabSandboxResult{}, &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	outcome, err := provider.config.Cluster.Collect(ctx, provider.config.Namespace, name, uid, time.Duration(request.Run.Limits.TimeoutSeconds)*time.Second)
	if err != nil {
		return attackLabSandboxResult{}, productionAttackLabProviderError(err, "outcome_unknown")
	}
	if !validAttackLabClusterOutcome(outcome) {
		return attackLabSandboxResult{}, &attackLabProviderFailure{code: "malformed", retryAfter: 30 * time.Second}
	}
	result := attackLabSandboxResult{CriterionObserved: outcome.CriterionObserved, CanaryTouched: outcome.CanaryTouched, Evidence: []string{
		"semantic:" + map[bool]string{true: "criterion observed", false: "criterion not observed"}[outcome.CriterionObserved],
		"gateway:" + outcome.GatewayEvidence, "egress:" + outcome.EgressEvidence, "kubernetes:" + outcome.KubernetesEvidence, "cloud:" + outcome.CloudEvidence,
	}}
	if outcome.CriterionObserved && outcome.CanaryTouched {
		result.Verdict = "verified"
	} else if !outcome.CriterionObserved && !outcome.CanaryTouched {
		result.Verdict = "not_reproduced"
	} else {
		result.Verdict, result.ErrorCode = "inconclusive", "outcome_unknown"
	}
	return result, nil
}

func (provider *productionAttackLabKubernetesProvider) Destroy(ctx context.Context, sandbox attackLabSandbox) error {
	if provider == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	name, uid, ok := attackLabSandboxIdentity(sandbox.Reference)
	if !ok {
		return errWorkerExecution
	}
	bounded, cancel := context.WithTimeout(ctx, provider.config.OperationTimeout)
	defer cancel()
	if err := provider.config.Cluster.Destroy(bounded, provider.config.Namespace, name, uid); err != nil {
		return productionAttackLabProviderError(err, "outcome_unknown")
	}
	return nil
}

func validProductionAttackLabSandboxRequest(request attackLabSandboxRequest, now time.Time) bool {
	return validProductionAttackLabSandboxReconcileRequest(request) && !now.IsZero() && now.Location() == time.UTC && !now.Before(*request.Run.AttemptStartedAt) && now.Before(request.Run.AttemptStartedAt.Add(300*time.Second))
}

func validProductionAttackLabSandboxReconcileRequest(request attackLabSandboxRequest) bool {
	if request.Scope.Validate() != nil || request.InputDigest == [sha256.Size]byte{} || request.Run.StartedAt == nil || request.Run.AttemptStartedAt == nil || request.Run.StartedAt.Location() != time.UTC || request.Run.AttemptStartedAt.Location() != time.UTC || request.Run.AttemptStartedAt.Before(*request.Run.StartedAt) || request.Run.Status != "leased" && request.Run.Status != "running" || request.Run.Attempt < 1 || request.Run.Attempt > 5 || request.Run.Environment == "production" || !stringInWorker(request.Run.Environment, "development", "test", "staging") || !stringInWorker(request.Run.CredentialClass, "read_only", "test_write") || request.Run.Limits != (apiserver.AttackLabSandboxLimits{CPU: "500m", Memory: "1Gi", EphemeralStorage: "2Gi", TimeoutSeconds: 300}) || request.Preflight.Environment != request.Run.Environment || request.Preflight.CredentialClass != request.Run.CredentialClass || request.Preflight.Destination != request.Run.Destination || len(request.Preflight.AllowedDestinations) != 1 || request.Preflight.AllowedDestinations[0] != request.Run.Destination || !validAttackLabWorkerDestination(request.Run.Destination) || !validAttackLabProviderText(request.Preflight.SuccessCriterion, 512) || len(request.Preflight.ExpectedSideEffects) < 1 || len(request.Preflight.ExpectedSideEffects) > 16 {
		return false
	}
	for _, value := range []string{request.Run.ID, request.Run.SourceRunID, request.Run.DefinitionID, request.Run.TargetID} {
		id, err := domain.ParseProductID(value)
		if err != nil || id.IsZero() {
			return false
		}
	}
	if request.Run.ID == request.Run.SourceRunID || request.Run.DefinitionVersion < 1 || request.Run.DefinitionVersion > 1_000_000 || !stringInWorker(request.Run.TargetKind, "agent_endpoint", "mcp_server", "coding_agent") {
		return false
	}
	for _, value := range request.Preflight.ExpectedSideEffects {
		if !validAttackLabProviderText(value, 256) {
			return false
		}
	}
	return true
}

func validAttackLabClusterOutcome(outcome attackLabClusterOutcome) bool {
	return validAttackLabProviderText(outcome.GatewayEvidence, 256) && validAttackLabProviderText(outcome.EgressEvidence, 256) && validAttackLabProviderText(outcome.KubernetesEvidence, 256) && validAttackLabProviderText(outcome.CloudEvidence, 256)
}

func validAttackLabProviderText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func attackLabJobName(scope domain.Scope, runID string) (string, bool) {
	if scope.Validate() != nil || !strings.HasPrefix(runID, "pid_") || !regexp.MustCompile(`^pid_[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`).MatchString(runID) {
		return "", false
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), runID}, "\x1f")))
	name := "zasp-attack-lab-" + hex.EncodeToString(digest[:16])
	return name, regexp.MustCompile(`^zasp-attack-lab-[a-f0-9]{32}$`).MatchString(name)
}

func attackLabSandboxIdentity(reference string) (string, string, bool) {
	if !attackLabWorkerSandboxReferencePattern.MatchString(reference) {
		return "", "", false
	}
	value := strings.TrimPrefix(reference, "k8s://attack-lab/jobs/")
	parts := strings.Split(value, "@")
	if len(parts) != 2 || !regexp.MustCompile(`^zasp-attack-lab-[a-f0-9]{32}$`).MatchString(parts[0]) || !attackLabKubernetesUIDPattern.MatchString(parts[1]) {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func signAttackLabEgressToken(key []byte, request attackLabSandboxRequest, now, expires time.Time) (string, error) {
	return attacklab.SignEgressCapability(key, attacklab.EgressGrant{Scope: request.Scope, RunID: request.Run.ID, Destination: request.Run.Destination, Methods: []string{"POST"}, ExpiresAt: expires, InputDigest: request.InputDigest}, now)
}

func verifyAttackLabEgressToken(key []byte, token string, scope domain.Scope, runID, destination, method string, now time.Time) error {
	grant, err := attacklab.VerifyEgressCapability(key, token, now)
	if err != nil || grant.Scope != scope || grant.RunID != runID || grant.Destination != destination || len(grant.Methods) != 1 || grant.Methods[0] != method {
		return errWorkerExecution
	}
	return nil
}

func productionAttackLabProviderError(err error, fallback string) error {
	var failure *attackLabProviderFailure
	if errors.As(err, &failure) && stringInWorker(failure.code, "retryable", "denied", "malformed", "outcome_unknown") {
		return failure
	}
	return &attackLabProviderFailure{code: fallback, retryAfter: 30 * time.Second}
}

var _ attackLabSandboxProvider = (*productionAttackLabKubernetesProvider)(nil)
