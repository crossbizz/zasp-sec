package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

func TestRedTeamProcessorRunsLeaseFencedTestPersistsEvidenceThenAcknowledges(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	runID := mustProductID(t, "pid_99200001-0000-4000-8000-000000000001")
	definitionID := "pid_99200002-0000-4000-8000-000000000002"
	inputDigest := sha256.Sum256([]byte("red-team-authority"))
	payload := redTeamQueuePayload(t, scope, runID.String(), definitionID, 1, inputDigest)
	steps := []string{}
	now := time.Now().UTC()
	started := now.Add(-time.Second)
	authority := &recordingRedTeamExecutionAuthority{steps: &steps, claim: apiserver.RedTeamRunClaim{Disposition: "claimed", Run: apiserver.RedTeamRun{ID: runID.String(), Version: 2, DefinitionID: definitionID, DefinitionVersion: 1, Status: "leased", Attempt: 1, QueuedAt: now.Add(-2 * time.Second), StartedAt: &started}, Definition: apiserver.RedTeamDefinition{ID: definitionID, Version: 1, Name: "Prompt injection", TargetID: "pid_99200003-0000-4000-8000-000000000003", TargetKind: "agent_endpoint", Categories: []string{"prompt_injection"}, Safety: apiserver.RedTeamSafety{Environment: "test", CredentialClass: "read_only", ExpectedSideEffects: []string{"bounded evaluation"}}, Enabled: true, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour)}, InputDigest: inputDigest, LeaseExpiresAt: now.Add(time.Minute)}}
	queue := &recordingDiscoveryQueue{deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: runID, Kind: "red-team", Payload: payload, AuthorityDigest: inputDigest}}}, steps: &steps}
	key := "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/" + runID.String()
	runner := &recordingRedTeamRunner{steps: &steps, result: redTeamExecutionResult{Verdict: "pass", Objective: "Reject prompt injection", Behavior: "The target refused the unsafe instruction.", Evidence: []string{"bounded refusal observed"}, EvidenceReference: "s3://zasp-evidence/" + key, EvidenceKey: key, EvidenceVersionID: "version-1", EvidenceChecksum: bytes.Repeat([]byte{0xdd}, 32), EvidenceSizeBytes: 128}}
	runner.result.InputArtifact = &apiserver.RedTeamArtifactReference{Reference: "s3://zasp-evidence/" + strings.TrimSuffix(key, runID.String()) + "pid_99200004-0000-4000-8000-000000000004", VersionID: "input-version-1", SHA256: strings.Repeat("a", 64), SizeBytes: 512}
	processor, err := newRedTeamProcessor(redTeamProcessorConfig{Authority: authority, Queue: queue, Runner: runner, WorkerID: "red-team-worker-01", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 32), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce error=%v steps=%v", err, steps)
	}
	if got, want := fmt.Sprint(steps), fmt.Sprint([]string{"consume", "claim", "run", "finish", "ack"}); got != want {
		t.Fatalf("steps=%v want=%v", steps, want)
	}
	if authority.completion.RunID != runID.String() || authority.completion.InputDigest != inputDigest || authority.completion.EvidenceReference != runner.result.EvidenceReference {
		t.Fatalf("completion=%#v", authority.completion)
	}
	if authority.completion.InputArtifact == nil || *authority.completion.InputArtifact != *runner.result.InputArtifact {
		t.Fatal("worker lost immutable input artifact binding")
	}
}

func redTeamQueuePayload(t *testing.T, scope domain.Scope, runID, definitionID string, version int64, digest [sha256.Size]byte) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(redTeamOutboxPayload{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), RunID: runID, DefinitionID: definitionID, DefinitionVersion: version, InputDigest: hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

type recordingRedTeamExecutionAuthority struct {
	steps      *[]string
	claim      apiserver.RedTeamRunClaim
	completion apiserver.RedTeamRunCompletion
}

func (authority *recordingRedTeamExecutionAuthority) Ready(context.Context) error { return nil }
func (authority *recordingRedTeamExecutionAuthority) ClaimRedTeamRun(context.Context, domain.Scope, string, string, string, int) (apiserver.RedTeamRunClaim, error) {
	*authority.steps = append(*authority.steps, "claim")
	return authority.claim, nil
}
func (*recordingRedTeamExecutionAuthority) HeartbeatRedTeamRun(context.Context, domain.Scope, string, string, string, int) (apiserver.RedTeamRunHeartbeat, error) {
	return apiserver.RedTeamRunHeartbeat{Renewed: true}, nil
}
func (authority *recordingRedTeamExecutionAuthority) FinishRedTeamRun(_ context.Context, _ domain.Scope, input apiserver.RedTeamRunCompletion) (apiserver.RedTeamRun, error) {
	*authority.steps = append(*authority.steps, "finish")
	authority.completion = input
	completed := time.Now().UTC()
	return apiserver.RedTeamRun{ID: input.RunID, Version: 3, DefinitionID: authority.claim.Run.DefinitionID, DefinitionVersion: authority.claim.Run.DefinitionVersion, Status: "complete", Attempt: authority.claim.Run.Attempt, QueuedAt: authority.claim.Run.QueuedAt, StartedAt: authority.claim.Run.StartedAt, CompletedAt: &completed, Verdict: input.Verdict, EvidenceReference: input.EvidenceReference}, nil
}
func (*recordingRedTeamExecutionAuthority) RetryRedTeamRun(context.Context, domain.Scope, string, string, string, [sha256.Size]byte, string, time.Time) (apiserver.RedTeamRun, error) {
	return apiserver.RedTeamRun{}, nil
}
func (*recordingRedTeamExecutionAuthority) CancelClaimedRedTeamRun(context.Context, domain.Scope, string, string, string, [sha256.Size]byte) (apiserver.RedTeamRun, error) {
	return apiserver.RedTeamRun{}, nil
}

type recordingRedTeamRunner struct {
	steps  *[]string
	result redTeamExecutionResult
}

func (runner *recordingRedTeamRunner) Run(context.Context, redTeamExecutionRequest) (redTeamExecutionResult, error) {
	*runner.steps = append(*runner.steps, "run")
	return runner.result, nil
}
