package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

func TestRedTeamOutboxProcessorPublishesExactTenantRunAndAcknowledges(t *testing.T) {
	scope := fixtureRedTeamScope(t)
	runID := mustProductID(t, "pid_99100001-0000-4000-8000-000000000001")
	definitionID := "pid_99100002-0000-4000-8000-000000000002"
	inputDigest := sha256.Sum256([]byte("red-team-input"))
	payload, err := json.Marshal(map[string]any{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "run_id": runID.String(), "definition_id": definitionID, "definition_version": 7, "input_digest": hex.EncodeToString(inputDigest[:])})
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(payload)
	authority := &recordingRedTeamOutboxAuthority{events: []apiserver.RedTeamOutboxEvent{{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), ID: "pid_99100003-0000-4000-8000-000000000003", Topic: apiserver.RedTeamOutboxTopic, Payload: payload, PayloadDigest: payloadDigest[:], Attempt: 1, LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}}}
	publisher := &recordingOutboxPublisher{result: jobqueue.PublishResult{JobIDs: []domain.ProductID{runID}, Acknowledgements: []jobqueue.PublishAcknowledgement{{JobID: runID, ProviderAck: canonicalProviderAck(t, "red-team-provider-message")}}}}
	processor, err := newRedTeamOutboxProcessor(redTeamOutboxProcessorConfig{Authority: authority, Publisher: publisher, WorkerID: "red-team-outbox-01", LeaseSeconds: 60, BatchSize: 10, RetrySeconds: 30, HeartbeatInterval: 20 * time.Millisecond, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 32), nil }, Ready: readyOutboxDependency})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(publisher.jobs) != 1 || publisher.jobs[0].Kind != "red-team" || publisher.jobs[0].Scope != scope || publisher.jobs[0].JobID != runID || publisher.jobs[0].AuthorityDigest != inputDigest {
		t.Fatalf("jobs=%#v", publisher.jobs)
	}
	if authority.acknowledged != 1 || authority.retried != 0 || authority.heartbeats < 1 {
		t.Fatalf("ack=%d retry=%d heartbeat=%d", authority.acknowledged, authority.retried, authority.heartbeats)
	}
}

type recordingRedTeamOutboxAuthority struct {
	mu           sync.Mutex
	events       []apiserver.RedTeamOutboxEvent
	heartbeats   int
	acknowledged int
	retried      int
}

func (authority *recordingRedTeamOutboxAuthority) Ready(context.Context) error { return nil }
func (authority *recordingRedTeamOutboxAuthority) ClaimRedTeamOutbox(context.Context, string, string, int, int) ([]apiserver.RedTeamOutboxEvent, error) {
	return append([]apiserver.RedTeamOutboxEvent(nil), authority.events...), nil
}
func (authority *recordingRedTeamOutboxAuthority) HeartbeatRedTeamOutbox(context.Context, domain.Scope, string, string, string, int) (bool, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.heartbeats++
	return true, nil
}
func (authority *recordingRedTeamOutboxAuthority) AcknowledgeRedTeamOutbox(context.Context, domain.Scope, string, string, string, string) error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.acknowledged++
	return nil
}
func (authority *recordingRedTeamOutboxAuthority) RetryRedTeamOutbox(context.Context, domain.Scope, string, string, string, time.Time) error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.retried++
	return nil
}

func fixtureRedTeamScope(t *testing.T) domain.Scope {
	t.Helper()
	organization := mustProductID(t, "pid_99100010-0000-4000-8000-000000000010")
	workspace := mustProductID(t, "pid_99100011-0000-4000-8000-000000000011")
	environment := mustProductID(t, "pid_99100012-0000-4000-8000-000000000012")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
