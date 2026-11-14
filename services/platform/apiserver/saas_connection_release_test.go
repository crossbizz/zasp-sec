package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type saasReleaseStoreStub struct {
	claims    [][]SaaSConnectionRelease
	claimErr  error
	finished  []string
	finishErr error
}

func (stub *saasReleaseStoreStub) Claim(ctx context.Context, owner string, _, _ int) ([]SaaSConnectionRelease, error) {
	if !connectorMaintenanceStatement(ctx, postgresSaaSConnectionReleaseClaimSQL) {
		return nil, ErrAuthorizationDenied
	}
	if stub.claimErr != nil || len(stub.claims) == 0 {
		return []SaaSConnectionRelease{}, stub.claimErr
	}
	batch := stub.claims[0]
	stub.claims = stub.claims[1:]
	return batch, nil
}

func (stub *saasReleaseStoreStub) Finish(_ context.Context, release SaaSConnectionRelease, released bool, errorCode string) (SaaSConnectionReleaseOutcome, error) {
	outcome := "retry"
	if released {
		outcome = "released"
	}
	stub.finished = append(stub.finished, release.ConnectionReference+" "+outcome+" "+errorCode)
	return SaaSConnectionReleaseOutcome{Status: map[bool]string{true: "released", false: "pending"}[released], Attempt: release.Attempt}, stub.finishErr
}

type saasReleaseRemoverStub struct {
	errors   map[string]error
	removed  []string
	deadline []bool
}

func (stub *saasReleaseRemoverStub) RemoveConnection(ctx context.Context, release SaaSConnectionRelease) error {
	_, bounded := ctx.Deadline()
	stub.removed, stub.deadline = append(stub.removed, release.ConnectionReference), append(stub.deadline, bounded)
	return stub.errors[release.ConnectionReference]
}

func saasReleaseFixture(reference string, lease time.Duration) SaaSConnectionRelease {
	return SaaSConnectionRelease{OrganizationID: "pid_61000001-0000-4000-8000-000000000001", WorkspaceID: "pid_61000002-0000-4000-8000-000000000002", EnvironmentID: "pid_61000003-0000-4000-8000-000000000003",
		ConnectionReference: reference, IntegrationID: "pid_61000004-0000-4000-8000-000000000004", Platform: "servicenow", Reason: "integration_deleted", Attempt: 1,
		LeaseOwner: "release-worker", LeaseToken: strings.Repeat("a", 64), LeaseExpiresAt: time.Now().Add(lease)}
}

// The worker deletes each claimed connection before its lease ends and
// records a stable outcome: released, or the reason it is tried again.
func TestSaaSConnectionReleaserRecordsAnOutcomeForEachClaim(t *testing.T) {
	const gone, down, unknown, late = "ref:nango/connection/11111111-1111-4111-8111-111111111111", "ref:nango/connection/22222222-2222-4222-8222-222222222222", "ref:nango/connection/33333333-3333-4333-8333-333333333333", "ref:nango/connection/44444444-4444-4444-8444-444444444444"
	store := &saasReleaseStoreStub{claims: [][]SaaSConnectionRelease{{saasReleaseFixture(gone, 30*time.Second), saasReleaseFixture(down, 30*time.Second), saasReleaseFixture(unknown, 30*time.Second), saasReleaseFixture(late, time.Second)}}}
	remover := &saasReleaseRemoverStub{errors: map[string]error{down: errors.New("nango refused"), unknown: ErrRepositoryConfiguration}}
	releaser, err := NewSaaSConnectionReleaser(SaaSConnectionReleaserConfig{Repository: store, Remover: remover, Owner: "release-worker", LeaseSeconds: 30, Limit: 10, Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := releaser.releaseOnce(context.Background())
	if err != nil || claimed != 4 {
		t.Fatalf("claimed=%d err=%v", claimed, err)
	}
	// A lease too close to its end is left for the next claim: Nango is not
	// asked when the outcome could no longer be recorded.
	if strings.Join(remover.removed, ",") != gone+","+down+","+unknown {
		t.Fatalf("removed %v", remover.removed)
	}
	for index, bounded := range remover.deadline {
		if !bounded {
			t.Fatalf("removal %d ran without the lease's deadline", index)
		}
	}
	if strings.Join(store.finished, "|") != gone+" released |"+down+" retry nango_unavailable|"+unknown+" retry platform_unavailable" {
		t.Fatalf("outcomes %v", store.finished)
	}
	// Nothing due: nothing asked.
	if claimed, err := releaser.releaseOnce(context.Background()); err != nil || claimed != 0 || len(remover.removed) != 3 {
		t.Fatalf("empty pass claimed=%d err=%v", claimed, err)
	}
	// A failed claim or a failed outcome is reported and does not panic.
	store.claimErr = ErrRepositoryUnavailable
	if _, err := releaser.releaseOnce(context.Background()); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("claim failure: %v", err)
	}
	store.claimErr, store.finishErr = nil, ErrRepositoryConflict
	store.claims = [][]SaaSConnectionRelease{{saasReleaseFixture(gone, 30*time.Second)}}
	if _, err := releaser.releaseOnce(context.Background()); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("outcome failure: %v", err)
	}
}

// Run survives failing passes and ends, without an error, when its context
// ends: a lifecycle worker that returned early would take the API down.
func TestSaaSConnectionReleaserRunEndsOnlyWithItsContext(t *testing.T) {
	store := &saasReleaseStoreStub{claimErr: ErrRepositoryUnavailable}
	releaser, err := NewSaaSConnectionReleaser(SaaSConnectionReleaserConfig{Repository: store, Remover: &saasReleaseRemoverStub{}, Owner: "release-worker", LeaseSeconds: 30, Limit: 10, Interval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- releaser.Run(ctx) }()
	select {
	case err := <-done:
		t.Fatalf("the worker ended while its context was live: %v", err)
	case <-time.After(80 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the worker ended with %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the worker did not end with its context")
	}
	for name, config := range map[string]SaaSConnectionReleaserConfig{
		"no repository": {Remover: &saasReleaseRemoverStub{}, Owner: "release-worker", LeaseSeconds: 30, Limit: 10, Interval: time.Second},
		"no remover":    {Repository: store, Owner: "release-worker", LeaseSeconds: 30, Limit: 10, Interval: time.Second},
		"short owner":   {Repository: store, Remover: &saasReleaseRemoverStub{}, Owner: "x", LeaseSeconds: 30, Limit: 10, Interval: time.Second},
		"short lease":   {Repository: store, Remover: &saasReleaseRemoverStub{}, Owner: "release-worker", LeaseSeconds: 1, Limit: 10, Interval: time.Second},
		"no limit":      {Repository: store, Remover: &saasReleaseRemoverStub{}, Owner: "release-worker", LeaseSeconds: 30, Interval: time.Second},
		"no interval":   {Repository: store, Remover: &saasReleaseRemoverStub{}, Owner: "release-worker", LeaseSeconds: 30, Limit: 10},
	} {
		if _, err := NewSaaSConnectionReleaser(config); !errors.Is(err, ErrRepositoryConfiguration) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// The repository sends the lease with every outcome and refuses a claim or
// an outcome that PostgreSQL did not answer in the exact shape.
func TestSaaSConnectionReleaseRepositoryIsExact(t *testing.T) {
	const reference = "ref:nango/connection/11111111-1111-4111-8111-111111111111"
	expires := time.Now().UTC().Add(20 * time.Second).Format(time.RFC3339Nano)
	item := `{"organization_id":"pid_61000001-0000-4000-8000-000000000001","workspace_id":"pid_61000002-0000-4000-8000-000000000002","environment_id":"pid_61000003-0000-4000-8000-000000000003","connection_reference":"` + reference + `","integration_id":"pid_61000004-0000-4000-8000-000000000004","platform":"servicenow","reason":"integration_deleted","attempt":1,"lease_owner":"release-worker","lease_token":"` + strings.Repeat("a", 64) + `","lease_expires_at":"` + expires + `"}`
	database := &connectorCallDatabase{responses: map[string]json.RawMessage{
		postgresSaaSConnectionReleaseReadySQL:  json.RawMessage(`true`),
		postgresSaaSConnectionReleaseClaimSQL:  json.RawMessage(`{"items":[` + item + `]}`),
		postgresSaaSConnectionReleaseFinishSQL: json.RawMessage(`{"status":"released","attempt":1,"available_at":"` + expires + `"}`),
	}}
	repository, err := NewSaaSConnectionReleaseRepository(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := repository.Claim(context.Background(), "release-worker", 30, 10)
	if err != nil || len(claimed) != 1 || claimed[0].ConnectionReference != reference || len(database.args) != 3 || database.args[0] != "release-worker" {
		t.Fatalf("claim %+v %v args=%v", claimed, err, database.args)
	}
	outcome, err := repository.Finish(context.Background(), claimed[0], true, "")
	if err != nil || outcome.Status != "released" || len(database.args) != 8 || database.args[3] != reference || database.args[4] != "release-worker" || database.args[5] != claimed[0].LeaseToken || database.args[6] != true || database.args[7] != "" {
		t.Fatalf("finish %+v %v args=%v", outcome, err, database.args)
	}
	// An outcome is released without a code, or not released with one.
	for name, call := range map[string]func() error{
		"released with a code": func() error {
			_, err := repository.Finish(context.Background(), claimed[0], true, "nango_unavailable")
			return err
		},
		"failed without a code": func() error { _, err := repository.Finish(context.Background(), claimed[0], false, ""); return err },
		"a code with a secret": func() error {
			_, err := repository.Finish(context.Background(), claimed[0], false, "Bearer abc")
			return err
		},
		"a claim for nobody": func() error { _, err := repository.Claim(context.Background(), "", 30, 10); return err },
		"an endless lease":   func() error { _, err := repository.Claim(context.Background(), "release-worker", 3600, 10); return err },
	} {
		if err := call(); !errors.Is(err, ErrRepositoryOperation) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// PostgreSQL said the retry is pending while the worker reported success.
	database.responses[postgresSaaSConnectionReleaseFinishSQL] = json.RawMessage(`{"status":"pending","attempt":1,"available_at":"` + expires + `"}`)
	if _, err := repository.Finish(context.Background(), claimed[0], true, ""); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("a mismatched outcome was accepted: %v", err)
	}
	for name, hostile := range map[string]string{
		"another owner's lease": strings.Replace(item, `"lease_owner":"release-worker"`, `"lease_owner":"someone-else"`, 1),
		"an expired lease":      strings.Replace(item, expires, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), 1),
		"a token":               strings.Replace(item, `"platform":"servicenow"`, `"platform":"servicenow","access_token":"x"`, 1),
		"another reference":     strings.Replace(item, reference, "ref:nango/service-key-0001", 1),
	} {
		database.responses[postgresSaaSConnectionReleaseClaimSQL] = json.RawMessage(`{"items":[` + hostile + `]}`)
		if _, err := repository.Claim(context.Background(), "release-worker", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("%s was accepted: %v", name, err)
		}
	}
	// A database without the section has no repository; the API starts without the worker.
	database.responses[postgresSaaSConnectionReleaseReadySQL] = json.RawMessage(`false`)
	if _, err := NewSaaSConnectionReleaseRepository(context.Background(), database); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("a database without the section: %v", err)
	}
}

// Every reference-authorized provider is revoked as a reference: the local
// transition alone. No OAuth provider answers for them.
func TestReferenceConnectorKeysAreTheReferenceAuthorizedProviders(t *testing.T) {
	for _, key := range referenceAuthorizedProviders {
		if !referenceConnectorKey(key) {
			t.Fatalf("%s is not revoked as a reference connector", key)
		}
	}
	for _, key := range []string{"github", "okta", "nango:slack", "slack", ""} {
		if referenceConnectorKey(key) {
			t.Fatalf("%s is revoked as a reference connector", key)
		}
	}
}
