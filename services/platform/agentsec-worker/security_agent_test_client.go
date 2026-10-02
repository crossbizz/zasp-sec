package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/legacytests"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type existingTestQuery interface {
	QueryJSON(context.Context, string, ...any) (json.RawMessage, error)
}
type existingTestClient struct {
	db     existingTestQuery
	worker string
	now    func() time.Time
}
type existingTestClaim struct {
	scope              domain.Scope
	run, step, testRun string
	version            int64
	generation         string
	expires            time.Time
	token              [32]byte
	worker             string
}

func newExistingTestClient(db existingTestQuery, worker string, now func() time.Time) (*existingTestClient, error) {
	if nilWorkerDependency(db) || !workerIdentityPattern.MatchString(worker) || now == nil {
		return nil, errRuntimeUnavailable
	}
	if probe, ok := db.(interface {
		LegacyTestsAvailable(context.Context, string) (bool, error)
	}); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		installed, err := probe.LegacyTestsAvailable(ctx, "zasp_security_agent_worker")
		cancel()
		if err != nil {
			return nil, errRuntimeUnavailable
		}
		if installed {
			db = legacytests.Database{DB: db, Role: "zasp_security_agent_worker"}
		}
	}
	return &existingTestClient{db: db, worker: worker, now: now}, nil
}

func (c *existingTestClient) query(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if c == nil || nilWorkerDependency(c.db) || c.now == nil || ctx == nil || ctx.Err() != nil {
		return nil, errRuntimeUnavailable
	}
	args = append(args, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
	raw, err := c.db.QueryJSON(ctx, q, args...)
	if err != nil || ctx.Err() != nil || len(raw) == 0 || len(raw) > 131072 {
		return nil, errRuntimeUnavailable
	}
	return raw, nil
}

func (c *existingTestClient) Claim(ctx context.Context, scope domain.Scope, seconds, limit int) ([]existingTestClaim, error) {
	if c == nil || scope.Validate() != nil || seconds < 10 || seconds > 300 || limit < 1 || limit > 25 {
		return nil, errRuntimeUnavailable
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, errRuntimeUnavailable
	}
	raw, err := c.query(ctx, "SELECT zasp_production_security_agent_existing_tests_reconcile_claim($1,$2,$3,$4,$5,$6,$7,$8,$9)", scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), c.worker, token[:], seconds, limit)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Organization string `json:"organization_id"`
		Workspace    string `json:"workspace_id"`
		Environment  string `json:"environment_id"`
		Run          string `json:"run_id"`
		Step         string `json:"step_id"`
		TestRun      string `json:"test_run_id"`
		Version      int64  `json:"version"`
		Generation   string `json:"generation"`
		Expires      string `json:"lease_expires_at"`
	}
	if decodeRedTeamEvidenceJSON(redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}, raw, &rows) != nil || rows == nil || len(rows) > limit {
		return nil, errRuntimeUnavailable
	}
	result := make([]existingTestClaim, 0, len(rows))
	seen := map[string]bool{}
	for _, row := range rows {
		expiry, err := time.Parse(time.RFC3339Nano, row.Expires)
		claim := existingTestClaim{scope: scope, run: row.Run, step: row.Step, testRun: row.TestRun, version: row.Version, generation: row.Generation, expires: expiry, token: token, worker: c.worker}
		key := row.Run + "/" + row.Step
		if err != nil || expiry.After(c.now().Add(time.Duration(seconds+5)*time.Second)) || row.Organization != scope.OrganizationID().String() || row.Workspace != scope.WorkspaceID().String() || row.Environment != scope.EnvironmentID().String() || seen[key] || !c.valid(claim) {
			return nil, errRuntimeUnavailable
		}
		seen[key] = true
		result = append(result, claim)
	}
	return result, nil
}

func (c *existingTestClient) valid(claim existingTestClaim) bool {
	if c == nil || c.now == nil || claim.scope.Validate() != nil || claim.worker != c.worker || claim.version < 1 || claim.version > 1000000 || !validExistingTestGeneration(claim.generation) || claim.token == [32]byte{} || !claim.expires.After(c.now()) {
		return false
	}
	for _, id := range []string{claim.run, claim.step, claim.testRun} {
		if _, err := domain.ParseProductID(id); err != nil {
			return false
		}
	}
	return true
}

func (claim existingTestClaim) args() []any {
	return []any{claim.scope.OrganizationID().String(), claim.scope.WorkspaceID().String(), claim.scope.EnvironmentID().String(), claim.run, claim.step, claim.worker, append([]byte(nil), claim.token[:]...), claim.version, claim.generation}
}

func validExistingTestGeneration(value string) bool {
	_, err := domain.ParseProductID("pid_" + value)
	return err == nil
}

func (c *existingTestClient) Evidence(ctx context.Context, claim existingTestClaim) (existingTestSnapshot, error) {
	if !c.valid(claim) {
		return existingTestSnapshot{}, errRuntimeUnavailable
	}
	raw, err := c.query(ctx, "SELECT zasp_production_security_agent_existing_tests_reconcile_evidence($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", claim.args()...)
	if err != nil || !c.valid(claim) {
		return existingTestSnapshot{}, errRuntimeUnavailable
	}
	return decodeExistingTestSnapshot(raw, claim.scope, claim.run, claim.step, claim.testRun, claim.version, claim.generation, c.now())
}

func (c *existingTestClient) CancelStopped(ctx context.Context, claim existingTestClaim) error {
	if !c.valid(claim) {
		return errRuntimeUnavailable
	}
	raw, err := c.query(ctx, "SELECT zasp_production_security_agent_existing_tests_reconcile_cancel_stopped($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", claim.args()...)
	var wire struct {
		Generation string  `json:"generation"`
		Run        string  `json:"test_run_id"`
		State      string  `json:"state"`
		Outcome    *string `json:"cancellation_outcome"`
		Changed    *bool   `json:"changed"`
	}
	if err != nil || !c.valid(claim) || decodeRedTeamEvidenceJSON(redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}, raw, &wire) != nil || wire.Generation != claim.generation || wire.Run != claim.testRun || wire.Changed == nil || !stringInWorker(wire.State, "queued", "leased", "retryable", "complete", "failed", "cancelled") {
		return errRuntimeUnavailable
	}
	if wire.Outcome != nil && !stringInWorker(*wire.Outcome, "cancelled_before_execution", "cancelled_after_partial_execution", "outcome_unknown") {
		return errRuntimeUnavailable
	}
	if *wire.Changed && wire.Outcome == nil || wire.Outcome != nil && (*wire.Outcome == "outcome_unknown" && wire.State != "failed" || *wire.Outcome != "outcome_unknown" && wire.State != "cancelled") {
		return errRuntimeUnavailable
	}
	return nil
}

func (c *existingTestClient) Heartbeat(ctx context.Context, claim existingTestClaim, seconds int) (existingTestClaim, error) {
	if !c.valid(claim) || seconds < 10 || seconds > 300 {
		return existingTestClaim{}, errRuntimeUnavailable
	}
	raw, err := c.query(ctx, "SELECT zasp_production_security_agent_existing_tests_reconcile_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)", append(claim.args(), seconds)...)
	var wire struct {
		Generation string `json:"generation"`
		Run        string `json:"run_id"`
		Step       string `json:"step_id"`
		Version    int64  `json:"version"`
		Expires    string `json:"lease_expires_at"`
	}
	if err != nil || !c.valid(claim) || decodeRedTeamEvidenceJSON(redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}, raw, &wire) != nil || wire.Generation != claim.generation || wire.Run != claim.run || wire.Step != claim.step || wire.Version != claim.version {
		return existingTestClaim{}, errRuntimeUnavailable
	}
	expiry, err := time.Parse(time.RFC3339Nano, wire.Expires)
	if err != nil || !expiry.After(c.now()) || expiry.After(c.now().Add(time.Duration(seconds+5)*time.Second)) {
		return existingTestClaim{}, errRuntimeUnavailable
	}
	claim.expires = expiry
	return claim, nil
}

func (c *existingTestClient) Release(ctx context.Context, claim existingTestClaim, delay int) (time.Time, error) {
	if !c.valid(claim) || delay < 10 || delay > 300 {
		return time.Time{}, errRuntimeUnavailable
	}
	raw, err := c.query(ctx, "SELECT zasp_production_security_agent_existing_tests_reconcile_release($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)", append(claim.args(), delay)...)
	var wire struct {
		Generation string `json:"generation"`
		Run        string `json:"run_id"`
		Step       string `json:"step_id"`
		Version    int64  `json:"version"`
		State      string `json:"state"`
		Next       string `json:"next_check_at"`
	}
	if err != nil || !c.valid(claim) || decodeRedTeamEvidenceJSON(redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}, raw, &wire) != nil || wire.Generation != claim.generation || wire.Run != claim.run || wire.Step != claim.step || wire.Version != min(claim.version+1, 1000000) || wire.State != "pending" {
		return time.Time{}, errRuntimeUnavailable
	}
	next, err := time.Parse(time.RFC3339Nano, wire.Next)
	if err != nil || !next.After(c.now()) || next.After(c.now().Add(time.Duration(delay+5)*time.Second)) {
		return time.Time{}, errRuntimeUnavailable
	}
	return next, nil
}
