package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type attackLabLinkClient struct {
	db     existingTestQuery
	worker string
	now    func() time.Time
}
type attackLabLinkClaim struct {
	Organization string    `json:"organization_id"`
	Workspace    string    `json:"workspace_id"`
	Environment  string    `json:"environment_id"`
	Run          string    `json:"run_id"`
	Step         string    `json:"step_id"`
	Execution    string    `json:"execution_id"`
	Version      int64     `json:"version"`
	Generation   string    `json:"generation"`
	Expires      time.Time `json:"lease_expires_at"`
	scope        domain.Scope
	token        [32]byte
	worker       string
}
type attackLabLinkSettlement struct {
	claim    attackLabLinkClaim
	snapshot json.RawMessage
	proof    []byte
	digest   string
}

func newAttackLabLinkClient(db existingTestQuery, worker string, now func() time.Time) (*attackLabLinkClient, error) {
	if nilWorkerDependency(db) || !workerIdentityPattern.MatchString(worker) || now == nil {
		return nil, errRuntimeUnavailable
	}
	return &attackLabLinkClient{db, worker, now}, nil
}
func (c *attackLabLinkClient) query(ctx context.Context, operation string, args ...any) (json.RawMessage, error) {
	if c == nil || nilWorkerDependency(c.db) || ctx == nil || ctx.Err() != nil || c.now == nil {
		return nil, errRuntimeUnavailable
	}
	args = append(args, migrations.ProductionSecurityAgentAttackLab().Checksum(), migrations.SecurityAgentAttackLabFingerprint())
	positions := make([]string, len(args))
	for i := range args {
		positions[i] = fmt.Sprintf("$%d", i+1)
	}
	raw, err := c.db.QueryJSON(ctx, "SELECT zasp_sa_attack_lab_reconcile_"+operation+"("+strings.Join(positions, ",")+")", args...)
	if err != nil || ctx.Err() != nil || len(raw) == 0 || len(raw) > 131072 {
		return nil, errRuntimeUnavailable
	}
	return raw, nil
}
func (c *attackLabLinkClient) valid(v attackLabLinkClaim, live bool) bool {
	if c == nil || c.now == nil || v.scope.Validate() != nil || v.worker != c.worker || v.token == [32]byte{} || v.Version < 1 || !validExistingTestGeneration(v.Generation) || live && !v.Expires.After(c.now()) || v.Organization != v.scope.OrganizationID().String() || v.Workspace != v.scope.WorkspaceID().String() || v.Environment != v.scope.EnvironmentID().String() {
		return false
	}
	for _, id := range []string{v.Run, v.Step, v.Execution} {
		if _, err := domain.ParseProductID(id); err != nil {
			return false
		}
	}
	return true
}
func (v attackLabLinkClaim) args() []any {
	return []any{v.Organization, v.Workspace, v.Environment, v.Run, v.Step, v.worker, append([]byte(nil), v.token[:]...), v.Version, v.Generation}
}

func (c *attackLabLinkClient) Claim(ctx context.Context, scope domain.Scope) ([]attackLabLinkClaim, error) {
	if scope.Validate() != nil {
		return nil, errRuntimeUnavailable
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, errRuntimeUnavailable
	}
	raw, err := c.query(ctx, "claim", scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), c.worker, token[:], 60, 1)
	if err != nil {
		return nil, err
	}
	var rows []attackLabLinkClaim
	if decodeAttackLabJSON(raw, &rows) != nil || rows == nil || len(rows) > 1 {
		return nil, errRuntimeUnavailable
	}
	for i := range rows {
		rows[i].scope = scope
		rows[i].token = token
		rows[i].worker = c.worker
		if !c.valid(rows[i], true) || rows[i].Expires.After(c.now().Add(65*time.Second)) {
			return nil, errRuntimeUnavailable
		}
	}
	return rows, nil
}
func (c *attackLabLinkClient) Heartbeat(ctx context.Context, v attackLabLinkClaim) (attackLabLinkClaim, error) {
	if !c.valid(v, true) {
		return attackLabLinkClaim{}, errRuntimeUnavailable
	}
	raw, err := c.query(ctx, "heartbeat", append(v.args(), 60)...)
	if err != nil {
		return attackLabLinkClaim{}, err
	}
	var next attackLabLinkClaim
	if strictAttackLabJSON(raw, &next) != nil {
		return next, errRuntimeUnavailable
	}
	next.scope, next.token, next.worker = v.scope, v.token, v.worker
	if !c.valid(v, true) || !c.valid(next, true) || next.Run != v.Run || next.Step != v.Step || next.Execution != v.Execution || next.Version != v.Version+1 || next.Generation == v.Generation || next.Expires.Before(v.Expires) || next.Expires.After(c.now().Add(65*time.Second)) {
		return attackLabLinkClaim{}, errRuntimeUnavailable
	}
	return next, nil
}
func (c *attackLabLinkClient) CancelStopped(ctx context.Context, v attackLabLinkClaim) error {
	if !c.valid(v, true) {
		return errRuntimeUnavailable
	}
	raw, err := c.query(ctx, "cancel_stopped", v.args()...)
	var result struct {
		Execution  string `json:"execution_id"`
		State      string `json:"state"`
		Cancelled  *bool  `json:"cancel_requested"`
		Changed    *bool  `json:"changed"`
		Version    int64  `json:"version"`
		Generation string `json:"generation"`
	}
	if err != nil || !c.valid(v, true) || strictAttackLabJSON(raw, &result) != nil || result.Execution != v.Execution || result.Version != v.Version || result.Generation != v.Generation || result.Cancelled == nil || result.Changed == nil || !stringInWorker(result.State, "queued", "leased", "running", "retryable", "cleanup", "complete", "failed", "cancelled") || *result.Changed && !*result.Cancelled {
		return errRuntimeUnavailable
	}
	return nil
}
func (c *attackLabLinkClient) Evidence(ctx context.Context, v attackLabLinkClaim) (attackLabLinkSnapshot, error) {
	var empty attackLabLinkSnapshot
	if !c.valid(v, true) {
		return empty, errRuntimeUnavailable
	}
	raw, err := c.query(ctx, "evidence", v.args()...)
	if err != nil {
		return empty, err
	}
	var envelope struct {
		Version    int64           `json:"version"`
		Generation string          `json:"generation"`
		Expires    time.Time       `json:"lease_expires_at"`
		Snapshot   json.RawMessage `json:"snapshot"`
	}
	if strictAttackLabJSON(raw, &envelope) != nil || envelope.Version != v.Version || envelope.Generation != v.Generation || !envelope.Expires.Equal(v.Expires) || !c.valid(v, true) {
		return empty, errRuntimeUnavailable
	}
	var s attackLabLinkSnapshot
	if strictAttackLabJSON(envelope.Snapshot, &s, "schema_version", "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "source", "source_valid", "execution") != nil {
		return empty, errRuntimeUnavailable
	}
	s.scope = v.scope
	s.raw = append(json.RawMessage(nil), envelope.Snapshot...)
	x := s.Execution
	if s.Schema != "security-agent-attack-lab-snapshot-v1" || s.Organization != v.Organization || s.Workspace != v.Workspace || s.Environment != v.Environment || s.Run != v.Run || s.Step != v.Step || x.Run != v.Execution || x.Attempt < 0 || x.Attempt > 5 || !validAttackLabLinkDigest(x.InputDigest) || s.SourceValid == nil || x.Cancelled == nil || x.CleanupComplete == nil || x.Unknown == nil || x.Denied == nil || !stringInWorker(x.State, "queued", "leased", "running", "retryable", "cleanup", "complete", "failed", "cancelled") || !stringInWorker(x.CleanupState, "pending", "in_progress", "complete", "failed") {
		return empty, errRuntimeUnavailable
	}
	if s.Source.Attempt < 1 || s.Source.Attempt > 5 || s.Source.DefinitionVersion < 1 || s.Source.DefinitionVersion > 1000000 || !validAttackLabLinkDigest(s.Source.InputDigest) || !stringInWorker(s.Source.Kind, "agent_endpoint", "mcp_server", "coding_agent") || s.Source.Run == x.Run {
		return empty, errRuntimeUnavailable
	}
	for _, id := range []string{s.Source.Run, s.Source.Definition, s.Source.Target} {
		if _, err := domain.ParseProductID(id); err != nil {
			return empty, errRuntimeUnavailable
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, s.Source.Completed); err != nil {
		return empty, errRuntimeUnavailable
	}
	if x.Verdict != nil && !stringInWorker(*x.Verdict, "verified", "not_reproduced", "inconclusive") || x.Error != nil && !stringInWorker(*x.Error, "retryable", "denied", "malformed", "outcome_unknown", "cleanup_failed", "cancelled", "exhausted") || x.Sandbox != nil && !attackLabWorkerSandboxReferencePattern.MatchString(*x.Sandbox) || *x.CleanupComplete && (x.CleanupState != "complete" || !stringInWorker(x.State, "complete", "failed", "cancelled")) {
		return empty, errRuntimeUnavailable
	}
	return s, nil
}
func (c *attackLabLinkClient) Release(ctx context.Context, v attackLabLinkClaim) error {
	if !c.valid(v, true) {
		return errRuntimeUnavailable
	}
	raw, err := c.query(ctx, "release", append(v.args(), 30)...)
	var result struct {
		Run        string    `json:"run_id"`
		Step       string    `json:"step_id"`
		Version    int64     `json:"version"`
		Generation string    `json:"generation"`
		State      string    `json:"state"`
		Next       time.Time `json:"next_check_at"`
	}
	if err != nil || strictAttackLabJSON(raw, &result) != nil || !c.valid(v, true) || result.Run != v.Run || result.Step != v.Step || result.Version != v.Version+1 || result.Generation != v.Generation || result.State != "pending" || !result.Next.After(c.now()) || result.Next.After(c.now().Add(35*time.Second)) {
		return errRuntimeUnavailable
	}
	return nil
}
func (c *attackLabLinkClient) PrepareSettlement(v attackLabLinkClaim, s attackLabLinkSnapshot, p attackLabLinkProof) (attackLabLinkSettlement, error) {
	if !c.valid(v, true) || s.scope != v.scope || s.Run != v.Run || s.Step != v.Step || s.Execution.Run != v.Execution || len(s.raw) == 0 {
		return attackLabLinkSettlement{}, errRuntimeUnavailable
	}
	proof, err := attackLabProofBytes(p)
	if err != nil {
		return attackLabLinkSettlement{}, err
	}
	digest := sha256.Sum256(proof)
	return attackLabLinkSettlement{claim: v, snapshot: append(json.RawMessage(nil), s.raw...), proof: proof, digest: hex.EncodeToString(digest[:])}, nil
}
func (c *attackLabLinkClient) Settle(ctx context.Context, request attackLabLinkSettlement) error {
	v := request.claim
	if !c.valid(v, false) || len(request.snapshot) == 0 || len(request.proof) == 0 {
		return errRuntimeUnavailable
	}
	raw, err := c.query(ctx, "settle", append(v.args(), json.RawMessage(append([]byte(nil), request.snapshot...)), append([]byte(nil), request.proof...))...)
	var result struct {
		Run         string `json:"run_id"`
		Step        string `json:"step_id"`
		State       string `json:"state"`
		StepState   string `json:"step_state"`
		EffectState string `json:"effect_state"`
		Outcome     string `json:"outcome"`
		Reason      string `json:"reason"`
		Cleanup     *bool  `json:"cleanup_complete"`
		Digest      string `json:"proof_sha256"`
		Version     int64  `json:"version"`
		Generation  string `json:"generation"`
	}
	if err != nil || strictAttackLabJSON(raw, &result) != nil || result.Run != v.Run || result.Step != v.Step || result.Version != v.Version || result.Generation != v.Generation || result.Digest != request.digest || result.Cleanup == nil || !*result.Cleanup || !stringInWorker(result.Outcome, "needs_human", "inconclusive", "cancelled", "failed") || !stringInWorker(result.State, "needs_human", "inconclusive", "cancelled", "failed") {
		return errRuntimeUnavailable
	}
	var proof attackLabLinkProof
	var fields map[string]json.RawMessage
	json.Unmarshal(request.proof, &fields)
	delete(fields, "sha256")
	body, _ := json.Marshal(fields)
	if json.Unmarshal(body, &proof) != nil || result.Outcome != proof.Outcome || result.Reason != proof.Reason {
		return errRuntimeUnavailable
	}
	wantStep, wantEffect := proof.Outcome, "known_failure"
	if proof.Outcome == "needs_human" {
		wantStep, wantEffect = "succeeded", "succeeded"
	}
	if proof.Outcome == "inconclusive" {
		wantEffect = "unknown_outcome"
	}
	if result.StepState != wantStep || result.EffectState != wantEffect {
		return errRuntimeUnavailable
	}
	return nil
}
