package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	runtimeopensearch "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
)

const (
	retentionCleanupClaimSQL     = `SELECT zasp_retention_v1.cleanup_claim($1::jsonb)`
	retentionCleanupAuthorizeSQL = `SELECT zasp_retention_v1.cleanup_authorize($1::jsonb)`
	retentionCleanupSettleSQL    = `SELECT zasp_retention_v1.cleanup_settle($1::jsonb)`
	retentionCleanupLeaseLayout  = "2006-01-02T15:04:05.000000Z"
)

type retentionCleanupTransactions interface {
	BeginRetentionCleanup(context.Context) (pgx.Tx, error)
}
type retentionCleanupPurge interface {
	PurgeEvent(context.Context, domain.Scope, string) (runtimeopensearch.RetentionPurgeObservation, error)
	FixedKind() string
}
type retentionCleanupPurgeFactory func(runtimeopensearch.RetentionPurgeAuthority) (retentionCleanupPurge, error)

// A private captured SQL claim, never a workflow argument, log, or API payload.
type retentionCleanupClaim struct {
	ClaimID        string `json:"claim_id"`
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	EventID        string `json:"event_id"`
	SourceDigest   string `json:"source_digest"`
	Kind           string `json:"kind"`
	WorkerID       string `json:"worker_id"`
	LeaseToken     string `json:"lease_token"`
	LeaseUntil     string `json:"lease_until"`
}

func (retentionCleanupClaim) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "retention-cleanup-claim[redacted]")
}
func (c retentionCleanupClaim) scope() (domain.Scope, error) {
	o, oe := domain.ParseProductID(c.OrganizationID)
	w, we := domain.ParseProductID(c.WorkspaceID)
	e, ee := domain.ParseProductID(c.EnvironmentID)
	if oe != nil || we != nil || ee != nil {
		return domain.Scope{}, errRuntimeUnavailable
	}
	return domain.NewScope(o, w, e)
}
func (c retentionCleanupClaim) valid(worker string) bool {
	if !retentionCycleKeyPattern.MatchString(c.ClaimID) || !retentionCycleKeyPattern.MatchString(c.SourceDigest) || !retentionCycleKeyPattern.MatchString(c.LeaseToken) || c.WorkerID != worker {
		return false
	}
	if _, err := c.scope(); err != nil {
		return false
	}
	if _, err := domain.ParseProductID(c.EventID); err != nil {
		return false
	}
	if c.Kind != "raw-index" && c.Kind != "session-index-v1" && c.Kind != "session-index-v2" {
		return false
	}
	until, err := time.Parse(retentionCleanupLeaseLayout, c.LeaseUntil)
	return err == nil && until.Format(retentionCleanupLeaseLayout) == c.LeaseUntil && until.After(time.Now())
}

type retentionCleanup struct {
	database                    retentionCleanupTransactions
	checksum, workerID          string
	factories                   map[string]retentionCleanupPurgeFactory
	rpcTimeout, shutdownTimeout time.Duration
	mu                          sync.Mutex
	closing, running            bool
	borrowers                   int
	joined                      chan struct{}
}

// Production composition supplies the actual original index connection and
// three fixed SDK targets. It introduces no pool, DSN, credentials or role.
func newRetentionCleanup(database recoveryJSONDatabase, checksum, workerID string, raw *runtimeopensearch.Driver, sessionV1, sessionV2 *runtimeopensearch.SessionIndex, rpcTimeout, shutdownTimeout time.Duration) (*retentionCleanup, error) {
	factories := map[string]retentionCleanupPurgeFactory{
		"raw-index": func(a runtimeopensearch.RetentionPurgeAuthority) (retentionCleanupPurge, error) {
			return runtimeopensearch.NewRawRetentionPurger(raw, a)
		},
		"session-index-v1": func(a runtimeopensearch.RetentionPurgeAuthority) (retentionCleanupPurge, error) {
			return runtimeopensearch.NewSessionRetentionPurger(sessionV1, a)
		},
		"session-index-v2": func(a runtimeopensearch.RetentionPurgeAuthority) (retentionCleanupPurge, error) {
			return runtimeopensearch.NewSessionRetentionPurger(sessionV2, a)
		},
	}
	r, err := newRetentionCleanupWithFactories(database, checksum, workerID, factories, rpcTimeout, shutdownTimeout)
	if err != nil {
		return nil, err
	}
	// Check exact factory-to-intent binding at composition, before any SQL claim.
	// This authority grants nothing and the SDK constructors perform no I/O.
	denied := retentionCleanupDeniedAuthority{}
	for kind, factory := range factories {
		target, err := factory(denied)
		if err != nil || nilWorkerDependency(target) || target.FixedKind() != kind {
			return nil, errRuntimeUnavailable
		}
	}
	return r, nil
}

type retentionCleanupDeniedAuthority struct{}

func (retentionCleanupDeniedAuthority) AuthorizeRetentionPurge(context.Context, domain.Scope, string) error {
	return errRuntimeUnavailable
}

func newRetentionCleanupWithFactories(database recoveryJSONDatabase, checksum, workerID string, factories map[string]retentionCleanupPurgeFactory, rpcTimeout, shutdownTimeout time.Duration) (*retentionCleanup, error) {
	transactions, ok := database.(retentionCleanupTransactions)
	if !ok || nilWorkerDependency(transactions) || !migrations.IsRetentionProfileChecksum(checksum) || workerID == "" || len(workerID) > 128 || strings.TrimSpace(workerID) != workerID || strings.ContainsAny(workerID, "\x00\r\n\t") || len(factories) != 3 || rpcTimeout <= 0 || rpcTimeout > 30*time.Second || shutdownTimeout < time.Second || shutdownTimeout > time.Minute {
		return nil, errRuntimeUnavailable
	}
	copied := make(map[string]retentionCleanupPurgeFactory, 3)
	for _, kind := range []string{"raw-index", "session-index-v1", "session-index-v2"} {
		if factories[kind] == nil {
			return nil, errRuntimeUnavailable
		}
		copied[kind] = factories[kind]
	}
	joined := make(chan struct{})
	close(joined)
	return &retentionCleanup{database: transactions, checksum: checksum, workerID: workerID, factories: copied, rpcTimeout: rpcTimeout, shutdownTimeout: shutdownTimeout, joined: joined}, nil
}

func (r *retentionCleanup) borrow(run bool) (func(), error) {
	if r == nil {
		return nil, errRuntimeUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || run && r.running {
		return nil, errRuntimeUnavailable
	}
	if r.borrowers == 0 {
		r.joined = make(chan struct{})
	}
	r.borrowers++
	if run {
		r.running = true
	}
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.borrowers--
		if run {
			r.running = false
		}
		if r.borrowers == 0 {
			close(r.joined)
		}
	}, nil
}

// transact validates replies before committing and never publishes a claim or
// admission after an uncertain COMMIT. Captured observation settlement skips
// forward caller_ready: SQL checks the original login/nonce and grants no send.
func (r *retentionCleanup) transact(ctx context.Context, current bool, sql string, body []byte, decode func([]byte) error) error {
	if ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, r.rpcTimeout)
	defer cancel()
	tx, err := r.database.BeginRetentionCleanup(bounded)
	if err != nil || tx == nil {
		return errRuntimeUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if current {
		var ready bool
		if tx.QueryRow(bounded, `SELECT zasp_retention_v1.caller_ready('runtime-index',$1)`, r.checksum).Scan(&ready) != nil || !ready {
			return errRuntimeUnavailable
		}
	}
	if sql != "" {
		var raw []byte
		if tx.QueryRow(bounded, sql, body).Scan(&raw) != nil || len(raw) == 0 || len(raw) > 32<<10 || decode == nil || decode(raw) != nil {
			return errRuntimeUnavailable
		}
	}
	if tx.Commit(bounded) != nil || bounded.Err() != nil {
		return errRuntimeUnavailable
	}
	return nil
}
func (r *retentionCleanup) Ready(ctx context.Context) error {
	release, err := r.borrow(false)
	if err != nil {
		return err
	}
	defer release()
	return r.transact(ctx, true, "", nil, nil)
}

type retentionCleanupClaimAuthority struct {
	runtime *retentionCleanup
	claim   retentionCleanupClaim
}

func (a retentionCleanupClaimAuthority) AuthorizeRetentionPurge(ctx context.Context, scope domain.Scope, eventID string) error {
	original, err := a.claim.scope()
	if err != nil || original != scope || a.claim.EventID != eventID || !a.claim.valid(a.runtime.workerID) {
		return errRuntimeUnavailable
	}
	body, _ := json.Marshal(a.claim)
	if err := a.runtime.transact(ctx, true, retentionCleanupAuthorizeSQL, body, func(raw []byte) error {
		var reply struct {
			Authorized *bool `json:"authorized"`
		}
		if decodeStrictWorkerJSON(raw, &reply) != nil || reply.Authorized == nil || !*reply.Authorized {
			return errRuntimeUnavailable
		}
		return nil
	}); err != nil {
		return err
	}
	if !a.claim.valid(a.runtime.workerID) {
		return errRuntimeUnavailable
	}
	return nil
}

func (r *retentionCleanup) RunOnce(ctx context.Context) error {
	release, err := r.borrow(true)
	if err != nil {
		return err
	}
	defer release()
	request, _ := json.Marshal(struct {
		WorkerID string `json:"worker_id"`
	}{r.workerID})
	var claim *retentionCleanupClaim
	found := false
	if err := r.transact(ctx, true, retentionCleanupClaimSQL, request, func(raw []byte) error {
		var wire struct {
			Found *bool           `json:"found"`
			Claim json.RawMessage `json:"claim"`
		}
		if decodeStrictWorkerJSON(raw, &wire) != nil || wire.Found == nil || len(wire.Claim) == 0 {
			return errRuntimeUnavailable
		}
		if strings.TrimSpace(string(wire.Claim)) == "null" {
			if *wire.Found {
				return errRuntimeUnavailable
			}
			found = false
			claim = nil
			return nil
		}
		if !*wire.Found {
			return errRuntimeUnavailable
		}
		var captured retentionCleanupClaim
		if decodeStrictWorkerJSON(wire.Claim, &captured) != nil || !captured.valid(r.workerID) {
			return errRuntimeUnavailable
		}
		found = true
		claim = &captured
		return nil
	}); err != nil {
		return err
	}
	if !found {
		return nil
	}
	if !claim.valid(r.workerID) {
		return errRuntimeUnavailable
	}
	scope, err := claim.scope()
	if err != nil {
		return errRuntimeUnavailable
	}
	factory := r.factories[claim.Kind]
	target, err := factory(retentionCleanupClaimAuthority{runtime: r, claim: *claim})
	if err != nil || nilWorkerDependency(target) || target.FixedKind() != claim.Kind {
		return errRuntimeUnavailable
	}
	until, _ := time.Parse(retentionCleanupLeaseLayout, claim.LeaseUntil)
	operation, cancel := context.WithDeadline(ctx, until)
	observation, purgeErr := target.PurgeEvent(operation, scope, claim.EventID)
	cancel()
	if observation.DocumentsChecked < 0 || observation.DocumentsChecked > 64 || observation.DocumentsAbsent < 0 || observation.DocumentsAbsent > observation.DocumentsChecked || observation.IndexObservedEmpty && (purgeErr != nil || observation.DocumentsAbsent != observation.DocumentsChecked) {
		return errRuntimeUnavailable
	}
	settle := struct {
		retentionCleanupClaim
		IndexObservedEmpty bool `json:"index_observed_empty"`
		DocumentsChecked   int  `json:"documents_checked"`
		Absent             int  `json:"absent"`
	}{*claim, observation.IndexObservedEmpty, observation.DocumentsChecked, observation.DocumentsAbsent}
	body, _ := json.Marshal(settle)
	// Bounded captured settlement remains possible after caller cancellation or
	// forward revocation. Close joins this borrower before closing SDK/SQL clients.
	settleCtx, settleCancel := context.WithTimeout(context.Background(), r.rpcTimeout)
	defer settleCancel()
	if err := r.transact(settleCtx, false, retentionCleanupSettleSQL, body, func(raw []byte) error {
		var wire struct {
			Recorded *bool `json:"recorded"`
			Drained  *bool `json:"drained"`
			Complete *bool `json:"complete"`
		}
		if decodeStrictWorkerJSON(raw, &wire) != nil || wire.Recorded == nil || !*wire.Recorded || wire.Drained == nil || wire.Complete == nil || *wire.Complete && (!*wire.Drained || !observation.IndexObservedEmpty || purgeErr != nil) {
			return errRuntimeUnavailable
		}
		return nil
	}); err != nil {
		return err
	}
	if purgeErr != nil {
		return errRuntimeUnavailable
	}
	return nil
}

// Close marks the drainer closed and joins every admitted SQL/HTTP borrower.
// Timeout preserves external clients; a later call can join the remaining work.
func (r *retentionCleanup) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	r.closing = true
	joined := r.joined
	r.mu.Unlock()
	timer := time.NewTimer(r.shutdownTimeout)
	defer timer.Stop()
	select {
	case <-joined:
		return nil
	case <-timer.C:
		return errRuntimeUnavailable
	}
}
