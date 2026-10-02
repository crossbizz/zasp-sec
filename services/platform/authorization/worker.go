package authorization

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrDenied = errors.New("authorization denied")

type WorkerPurpose string

const (
	WorkerForward        WorkerPurpose = "worker-forward"
	CapturedCompensation WorkerPurpose = "captured-compensation"
)

// WorkerKey never accepts an API identity or human attestation purpose.
type WorkerKey struct {
	purpose WorkerPurpose
	key     [32]byte
	version string
}

func NewWorkerKey(purpose WorkerPurpose, seed []byte) (*WorkerKey, error) {
	if purpose != WorkerForward && purpose != CapturedCompensation || len(seed) < 32 || len(seed) > 4096 {
		return nil, ErrInvalid
	}
	mac := hmac.New(sha256.New, seed)
	_, _ = mac.Write([]byte("zasp-authorization-" + string(purpose) + "-key-v1"))
	k := &WorkerKey{purpose: purpose}
	copy(k.key[:], mac.Sum(nil))
	id := sha256.Sum256(k.key[:])
	k.version = hex.EncodeToString(id[:])
	return k, nil
}

func (k *WorkerKey) Version() string {
	if k == nil {
		return ""
	}
	return k.version
}

// Verifier is only for explicit registered migration-session provisioning.
func (k *WorkerKey) Verifier() []byte {
	if k == nil {
		return nil
	}
	return append([]byte(nil), k.key[:]...)
}

type WorkerOperation string

const (
	FindingApply   WorkerOperation = "finding.apply"
	FindingReplay  WorkerOperation = "finding.replay"
	FindingCleanup WorkerOperation = "finding.cleanup"
)

type workerFacts struct {
	OrganizationID        string   `json:"organization_id"`
	WorkspaceID           string   `json:"workspace_id"`
	EnvironmentID         string   `json:"environment_id"`
	RunID                 string   `json:"run_id"`
	TaskID                string   `json:"task_id"`
	PrincipalID           string   `json:"principal_id"`
	GrantorID             string   `json:"grantor_id"`
	DefinitionID          string   `json:"definition_id"`
	TestID                string   `json:"test_id"`
	TargetID              string   `json:"target_id"`
	TargetKind            string   `json:"target_kind"`
	TriggerID             string   `json:"trigger_id"`
	TriggerKind           string   `json:"trigger_kind"`
	RuntimeProtocol       string   `json:"runtime_protocol"`
	SourceSessionID       string   `json:"source_session_id"`
	SourceAgentID         string   `json:"source_agent_id"`
	SourceDeviceIDs       []string `json:"source_device_ids"`
	RuntimeDigest         string   `json:"runtime_digest"`
	OrderedActionKey      string   `json:"ordered_action_key"`
	OrderedDeviceIDs      []string `json:"ordered_device_ids"`
	OrderedPolicyDeviceID string   `json:"ordered_policy_device_id"`
	OrderedPolicyIDs      []string `json:"ordered_policy_ids"`
	OrderedSourceRunIDs   []string `json:"ordered_source_run_ids"`
	SessionUser           string   `json:"session_user"`
	Checks                []struct {
		Kind       string `json:"kind"`
		ID         string `json:"id"`
		Permission string `json:"permission"`
	} `json:"checks"`
}

// WorkerDecision is opaque outside this package. Native consumers authenticate
// its exact metadata, operation and scope again in the effect transaction.
type WorkerDecision struct {
	operation WorkerOperation
	request   json.RawMessage
	envelope  []byte
}

type WorkerExecutor struct {
	pool             *pgxpool.Pool
	checker          Checker
	storeID, modelID string
	key              *WorkerKey
	adapter          bool
	discovery        bool
}

func NewWorkerExecutor(pool *pgxpool.Pool, checker Checker, storeID, modelID string, key *WorkerKey) (*WorkerExecutor, error) {
	if pool == nil || key == nil || key.purpose != WorkerForward && key.purpose != CapturedCompensation || key.purpose == WorkerForward && (checker == nil || !projectionULID.MatchString(storeID) || !projectionULID.MatchString(modelID)) {
		return nil, ErrInvalid
	}
	return &WorkerExecutor{pool: pool, checker: checker, storeID: storeID, modelID: modelID, key: key}, nil
}

// NewWorkerAdapter can authorize only the closed adapter operation set. Its
// native readers verify the separately registered adapter database session.
func NewWorkerAdapter(pool *pgxpool.Pool, checker Checker, storeID, modelID string, key *WorkerKey) (*WorkerExecutor, error) {
	if key == nil || key.purpose != WorkerForward {
		return nil, ErrInvalid
	}
	e, err := NewWorkerExecutor(pool, checker, storeID, modelID, key)
	if err != nil {
		return nil, err
	}
	e.adapter = true
	return e, nil
}

func (e *WorkerExecutor) Ready(ctx context.Context) error {
	if e == nil || e.key == nil || e.pool == nil || ctx == nil {
		return ErrInvalid
	}
	var ready bool
	statement := `SELECT zasp_authorization80_worker.key_ready($1,$2)`
	if e.adapter {
		statement = `SELECT zasp_authorization80_worker.adapter_key_ready($1,$2)`
	} else if e.discovery {
		statement = `SELECT zasp_authorization80_worker.discovery72_key_ready($1,$2)`
	}
	if err := e.pool.QueryRow(ctx, statement, string(e.key.purpose), e.key.version).Scan(&ready); err != nil {
		return workerDatabaseError(err)
	}
	if !ready {
		return ErrDenied
	}
	return nil
}

// ReadyFor verifies the configured role and key purpose for a closed operation.
func (e *WorkerExecutor) ReadyFor(ctx context.Context, operation WorkerOperation) error {
	spec, ok := workerOperation(operation)
	if e == nil || e.key == nil || !ok || e.adapter != spec.adapter || e.discovery != spec.discovery || e.key.purpose != spec.purpose {
		return ErrInvalid
	}
	return e.Ready(ctx)
}

func (e *WorkerExecutor) PrepareFinding(ctx context.Context, request json.RawMessage) error {
	if e == nil || e.key == nil || e.pool == nil || e.adapter || e.discovery || ctx == nil || e.key.purpose != WorkerForward || !json.Valid(request) {
		return ErrInvalid
	}
	_, err := e.pool.Exec(ctx, `SELECT zasp_authorization80_worker.prepare_finding($1::jsonb)`, request)
	return workerDatabaseError(err)
}

func (e *WorkerExecutor) PrepareTest74(ctx context.Context, request json.RawMessage) error {
	if e == nil || e.key == nil || e.pool == nil || e.adapter || e.discovery || ctx == nil || e.key.purpose != WorkerForward || len(request) > 4096 || !json.Valid(request) {
		return ErrInvalid
	}
	_, err := e.pool.Exec(ctx, `SELECT zasp_authorization80_worker.prepare_test74($1::jsonb)`, request)
	return workerDatabaseError(err)
}

func (e *WorkerExecutor) Revision(ctx context.Context, organization string) (Revision, error) {
	var r Revision
	var raw []byte
	if e == nil || e.key == nil || e.pool == nil || ctx == nil || e.key.purpose != WorkerForward {
		return r, ErrInvalid
	}
	statement := `SELECT zasp_authorization80_worker.revision($1)`
	if e.adapter {
		statement = `SELECT zasp_authorization80_worker.adapter_revision($1)`
	} else if e.discovery {
		statement = `SELECT zasp_authorization80_worker.discovery72_revision($1)`
	}
	if err := e.pool.QueryRow(ctx, statement, organization).Scan(&raw); err != nil {
		return r, workerDatabaseError(err)
	}
	if json.Unmarshal(raw, &r) != nil {
		return Revision{}, ErrInvalid
	}
	return r, nil
}

func (e *WorkerExecutor) Authorize(ctx context.Context, operation WorkerOperation, request json.RawMessage) (WorkerDecision, error) {
	spec, supported := workerOperation(operation)
	if e == nil || e.key == nil || e.pool == nil || ctx == nil || !supported || e.adapter != spec.adapter || e.discovery != spec.discovery || len(request) > spec.limit || !json.Valid(request) || e.key.purpose != spec.purpose {
		return WorkerDecision{}, ErrInvalid
	}
	read := func() ([]byte, error) {
		var raw []byte
		err := e.pool.QueryRow(ctx, spec.source, spec.phase, request).Scan(&raw)
		return raw, workerDatabaseError(err)
	}
	raw, err := read()
	if err != nil {
		return WorkerDecision{}, err
	}
	var facts workerFacts
	if json.Unmarshal(raw, &facts) != nil || facts.SessionUser == "" {
		return WorkerDecision{}, ErrInvalid
	}
	var revision Revision
	if spec.current {
		if !workerCheckShape(spec, facts) {
			return WorkerDecision{}, ErrInvalid
		}
		var requests []CheckRequest
		taskID := facts.RunID
		if spec.discovery {
			taskID = facts.TaskID
		}
		for _, target := range facts.Checks {
			for _, subject := range []struct{ kind, id, task string }{{"user", facts.GrantorID, ""}, {"service", facts.PrincipalID, taskID}} {
				requests = append(requests, CheckRequest{PrincipalKind: subject.kind, PrincipalID: subject.id, TaskID: subject.task, OrganizationID: facts.OrganizationID, WorkspaceID: facts.WorkspaceID, EnvironmentID: facts.EnvironmentID, ResourceType: target.Kind, ResourceID: target.ID, Permission: target.Permission})
			}
		}
		if facts.TriggerKind == "runtime_decision" && (spec.testPlanning || spec.testExecution) {
			revision, err = checkRuntimeTestRevisionSet(ctx, e, e.checker, spec, facts, requests, e.storeID, e.modelID)
			if err != nil {
				return WorkerDecision{}, err
			}
		} else if spec.orderedTest && spec.phase == "progress" {
			revision, err = checkOrderedProgressRevisionSet(ctx, e, e.checker, spec, facts, requests, e.storeID, e.modelID)
			if err != nil {
				return WorkerDecision{}, err
			}
		} else if orderedTestRevisionPhase(spec) {
			revision, err = checkOrderedTestRevisionSet(ctx, e, e.checker, spec, facts, requests, e.storeID, e.modelID)
			if err != nil {
				return WorkerDecision{}, err
			}
		} else if e.adapter {
			revision, err = checkAdapterRevisionSet(ctx, e, e.checker, requests, e.storeID, e.modelID)
			if err != nil {
				return WorkerDecision{}, err
			}
		} else if spec.testPlanning {
			revision, err = checkTestPlanningRevisionSet(ctx, e, e.checker, requests, e.storeID, e.modelID)
			if err != nil {
				return WorkerDecision{}, err
			}
		} else if spec.orderedPlanning {
			revision, err = checkOrderedPlanningRevisionSet(ctx, e, e.checker, requests, e.storeID, e.modelID)
			if err != nil {
				return WorkerDecision{}, err
			}
		} else if spec.orderedExecution || spec.orderedSigning || spec.orderedDomain {
			revision, err = checkOrderedExecutionRevisionSet(ctx, e, e.checker, spec, facts, requests, e.storeID, e.modelID)
			if err != nil {
				return WorkerDecision{}, err
			}
		} else {
			for _, request := range requests {
				checked, checkErr := CheckRevision(ctx, e, e.checker, request, e.storeID, e.modelID)
				if checkErr != nil {
					return WorkerDecision{}, checkErr
				}
				if !checked.Decision.Allowed {
					return WorkerDecision{}, ErrDenied
				}
				if revision.OrganizationID != "" && revision != checked.Revision {
					return WorkerDecision{}, ErrConflict
				}
				revision = checked.Revision
			}
		}
	} else if len(facts.Checks) != 0 {
		return WorkerDecision{}, ErrInvalid
	}
	current, err := read()
	if err != nil {
		return WorkerDecision{}, err
	}
	if !bytes.Equal(raw, current) {
		return WorkerDecision{}, ErrConflict
	}
	if spec.current {
		currentRevision, err := e.Revision(ctx, facts.OrganizationID)
		if err != nil {
			return WorkerDecision{}, err
		}
		if currentRevision != revision {
			return WorkerDecision{}, ErrConflict
		}
	}
	now := time.Now().UTC()
	boundRequest := request
	if !spec.bindRequest {
		// The authenticated metadata contains PostgreSQL's canonical digest of
		// the exact bounded request. Provider bodies never enter a proof.
		boundRequest = nil
	}
	return e.signWorkerDecision(operation, request, boundRequest, raw, revision, facts.SessionUser, now)
}

func (e *WorkerExecutor) signWorkerDecision(operation WorkerOperation, request, boundRequest, raw json.RawMessage, revision Revision, sessionUser string, now time.Time) (WorkerDecision, error) {
	body, err := json.Marshal(struct {
		Purpose     WorkerPurpose   `json:"purpose"`
		KeyVersion  string          `json:"key_version"`
		Operation   WorkerOperation `json:"operation"`
		Request     json.RawMessage `json:"request"`
		Facts       json.RawMessage `json:"facts"`
		Revision    Revision        `json:"revision"`
		SessionUser string          `json:"session_user"`
		IssuedAt    int64           `json:"issued_at"`
		ExpiresAt   int64           `json:"expires_at"`
	}{e.key.purpose, e.key.version, operation, boundRequest, raw, revision, sessionUser, now.UnixMilli(), now.Add(30 * time.Second).UnixMilli()})
	if err != nil || len(body) > 32768 {
		return WorkerDecision{}, ErrInvalid
	}
	mac := hmac.New(sha256.New, e.key.key[:])
	_, _ = mac.Write([]byte("zasp-authorization-" + string(e.key.purpose) + "-v1\x00"))
	_, _ = mac.Write(body)
	envelope, err := json.Marshal(struct {
		Body    []byte `json:"body"`
		Version string `json:"version"`
		MAC     string `json:"mac"`
	}{body, e.key.version, hex.EncodeToString(mac.Sum(nil))})
	if err != nil {
		return WorkerDecision{}, ErrInvalid
	}
	return WorkerDecision{operation: operation, request: append(json.RawMessage(nil), request...), envelope: envelope}, nil
}

// Execute performs no FGA/provider RPC. On any conflict callers must authorize
// afresh, preserving the original request/effect identity.
func (e *WorkerExecutor) Execute(ctx context.Context, decision WorkerDecision) (json.RawMessage, error) {
	if _, signing := orderedSigningPurpose(decision.operation); signing {
		return nil, ErrInvalid
	}
	spec, supported := workerOperation(decision.operation)
	if e == nil || e.key == nil || e.pool == nil || ctx == nil || !supported || e.adapter != spec.adapter || e.discovery != spec.discovery || len(decision.envelope) == 0 || e.key.purpose != spec.purpose {
		return nil, ErrInvalid
	}
	return e.executeWorkerStatement(ctx, decision, spec.statement)
}

// Callers validate the closed operation and supply a compiled literal only.
func (e *WorkerExecutor) executeWorkerStatement(ctx context.Context, decision WorkerDecision, statement string) (json.RawMessage, error) {
	tx, err := e.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, workerDatabaseError(err)
	}
	defer func() {
		rollback, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(rollback)
	}()
	if _, err = tx.Exec(ctx, `SELECT set_config('zasp.worker_proof',$1,true)`, string(decision.envelope)); err != nil {
		return nil, workerDatabaseError(err)
	}
	var result json.RawMessage
	if err = tx.QueryRow(ctx, statement, decision.request).Scan(&result); err != nil {
		return nil, workerDatabaseError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, workerDatabaseError(err)
	}
	return result, nil
}

func workerDatabaseError(err error) error {
	var native *pgconn.PgError
	if errors.As(err, &native) {
		switch native.Code {
		case "42501":
			return ErrDenied
		case "22023", "25001":
			return ErrInvalid
		}
	}
	return projectionDatabaseError(err)
}
