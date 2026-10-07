package approvalmaintenance

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Executor is the restricted maintenance caller. It creates only signed
// decisions from native-loaded facts and real revision-fenced authorization.
// It cannot create native origins, projection tuples or delivery delegations.
type Executor struct {
	pool                           *pgxpool.Pool
	checker                        authorization.Checker
	store, model, profile, version string
	key                            []byte
	keyMu                          sync.RWMutex
}

func NewExecutor(pool *pgxpool.Pool, checker authorization.Checker, store, model, profile string, key []byte) (*Executor, error) {
	if pool == nil || missing(checker) || !hex64(profile) || len(key) != 32 || !maintenanceULID.MatchString(store) || !maintenanceULID.MatchString(model) {
		return nil, ErrConfiguration
	}
	// The revision fence validates actual exact store/model ULIDs. No fallback.
	h := sha256.Sum256(key)
	return &Executor{pool: pool, checker: checker, store: store, model: model, profile: profile, version: hex.EncodeToString(h[:]), key: append([]byte(nil), key...)}, nil
}

var maintenanceULID = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

func (e *Executor) keySnapshot() ([]byte, error) {
	if e == nil {
		return nil, ErrUnavailable
	}
	e.keyMu.RLock()
	defer e.keyMu.RUnlock()
	if len(e.key) != 32 {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), e.key...), nil
}
func (e *Executor) Close() {
	if e != nil {
		e.keyMu.Lock()
		defer e.keyMu.Unlock()
		clear(e.key)
		e.key = nil
	}
}
func (e *Executor) Ready(ctx context.Context) error {
	if e == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	key, err := e.keySnapshot()
	if err != nil {
		return ErrUnavailable
	}
	clear(key)
	return e.withTx(ctx, func(tx pgx.Tx) error {
		var ok bool
		err := tx.QueryRow(ctx, `SELECT zasp_approval_maintenance.caller_ready($1,$2)`, e.profile, e.version).Scan(&ok)
		if err != nil || !ok {
			return ErrUnavailable
		}
		return nil
	})
}
func (e *Executor) withTx(ctx context.Context, f func(pgx.Tx) error) (err error) {
	if e == nil || e.pool == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	tx, err := e.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return databaseError(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_approval_maintenance_worker`); err != nil {
		return databaseError(err)
	}
	if err = f(tx); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	return databaseError(tx.Commit(ctx))
}
func (e *Executor) query(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	var raw []byte
	err := e.withTx(ctx, func(tx pgx.Tx) error { return databaseError(tx.QueryRow(ctx, sql, args...).Scan(&raw)) })
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > 131072 || !json.Valid(raw) {
		return nil, ErrUnavailable
	}
	return json.RawMessage(raw), nil
}
func (e *Executor) Invoke(ctx context.Context, op Operation, q json.RawMessage, proof []byte) (json.RawMessage, error) {
	if ctx == nil || ctx.Err() != nil || len(q) > 32768 || len(proof) > 65536 {
		return nil, ErrUnavailable
	}
	switch op {
	case NativeReserve:
		var in struct {
			Owner   string `json:"owner"`
			Token   string `json:"token"`
			Seconds int    `json:"seconds"`
		}
		if exactDecode(q, &in, "owner", "token", "seconds") != nil {
			return nil, ErrUnavailable
		}
		return e.query(ctx, `SELECT zasp_approval_maintenance.reserve($1,$2,$3)`, in.Owner, in.Token, in.Seconds)
	case NativePauseDenied, NativeRelease:
		return e.query(ctx, `SELECT zasp_approval_maintenance.release($1::jsonb,$2)`, q, op == NativePauseDenied)
	case NativeBeginDelivery, NativeBeginSecretFailure:
		kind := "delivery"
		if op == NativeBeginSecretFailure {
			kind = "secret_failure"
		}
		return e.query(ctx, `SELECT zasp_approval_maintenance.begin_attempt($1::jsonb,$2,$3::json)`, q, kind, json.RawMessage(proof))
	case NativeComplete, NativeFail:
		return e.query(ctx, `SELECT zasp_approval_maintenance.settle($1::jsonb,$2::json,$3)`, q, json.RawMessage(proof), op == NativeComplete)
	case NativeBeforeSecrets, NativeBeforeDelivery, NativeBeforeSecretFailure:
		return e.authorize(ctx, op, q)
	default:
		return nil, ErrUnavailable
	}
}

type executorFacts struct {
	Reference             nativeReference `json:"reference"`
	ApprovalID            string          `json:"approval_id"`
	RunID                 string          `json:"run_id"`
	Family                string          `json:"family"`
	SourceDigest          string          `json:"source_digest"`
	Facts                 json.RawMessage `json:"facts"`
	Delegation            json.RawMessage `json:"delegation"`
	DestinationDigest     string          `json:"destination_digest"`
	SecretReferenceDigest string          `json:"secret_reference_digest"`
	LeaseExpiresAt        time.Time       `json:"lease_expires_at"`
	Attempt               int             `json:"attempt"`
	SessionUser           string          `json:"session_user"`
}
type originFacts struct {
	Organization string `json:"organization_id"`
	Workspace    string `json:"workspace_id"`
	Environment  string `json:"environment_id"`
	RunID        string `json:"run_id"`
	DefinitionID string `json:"definition_id"`
	Principal    string `json:"principal_id"`
	Grantor      string `json:"grantor_id"`
	Checks       []struct {
		Kind       string `json:"kind"`
		ID         string `json:"id"`
		Permission string `json:"permission"`
	} `json:"checks"`
}
type deliveryDelegation struct {
	TaskID    string `json:"task_id"`
	Purpose   string `json:"purpose"`
	Principal string `json:"principal_id"`
	Grantor   string `json:"grantor_id"`
}

func (e *Executor) authorize(ctx context.Context, op Operation, q json.RawMessage) (json.RawMessage, error) {
	key, keyErr := e.keySnapshot()
	if keyErr != nil {
		return nil, keyErr
	}
	defer clear(key)
	raw, err := e.query(ctx, `SELECT zasp_approval_maintenance.source($1::jsonb)`, q)
	if err != nil {
		return nil, err
	}
	var f executorFacts
	if exactDecode(raw, &f, "reference", "approval_id", "run_id", "family", "source_digest", "facts", "delegation", "destination_digest", "secret_reference_digest", "lease_expires_at", "attempt", "session_user") != nil || !hex64(f.SourceDigest) || !hex64(f.DestinationDigest) || !hex64(f.SecretReferenceDigest) || f.SessionUser == "" || f.Attempt < 0 || f.Attempt >= 10 || !f.LeaseExpiresAt.Add(-2*time.Second).After(time.Now()) {
		return nil, ErrUnavailable
	}
	ref, _ := json.Marshal(f.Reference)
	var expected nativeReference
	if exactDecode(q, &expected, "organization_id", "workspace_id", "environment_id", "delivery_id", "lease_owner", "lease_token", "payload_digest") != nil || f.Reference != expected {
		return nil, ErrUnavailable
	}
	var origin originFacts
	var d deliveryDelegation
	if json.Unmarshal(f.Facts, &origin) != nil || exactDecode(f.Delegation, &d, "task_id", "purpose", "principal_id", "grantor_id") != nil || d.Purpose != "approval_notification_delivery" || d.Principal != origin.Principal || d.Grantor != origin.Grantor || origin.RunID != f.RunID || origin.Organization != f.Reference.Organization || origin.Workspace != f.Reference.Workspace || origin.Environment != f.Reference.Environment {
		return nil, ErrUnavailable
	}
	if _, err := domain.ParseProductID(d.TaskID); err != nil {
		return nil, ErrUnavailable
	}
	counts := map[string]int{"finding78": 3, "test74": 4, "ordered68": 5}
	min, ok := counts[f.Family]
	if !ok || len(origin.Checks) < min || len(origin.Checks) > 5 {
		return nil, ErrUnavailable
	}
	requiredAgent, requiredRun := false, false
	seen := map[string]bool{}
	revision, err := e.Revision(ctx, origin.Organization)
	if err != nil || revision.OrganizationID != origin.Organization || revision.Desired < 1 || revision.Applied != revision.Desired || revision.Generation < 1 || revision.StoreID != e.store || revision.ModelID != e.model {
		return nil, ErrUnavailable
	}
	for _, c := range origin.Checks {
		if c.Permission == "manage_workflows" && c.Kind == "security_agent" && c.ID == origin.DefinitionID {
			requiredAgent = true
		} else if c.Permission == "manage_workflows" && c.Kind == "security_agent_run" && c.ID == origin.RunID {
			requiredRun = true
		} else if c.Permission != "view" || (c.Kind != "finding" && c.Kind != "attack_path" && c.Kind != "test" && c.Kind != "agent" && c.Kind != "tool") {
			return nil, ErrUnavailable
		}
		identity := c.Kind + "\x00" + c.ID + "\x00" + c.Permission
		if seen[identity] {
			return nil, ErrUnavailable
		}
		seen[identity] = true
		for _, s := range []struct{ Kind, ID, Task string }{{"user", d.Grantor, ""}, {"service", d.Principal, d.TaskID}} {
			request := authorization.CheckRequest{PrincipalKind: s.Kind, PrincipalID: s.ID, TaskID: s.Task, OrganizationID: origin.Organization, WorkspaceID: origin.Workspace, EnvironmentID: origin.Environment, ResourceType: c.Kind, ResourceID: c.ID, Permission: c.Permission}
			if _, err := authorization.Map(request); err != nil {
				return nil, ErrUnavailable
			}
			decision, err := e.checker.Check(ctx, request)
			if err != nil {
				return nil, ErrUnavailable
			}
			if decision.ModelID != revision.ModelID {
				return nil, ErrUnavailable
			}
			if !decision.Allowed {
				return nil, ErrDenied
			}
		}
	}
	after, err := e.Revision(ctx, origin.Organization)
	if err != nil || after != revision {
		return nil, ErrUnavailable
	}
	if !requiredAgent || !requiredRun {
		return nil, ErrUnavailable
	}
	fresh, err := e.query(ctx, `SELECT zasp_approval_maintenance.source($1::jsonb)`, q)
	if err != nil || !bytes.Equal(raw, fresh) || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	phase := "before_secrets"
	if op == NativeBeforeDelivery {
		phase = "before_delivery"
	} else if op == NativeBeforeSecretFailure {
		phase = "before_secret_failure"
	}
	now := time.Now()
	expiry := now.Add(60 * time.Second)
	if bound := f.LeaseExpiresAt.Add(-2 * time.Second); bound.Before(expiry) {
		expiry = bound
	}
	if !expiry.After(now) {
		return nil, ErrUnavailable
	}
	body, err := json.Marshal(map[string]any{"purpose": "approval-forward", "key_version": e.version, "phase": phase, "reference": json.RawMessage(ref), "revision": revision, "facts": json.RawMessage(raw), "issued_at": now.UnixMilli(), "expires_at": expiry.UnixMilli(), "session_user": f.SessionUser})
	if err != nil {
		return nil, ErrUnavailable
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("zasp-approval-forward-v1\x00"))
	_, _ = mac.Write(body)
	envelope, _ := json.Marshal(map[string]string{"body": base64.StdEncoding.EncodeToString(body), "version": e.version, "mac": hex.EncodeToString(mac.Sum(nil))})
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	stillOpen, err := e.keySnapshot()
	if err != nil {
		return nil, ErrUnavailable
	}
	clear(stillOpen)
	return json.Marshal(map[string][]byte{"forward_proof": envelope})
}
func (e *Executor) Revision(ctx context.Context, o string) (authorization.Revision, error) {
	if _, err := domain.ParseProductID(o); err != nil {
		return authorization.Revision{}, ErrUnavailable
	}
	raw, err := e.query(ctx, `SELECT zasp_approval_maintenance.revision($1)`, o)
	if err != nil {
		return authorization.Revision{}, err
	}
	var v authorization.Revision
	if json.Unmarshal(raw, &v) != nil {
		return authorization.Revision{}, ErrUnavailable
	}
	return v, nil
}
func databaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrDenied) {
		return ErrDenied
	}
	var p *pgconn.PgError
	if errors.As(err, &p) && p.Code == "42501" {
		return ErrDenied
	}
	return ErrUnavailable
}

// DeliveryPayload is materialized only behind a fresh BeforeSecrets decision.
// The provider may use this exact immutable payload after native Begin binds it;
// it never fetches caller-selected destination/secret/payload arguments.
type DeliveryPayload struct {
	Organization    string    `json:"organization_id"`
	Workspace       string    `json:"workspace_id"`
	Environment     string    `json:"environment_id"`
	DeliveryID      string    `json:"delivery_id"`
	ApprovalID      string    `json:"approval_id"`
	RunID           string    `json:"run_id"`
	Payload         string    `json:"payload"`
	PayloadDigest   string    `json:"payload_digest"`
	DestinationURL  string    `json:"destination_url"`
	SecretReference string    `json:"secret_reference"`
	LeaseToken      string    `json:"lease_token"`
	LeaseExpiresAt  time.Time `json:"lease_expires_at"`
	Attempt         int       `json:"attempt"`
}

func (e *Executor) LoadDelivery(ctx context.Context, r Reservation) (DeliveryPayload, error) {
	raw, err := e.authorize(ctx, NativeBeforeSecrets, json.RawMessage(r.Reference))
	if err != nil {
		return DeliveryPayload{}, err
	}
	var wire struct {
		Proof []byte `json:"forward_proof"`
	}
	if exactDecode(raw, &wire, "forward_proof") != nil {
		return DeliveryPayload{}, ErrUnavailable
	}
	payload, err := e.query(ctx, `SELECT zasp_approval_maintenance.authorized_payload($1::jsonb,$2::json)`, json.RawMessage(r.Reference), json.RawMessage(wire.Proof))
	clear(wire.Proof)
	if err != nil {
		return DeliveryPayload{}, err
	}
	var d DeliveryPayload
	if exactDecode(payload, &d, "organization_id", "workspace_id", "environment_id", "delivery_id", "approval_id", "run_id", "payload", "payload_digest", "destination_url", "secret_reference", "lease_token", "lease_expires_at", "attempt") != nil {
		return DeliveryPayload{}, ErrUnavailable
	}
	var ref nativeReference
	if exactDecode([]byte(r.Reference), &ref, "organization_id", "workspace_id", "environment_id", "delivery_id", "lease_owner", "lease_token", "payload_digest") != nil || d.Organization != ref.Organization || d.Workspace != ref.Workspace || d.Environment != ref.Environment || d.DeliveryID != ref.Delivery || d.LeaseToken != ref.Token || d.PayloadDigest != ref.PayloadDigest || !d.LeaseExpiresAt.Equal(r.ExpiresAt) || d.Attempt < 0 || d.Attempt >= 10 {
		return DeliveryPayload{}, ErrUnavailable
	}
	return d, nil
}
