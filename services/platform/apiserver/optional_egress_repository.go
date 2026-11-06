package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/optionalegress"
)

// OptionalEgressRepository owns only the supplementary profile's closed calls.
// The forward and captured-settlement connections have separate registered roles.
// Neither connection exposes a caller-selected statement or a table mutation.
type OptionalEgressRepository struct {
	forward, settlement *PostgresJSONDatabase
	profileChecksum     string
}

func rollbackOptionalEgress(tx pgx.Tx) {
	cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = tx.Rollback(cleanup)
}

func NewOptionalEgressRepository(forward, settlement *PostgresJSONDatabase) (*OptionalEgressRepository, error) {
	return NewOptionalEgressRepositoryForProfile(forward, settlement, migrations.OptionalEgressProfileChecksum())
}

func NewOptionalEgressRepositoryForProfile(forward, settlement *PostgresJSONDatabase, checksum string) (*OptionalEgressRepository, error) {
	if forward == nil || settlement == nil || forward == settlement {
		return nil, ErrRepositoryConfiguration
	}
	for _, database := range []*PostgresJSONDatabase{forward, settlement} {
		if _, ok := database.driver.(AuthorizationTransactionDriver); !ok {
			return nil, ErrRepositoryConfiguration
		}
	}
	if !migrations.IsOptionalEgressProfileChecksum(checksum) {
		return nil, ErrRepositoryConfiguration
	}
	return &OptionalEgressRepository{forward: forward, settlement: settlement, profileChecksum: checksum}, nil
}

func (r *OptionalEgressRepository) Ready(ctx context.Context) error {
	if r == nil || r.forward == nil || r.settlement == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	for index, database := range []*PostgresJSONDatabase{r.forward, r.settlement} {
		database.mu.RLock()
		if database.closed || nilInterface(database.driver) {
			database.mu.RUnlock()
			return ErrRepositoryUnavailable
		}
		driver, ok := database.driver.(AuthorizationTransactionDriver)
		if !ok {
			database.mu.RUnlock()
			return ErrRepositoryUnavailable
		}
		tx, err := driver.Begin(ctx)
		if err != nil {
			database.mu.RUnlock()
			return ErrRepositoryUnavailable
		}
		purpose := []string{"human-forward", "captured-settlement"}[index]
		role := []string{`SET LOCAL ROLE zasp_security_agent_api`, `SET LOCAL ROLE zasp_temporal_compensation`}[index]
		_, err = tx.Exec(ctx, role)
		var ready bool
		if err == nil {
			err = tx.QueryRow(ctx, `SELECT zasp_optional_egress_v1.caller_ready($1,$2)`, purpose, r.profileChecksum).Scan(&ready)
		}
		if err == nil && ready {
			err = tx.Commit(ctx)
		}
		rollbackOptionalEgress(tx)
		database.mu.RUnlock()
		if err != nil || !ready {
			return ErrRepositoryUnavailable
		}
	}
	return nil
}

func (r *OptionalEgressRepository) query(ctx context.Context, proof optionalegress.Proof, operation string, input, output any) error {
	if r == nil || r.forward == nil || r.settlement == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	var statement string
	database := r.forward
	purpose, role := "human-forward", `SET LOCAL ROLE zasp_security_agent_api`
	switch operation {
	case "catalog":
		statement = `SELECT zasp_optional_egress_v1.catalog($1::jsonb)`
	case "update":
		statement = `SELECT zasp_optional_egress_v1.update_enabled($1::jsonb)`
	case "source":
		statement = `SELECT zasp_optional_egress_v1.source($1::jsonb)`
	case "replay":
		statement = `SELECT zasp_optional_egress_v1.replay($1::jsonb)`
	case "reserve":
		statement = `SELECT zasp_optional_egress_v1.reserve($1::jsonb)`
	case "dispatch":
		statement = `SELECT zasp_optional_egress_v1.dispatch($1::jsonb)`
	case "settle":
		statement = `SELECT zasp_optional_egress_v1.settle($1::jsonb)`
		database = r.settlement
		purpose, role = "captured-settlement", `SET LOCAL ROLE zasp_temporal_compensation`
	default:
		return ErrRepositoryOperation
	}
	if operation == "settle" {
		if len(proof) != 0 {
			return ErrAuthorizationDenied
		}
	} else if len(proof) == 0 || len(proof) > 65536 || !json.Valid(proof) {
		return ErrAuthorizationDenied
	}
	raw, err := json.Marshal(input)
	if err != nil || len(raw) > 16384 {
		return ErrRepositoryOperation
	}
	database.mu.RLock()
	defer database.mu.RUnlock()
	if database.closed || nilInterface(database.driver) {
		return ErrRepositoryUnavailable
	}
	driver, ok := database.driver.(AuthorizationTransactionDriver)
	if !ok {
		return ErrRepositoryUnavailable
	}
	tx, err := driver.Begin(ctx)
	if err != nil {
		return classifyPostgresError(err)
	}
	defer rollbackOptionalEgress(tx)
	if _, err := tx.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL READ COMMITTED`); err != nil {
		return classifyPostgresError(err)
	}
	if _, err := tx.Exec(ctx, role); err != nil {
		return classifyPostgresError(err)
	}
	var ready bool
	if err := tx.QueryRow(ctx, `SELECT zasp_optional_egress_v1.caller_ready($1,$2)`, purpose, r.profileChecksum).Scan(&ready); err != nil || !ready {
		return ErrRepositoryUnavailable
	}
	if operation != "settle" {
		// Existing attestation verification, live revision, credential and source
		// fencing run on every call; a JSON "allowed" field is never authority.
		if _, err := tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof)); err != nil {
			return classifyPostgresError(err)
		}
	}
	var result []byte
	if err := tx.QueryRow(ctx, statement, json.RawMessage(raw)).Scan(&result); err != nil {
		return classifyPostgresError(err)
	}
	if len(result) == 0 || len(result) > 128*1024 {
		return ErrRepositoryUnavailable
	}
	destination := reflect.ValueOf(output)
	if destination.Kind() != reflect.Pointer || destination.IsNil() {
		return ErrRepositoryOperation
	}
	pending := reflect.New(destination.Elem().Type())
	decoder := json.NewDecoder(bytes.NewReader(result))
	decoder.DisallowUnknownFields()
	if decoder.Decode(pending.Interface()) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrRepositoryUnavailable
	}
	// Only an observed successful commit can return NewlyStarted and its nonce.
	if err := tx.Commit(ctx); err != nil {
		return ErrRepositoryUnavailable
	}
	destination.Elem().Set(pending.Elem())
	return nil
}

func (r *OptionalEgressRepository) Replay(ctx context.Context, intent optionalegress.Intent, proof optionalegress.Proof) (out optionalegress.ReplayResult, err error) {
	err = r.query(ctx, proof, "replay", intent, &out)
	return
}
func (r *OptionalEgressRepository) Source(ctx context.Context, intent optionalegress.Intent, proof optionalegress.Proof) (out optionalegress.Source, err error) {
	err = r.query(ctx, proof, "source", intent, &out)
	return
}
func (r *OptionalEgressRepository) Reserve(ctx context.Context, binding optionalegress.Binding, proof optionalegress.Proof) (out optionalegress.Reservation, err error) {
	err = r.query(ctx, proof, "reserve", binding, &out)
	return
}
func (r *OptionalEgressRepository) Dispatch(ctx context.Context, binding optionalegress.Binding, proof optionalegress.Proof) (out optionalegress.DispatchResult, err error) {
	err = r.query(ctx, proof, "dispatch", binding, &out)
	return
}
func (r *OptionalEgressRepository) Settle(ctx context.Context, settlement optionalegress.Settlement) (out optionalegress.Receipt, err error) {
	err = r.query(ctx, nil, "settle", settlement, &out)
	return
}
