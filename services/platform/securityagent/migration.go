package securityagent

import (
	"context"
	"reflect"
	"strings"
)

const migration = `
CREATE TABLE IF NOT EXISTS security_agents (organization_id text NOT NULL, id text NOT NULL, definition_version integer NOT NULL, enabled boolean NOT NULL, deleted_at timestamptz, definition jsonb NOT NULL, PRIMARY KEY (organization_id, id));
CREATE INDEX IF NOT EXISTS security_agents_trigger_idx ON security_agents (organization_id, enabled) WHERE deleted_at IS NULL;
CREATE TABLE IF NOT EXISTS security_agent_runs (organization_id text NOT NULL, id text NOT NULL, agent_id text NOT NULL, state text NOT NULL, trigger_evidence_ids jsonb NOT NULL, definition_version integer NOT NULL, version bigint NOT NULL, PRIMARY KEY (organization_id, id));
CREATE TABLE IF NOT EXISTS security_agent_steps (organization_id text NOT NULL, id text NOT NULL, run_id text NOT NULL, step_index integer NOT NULL, action_key text NOT NULL, state text NOT NULL, version bigint NOT NULL, PRIMARY KEY (organization_id, id), UNIQUE (organization_id, run_id, step_index));
CREATE TABLE IF NOT EXISTS security_agent_approvals (organization_id text NOT NULL, id text NOT NULL, run_id text NOT NULL, step_id text NOT NULL, state text NOT NULL, expires_at timestamptz NOT NULL, approver_id text, fresh_auth_at timestamptz, version bigint NOT NULL, PRIMARY KEY (organization_id, id));
CREATE TABLE IF NOT EXISTS security_action_idempotency (organization_id text NOT NULL, run_id text NOT NULL, step_id text NOT NULL, action_key text NOT NULL, state text NOT NULL, outcome_id text NOT NULL, PRIMARY KEY (organization_id, run_id, step_id, action_key));
ALTER TABLE security_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_agent_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_agent_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_agent_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_action_idempotency ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN CREATE POLICY security_agents_tenant ON security_agents USING (organization_id = current_setting('zasp.organization_id', true)); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE POLICY security_agent_runs_tenant ON security_agent_runs USING (organization_id = current_setting('zasp.organization_id', true)); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE POLICY security_agent_steps_tenant ON security_agent_steps USING (organization_id = current_setting('zasp.organization_id', true)); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE POLICY security_agent_approvals_tenant ON security_agent_approvals USING (organization_id = current_setting('zasp.organization_id', true)); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE POLICY security_action_idempotency_tenant ON security_action_idempotency USING (organization_id = current_setting('zasp.organization_id', true)); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
`

type MigrationExecutor interface {
	Exec(context.Context, string, ...any) error
}

func ApplyMigration(ctx context.Context, executor MigrationExecutor) (resultErr error) {
	if ctx == nil || ctx.Err() != nil || nilMigrationExecutor(executor) {
		return ErrRejected
	}
	defer func() {
		if recover() != nil {
			resultErr = ErrRejected
		}
	}()
	if err := executor.Exec(ctx, MigrationSQL()); err != nil || ctx.Err() != nil {
		return ErrRejected
	}
	return nil
}

func MigrationSQL() string { return strings.TrimSpace(migration) }
func ValidateMigration(source string) error {
	if source != MigrationSQL() {
		return ErrRejected
	}
	for _, table := range []string{"security_agents", "security_agent_runs", "security_agent_steps", "security_agent_approvals", "security_action_idempotency"} {
		if strings.Count(source, "CREATE TABLE IF NOT EXISTS "+table+" ") != 1 || strings.Count(source, "ALTER TABLE "+table+" ENABLE ROW LEVEL SECURITY;") != 1 || !strings.Contains(source, "CREATE POLICY "+table+"_tenant ON "+table+" USING (organization_id = current_setting('zasp.organization_id', true)); EXCEPTION WHEN duplicate_object THEN NULL;") {
			return ErrRejected
		}
	}
	return nil
}

func nilMigrationExecutor(value MigrationExecutor) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
