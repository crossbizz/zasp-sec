package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Exercise the actual compiler: retirement must follow the original lifecycle
// copies and precede final ownership/pinning. Native43638 is the behavioral ACL RED.
func TestOrdered69RetirementAssembly(t *testing.T) {
	source, checksum := authorizationWorkerProfileSource()
	last := -1
	for _, marker := range []string{"DO $ordered_lifecycle_copies$", "DO $ordered69_retirement$", "CREATE OR REPLACE FUNCTION zasp_temporal69.fingerprint() RETURNS text LANGUAGE sql STABLE", "FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_authorization80_worker'::regnamespace LOOP"} {
		at := strings.Index(source, marker)
		if at <= last || strings.Count(source, marker) != 1 {
			t.Fatalf("missing/repeated/unordered retirement boundary: %s", marker)
		}
		last = at
	}
	for _, grant := range []string{"REVOKE EXECUTE ON FUNCTION zasp_temporal69.inspect(jsonb) FROM zasp_temporal_executor,zasp_temporal_compensation;", "REVOKE EXECUTE ON FUNCTION zasp_temporal69.inspect_message(jsonb) FROM zasp_temporal_executor;", "REVOKE EXECUTE ON FUNCTION zasp_temporal69.stop(jsonb) FROM zasp_temporal_compensation;"} {
		if strings.Count(source, grant) != 1 {
			t.Fatal("exact retirement edge missing", grant)
		}
	}
	if strings.Contains(source, "-- retirement69 original fingerprint") || !strings.Contains(source, "zasp_temporal69.fingerprint() IS DISTINCT FROM '"+TemporalWorkflowFingerprint()+"'") || !strings.Contains(source, "checksum='"+checksum+"'") {
		t.Fatal("retirement compiler pins not substituted")
	}
	if !strings.Contains(source, "SELECT zasp_temporal78.current_ready() AND false") {
		t.Fatal("runtime gate changed")
	}
	if strings.Contains(source, "GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.projected69(") {
		t.Fatal("private projection exposed")
	}
}

// An existing profile is never replayed/reblessed by the fresh installer. The
// fake controls only installed metadata; the real Runner chooses its statements.
type retirementExistingDatabase struct {
	tx *retirementExistingTransaction
}

func (d retirementExistingDatabase) Begin(context.Context) (Transaction, error) { return d.tx, nil }
func (d retirementExistingDatabase) QueryRow(context.Context, string, ...any) Row {
	return retirementBoolRow(false)
}

type retirementExistingTransaction struct {
	queries, execs        []string
	committed, rolledBack bool
}

func (tx *retirementExistingTransaction) Exec(_ context.Context, q string, _ ...any) error {
	tx.execs = append(tx.execs, q)
	return nil
}
func (tx *retirementExistingTransaction) QueryRow(_ context.Context, q string, args ...any) Row {
	tx.queries = append(tx.queries, q)
	if strings.HasPrefix(q, "SELECT EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum=$1)") {
		return retirementBoolRow(false)
	}
	return retirementBoolRow(true)
}
func (tx *retirementExistingTransaction) Commit(context.Context) error {
	tx.committed = true
	return nil
}
func (tx *retirementExistingTransaction) Rollback(context.Context) error {
	tx.rolledBack = true
	return nil
}

type retirementBoolRow bool

func (r retirementBoolRow) Scan(dest ...any) error {
	if len(dest) != 1 {
		return errors.New("unexpected scan")
	}
	p, ok := dest[0].(*bool)
	if !ok {
		return errors.New("unexpected destination")
	}
	*p = bool(r)
	return nil
}
func TestOrdered69RetirementExistingWorkerFailsClosed(t *testing.T) {
	tx := &retirementExistingTransaction{}
	r, err := NewRunner(retirementExistingDatabase{tx})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.UpProductionAuthorizationWorkerProfile(context.Background()); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("existing different profile accepted: %v", err)
	}
	if tx.committed || !tx.rolledBack || len(tx.execs) != 1 || !strings.Contains(tx.execs[0], "pg_advisory_xact_lock(") {
		t.Fatalf("existing profile was mutated/reblessed: statements=%d committed=%t rollback=%t", len(tx.execs), tx.committed, tx.rolledBack)
	}
	if len(tx.queries) == 0 || !strings.Contains(tx.queries[len(tx.queries)-1], "checksum=$1") {
		t.Fatal("missing compiled-checksum fence")
	}
}
