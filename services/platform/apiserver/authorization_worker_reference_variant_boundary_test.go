package apiserver

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type orderedReferenceState struct {
	Session, Current, Inventory string
	Scratch, Migrated           bool
}

type orderedReferenceIO struct {
	snapshot func(context.Context) (orderedReferenceState, error)
	exec     func(context.Context, string) error
}

// Test-only boundary; no server or migrations are started here.
func prepareOrderedReferenceVariant(ctx context.Context, io orderedReferenceIO) (result error) {
	if ctx == nil || ctx.Err() != nil || io.snapshot == nil || io.exec == nil {
		return errors.New("reference preparation dependencies")
	}
	before, err := io.snapshot(ctx)
	if err != nil || before.Session != "zasp_e2e" || before.Current != "zasp_e2e" || before.Inventory == "" || before.Scratch || before.Migrated {
		return errors.New("reference preparation pristine owner/state")
	}
	if ctx.Err() != nil {
		return errors.New("reference preparation cancelled")
	}
	if err := io.exec(ctx, "BEGIN"); err != nil {
		return errors.New("reference preparation begin")
	}
	committed := false
	defer func() {
		if !committed {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancel()
			if io.exec(cleanup, "ROLLBACK") != nil {
				result = errors.Join(result, errors.New("reference preparation rollback"))
			}
		}
	}()
	statements := []string{"CREATE SCHEMA p7_reference_oid_shift"}
	for i := 0; i < 32; i++ {
		statements = append(statements,
			fmt.Sprintf("CREATE TABLE p7_reference_oid_shift.t%02d (value text)", i),
			fmt.Sprintf("CREATE FUNCTION p7_reference_oid_shift.f%02d() RETURNS integer LANGUAGE sql AS 'SELECT 1'", i))
	}
	statements = append(statements, "DROP SCHEMA p7_reference_oid_shift CASCADE", "COMMIT")
	for _, statement := range statements {
		if ctx.Err() != nil || io.exec(ctx, statement) != nil {
			return errors.New("reference preparation statement")
		}
	}
	committed = true
	after, err := io.snapshot(ctx)
	if err != nil || ctx.Err() != nil || after != before {
		return errors.New("reference preparation residue")
	}
	return nil
}
