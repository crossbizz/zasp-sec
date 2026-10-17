package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const principalPreflightBindingSQL = `SELECT session_user=$1 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=$1 AND authority_role='zasp_discovery_authority')`

// Application transaction boundary model only; actual installed RLS/role
// acceptance requires the mandatory native release checks.
type principalPreflightQueryer struct {
	session                                                  string
	bound                                                    bool
	beginDenied, roleDenied, uncertainCommit, nilTransaction bool
	active, authority, committed, rolled, commitAttempted    bool
	begins, reads, outsideReads                              int
	statement                                                string
	arguments                                                []any
}

func (q *principalPreflightQueryer) QueryRow(_ context.Context, s string, args ...any) pgx.Row {
	if q == nil {
		return releaseReadinessErrorRow{}
	}
	q.reads++
	q.statement = s
	q.arguments = args
	if !q.active || !q.authority {
		q.outsideReads++
		return releaseReadinessErrorRow{}
	}
	accepted := s == principalPreflightBindingSQL && len(args) == 1 && args[0] == q.session && q.bound
	return scriptedPrincipalRow{value: accepted}
}
func (q *principalPreflightQueryer) beginPrincipalAuthorityTransaction(context.Context) (retentionOperatorTransaction, error) {
	if q == nil {
		return nil, errors.New("nil recorder")
	}
	q.begins++
	if q.beginDenied {
		return nil, errors.New("private begin detail")
	}
	if q.nilTransaction {
		return nil, nil
	}
	q.active = true
	return &principalPreflightTransaction{q}, nil
}

type principalPreflightTransaction struct{ q *principalPreflightQueryer }

func (x *principalPreflightTransaction) QueryRow(c context.Context, s string, a ...any) pgx.Row {
	return x.q.QueryRow(c, s, a...)
}
func (x *principalPreflightTransaction) Exec(_ context.Context, s string, _ ...any) (pgconn.CommandTag, error) {
	if s != "SET LOCAL ROLE zasp_discovery_authority" || x.q.roleDenied {
		return pgconn.CommandTag{}, errors.New("private role detail")
	}
	x.q.authority = true
	return pgconn.NewCommandTag("SET"), nil
}
func (x *principalPreflightTransaction) Commit(context.Context) error {
	x.q.commitAttempted = true
	if x.q.uncertainCommit {
		return errors.New("private uncertain commit detail")
	}
	x.q.committed = true
	x.q.active = false
	x.q.authority = false
	return nil
}
func (x *principalPreflightTransaction) Rollback(context.Context) error {
	x.q.rolled = true
	x.q.active = false
	x.q.authority = false
	return nil
}

func TestPrincipalPreflightPreservesBindingInBoundedAuthorityTransaction(t *testing.T) {
	for _, mode := range []string{"accepted", "binding-denied", "wrong-session", "canceled", "begin-refused", "role-refused", "uncertain-commit", "nil-transaction"} {
		t.Run(mode, func(t *testing.T) {
			q := &principalPreflightQueryer{session: "registered_source_login", bound: mode != "binding-denied", beginDenied: mode == "begin-refused", roleDenied: mode == "role-refused", uncertainCommit: mode == "uncertain-commit", nilTransaction: mode == "nil-transaction"}
			principal := q.session
			if mode == "wrong-session" {
				principal = "other_login"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			r := &registeredReleaseMigrationRunner{releaseMigrationRunner: &scriptedMigrationRunner{version: 61}, queryer: q, registration: discoveryPrincipalRegistration{migration: principal}}
			err := r.auditProfilePrincipal(ctx)
			if q.outsideReads != 0 {
				t.Fatal("protected binding read outside local authority transaction")
			}
			if mode == "canceled" {
				if err == nil || q.begins != 0 || q.reads != 0 || q.committed {
					t.Fatal("canceled preflight reached transaction or binding")
				}
				return
			}
			if q.begins != 1 {
				t.Fatal("preflight did not select same recorder transaction exactly once")
			}
			if mode == "begin-refused" || mode == "nil-transaction" {
				if err == nil || q.reads != 0 || q.committed {
					t.Fatal("unavailable transaction fell back to plain query")
				}
				return
			}
			if !q.rolled || q.active || q.authority {
				t.Fatal("preflight omitted bounded cleanup or leaked role")
			}
			if mode == "role-refused" {
				if err == nil || q.reads != 0 || q.commitAttempted {
					t.Fatal("role refusal reached binding or commit")
				}
				return
			}
			if q.reads != 1 || q.statement != principalPreflightBindingSQL || len(q.arguments) != 1 || q.arguments[0] != principal {
				t.Fatal("mandatory configured-session and exact registered-binding SQL changed")
			}
			if mode == "accepted" {
				if err != nil || !q.committed {
					t.Fatal("legitimate restricted principal was refused")
				}
			} else if err == nil || q.committed {
				t.Fatal("refused or uncertain preflight admitted installer")
			}
		})
	}
}

type principalPlainPreflightQueryer struct{ reads int }

func (q *principalPlainPreflightQueryer) QueryRow(context.Context, string, ...any) pgx.Row {
	q.reads++
	return scriptedPrincipalRow{value: true}
}

type principalGenericPreflightQueryer struct {
	principalPlainPreflightQueryer
	begins int
}

func (q *principalGenericPreflightQueryer) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	q.begins++
	return nil, errors.New("generic provider not same concrete connection")
}
func TestPrincipalPreflightRejectsUnknownNontransactionalAndTypedNilQueryers(t *testing.T) {
	plain := &principalPlainPreflightQueryer{}
	generic := &principalGenericPreflightQueryer{}
	var typedNil *principalPreflightQueryer
	for _, q := range []principalQueryer{plain, generic, typedNil} {
		r := &registeredReleaseMigrationRunner{releaseMigrationRunner: &scriptedMigrationRunner{version: 61}, queryer: q, registration: discoveryPrincipalRegistration{migration: "registered_source_login"}}
		if err := r.auditProfilePrincipal(context.Background()); !errors.Is(err, errReleasePrincipalRegistration) {
			t.Fatal("unsupported queryer reached configured binding admission")
		}
	}
	if plain.reads != 0 || generic.reads != 0 || generic.begins != 0 {
		t.Fatal("unsupported queryer used plain query or generic transaction fallback")
	}
}

type principalPreflightDispatchRunner struct {
	*maintenanceProfileRunner
	q          *principalPreflightQueryer
	dispatched bool
}

func (r *principalPreflightDispatchRunner) UpProductionApprovalMaintenanceProfile(context.Context) error {
	r.dispatched = true
	if !r.q.committed || r.q.active || r.q.authority {
		return errors.New("installer entered before committed original-role preflight")
	}
	return nil
}
func TestPrincipalPreflightActualMaintenanceDispatchFollowsConfirmedCommit(t *testing.T) {
	for _, mode := range []string{"accepted", "binding-denied", "uncertain-commit"} {
		t.Run(mode, func(t *testing.T) {
			q := &principalPreflightQueryer{session: "registered_source_login", bound: mode != "binding-denied", uncertainCommit: mode == "uncertain-commit"}
			base := &principalPreflightDispatchRunner{maintenanceProfileRunner: &maintenanceProfileRunner{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}, q: q}
			r := &registeredReleaseMigrationRunner{releaseMigrationRunner: base, queryer: q, registration: discoveryPrincipalRegistration{migration: q.session}}
			err := runReleaseMigration(context.Background(), r, []string{"up-approval-maintenance-profile"})
			if mode == "accepted" {
				if err != nil || !base.dispatched {
					t.Fatal("actual maintenance installer did not follow confirmed preflight")
				}
			} else if err == nil || base.dispatched {
				t.Fatal("refused preflight reached actual installer dispatch")
			}
			if strings.Contains(q.statement, "GRANT") {
				t.Fatal("principal preflight modified permissions")
			}
		})
	}
}
