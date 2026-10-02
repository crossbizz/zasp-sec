package apiserver

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"strings"
	"testing"
)

type identityObservedMigrationDatabase struct {
	connection *pgx.Conn
	t          *testing.T
}

func (d *identityObservedMigrationDatabase) QueryRow(c context.Context, q string, a ...any) migrations.Row {
	return d.connection.QueryRow(c, q, a...)
}
func (d *identityObservedMigrationDatabase) Begin(c context.Context) (migrations.Transaction, error) {
	tx, e := d.connection.Begin(c)
	if e != nil {
		return nil, e
	}
	return &identityObservedMigrationTransaction{orderedAdmissionMigrationTransaction{integrationMigrationTransaction: integrationMigrationTransaction{transaction: tx}, t: d.t}}, nil
}

type identityObservedMigrationTransaction struct {
	orderedAdmissionMigrationTransaction
}

func (tx *identityObservedMigrationTransaction) QueryRow(c context.Context, q string, a ...any) migrations.Row {
	if strings.Contains(q, "WITH identities(value)") {
		var value string
		prefix, _, _ := strings.Cut(q, ")=$1 AND")
		e := tx.transaction.QueryRow(c, prefix+")::text").Scan(&value)
		tx.t.Logf("identity compiled predecessor=%s error=%v", value, e)
		e = tx.transaction.QueryRow(c, `SELECT jsonb_build_array(public.zasp_identity_admin_security_ready(),zasp_authorization80_audit.guard_ready(),public.zasp_sa_multistep_registered_live_fingerprint())::text`).Scan(&value)
		tx.t.Logf("identity predecessor checks=%s error=%v", value, e)
	}
	if strings.HasPrefix(q, "SELECT jsonb_build_array(zasp_authorization80_audit.projected57()") {
		var value string
		e := tx.transaction.QueryRow(c, q).Scan(&value)
		tx.t.Logf("identity ancestry [57,61,79,80,audit]=%s error=%v", value, e)
	}
	if strings.HasPrefix(q, "SELECT zasp_authorization80_identity.projected19()") {
		var value string
		e := tx.transaction.QueryRow(c, `SELECT jsonb_build_array(public.zasp_identity_administration_live_fingerprint(),zasp_authorization80_identity.projected19(),public.zasp_identity_admin_security_ready())::text`).Scan(&value)
		tx.t.Logf("identity final [actual19,projected19,security]=%s error=%v", value, e)
		e = tx.transaction.QueryRow(c, `SELECT jsonb_build_object('before',jsonb_build_object('definition',s.definition,'owner',s.owner_name,'acl',s.acl),'after',jsonb_build_object('definition',pg_get_functiondef(p.oid),'owner',p.proowner::regrole::text,'acl',p.proacl::text))::text FROM zasp_authorization80_identity.predecessor s CROSS JOIN pg_proc p WHERE p.oid='public.zasp_identity_admin_reconcile_deprovision(text,text,text,text,bytea,text)'::regprocedure`).Scan(&value)
		tx.t.Logf("identity exact public function delta=%s error=%v", value, e)
	}
	return tx.orderedAdmissionMigrationTransaction.QueryRow(c, q, a...)
}
