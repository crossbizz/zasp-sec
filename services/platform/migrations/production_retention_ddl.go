package migrations

import (
	"context"
	"errors"
	"regexp"
	"time"
)

var ErrRetentionPublicDDLPrerequisite = errors.New("retention public DDL requires explicit schema-owner provisioning")
var ErrRetentionDDLAuthority = errors.New("retention schema-owner DDL authority rejected")

var retentionDDLPrincipalPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
var retentionDDLDatabasePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,62}$`)

// The target role and schema are compiled constants, never request fields.
type RetentionDDLBootstrapRequest struct {
	Principal string
	Database  string
}

func (request RetentionDDLBootstrapRequest) Validate() error {
	if !retentionDDLPrincipalPattern.MatchString(request.Principal) || !retentionDDLDatabasePattern.MatchString(request.Database) {
		return ErrRetentionDDLAuthority
	}
	return nil
}

type RetentionDDLBootstrapReceipt struct {
	Capability  string `json:"capability"`
	Principal   string `json:"principal"`
	Database    string `json:"database"`
	Schema      string `json:"schema"`
	Grantee     string `json:"grantee"`
	DatabaseOID int64  `json:"database_oid"`
	SchemaOID   int64  `json:"schema_oid"`
	GranteeOID  int64  `json:"grantee_oid"`
}

// This capability is a mutable DDL prerequisite, not a runtime structural seal.
// Existing captured cleanup and ACTIVE replay do not depend on this query.
const retentionPublicDDLReadySQL = `SELECT coalesce(EXISTS(
 SELECT 1 FROM pg_catalog.pg_roles authority CROSS JOIN pg_catalog.pg_namespace ns
 WHERE authority.rolname='zasp_discovery_authority' AND ns.nspname='public'
 AND NOT authority.rolcanlogin AND NOT authority.rolinherit AND NOT authority.rolsuper
 AND NOT authority.rolcreatedb AND NOT authority.rolcreaterole AND NOT authority.rolreplication AND NOT authority.rolbypassrls
 AND pg_catalog.has_schema_privilege(authority.oid,ns.oid,'CREATE')),false)`

// Superuser privilege inference is deliberately insufficient: the invoking
// identity must own this namespace (including actual pg_database_owner), or
// hold an explicit direct CREATE grant option. No inherited-role guess is made.
const retentionDDLBootstrapIdentitySQL = `SELECT
 coalesce(session_user=$1 AND current_user=session_user AND current_database()=$2
 AND NOT authority.rolcanlogin AND NOT authority.rolinherit AND NOT authority.rolsuper
 AND NOT authority.rolcreatedb AND NOT authority.rolcreaterole AND NOT authority.rolreplication AND NOT authority.rolbypassrls
 AND (ns.nspowner=caller.oid OR (owner_role.rolname='pg_database_owner' AND db.datdba=caller.oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(ns.nspacl,pg_catalog.acldefault('n',ns.nspowner))) acl
 WHERE acl.grantee=caller.oid AND acl.privilege_type='CREATE' AND acl.is_grantable)),false),
 db.oid::bigint,ns.oid::bigint,authority.oid::bigint
 FROM pg_catalog.pg_database db CROSS JOIN pg_catalog.pg_namespace ns
 JOIN pg_catalog.pg_roles owner_role ON owner_role.oid=ns.nspowner
 CROSS JOIN pg_catalog.pg_roles authority CROSS JOIN pg_catalog.pg_roles caller
 WHERE db.datname=current_database() AND ns.nspname='public'
 AND authority.rolname='zasp_discovery_authority' AND caller.rolname=session_user`

const retentionDDLBootstrapPostcheckSQL = `SELECT coalesce(EXISTS(
 SELECT 1 FROM pg_catalog.pg_database db CROSS JOIN pg_catalog.pg_namespace ns CROSS JOIN pg_catalog.pg_roles authority
 WHERE session_user=$1 AND current_user=session_user AND current_database()=$2
 AND db.datname=current_database() AND db.oid::bigint=$3 AND ns.nspname='public' AND ns.oid::bigint=$4
 AND authority.rolname='zasp_discovery_authority' AND authority.oid::bigint=$5
 AND NOT authority.rolcanlogin AND NOT authority.rolinherit AND NOT authority.rolsuper
 AND NOT authority.rolcreatedb AND NOT authority.rolcreaterole AND NOT authority.rolreplication AND NOT authority.rolbypassrls
 AND pg_catalog.has_schema_privilege(authority.oid,ns.oid,'CREATE')),false)`

// BootstrapProductionRetentionPublicDDL is an explicit owner operation. It
// never selects alternate credentials, changes roles or activates a profile.
// A receipt exists only after the shared transaction helper confirms COMMIT.
func (r *Runner) BootstrapProductionRetentionPublicDDL(ctx context.Context, request RetentionDDLBootstrapRequest) (RetentionDDLBootstrapReceipt, error) {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return RetentionDDLBootstrapReceipt{}, ErrInvalidRunner
	}
	if err := request.Validate(); err != nil {
		return RetentionDDLBootstrapReceipt{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var receipt RetentionDDLBootstrapReceipt
	err := r.withTransaction(bounded, func(ctx context.Context, tx Transaction) error {
		if err := tx.Exec(ctx, `SET LOCAL lock_timeout='3s';SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		var allowed bool
		var databaseOID, schemaOID, granteeOID int64
		if err := scanRow(ctx, tx, retentionDDLBootstrapIdentitySQL, []any{request.Principal, request.Database}, &allowed, &databaseOID, &schemaOID, &granteeOID); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !allowed || databaseOID < 1 || schemaOID < 1 || granteeOID < 1 {
			return ErrRetentionDDLAuthority
		}
		if err := tx.Exec(ctx, `GRANT CREATE ON SCHEMA public TO zasp_discovery_authority`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := scanRow(ctx, tx, retentionDDLBootstrapPostcheckSQL, []any{request.Principal, request.Database, databaseOID, schemaOID, granteeOID}, &allowed); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !allowed {
			return ErrRetentionPublicDDLPrerequisite
		}
		receipt = RetentionDDLBootstrapReceipt{Capability: "retention-public-create-v1", Principal: request.Principal, Database: request.Database, Schema: "public", Grantee: "zasp_discovery_authority", DatabaseOID: databaseOID, SchemaOID: schemaOID, GranteeOID: granteeOID}
		return nil
	})
	if err != nil {
		return RetentionDDLBootstrapReceipt{}, err
	}
	return receipt, nil
}
