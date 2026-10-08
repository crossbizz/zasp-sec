package migrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Preserve the v2 SQL bytes as historical input. The v3 compiled successor
// binds the corrected installer association to a new whole-source pin.
func approvalMaintenanceSQLSuccessor() string {
	const legacySHA256 = "e894ab1c8045a23e4055ced58a89af8a795b26ebf8f4518c83caa89de53a269b"
	h := sha256.Sum256([]byte(approvalMaintenanceSQL))
	if hex.EncodeToString(h[:]) != legacySHA256 {
		panic("approval maintenance predecessor changed")
	}
	return "-- " + ApprovalMaintenanceProfileName + "\n" + approvalMaintenanceSQL
}

func approvalMaintenanceDefinitions(source string) (string, error) {
	const ddl = "CREATE SCHEMA zasp_approval_maintenance AUTHORIZATION zasp_discovery_authority;"
	if strings.Count(source, ddl) != 1 {
		return "", ErrInvalidState
	}
	index := strings.Index(source, ddl)
	for _, line := range strings.Split(source[:index], "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "--") {
			return "", ErrInvalidState
		}
	}
	definitions := strings.TrimSpace(source[index+len(ddl):])
	if definitions == "" {
		return "", ErrInvalidState
	}
	return definitions, nil
}

// Supplementary activation tables reference only the original organization id.
// Grant that one FK privilege as operator; no DML, table-wide privilege or
// inherited catalog definition changes are permitted by this prerequisite.
func ensureMaintenanceOrganizationReference(ctx context.Context, tx Transaction) error {
	check := func(query string, arguments ...any) error {
		var valid bool
		if err := scanRow(ctx, tx, query, arguments, &valid); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !valid {
			return ErrInvalidState
		}
		return nil
	}
	if err := check(`SELECT zasp_authorization80.ready($1) AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`, ProductionAuthorizationEnforcement().Checksum()); err != nil {
		return err
	}
	if err := check(`SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid JOIN pg_constraint k ON k.conrelid=c.oid WHERE n.nspname='public' AND c.relname='zasp_organizations' AND c.relkind='r' AND a.attname='id' AND NOT a.attisdropped AND a.attnotnull AND a.atttypid='text'::regtype AND k.contype='p' AND k.conkey=ARRAY[a.attnum])`); err != nil {
		return err
	}
	var present bool
	if err := scanRow(ctx, tx, `SELECT has_column_privilege('zasp_discovery_authority','public.zasp_organizations','id','REFERENCES')`, nil, &present); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	if !present {
		if err := tx.Exec(ctx, `GRANT REFERENCES(id) ON public.zasp_organizations TO zasp_discovery_authority`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
	}
	return check(`SELECT has_column_privilege('zasp_discovery_authority','public.zasp_organizations','id','REFERENCES') AND zasp_authorization80.ready($1)`, ProductionAuthorizationEnforcement().Checksum())
}
