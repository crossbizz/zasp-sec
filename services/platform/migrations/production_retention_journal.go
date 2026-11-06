package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const RetentionJournalProfileName = "canonical61-temporal78-authorization79-80-audit-identity-retention-journal-v1"

//go:embed sql/retention_journal.sql
var retentionJournalSQL string

func retentionJournalProfileSource() (string, string) {
	source := strings.ReplaceAll(retentionJournalSQL, "-- journal parent checksum", RetentionAuditProfileChecksum())
	sum := sha256.Sum256([]byte(source))
	pin := hex.EncodeToString(sum[:])
	return strings.ReplaceAll(source, "-- journal checksum", pin), pin
}
func RetentionJournalProfileChecksum() string { _, pin := retentionJournalProfileSource(); return pin }
func IsRetentionJournalProfileChecksum(pin string) bool {
	return len(pin) == 64 && pin == RetentionJournalProfileChecksum()
}

// Installation seals the complete independent recipe but enrolls no tenant.
// Scope enrollment is a separate irreversible original-operator operation.
func (r *Runner) UpProductionRetentionJournalProfile(ctx context.Context) error {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return ErrInvalidRunner
	}
	source, pin := retentionJournalProfileSource()
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Exec(ctx, `SET LOCAL lock_timeout='3s';SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0));SET LOCAL ROLE zasp_discovery_authority`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		var ok, present bool
		if err := scanRow(ctx, tx, `SELECT zasp_authorization79.operator() AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') AND zasp_retention_v1.effective_catalog_ready($1)`, []any{RetentionAuditProfileChecksum()}, &ok); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !ok {
			return ErrInvalidState
		}
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_retention_journal_v1') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !present {
			// Original registered NOINHERIT source login has database CREATE; no
			// alternate credential or schema privilege fallback is selected here.
			if err := tx.Exec(ctx, `SET LOCAL ROLE NONE;CREATE SCHEMA zasp_retention_journal_v1 AUTHORIZATION zasp_discovery_authority;SET LOCAL ROLE zasp_discovery_authority`); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, source); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := scanRow(ctx, tx, `SELECT zasp_retention_journal_v1.raw_ready($1) AND zasp_retention_v1.effective_catalog_ready($2)`, []any{pin, RetentionAuditProfileChecksum()}, &ok); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !ok {
			return ErrInvalidState
		}
		return nil
	})
}
