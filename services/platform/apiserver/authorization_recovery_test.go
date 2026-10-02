package apiserver

import (
	"context"
	"crypto/sha256"
	"testing"
)

func TestP7RecoveryCheckedStatements(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, RequestAuthorization{})
	digest := sha256.Sum256([]byte("recovery-current-proof"))
	backup := RecoveryBackupMutation{BackupID: testRecoveryBackupID, RetentionDays: 30, IdempotencyKey: "recovery-current-proof-01", RequestDigest: digest[:], AuditID: "pid_71000004-0000-4000-8000-000000000004", CorrelationID: testCorrelationID, ReceiptID: "pid_71000005-0000-4000-8000-000000000005"}
	restore := RecoveryRestoreMutation{RestoreID: testRecoveryRestoreID, TargetEnvironment: "owned-recovery-fixture", Manifest: recoveryManifestFixture(identity), IdempotencyKey: backup.IdempotencyKey, RequestDigest: digest[:], AuditID: backup.AuditID, CorrelationID: backup.CorrelationID, ReceiptID: backup.ReceiptID}
	for _, tc := range []struct {
		name, sql string
		call      func(*RecoveryPublicRepository)
	}{
		{"start backup", `SELECT zasp_authorization80.recovery_create_backup($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, func(r *RecoveryPublicRepository) { _, _ = r.StartBackup(ctx, identity, backup) }},
		{"get backup", `SELECT zasp_authorization80.recovery_get_backup($1,$2,$3,$4)`, func(r *RecoveryPublicRepository) { _, _ = r.GetBackup(ctx, identity, testRecoveryBackupID) }},
		{"start restore", `SELECT zasp_authorization80.recovery_create_restore($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`, func(r *RecoveryPublicRepository) { _, _ = r.StartRestore(ctx, identity, restore) }},
		{"get restore", `SELECT zasp_authorization80.recovery_get_restore($1,$2,$3,$4)`, func(r *RecoveryPublicRepository) { _, _ = r.GetRestore(ctx, identity, testRecoveryRestoreID) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &workflowCallDatabase{}
			tc.call(&RecoveryPublicRepository{database: db})
			if db.query != tc.sql {
				t.Fatalf("checked recovery query=%q want%q", db.query, tc.sql)
			}
		})
	}
}
