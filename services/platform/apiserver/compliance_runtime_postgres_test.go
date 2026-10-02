package apiserver

import (
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestComplianceRuntimePollingPostgres(t *testing.T) {
	withComplianceFixFixture(t, func(f *complianceFixFixture) {
		api := f.connect("security_agent_v33_discovery_api_login")
		f.exec(`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,version,body) VALUES($1,$2,$3,'policy','policy-production',7,'{"raw_prompt":"NEVER_EXPORT"}')`, complianceOrg, complianceWorkspace, complianceEnvironment)
		dir, err := os.MkdirTemp("/tmp", "compliance-runtime-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		object := filepath.Join(dir, "object.json")
		child := func(phase string, whileUploading func()) {
			t.Helper()
			ctx, cancel := context.WithTimeout(f.ctx, 16*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/compliance-worker.test", "-test.run=^TestComplianceRuntimeProcess$", "-test.v", "-test.timeout=15s")
			cmd.Env = append(os.Environ(), "ZASP_COMPLIANCE_RUNTIME_DSN="+f.dsn, "ZASP_COMPLIANCE_RUNTIME_PHASE="+phase, "ZASP_COMPLIANCE_RUNTIME_OBJECT="+object)
			if whileUploading == nil {
				out, err := cmd.CombinedOutput()
				t.Logf("joined %s: %s", phase, out)
				if err != nil {
					t.Fatalf("child %s: %v", phase, err)
				}
				return
			}
			done := make(chan struct{})
			var out []byte
			var runErr error
			go func() { out, runErr = cmd.CombinedOutput(); close(done) }()
			defer func() { cancel(); <-done }()
			for {
				if _, err := os.Stat(object + ".entered"); err == nil {
					break
				}
				select {
				case <-done:
					t.Fatalf("child exited before upload: %s %v", out, runErr)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(5 * time.Millisecond):
				}
			}
			whileUploading()
			if err := os.WriteFile(object+".release", []byte("continue"), 0600); err != nil {
				t.Fatal(err)
			}
			<-done
			t.Logf("joined %s: %s", phase, out)
			if runErr != nil {
				t.Fatal(runErr)
			}
		}
		id := f.job(api, "runtime-restart")
		child("interrupt", nil)
		var before, after []byte
		var state, storage string
		var retained int64
		if err := f.owner.QueryRow(f.ctx, `SELECT package,state,storage_state,retained_bytes FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&before, &state, &storage, &retained); err != nil || state != "pending" || storage != "unknown" || retained < 1 || strings.Contains(string(before), "NEVER_EXPORT") || !strings.Contains(string(before), `"source_version":7`) {
			t.Fatalf("SIGTERM intent state=%s storage=%s bytes=%d %v", state, storage, retained, err)
		}
		f.exec(`UPDATE zasp_workflow_records SET version=8 WHERE id='policy-production';UPDATE zasp_compliance_export_jobs SET next_attempt_at=clock_timestamp() WHERE export_id=$1`, id)
		child("resume", nil)
		if err := f.owner.QueryRow(f.ctx, `SELECT package,state,storage_state FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&after, &state, &storage); err != nil || state != "completed" || storage != "verified" || hex.EncodeToString(before) != hex.EncodeToString(after) {
			t.Fatalf("restart changed frozen bytes %s %s %v", state, storage, err)
		}
		f.exec(`UPDATE zasp_compliance_export_jobs SET retrieval_expires_at=clock_timestamp()-interval '1 second' WHERE export_id=$1`, id)
		child("cleanup_denied", nil)
		if err := f.owner.QueryRow(f.ctx, `SELECT storage_state,retained_bytes FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&storage, &retained); err != nil || storage != "delete_pending" || retained < 1 {
			t.Fatalf("denied cleanup released quota %s %d %v", storage, retained, err)
		}
		f.exec(`UPDATE zasp_compliance_export_jobs SET next_attempt_at=clock_timestamp() WHERE export_id=$1`, id)
		child("cleanup", nil)
		if err := f.owner.QueryRow(f.ctx, `SELECT storage_state,retained_bytes FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&storage, &retained); err != nil || storage != "deleted" || retained != 0 {
			t.Fatalf("verified cleanup retained quota %s %d %v", storage, retained, err)
		}
		id = f.job(api, "runtime-exhaustion")
		for i := 0; i < 5; i++ {
			child("unknown", nil)
			f.exec(`UPDATE zasp_compliance_export_jobs SET next_attempt_at=clock_timestamp() WHERE export_id=$1`, id)
		}
		if err := f.owner.QueryRow(f.ctx, `SELECT state,storage_state,retained_bytes FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&state, &storage, &retained); err != nil || state != "failed" || storage != "reconcile_required" || retained < 1 {
			t.Fatalf("exhaustion %s %s %d %v", state, storage, retained, err)
		}
		child("reconcile", nil)
		if err := f.owner.QueryRow(f.ctx, `SELECT state,storage_state FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&state, &storage); err != nil || state != "failed" || storage != "verified" {
			t.Fatalf("reconciler changed public failure %s %s %v", state, storage, err)
		}
		// Separate job/provider fixture, concurrent revocation after Put has begun.
		object = filepath.Join(dir, "revoked.json")
		id = f.job(api, "runtime-revocation")
		child("revoked", func() {
			f.exec(`UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE token_digest=$1`, f.digest[:])
		})
		if err := f.owner.QueryRow(f.ctx, `SELECT state,storage_state,retained_bytes FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&state, &storage, &retained); err != nil || state != "pending" || storage != "unknown" || retained < 1 {
			t.Fatalf("revocation published or released intent %s %s %d %v", state, storage, retained, err)
		}
		f.exec(`UPDATE zasp_product_sessions SET revoked_at=NULL WHERE token_digest=$1`, f.digest[:])
		// Keep the previous uncertain job out of the next execution poll.
		f.exec(`UPDATE zasp_compliance_export_jobs SET next_attempt_at=clock_timestamp()+interval '1 hour' WHERE export_id=$1`, id)
		object = filepath.Join(dir, "stale.json")
		id = f.job(api, "runtime-stale-lease")
		child("lease_lost", func() {
			f.exec(`UPDATE zasp_compliance_export_jobs SET generation=generation+1,lease_expires_at=clock_timestamp()-interval '1 second' WHERE export_id=$1`, id)
		})
		if err := f.owner.QueryRow(f.ctx, `SELECT state,storage_state,retained_bytes FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&state, &storage, &retained); err != nil || state != "pending" || storage != "intent" || retained < 1 {
			t.Fatalf("stale worker finalized/released intent %s %s %d %v", state, storage, retained, err)
		}
	})
}
