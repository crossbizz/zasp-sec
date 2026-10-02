package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Trusted fixture rows bring each independent counter one admission below its
// exact limit. Only registered API clients contend for the final slot.
func TestComplianceConcurrentQuotasPostgres(t *testing.T) {
	for _, tc := range []struct {
		name      string
		count     int
		bytes     int64
		state     string
		local     bool
		wantCount int
		wantBytes int64
	}{
		{"deployment_active_100", 99, 99, "pending", false, 100, 0},
		{"deployment_retained_bytes_16GiB", 2048, 17179869184 - 12582912, "failed", false, 2049, 17179869184},
		{"deployment_retained_jobs_10000", 9999, 9999, "failed", false, 10000, 0},
		{"scope_retained_jobs_100", 99, 99, "failed", true, 100, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withComplianceFixFixture(t, func(f *complianceFixFixture) {
				f.exec(`INSERT INTO zasp_compliance_export_scopes(organization_id,workspace_id,environment_id)
SELECT DISTINCT $1,$2,CASE WHEN $4 THEN $3 ELSE 'pid_7b000001-0000-4000-8000-'||lpad(n::text,12,'0') END FROM generate_series(1,$5::int) n;
INSERT INTO zasp_compliance_export_jobs(organization_id,workspace_id,environment_id,export_id,principal_id,session_digest,idempotency_key,request,request_digest,policy_revision,state,phase,retained_bytes)
SELECT $1,$2,CASE WHEN $4 THEN $3 ELSE 'pid_7b000001-0000-4000-8000-'||lpad(n::text,12,'0') END,'pid_7b000002-0000-4000-8000-'||lpad(n::text,12,'0'),$6,$7,'fixture-'||n,'{}',digest('{}','sha256'),'compliance-limits-v1',$8,CASE WHEN $8='pending' THEN 'queued' ELSE 'terminal' END,$9::bigint/$5::int+CASE WHEN n<=$9::bigint%$5::int THEN 1 ELSE 0 END FROM generate_series(1,$5::int) n`, complianceOrg, complianceWorkspace, complianceEnvironment, tc.local, tc.count, compliancePrincipal, f.digest[:], tc.state, tc.bytes)
				assertComplianceFinalSlot(t, f, func(ctx context.Context, c *pgx.Conn, n int) error {
					_, err := f.create(ctx, c, fmt.Sprintf("quota-contender-%d", n))
					return err
				})
				var count int
				var size int64
				if err := f.owner.QueryRow(f.ctx, `SELECT count(*),sum(retained_bytes) FROM zasp_compliance_export_jobs`).Scan(&count, &size); err != nil || count != tc.wantCount || tc.wantBytes != 0 && size != tc.wantBytes {
					t.Fatalf("boundary count=%d bytes=%d: %v", count, size, err)
				}
				t.Logf("registered concurrent clients: one admitted, one 54000; jobs=%d retained_bytes=%d", count, size)
			})
		})
	}
	t.Run("principal_scope_grants_20", func(t *testing.T) {
		withComplianceFixFixture(t, func(f *complianceFixFixture) {
			f.exec(`INSERT INTO zasp_compliance_export_scopes(organization_id,workspace_id,environment_id) VALUES($1,$2,$3);
INSERT INTO zasp_compliance_export_jobs(organization_id,workspace_id,environment_id,export_id,principal_id,session_digest,idempotency_key,request,request_digest,policy_revision,state,phase,storage_state,receipt_version,retained_bytes)
SELECT $1,$2,$3,'pid_7b000003-0000-4000-8000-'||lpad(n::text,12,'0'),$4,$5,'grant-'||n,'{}',digest('{}','sha256'),'compliance-limits-v1','completed','terminal','verified','immutable-v1',1 FROM generate_series(1,5) n;
INSERT INTO zasp_compliance_export_grants(organization_id,workspace_id,environment_id,export_id,grant_digest,principal_id,session_digest,format,expires_at)
SELECT $1,$2,$3,'pid_7b000003-0000-4000-8000-'||lpad(((n-1)/4+1)::text,12,'0'),digest('fixture-grant-'||n,'sha256'),$4,$5,'json',clock_timestamp()+interval '60 seconds' FROM generate_series(1,19) n`, complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal, f.digest[:])
			var id string
			if err := f.owner.QueryRow(f.ctx, `SELECT 'pid_7b000003-0000-4000-8000-000000000005'`).Scan(&id); err != nil {
				t.Fatal(err)
			}
			assertComplianceFinalSlot(t, f, func(ctx context.Context, c *pgx.Conn, n int) error {
				var raw json.RawMessage
				return c.QueryRow(ctx, `SELECT zasp_compliance_export_grant($1,$2,$3,$4,$5,$6,$7,'json','issue',$8,$9)`, complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal, f.digest[:], id, fmt.Sprintf("%064x", n+200), migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw)
			})
			var total, job int
			if err := f.owner.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE export_id=$1) FROM zasp_compliance_export_grants`, id).Scan(&total, &job); err != nil || total != 20 || job != 4 {
				t.Fatalf("principal grant boundary total=%d targetjob=%d: %v", total, job, err)
			}
			t.Log("registered concurrent clients: principal/S grants=20, target job grants=4; one admitted, one 54000")
		})
	})
}

func assertComplianceFinalSlot(t *testing.T, f *complianceFixFixture, call func(context.Context, *pgx.Conn, int) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
	defer cancel()
	clients := []*pgx.Conn{f.connect("security_agent_v33_discovery_api_login"), f.connect("security_agent_v33_discovery_api_login")}
	start := make(chan struct{})
	done := make(chan error, 2)
	for n, c := range clients {
		go func(n int, c *pgx.Conn) { <-start; done <- call(ctx, c, n) }(n, c)
	}
	close(start)
	wins, rejected := 0, 0
	// Query contexts are bounded; receive both results even when one fails.
	for range clients {
		err := <-done
		if err == nil {
			wins++
		} else if auditExportSQLState(err) == "54000" {
			rejected++
		} else {
			t.Errorf("unexpected admission error: %v", err)
		}
	}
	if wins != 1 || rejected != 1 {
		t.Fatalf("concurrent final slot: wins=%d quota_rejections=%d", wins, rejected)
	}
}
