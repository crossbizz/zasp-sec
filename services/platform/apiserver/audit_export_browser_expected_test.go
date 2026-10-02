package apiserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// This is a fixed, raw producer projection. Eligible operation/kind rows stay
// in the cursor even when malformed, so mapping fails closed instead of hiding
// them. It never selects policy/test bodies, receipts, or public export state.
const auditBrowserMixedRowsSQL = `
 SELECT 'admin' AS source,id,organization_id,workspace_id,environment_id,actor_id,action,target_id,outcome,metadata,occurred_at,
 ''::text AS operation,''::text AS resource_kind,''::text AS correlation_id,0::bigint AS resource_version,''::text AS receipt_id,NULL::bytea AS event_digest
 FROM zasp_admin_audit WHERE organization_id=$1
 UNION ALL
 SELECT 'policy',audit_id,organization_id,workspace_id,environment_id,principal_id,'',resource_id,'succeeded','{}'::jsonb,created_at,
 operation,resource_kind,correlation_id,resource_version,'',NULL::bytea
 FROM zasp_workflow_audit WHERE organization_id=$1 AND operation IN ('createPolicy','updatePolicy','deletePolicy','rolloutPolicy','disablePolicy')
 UNION ALL
 SELECT 'test',audit_id,organization_id,workspace_id,environment_id,actor_id,'',resource_id,'succeeded','{}'::jsonb,created_at,
 event_kind,'',correlation_id,0::bigint,receipt_id,event_digest
 FROM zasp_red_team_audit WHERE organization_id=$1 AND event_kind IN ('red_team_definition_created','red_team_definition_updated','red_team_run_queued','red_team_run_cancelled')`

var auditBrowserPolicyID = regexp.MustCompile(`^policy-[a-z0-9][a-z0-9-]{0,120}$`)

type auditBrowserMixedSource struct {
	tx           pgx.Tx
	organization string
	count        int64
	cursor, eof  bool
}

// Invalid eligible raw fields must fail before they can earn canonical bytes.
// Test IDs/digests are rejected by current producer constraints too; testing the
// raw mapper keeps that defense independent of a future constraint regression.
func TestAuditHTTPSizeExpectedMixedRawValidation(t *testing.T) {
	for _, source := range []string{"policy", "test"} {
		base := auditBrowserMixedRawRow{
			auditHTTPSizeSourceRow: auditHTTPSizeTestRow(0),
			source:                 source, operation: "createPolicy", resourceKind: "policy",
			correlation: auditHTTPSizeTestID(9701), receipt: auditHTTPSizeTestID(9702), version: 1,
			digest: make([]byte, 32),
		}
		base.event.TargetID = "policy-original"
		if source == "test" {
			base.operation = "red_team_run_cancelled"
			base.event.TargetID = auditHTTPSizeTestID(9703)
		}
		for _, tc := range []struct {
			name   string
			change func(*auditBrowserMixedRawRow)
			valid  bool
		}{
			{"valid", func(*auditBrowserMixedRawRow) {}, true},
			{"correlation", func(r *auditBrowserMixedRawRow) { r.correlation = "bad" }, false},
			{"target", func(r *auditBrowserMixedRawRow) { r.event.TargetID = "bad" }, false},
			{"kind", func(r *auditBrowserMixedRawRow) { r.resourceKind = "integration" }, source == "test"},
			{"version-zero", func(r *auditBrowserMixedRawRow) { r.version = 0 }, source == "test"},
			{"version-negative", func(r *auditBrowserMixedRawRow) { r.version = -1 }, source == "test"},
			{"receipt", func(r *auditBrowserMixedRawRow) { r.receipt = "bad" }, source == "policy"},
			{"digest-short", func(r *auditBrowserMixedRawRow) { r.digest = make([]byte, 31) }, source == "policy"},
			{"digest-long", func(r *auditBrowserMixedRawRow) { r.digest = make([]byte, 33) }, source == "policy"},
			{"operation", func(r *auditBrowserMixedRawRow) { r.operation = "unknown" }, false},
			{"principal", func(r *auditBrowserMixedRawRow) { r.event.ActorID = "bad" }, false},
			{"organization", func(r *auditBrowserMixedRawRow) { r.event.OrganizationID = auditHTTPSizeTestID(9999) }, false},
			{"workspace", func(r *auditBrowserMixedRawRow) { r.event.WorkspaceID = "bad" }, false},
			{"environment", func(r *auditBrowserMixedRawRow) { r.event.EnvironmentID = "bad" }, false},
			{"audit-id", func(r *auditBrowserMixedRawRow) { r.event.ID = "bad" }, false},
			{"timestamp", func(r *auditBrowserMixedRawRow) { r.stamp = time.Time{} }, false},
		} {
			t.Run(source+"/"+tc.name, func(t *testing.T) {
				raw := base
				tc.change(&raw)
				row, err := raw.project()
				if err == nil {
					e := auditHTTPSizeTestOracle(t, 1, func(int) auditHTTPSizeSourceRow { return row })
					_, err = e.Next(context.Background())
				}
				if (err == nil) != tc.valid {
					t.Fatal("raw eligible validation", tc.valid, err)
				}
			})
		}
	}
}

type auditBrowserMixedRawRow struct {
	auditHTTPSizeSourceRow
	source, operation, resourceKind, correlation, receipt string
	version                                               int64
	digest                                                []byte
}

func newAuditBrowserMixedExpected(ctx context.Context, conn *pgx.Conn, organizationID string) (*auditHTTPSizeExpected, error) {
	if conn == nil || conn.IsClosed() {
		return nil, errors.New("mixed snapshot requires an open borrowed PostgreSQL connection")
	}
	if _, err := domain.ParseProductID(organizationID); err != nil {
		return nil, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	s := &auditBrowserMixedSource{tx: tx, organization: organizationID}
	// Taking the count now also pins the original MVCC snapshot before Reset.
	// The server aggregate also detects equal IDs at unequal timestamps. Client
	// memory stays bounded; PostgreSQL may sort or hash the original IDs here.
	var distinct int64
	err = tx.QueryRow(ctx, `SELECT count(*),count(DISTINCT id COLLATE "C") FROM (`+auditBrowserMixedRowsSQL+") original", organizationID).Scan(&s.count, &distinct)
	if err == nil && s.count != distinct {
		err = fmt.Errorf("mixed original snapshot contains duplicate IDs: rows=%d distinct=%d", s.count, distinct)
	}
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return nil, errors.Join(err, tx.Rollback(cleanup))
	}
	return &auditHTTPSizeExpected{source: s, organization: organizationID}, nil
}

func (s *auditBrowserMixedSource) snapshotConnection() *pgx.Conn {
	if s.tx == nil {
		return nil
	}
	return s.tx.Conn()
}
func (s *auditBrowserMixedSource) snapshotCount() int64 { return s.count }
func (s *auditBrowserMixedSource) reset(ctx context.Context) error {
	if s.cursor {
		if _, err := s.tx.Exec(ctx, "CLOSE audit_browser_mixed_original"); err != nil {
			return err
		}
		s.cursor = false
	}
	_, err := s.tx.Exec(ctx, "DECLARE audit_browser_mixed_original NO SCROLL CURSOR FOR SELECT * FROM ("+auditBrowserMixedRowsSQL+`) original ORDER BY occurred_at DESC,id COLLATE "C" DESC`, s.organization)
	if err == nil {
		s.cursor, s.eof = true, false
	}
	return err
}
func (s *auditBrowserMixedSource) next(ctx context.Context) (auditHTTPSizeSourceRow, error) {
	if s.eof {
		return auditHTTPSizeSourceRow{}, io.EOF
	}
	rows, err := s.tx.Query(ctx, "FETCH FORWARD 1 FROM audit_browser_mixed_original")
	if err != nil {
		return auditHTTPSizeSourceRow{}, err
	}
	// Rows are request-local. Even a Scan or transport failure joins this FETCH.
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return auditHTTPSizeSourceRow{}, err
		}
		s.eof = true
		return auditHTTPSizeSourceRow{}, io.EOF
	}
	var raw auditBrowserMixedRawRow
	err = rows.Scan(&raw.source, &raw.event.ID, &raw.event.OrganizationID, &raw.event.WorkspaceID, &raw.event.EnvironmentID, &raw.event.ActorID, &raw.event.Action, &raw.event.TargetID, &raw.event.Outcome, &raw.metadata, &raw.stamp, &raw.operation, &raw.resourceKind, &raw.correlation, &raw.version, &raw.receipt, &raw.digest)
	if err != nil {
		return auditHTTPSizeSourceRow{}, err
	}
	if rows.Next() {
		return auditHTTPSizeSourceRow{}, errors.New("one-row mixed FETCH returned extra rows")
	}
	if err := rows.Err(); err != nil {
		return auditHTTPSizeSourceRow{}, err
	}
	return raw.project()
}
func (s *auditBrowserMixedSource) close(ctx context.Context) error { return s.tx.Rollback(ctx) }

func (r auditBrowserMixedRawRow) project() (auditHTTPSizeSourceRow, error) {
	var metadata map[string]string
	switch r.source {
	case "admin":
		return r.auditHTTPSizeSourceRow, nil
	case "policy":
		if !auditBrowserPolicyID.MatchString(r.event.TargetID) || r.resourceKind != "policy" || r.version <= 0 {
			return auditHTTPSizeSourceRow{}, errors.New("malformed eligible policy source")
		}
		switch r.operation {
		case "createPolicy":
			r.event.Action = "policy.create"
		case "updatePolicy":
			r.event.Action = "policy.update"
		case "deletePolicy":
			r.event.Action = "policy.delete"
		case "rolloutPolicy":
			r.event.Action = "policy.rollout"
		case "disablePolicy":
			r.event.Action = "policy.disable"
		default:
			return auditHTTPSizeSourceRow{}, errors.New("unselected policy operation")
		}
		metadata = map[string]string{"source": "workflow_policy", "source_operation": r.operation, "correlation_id": r.correlation, "resource_version": strconv.FormatInt(r.version, 10)}
	case "test":
		if _, err := domain.ParseProductID(r.event.TargetID); err != nil {
			return auditHTTPSizeSourceRow{}, err
		}
		if _, err := domain.ParseProductID(r.receipt); err != nil {
			return auditHTTPSizeSourceRow{}, err
		}
		if len(r.digest) != 32 {
			return auditHTTPSizeSourceRow{}, errors.New("malformed eligible test digest")
		}
		switch r.operation {
		case "red_team_definition_created":
			r.event.Action = "test.create"
		case "red_team_definition_updated":
			r.event.Action = "test.update"
		case "red_team_run_queued":
			r.event.Action = "test.run.queued"
		case "red_team_run_cancelled":
			r.event.Action = "test.run.cancel_requested"
		default:
			return auditHTTPSizeSourceRow{}, errors.New("unselected test event kind")
		}
		metadata = map[string]string{"source": "red_team_mutation", "source_event_kind": r.operation, "correlation_id": r.correlation, "receipt_id": r.receipt, "event_sha256": hex.EncodeToString(r.digest)}
	default:
		return auditHTTPSizeSourceRow{}, errors.New("unselected original source")
	}
	if _, err := domain.ParseProductID(r.correlation); err != nil {
		return auditHTTPSizeSourceRow{}, err
	}
	r.event.Outcome = "succeeded"
	var err error
	r.metadata, err = json.Marshal(metadata)
	return r.auditHTTPSizeSourceRow, err
}
