//go:build darwin || linux

package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAuditExportPublicPageSparseCost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	a := f.createArgs()
	// Explicit owned scale records, not producer or completion evidence. All
	// three eligible branches and ten organizations share stable time ranges.
	for _, statement := range []string{
		`INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at)
 SELECT CASE WHEN i%10=0 THEN $1 ELSE 'pid_79820001-0000-4000-8000-'||lpad((i%10)::text,12,'0') END,$2,$3,'pid_79820002-0000-4000-8000-'||lpad(i::text,12,'0'),CASE WHEN i=40000 THEN $4 ELSE 'pid_79820003-0000-4000-8000-000000000001' END,CASE WHEN i%5000=0 THEN 'page.rare' ELSE 'page.bulk' END,'policy-scale',CASE WHEN i%5000=0 THEN 'rejected' ELSE 'succeeded' END,jsonb_build_object(repeat('k',2048),'x'),timestamptz '2026-01-01T00:00:00Z'+(i/2)*interval '1 second' FROM generate_series(1,40001) i`,
		`INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version,created_at)
 SELECT CASE WHEN i%10=0 THEN $1 ELSE 'pid_79820001-0000-4000-8000-'||lpad((i%10)::text,12,'0') END,$2,$3,'pid_79820004-0000-4000-8000-'||lpad(i::text,12,'0'),'pid_79820005-0000-4000-8000-'||lpad(i::text,12,'0'),$4,'updatePolicy','policy','policy-scale',1,timestamptz '2026-01-01T00:00:00Z'+(i/2)*interval '1 second' FROM generate_series(1,30000) i`,
		`INSERT INTO zasp_red_team_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,receipt_id,actor_id,event_kind,resource_id,event_digest,body,created_at)
 SELECT CASE WHEN i%10=0 THEN $1 ELSE 'pid_79820001-0000-4000-8000-'||lpad((i%10)::text,12,'0') END,$2,$3,'pid_79820006-0000-4000-8000-'||lpad(i::text,12,'0'),'pid_79820007-0000-4000-8000-'||lpad(i::text,12,'0'),'pid_79820008-0000-4000-8000-'||lpad(i::text,12,'0'),$4,'red_team_run_queued','pid_79820009-0000-4000-8000-000000000001',decode(repeat('a',64),'hex'),'{}',timestamptz '2026-01-01T00:00:00Z'+(i/2)*interval '1 second' FROM generate_series(1,30000) i`,
	} {
		if _, err := f.admin.Exec(ctx, statement, a[:4]...); err != nil {
			t.Fatal("scale fixture", err)
		}
	}
	if _, err := f.admin.Exec(ctx, `ANALYZE zasp_admin_audit;ANALYZE zasp_workflow_audit;ANALYZE zasp_red_team_audit`); err != nil {
		t.Fatal(err)
	}
	var count, logicalBytes int64
	if err := f.admin.QueryRow(ctx, `SELECT count(*),sum(octet_length(metadata::text)) FROM zasp_audit_export_public_source_v1`).Scan(&count, &logicalBytes); err != nil || count < 100001 || logicalBytes <= 64*1024*1024 {
		t.Fatal("mixed scale threshold", count, logicalBytes, err)
	}
	t.Logf("owned mixed source rows=%d logical_metadata_bytes=%d", count, logicalBytes)
	for _, tc := range []struct {
		name, filter       string
		afterTime, afterID any
		want               int
	}{
		{"newest", `{}`, nil, nil, 50},
		{"sparse", `{"action":"page.rare"}`, nil, nil, 8},
		{"no-match", `{"action":"absent.action"}`, nil, nil, 0},
		{"failed-is-not-denied", `{"outcome":"failed"}`, nil, nil, 0},
		{"all-five", fmt.Sprintf(`{"actor_id":%q,"action":"page.rare","outcome":"denied","from":"2026-01-01T05:33:20.000000Z","to":"2026-01-01T05:33:20.000001Z"}`, a[3]), nil, nil, 1},
		{"deep", `{"from":"2026-01-01T00:00:00.000000Z","to":"2026-01-01T00:30:00.000000Z"}`, time.Date(2026, 1, 1, 0, 20, 0, 0, time.UTC), "pid_ffffffff-ffff-4fff-8fff-ffffffffffff", 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			callCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			defer stop()
			started := time.Now()
			items, _, raw := auditPublicPageRead(t, callCtx, f, tc.filter, tc.afterTime, tc.afterID, 50)
			elapsed := time.Since(started)
			if elapsed >= 5*time.Second || len(items) != tc.want {
				t.Fatal("owned query budget/result", elapsed, len(items), tc.want)
			}
			t.Logf("registered page elapsed=%s bytes=%d rows=%d", elapsed, len(raw), len(items))
		})
	}
	// Traverse well beyond the former 20-page UI ceiling against an independent
	// persisted ID list. No source writes occur during this live-list traversal.
	rows, err := f.admin.Query(ctx, `SELECT id FROM zasp_admin_audit WHERE organization_id=$1 AND action='page.bulk' ORDER BY occurred_at DESC,id COLLATE "C" DESC`, a[0])
	if err != nil {
		t.Fatal(err)
	}
	var expected []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		expected = append(expected, id)
	}
	rows.Close()
	if rows.Err() != nil || len(expected) <= 2000 {
		t.Fatal("traversal fixture", rows.Err())
	}
	var seen []string
	var afterTime, afterID any
	for page := 0; page < 100; page++ {
		items, more, _ := auditPublicPageRead(t, ctx, f, `{"action":"page.bulk"}`, afterTime, afterID, 100)
		for _, item := range items {
			var id, stamp string
			json.Unmarshal(item["id"], &id)
			json.Unmarshal(item["occurred_at"], &stamp)
			seen = append(seen, id)
			afterID = id
			parsed, err := time.Parse(time.RFC3339Nano, stamp)
			if err != nil {
				t.Fatal(err)
			}
			afterTime = parsed
		}
		if !more {
			break
		}
		if page == 99 {
			t.Fatal("unbounded traversal")
		}
	}
	if strings.Join(seen, "\n") != strings.Join(expected, "\n") {
		t.Fatal("keyset traversal duplicated/skipped original IDs")
	}
	// Explain the actual statement extracted from the installed fixed function,
	// with bound arguments, not a separately optimized stand-in query.
	var definition string
	if err := f.admin.QueryRow(ctx, `SELECT prosrc FROM pg_proc WHERE oid='zasp_audit_export_public_page(text,text,text,text,bytea,text,jsonb,timestamptz,text,integer,text,text)'::regprocedure`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	start := strings.Index(definition, "WITH candidates AS MATERIALIZED (")
	if start < 0 {
		t.Fatal("actual candidate statement not found")
	}
	query := definition[start:]
	end := strings.Index(query, "\n LOOP")
	if end < 0 {
		t.Fatal("actual candidate statement end")
	}
	query = query[:end]
	query = strings.NewReplacer("org_value", "$1::text", "filters_value", "$2::jsonb", "from_value", "$3::timestamptz", "to_value", "$4::timestamptz", "after_time_value", "$5::timestamptz", "after_id_value", "$6::text", "limit_value", "$7::integer").Replace(query)
	planTx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		closeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = planTx.Rollback(closeCtx)
	}()
	if _, err := planTx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
		t.Fatal("plan authority", err)
	}
	var planRole string
	if err := planTx.QueryRow(ctx, `SELECT current_user`).Scan(&planRole); err != nil || planRole != "zasp_discovery_authority" {
		t.Fatal("plan did not use actual function authority", err)
	}
	for _, planFilter := range []string{`{}`, `{"action":"policy.update"}`, `{"action":"test.run.queued"}`} {
		var plan []byte
		if err := planTx.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,VERBOSE,FORMAT JSON) "+query, a[0], planFilter, nil, nil, nil, nil, 50).Scan(&plan); err != nil {
			t.Fatal("actual source plan", err)
		}
		t.Logf("actual page source filter=%s EXPLAIN=%s", planFilter, plan)
		var decoded []map[string]any
		if json.Unmarshal(plan, &decoded) != nil {
			t.Fatal("plan decode")
		}
		bounded := false
		var visit func(map[string]any)
		visit = func(node map[string]any) {
			// A bounded candidate CTE alone is insufficient: a flattened hash join
			// can still construct whole-source composites before matching those IDs.
			if output, ok := node["Output"].([]any); ok {
				for _, value := range output {
					text := value.(string)
					if (strings.Contains(text, ".metadata") || strings.Contains(text, "jsonb_build_object")) && node["Actual Rows"].(float64)*node["Actual Loops"].(float64) > 51 {
						t.Fatal("actual plan constructs metadata before bounded identity fetch", node["Node Type"], node["Actual Rows"], node["Actual Loops"])
					}
				}
			}
			if node["Subplan Name"] == "CTE candidates" {
				if node["Actual Rows"].(float64) > 51 || node["Node Type"] != "Limit" {
					t.Fatal("candidate materialization not count bounded")
				}
				bounded = true
				for _, output := range node["Output"].([]any) {
					if strings.Contains(output.(string), "metadata") || strings.Contains(output.(string), "body") {
						t.Fatal("raw source materialized before count")
					}
				}
			}
			if children, ok := node["Plans"].([]any); ok {
				for _, child := range children {
					visit(child.(map[string]any))
				}
			}
		}
		visit(decoded[0]["Plan"].(map[string]any))
		if !bounded {
			t.Fatal("actual plan omitted materialized candidate bound")
		}
	}
}
