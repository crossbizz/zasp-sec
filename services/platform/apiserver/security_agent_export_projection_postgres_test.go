package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func readExportProjection(f *exportDBFixture, o, w, e, r string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := f.api.QueryRow(f.ctx, `SELECT zasp_production_security_agent_existing_tests_run_context($1,$2,$3,$4,$5,$6)`, o, w, e, r, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw)
	return raw, err
}

func assertExportProjection(t *testing.T, f *exportDBFixture, state string) {
	t.Helper()
	raw, err := readExportProjection(f, f.o, f.w, f.e, exportFixtureRun)
	if err != nil {
		t.Fatalf("registered export action projection: %v", err)
	}
	if strings.Contains(string(raw), "PRIVATE_PROVIDER_VERSION") || strings.Contains(string(raw), "PRIVATE_PACKAGE_BYTES") || strings.Contains(string(raw), "storage_state") {
		t.Fatalf("private export storage facts leaked: %s", raw)
	}
	var envelope struct {
		Actions struct {
			Steps []struct {
				Arguments struct {
					TargetID  string          `json:"target_id"`
					Selection json.RawMessage `json:"evidence_ids"`
				} `json:"arguments"`
				Effect *struct {
					State string `json:"state"`
				} `json:"effect"`
			} `json:"steps"`
		} `json:"action_details"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Actions.Steps) != 1 {
		t.Fatalf("export action envelope: %s", raw)
	}
	s := envelope.Actions.Steps[0]
	var got, want any
	if json.Unmarshal(s.Arguments.Selection, &got) != nil || json.Unmarshal(f.selection, &want) != nil || !reflect.DeepEqual(got, want) || s.Arguments.TargetID != exportFixtureRun {
		t.Fatalf("original ordered export selection changed: %s", raw)
	}
	if state == "" && s.Effect != nil || state != "" && (s.Effect == nil || s.Effect.State != state) {
		t.Fatalf("export effect state wanted %q: %s", state, raw)
	}
	value, err := decodeSecurityAgentRunContextEnvelope(raw, exportFixtureRun)
	if err != nil || len(value.ActionDetails) != 1 {
		t.Fatalf("public export decoder: %v", err)
	}
	a := value.ActionDetails[0]
	verification, source := "pending", "effect_record"
	switch state {
	case "":
		verification, source = "unavailable", "none"
	case "known_failure":
		verification = "failed"
	case "cleanup_pending":
		verification = "inconclusive"
	}
	if a.Verification.State != verification || a.Verification.Source != source || a.Rollback.Support != "not_supported" || a.Rollback.State != "unavailable" || a.Rollback.Verification.State != "unavailable" || a.Rollback.Verification.Source != "none" || a.TTLSeconds != nil || a.ControlExpiresAt != nil {
		t.Fatalf("export claimed unsupported security verification or rollback: %+v", a)
	}
}

func TestSecurityAgentExportProjectionPostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		// Two distinguishable references prove the original array order survives.
		if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_identity_memberships SET role='security_admin' WHERE principal_id=$6; INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body) VALUES($1,$2,$3,$5,$5,$4,$6,'fixture_event',decode(repeat('ac',32),'hex'),'{}')`, pgx.QueryExecModeSimpleProtocol, f.o, f.w, f.e, exportFixtureRun, "pid_8e100021-0000-4000-8000-000000000021", f.actor); err != nil {
			t.Fatal(err)
		}
		f.selection = json.RawMessage(strings.TrimSuffix(string(f.selection), "]") + `,{"source_kind":"run_audit","source_id":"pid_8e100021-0000-4000-8000-000000000021","source_version":1,"association_digest":"sha256:` + strings.Repeat("ac", 32) + `"}]`)
		f.setSelection(t, f.selection)
		assertExportProjection(t, f, "")
		if _, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); err != nil {
			t.Fatal(err)
		}
		assertExportProjection(t, f, "pending")
		var reordered json.RawMessage
		if err := f.owner.QueryRow(f.ctx, `SELECT jsonb_build_array(selection->1,selection->0) FROM zasp_sa_export_links WHERE run_id=$1`, exportFixtureRun).Scan(&reordered); err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_sa_export_links SET selection=$2 WHERE run_id=$1`, exportFixtureRun, reordered); err != nil {
			t.Fatal(err)
		}
		if raw, err := readExportProjection(f, f.o, f.w, f.e, exportFixtureRun); err == nil {
			t.Fatalf("reordered linked selection accepted: %s", raw)
		}
	})
}

func TestSecurityAgentExportProjectionSettledPostgres(t *testing.T) {
	for _, state := range []string{"succeeded", "known_failure", "cleanup_pending"} {
		t.Run(state, func(t *testing.T) {
			runExportDBFixture(t, func(f *exportDBFixture) {
				raw, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease)
				if err != nil {
					t.Fatal(err)
				}
				var dispatched map[string]any
				if json.Unmarshal(raw, &dispatched) != nil {
					t.Fatal(string(raw))
				}
				id := dispatched["export_id"].(string)
				f.capture(t, id)
				cfg := f.owner.Config().Copy()
				cfg.User = "export_source_executor"
				executor, err := pgx.ConnectConfig(f.ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer executor.Close(context.Background())
				call := func(fn string, payload any) {
					t.Helper()
					if err := executor.QueryRow(f.ctx, fmt.Sprintf(`SELECT %s($1,$2,$3,$4,'export-source-worker',$5,1,$6,$7,$8)`, fn), f.o, f.w, f.e, id, strings.Repeat("b", 64), payload, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw); err != nil {
						t.Fatal(err)
					}
				}
				body := []byte("PRIVATE_PACKAGE_BYTES")
				digest := sha256.Sum256(body)
				if state != "known_failure" {
					call("zasp_compliance_export_prepare_artifact", map[string]any{"renderer_revision": "security-agent-evidence-envelope-v1", "reference": id, "bytes_hex": hex.EncodeToString(body), "sha256": hex.EncodeToString(digest[:]), "size": len(body), "format_sizes": map[string]int{"json": 5, "csv": 5, "readable": 5}})
				}
				if state == "succeeded" {
					call("zasp_compliance_export_finish", map[string]any{"reference": id, "version": "PRIVATE_PROVIDER_VERSION", "sha256": hex.EncodeToString(digest[:]), "size": len(body)})
				} else if err = f.api.QueryRow(f.ctx, `SELECT zasp_security_agent_cancel_run($1,$2,$3,$4,$5,'export-projection-cancel',4,'pid_8e100051-0000-4000-8000-000000000051','pid_8e100052-0000-4000-8000-000000000052','pid_8e100053-0000-4000-8000-000000000053')`, f.o, f.w, f.e, exportFixtureRun, f.actor).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				if err = f.worker.QueryRow(f.ctx, `SELECT zasp_sa_export_settlement_claim($1,'export-projection-settle',60,1,$2,$3)`, exportFixtureWorker, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				if err = f.worker.QueryRow(f.ctx, `SELECT zasp_sa_export_settle($1,$2,$3,$4,$5,'export-projection-settle','pid_8e100007-0000-4000-8000-000000000007','pid_8e100008-0000-4000-8000-000000000008',$6,$7)`, f.o, f.w, f.e, exportFixtureRun, exportFixtureWorker, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				assertExportProjection(t, f, state)
				// Historical projection must not recollect the latest source version.
				if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_risk_findings SET version=version+1 WHERE id=$1`, exportFixtureFinding); err != nil {
					t.Fatal(err)
				}
				assertExportProjection(t, f, state)
				if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_effects SET result_digest=decode(repeat('fa',32),'hex') WHERE run_id=$1`, exportFixtureRun); err != nil {
					t.Fatal(err)
				}
				if raw, err = readExportProjection(f, f.o, f.w, f.e, exportFixtureRun); err == nil {
					t.Fatalf("settlement digest drift accepted: %s", raw)
				}
			})
		})
	}
}

func TestSecurityAgentExportProjectionStoppedParentPostgres(t *testing.T) {
	for _, parent := range []string{"contained", "remediated", "inconclusive"} {
		t.Run(parent, func(t *testing.T) {
			runExportDBFixture(t, func(f *exportDBFixture) {
				if _, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); err != nil {
					t.Fatal(err)
				}
				// This is pre-existing parent history, not a security outcome caused
				// by export. The registered settler must preserve it and its version.
				if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_runs SET state=$2,last_error_code='prior_parent_stop' WHERE run_id=$1`, exportFixtureRun, parent); err != nil {
					t.Fatal(err)
				}
				var raw json.RawMessage
				if err := f.worker.QueryRow(f.ctx, `SELECT zasp_sa_export_settlement_claim($1,'export-stopped-projection',60,1,$2,$3)`, exportFixtureWorker, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				if err := f.worker.QueryRow(f.ctx, `SELECT zasp_sa_export_settle($1,$2,$3,$4,$5,'export-stopped-projection','pid_8e100007-0000-4000-8000-000000000007','pid_8e100008-0000-4000-8000-000000000008',$6,$7)`, f.o, f.w, f.e, exportFixtureRun, exportFixtureWorker, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var receipt struct {
					State   string `json:"state"`
					Reason  string `json:"reason"`
					Version int    `json:"run_version"`
				}
				if json.Unmarshal(raw, &receipt) != nil || receipt.State != parent || receipt.Reason != "export_parent_stopped" || receipt.Version != 4 {
					t.Fatalf("settlement changed stopped parent: %s", raw)
				}
				assertExportProjection(t, f, "known_failure")
			})
		})
	}
}

func TestSecurityAgentExportProjectionRefusalsPostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		for _, selection := range []json.RawMessage{json.RawMessage(`[]`), json.RawMessage(strings.Replace(string(f.selection), `"source_kind":`, `"private_locator":"DO_NOT_LEAK","source_kind":`, 1))} {
			f.setSelection(t, selection)
			if raw, err := readExportProjection(f, f.o, f.w, f.e, exportFixtureRun); err == nil {
				t.Fatalf("malformed selection accepted: %s", raw)
			}
		}
		f.setSelection(t, f.selection)
		if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_plans SET plan=jsonb_set(plan,'{steps,0,target_id}',to_jsonb($2::text)) WHERE run_id=$1`, exportFixtureRun, exportFixtureFinding); err != nil {
			t.Fatal(err)
		}
		f.setSelection(t, f.selection)
		if raw, err := readExportProjection(f, f.o, f.w, f.e, exportFixtureRun); err == nil {
			t.Fatalf("foreign parent target accepted: %s", raw)
		}
		if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_plans SET plan=jsonb_set(plan,'{steps,0,target_id}',to_jsonb($1::text)) WHERE run_id=$1`, exportFixtureRun); err != nil {
			t.Fatal(err)
		}
		f.setSelection(t, f.selection)
		if _, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); err != nil {
			t.Fatal(err)
		}
		assertExportProjection(t, f, "pending")
		for i := 0; i < 4; i++ {
			ids := []string{f.o, f.w, f.e, exportFixtureRun}
			ids[i] = "pid_8e100099-0000-4000-8000-000000000099"
			if raw, err := readExportProjection(f, ids[0], ids[1], ids[2], ids[3]); err != pgx.ErrNoRows {
				t.Fatalf("foreign dimension %d exposed projection: %s %v", i, raw, err)
			}
		}
		// Each committed corruption is restored before the next independent check.
		for _, mutation := range []struct{ table, column, sql string }{
			{"zasp_security_agent_effects", "result_digest", "decode(repeat('ae',32),'hex')"},
			{"zasp_sa_export_links", "input_digest", "decode(repeat('ae',32),'hex')"},
			{"zasp_sa_export_links", "selection", `jsonb_set(selection,'{0,source_version}','2')`},
			{"zasp_compliance_export_jobs", "request", `jsonb_set(request,'{selection,0,source_version}','2')`},
		} {
			key := "run_id"
			if mutation.table == "zasp_compliance_export_jobs" {
				key = "agent_run_id"
			}
			var before string
			if err := f.owner.QueryRow(f.ctx, fmt.Sprintf("SELECT %s::text FROM %s WHERE %s=$1", mutation.column, mutation.table, key), exportFixtureRun).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err := f.owner.Exec(f.ctx, fmt.Sprintf("UPDATE %s SET %s=%s WHERE %s=$1", mutation.table, mutation.column, mutation.sql, key), exportFixtureRun); err != nil {
				t.Fatal(err)
			}
			if raw, err := readExportProjection(f, f.o, f.w, f.e, exportFixtureRun); err == nil {
				t.Errorf("%s.%s drift accepted: %s", mutation.table, mutation.column, raw)
			}
			cast := "jsonb"
			if strings.HasSuffix(mutation.column, "digest") {
				cast = "bytea"
			}
			if _, err := f.owner.Exec(f.ctx, fmt.Sprintf("UPDATE %s SET %s=$2::%s WHERE %s=$1", mutation.table, mutation.column, cast, key), exportFixtureRun, before); err != nil {
				t.Fatal(err)
			}
		}
		assertExportProjection(t, f, "pending")
	})
}
