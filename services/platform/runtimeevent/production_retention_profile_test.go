package runtimeevent

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestRetentionRuntimeProfileRoutesWholeOriginalReceipts(t *testing.T) {
	sources := []string{productionPipelineFinishSessionSQL, `SELECT zasp_runtime_finish_sandbox_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, productionPreciseFinishSessionSQL}
	destinations := []string{`SELECT zasp_retention_v1.current_finish_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, `SELECT zasp_retention_v1.current_finish_sandbox_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, `SELECT zasp_retention_v1.current_finish_precise_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`}
	for i, q := range sources {
		t.Run(destinations[i], func(t *testing.T) {
			db := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":true}`), json.RawMessage(`{"receipt":"complete"}`)}}
			repo, err := NewPostgresRetentionRuntimePipelineRepository(db, ProductionPipelineAuthorityCoordinator, migrations.RetentionAuditProfileChecksum())
			if err != nil {
				t.Fatal(err)
			}
			args := []any{"org", "ws", "env", "batch", int64(4), "original-worker", "original-token", 3, []byte("original-input"), "runtime-complete-v3", "succeeded", []byte("effect"), "ref", "version", []byte("result"), nil, 0, []byte("whole-original-mixed-expired-live-receipt")}
			raw, err := repo.database.QueryJSON(context.Background(), q, args...)
			if err != nil || string(raw) != `{"receipt":"complete"}` {
				t.Fatal("original receipt call lost", err)
			}
			if len(db.statements) != 2 || db.statements[1] != destinations[i] || !reflect.DeepEqual(db.arguments[1], args) {
				t.Fatal("receipt/capability arguments changed or wrong destination")
			}
		})
	}
}

func TestRetentionRuntimeProfileRejectsDriftAndUnlistedQueries(t *testing.T) {
	db := &productionIngestDatabaseStub{responses: []json.RawMessage{json.RawMessage(`{"ready":false}`), json.RawMessage(`{"ready":true}`)}}
	repo, err := NewPostgresRetentionRuntimePipelineRepository(db, ProductionPipelineAuthorityCoordinator, migrations.RetentionAuditProfileChecksum())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.database.QueryJSON(context.Background(), productionPipelineFinishSessionSQL); err == nil || len(db.statements) != 1 {
		t.Fatal("new profile failure fell back")
	}
	if _, err := repo.database.QueryJSON(context.Background(), `SELECT arbitrary_retention_query()`); err == nil || len(db.statements) != 1 {
		t.Fatal("unlisted query reached database")
	}
	if got, err := NewPostgresRetentionRuntimePipelineRepository(db, ProductionPipelineAuthorityCoordinator, ""); got != nil || !errors.Is(err, ErrProductionPipeline) {
		t.Fatal("uncompiled pin admitted")
	}
}
