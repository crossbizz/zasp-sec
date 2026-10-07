package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type findingHumanFamilyDB struct {
	JSONDatabase
	family      json.RawMessage
	familyError error
	mutations   int
	absent      bool
}

func (d *findingHumanFamilyDB) QueryJSON(_ context.Context, sql string, _ ...any) (json.RawMessage, error) {
	switch sql {
	case `SELECT to_jsonb(to_regnamespace('zasp_temporal78') IS NOT NULL)`:
		if d.absent {
			return json.RawMessage(`false`), nil
		}
		return json.RawMessage(`true`), nil
	case `SELECT to_jsonb(zasp_temporal78.api_ready($1,$2))`:
		return json.RawMessage(`true`), nil
	case `SELECT COALESCE((SELECT to_jsonb(zasp_temporal78.family($1,$2,$3,$4,$5))),'null'::jsonb)`:
		return d.family, d.familyError
	case `SELECT COALESCE((SELECT zasp_temporal78.resource($1::jsonb)),'null'::jsonb)`:
		d.mutations++
		if string(d.family) == "false" {
			// The installed native nonfamily branch returns SQL NULL. QueryJSON
			// deliberately reports an empty row as NotFound, not a family hint.
			return nil, ErrRepositoryNotFound
		}
		return json.RawMessage(`{"id":"owned"}`), nil
	default:
		return nil, ErrRepositoryOperation
	}
}

func TestTemporalFindingHumanPositiveFamilyDispatch(t *testing.T) {
	t.Run("historical namespace absence remains unhandled", func(t *testing.T) {
		db := &findingHumanFamilyDB{absent: true}
		_, handled, err := runTemporalFindingHuman(context.Background(), db, orderedPublicIdentity(), SecurityAgentRunRequest{DefinitionID: "pid_f0807400-0000-4000-8000-000000000099"})
		if handled || err != nil || db.mutations != 0 {
			t.Fatalf("handled=%t error=%v mutations=%d", handled, err, db.mutations)
		}
	})
	for _, tc := range []struct {
		name                   string
		family                 json.RawMessage
		failure                error
		wantHandled, wantError bool
		mutations              int
	}{
		{"test family skips finding mutation", json.RawMessage(`false`), nil, false, false, 0},
		{"finding family consumes finding mutation", json.RawMessage(`true`), nil, true, false, 1},
		{"denied source refuses", nil, ErrRepositoryOperation, false, true, 0},
		{"not found is not nonfamily", nil, ErrRepositoryNotFound, false, true, 0},
		{"null is not false", json.RawMessage(`null`), nil, false, true, 0},
		{"malformed is not false", json.RawMessage(`{`), nil, false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &findingHumanFamilyDB{family: tc.family, familyError: tc.failure}
			_, handled, err := runTemporalFindingHuman(context.Background(), db, orderedPublicIdentity(), SecurityAgentRunRequest{DefinitionID: "pid_f0807400-0000-4000-8000-000000000099"})
			if handled != tc.wantHandled || (err != nil) != tc.wantError || db.mutations != tc.mutations || tc.failure != nil && !errors.Is(err, tc.failure) {
				t.Fatalf("handled=%t error=%v mutations=%d", handled, err, db.mutations)
			}
		})
	}
}
