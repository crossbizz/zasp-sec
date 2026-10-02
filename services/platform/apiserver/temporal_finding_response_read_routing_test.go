package apiserver

import (
	"context"
	"encoding/json"
	"testing"
)

type findingReadBoundaryDB struct {
	JSONDatabase
	response json.RawMessage
	err      error
	calls    int
}

func (d *findingReadBoundaryDB) QueryJSON(_ context.Context, _ string, _ ...any) (json.RawMessage, error) {
	d.calls++
	if d.calls <= 2 {
		return json.RawMessage("true"), nil
	}
	return d.response, d.err
}
func TestTemporalFindingResponseReadBoundary(t *testing.T) {
	for _, tc := range []struct {
		name            string
		raw             json.RawMessage
		failure         error
		handled, failed bool
	}{
		{"explicit nonowner", json.RawMessage("null"), nil, false, false},
		{"empty is unavailable", nil, nil, true, true},
		{"invalid JSON", json.RawMessage("{"), nil, true, true},
		{"denied never downgrades", nil, ErrRepositoryOperation, true, true},
		{"proof mismatch never downgrades", nil, ErrRepositoryConflict, true, true},
		{"valid envelope handled", json.RawMessage(`{"detail":{}}`), nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &findingReadBoundaryDB{response: tc.raw, err: tc.failure}
			_, handled, err := queryTemporalFindingResponse(context.Background(), d, `SELECT zasp_temporal78.run_context($1,$2,$3,$4)`)
			if handled != tc.handled || (err != nil) != tc.failed || d.calls != 3 {
				t.Fatalf("handled=%t failed=%t calls=%d", handled, err != nil, d.calls)
			}
		})
	}
}
