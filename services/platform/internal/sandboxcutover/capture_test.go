package sandboxcutover

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// This wire fixture isolates transport bounds without creating 10,001 owner
// authority batches. The separate PostgreSQL suite exercises the actual query.
type captureRowsFixture struct {
	pgx.Rows
	body      []byte
	remaining int
	err       error
	closed    bool
}

func TestPostgresFenceOperationPreservesEarlierDeadline(t *testing.T) {
	stored, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	caller, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	f := &postgresFence{ctx: stored}
	operation, done, err := f.operation(caller)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	want, _ := caller.Deadline()
	got, ok := operation.Deadline()
	if !ok || !got.Equal(want) {
		t.Fatal("operation exposed a later deadline to downstream SQL", got, want)
	}
}

func (r *captureRowsFixture) Next() bool {
	if r.remaining == 0 {
		return false
	}
	r.remaining--
	return true
}
func (r *captureRowsFixture) Scan(dest ...any) error { *dest[0].(*[]byte) = r.body; return nil }
func (r *captureRowsFixture) Err() error             { return r.err }
func (r *captureRowsFixture) Close()                 { r.closed = true }

type captureQueryFixture struct{ rows *captureRowsFixture }

func (q captureQueryFixture) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return q.rows, nil
}

func captureWireFixture(t *testing.T) []byte {
	t.Helper()
	w := captureWire{Organization: "pid_79510001-0000-4000-8000-000000000001", Workspace: "pid_79510002-0000-4000-8000-000000000002", Environment: "pid_79510003-0000-4000-8000-000000000003", Batch: "pid_79510005-0000-4000-8000-000000000005", Generation: 1, Digest: strings.Repeat("cd", 32), Reference: "s3://zasp-evidence/projected.json", Version: "projected-v1", ProjectVersion: "runtime-projection-v2", CompleteVersion: "runtime-complete-v2", Events: []string{"pid_79510006-0000-4000-8000-000000000006"}, Valid: true}
	id := sha256.Sum256([]byte("zasp.runtime-session-search.occurrence.v1\x00" + w.Organization + "\x00" + w.Workspace + "\x00" + w.Environment + "\x00" + w.Batch + "\x001\x00" + w.Events[0]))
	w.Documents = []string{hex.EncodeToString(id[:])}
	body, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestCaptureBoundsRefuseRatherThanAuthorizePrefix(t *testing.T) {
	valid := captureWireFixture(t)
	for _, tc := range []struct {
		name      string
		body      []byte
		rows      int
		streamErr error
		want      bool
	}{
		{"bounded", valid, 1, nil, true},
		{"exact row limit", valid, 10000, nil, true},
		{"row overflow", valid, 10001, nil, false},
		{"server row overflow sentinel", nil, 1, nil, false},
		{"wire row overflow", append(append([]byte{}, valid...), []byte(strings.Repeat(" ", 1<<20))...), 1, nil, false},
		{"total bytes overflow", append(append([]byte{}, valid...), []byte(strings.Repeat(" ", 512<<10))...), 33, nil, false},
		{"stream error after valid prefix", valid, 1, errors.New("connection lost"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := &captureRowsFixture{body: tc.body, remaining: tc.rows, err: tc.streamErr}
			got, err := captureReceipts(context.Background(), captureQueryFixture{rows})
			if (err == nil) != tc.want {
				t.Fatal("capture bound", len(got.Records), err)
			}
			if !rows.closed {
				t.Fatal("capture abandoned row stream")
			}
			if !tc.want && (got.Digest != "" || len(got.Records) != 0) {
				t.Fatal("refusal exposed authorized prefix")
			}
		})
	}
}
