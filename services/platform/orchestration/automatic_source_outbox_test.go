package orchestration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type automaticOutboxDatabase struct {
	t            *testing.T
	pending      []AutomaticSourceRef
	operations   []string
	acknowledged []string
	malformed    bool
}

func (d *automaticOutboxDatabase) QueryJSON(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	if _, ok := ctx.Deadline(); !ok {
		d.t.Fatal("unbounded database request")
	}
	switch {
	case strings.Contains(sql, "pending_sources"):
		require.Equal(d.t, []any{25}, args)
		if d.malformed {
			return json.RawMessage(`null`), nil
		}
		return json.Marshal(d.pending)
	case strings.Contains(sql, "attempt_source"):
		require.Len(d.t, args, 4)
		d.operations = append(d.operations, "attempt:"+args[3].(string))
		return json.RawMessage(`true`), nil
	case strings.Contains(sql, "ack_source"):
		require.Len(d.t, args, 5)
		d.operations = append(d.operations, "ack:"+args[3].(string))
		d.acknowledged = append(d.acknowledged, args[4].(string))
		return json.RawMessage(`true`), nil
	default:
		d.t.Fatalf("unexpected automatic outbox statement: %s", sql)
		return nil, ErrInvalid
	}
}

type automaticStartFunc func(context.Context, AutomaticSourceRef) error

func (f automaticStartFunc) Start(ctx context.Context, r AutomaticSourceRef) error { return f(ctx, r) }

func TestAutomaticSourceRelayRotatesBeforeStartAndAcknowledgesOnlyAcceptance(t *testing.T) {
	for _, mode := range []string{"new", "already_completed", "ambiguous", "nil_handle", "malformed_pending"} {
		t.Run(mode, func(t *testing.T) {
			db := &automaticOutboxDatabase{t: t, pending: []AutomaticSourceRef{automaticRef()}}
			c := automaticStartFixture(t, false)
			switch mode {
			case "new":
				c.startErr = nil
			case "ambiguous":
				c.startErr = context.DeadlineExceeded
			case "nil_handle":
				c.startErr = nil
				c.nilRun = true
			case "malformed_pending":
				db.malformed = true
			}
			starter, err := NewAutomaticSourceStarter(c, "tests", time.Second)
			require.NoError(t, err)
			relay := AutomaticSourceRelay{Store: AutomaticSourceSQLStore{Database: db, Timeout: time.Second}, Starter: automaticStartFunc(func(ctx context.Context, ref AutomaticSourceRef) error {
				require.Equal(t, []string{"attempt:" + ref.EventID}, db.operations)
				db.operations = append(db.operations, "start:"+ref.EventID)
				return starter.Start(ctx, ref)
			})}
			err = relay.RunOnce(context.Background())
			if mode == "new" || mode == "already_completed" {
				require.NoError(t, err)
				r := automaticRef()
				require.Equal(t, []string{"automatic-source/v1/" + r.OrganizationID + "/" + r.WorkspaceID + "/" + r.EnvironmentID + "/" + r.EventID}, db.acknowledged)
				require.Equal(t, "ack:"+r.EventID, db.operations[2])
			} else {
				require.Error(t, err)
				require.Empty(t, db.acknowledged)
			}
		})
	}
}

func TestAutomaticSourceRelayFailureDoesNotStrandLaterPending(t *testing.T) {
	second := automaticRef()
	second.EventID = "pid_f0773000-0000-4000-8000-000000000002"
	db := &automaticOutboxDatabase{t: t, pending: []AutomaticSourceRef{automaticRef(), second}}
	relay := AutomaticSourceRelay{Store: AutomaticSourceSQLStore{Database: db, Timeout: time.Second}, Starter: automaticStartFunc(func(_ context.Context, r AutomaticSourceRef) error {
		db.operations = append(db.operations, "start:"+r.EventID)
		if r.EventID == automaticRef().EventID {
			return ErrUnavailable
		}
		return nil
	})}
	require.Error(t, relay.RunOnce(context.Background()))
	require.Equal(t, []string{"attempt:" + automaticRef().EventID, "start:" + automaticRef().EventID, "attempt:" + second.EventID, "start:" + second.EventID, "ack:" + second.EventID}, db.operations)
	require.Len(t, db.acknowledged, 1)
}
