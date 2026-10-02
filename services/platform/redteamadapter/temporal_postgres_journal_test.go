package redteamadapter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type temporalBoundDatabase struct {
	t        *testing.T
	latest   context.Context
	response json.RawMessage
}

func (d *temporalBoundDatabase) QueryJSON(ctx context.Context, _ string, _ ...any) (json.RawMessage, error) {
	d.latest = ctx
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 10*time.Second || ctx.Err() != nil {
		d.t.Error("adapter SQL call lacks a live finite bound")
	}
	return d.response, nil
}

func TestTemporalJournalBoundsEveryDatabaseCall(t *testing.T) {
	r := journalRequestFixture(t)
	r.LeaseToken, r.EffectKey = "", strings.Repeat("b", 64)
	resolution := TargetResolution{Scope: r.Invocation.Scope, RunID: r.Invocation.RunID, EffectKey: r.EffectKey, TargetID: testTargetID, TargetKind: "agent_endpoint", Category: "prompt_injection"}
	for _, op := range []string{"ready", "resolve", "start", "complete", "standalone"} {
		t.Run(op, func(t *testing.T) {
			db := &temporalBoundDatabase{t: t}
			j, _ := NewTemporalPostgresJournal(db, strings.Repeat("d", 64), strings.Repeat("e", 64))
			var err error
			switch op {
			case "ready":
				db.response = json.RawMessage("true")
				err = j.Ready(context.Background())
			case "resolve", "standalone":
				db.response, _ = json.Marshal(r.Invocation.Binding)
				if op == "resolve" {
					_, err = j.ResolveTarget(context.Background(), resolution)
				} else {
					resolution.EffectKey, resolution.LeaseToken = "", strings.Repeat("a", 32)
					_, err = j.StandaloneResolver().ResolveTarget(context.Background(), resolution)
				}
			case "start", "complete":
				body := journalReceiptFixture(r, op == "complete")
				db.response = append(append([]byte{}, body[:len(body)-1]...), []byte(`,"effect_key":"`+r.EffectKey+`"}`)...)
				if op == "start" {
					_, err = j.Start(context.Background(), r)
				} else {
					protected := false
					err = j.Complete(context.Background(), r, 1, InvocationObservation{HTTPStatus: 200, ResponseDigest: strings.Repeat("c", 64), Protected: &protected, CredentialVersionDigest: strings.Repeat("d", 64)})
				}
			}
			if err != nil || db.latest == nil || db.latest.Err() != context.Canceled {
				t.Fatal("database bound was not released after operation", err)
			}
		})
	}
}
