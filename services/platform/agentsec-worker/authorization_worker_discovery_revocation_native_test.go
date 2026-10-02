package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func discovery72BoundaryRevocation(t *testing.T, ctx context.Context, owner *pgx.Conn, product *temporalDiscoveryProduct, provider *discoveryNativeProvider, start orchestration.DiscoveryStart, deadline time.Time, mode string, revoke, outage func(), counts func() (int32, int, int)) {
	t.Helper()
	called := false
	mutate := func() {
		if called {
			t.Fatal("provider retried after authority mutation")
		}
		called = true
		revoke()
	}
	if mode == "partial-revoke" {
		provider.partial = true
		provider.afterSend = mutate
	} else if mode == "lost-response" {
		provider.lostResponse = true
		provider.afterSend = mutate
	} else {
		provider.beforeSend = mutate
	}
	command := orchestration.DiscoveryPageCommand{Start: start, Deadline: deadline}
	page, err := product.CollectDiscoveryPage(ctx, command)
	sends, credentials, checks := counts()
	if err != nil || !called || credentials != 1 {
		t.Fatal("real guarded collection did not reach selected boundary", mode, err)
	}
	if mode == "partial-revoke" {
		if page.Outcome != "partial" || page.CheckpointVersion != 1 || page.ReceiptDigest == "" || sends != 1 {
			t.Fatal("admitted partial page did not settle after revoke", page, sends)
		}
	} else if mode == "per-send-revoke" {
		if page.Outcome != "revoked" || sends != 0 || page.CheckpointVersion != 0 || page.ReceiptDigest == "" {
			t.Fatal("per-send revoke escaped transport or lost its denial receipt", page, sends)
		}
	} else if page.Outcome != "outcome_unknown" || sends != 1 || page.ReceiptDigest == "" {
		t.Fatal("lost response invented a safe outcome", page, sends)
	}
	outage()
	replay, err := product.CollectDiscoveryPage(ctx, command)
	if err != nil || replay != page {
		t.Fatal("captured page replay after revoke/outage", err)
	}
	if afterSends, afterCredentials, afterChecks := counts(); afterSends != sends || afterCredentials != credentials || afterChecks != checks {
		t.Fatal("captured replay performed fresh IO")
	}
	if mode == "partial-revoke" {
		command.ExpectedCheckpointVersion = page.CheckpointVersion
		command.ExpectedCheckpointDigest = page.ReceiptDigest
		if _, err = product.CollectDiscoveryPage(ctx, command); !errors.Is(err, authorization.ErrDenied) {
			t.Fatal("next partial page escaped revoked authority", err)
		}
		// Match DiscoveryWorkflow's failed-next-page path. A page receipt is
		// not a committed snapshot receipt and cannot become a final receipt.
		settlement, err := product.ReconcileDiscoveryOutcome(ctx, orchestration.DiscoveryReconcile{Start: start, Deadline: deadline, Reason: "activity_failed"})
		if err != nil || settlement.Outcome != "incomplete" || settlement.ReceiptDigest != "" {
			t.Fatal("captured partial reconciliation", settlement, err)
		}
		if err = product.FinishDiscovery(ctx, orchestration.DiscoveryFinish{Start: start, Outcome: "incomplete"}); err != nil {
			t.Fatal("captured partial settlement replay", err)
		}
		var settled bool
		if err = owner.QueryRow(ctx, `SELECT state='incomplete' AND checkpoint_version=1 AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.active_owners($2) x WHERE x.job_id=$1) FROM zasp_temporal72.runs WHERE job_id=$1`, start.Ref.RunID, start.Ref.OrganizationID).Scan(&settled); err != nil || !settled {
			t.Fatal("positive partial receipt did not release settled ownership", err)
		}
	} else if mode == "lost-response" {
		var held bool
		if err = owner.QueryRow(ctx, `SELECT state='outcome_unknown' AND EXISTS(SELECT 1 FROM zasp_temporal72.active_owners($2) x WHERE x.job_id=$1) FROM zasp_temporal72.runs WHERE job_id=$1`, start.Ref.RunID, start.Ref.OrganizationID).Scan(&held); err != nil || !held {
			t.Fatal("unknown provider debt was released", err)
		}
	} else {
		var denied bool
		if err = owner.QueryRow(ctx, `SELECT state='revoked' AND checkpoint_version=0 AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.active_owners($2) x WHERE x.job_id=$1) FROM zasp_temporal72.runs WHERE job_id=$1`, start.Ref.RunID, start.Ref.OrganizationID).Scan(&denied); err != nil || !denied {
			t.Fatal("pre-send denial invented unresolved ownership", err)
		}
	}
	if afterSends, afterCredentials, _ := counts(); afterSends != sends || afterCredentials != credentials {
		t.Fatal("revoked next work performed IO")
	}
	t.Log("actual guarded boundary and captured recovery passed", mode)
}
