package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type callbackRecoveryBoundaryFixture struct {
	page           json.RawMessage
	calls          []connectorCallbackRecoveryOperation
	deleted        []string
	deleteErr      error
	beforeErr      error
	settleErr      error
	cancelOnDelete context.CancelFunc
	beforeHook     func(context.Context)
	deleteHook     func(context.Context)
	settleHook     func(context.Context)
}

func (f *callbackRecoveryBoundaryFixture) invokeCallbackRecovery(ctx context.Context, op connectorCallbackRecoveryOperation, q, proof json.RawMessage) (json.RawMessage, error) {
	f.calls = append(f.calls, op)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	switch op {
	case callbackRecoveryClaim:
		return f.page, nil
	case callbackRecoveryBefore:
		if f.beforeHook != nil {
			f.beforeHook(ctx)
		}
		if len(proof) == 0 {
			return nil, errors.New("missing proof")
		}
		return json.RawMessage(`{"valid":true}`), f.beforeErr
	case callbackRecoverySettle:
		if f.settleHook != nil {
			f.settleHook(ctx)
		}
		return json.RawMessage(`{"settled":true}`), f.settleErr
	}
	return nil, errors.New("unknown operation")
}
func (f *callbackRecoveryBoundaryFixture) Delete(ctx context.Context, ref string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	f.deleted = append(f.deleted, ref)
	if f.deleteHook != nil {
		f.deleteHook(ctx)
	}
	if f.cancelOnDelete != nil {
		f.cancelOnDelete()
	}
	return f.deleteErr
}
func callbackRecoveryFixture(t *testing.T) (*callbackRecoveryBoundaryFixture, connectorCallbackRecoveryItem) {
	t.Helper()
	id := fixtureRequestIdentity(t)
	item := connectorCallbackRecoveryItem{OrganizationID: id.Scope.OrganizationID().String(), WorkspaceID: id.Scope.WorkspaceID().String(), EnvironmentID: id.Scope.EnvironmentID().String(), AttemptID: "pid_70000002-0000-4000-8000-000000000002", IntegrationID: "pid_70000001-0000-4000-8000-000000000001", AuthorizeEffectID: "pid_70000003-0000-4000-8000-000000000003", CleanupEffectID: "pid_70000004-0000-4000-8000-000000000004", PKCEReference: "ref:oauth/pkce/callback-recovery", LeaseOwner: "callback-worker", LeaseToken: strings.Repeat("b", 64), LeaseExpiresAt: time.Now().Add(10 * time.Second).UTC(), Phase: "consumed", CapturedProof: json.RawMessage(`{"body":"b3BhcXVlLW5hdGl2ZS1ib2R5","version":"` + strings.Repeat("a", 64) + `","mac":"` + strings.Repeat("c", 64) + `"}`)}
	f := &callbackRecoveryBoundaryFixture{}
	setCallbackRecoveryPage(t, f, item)
	return f, item
}
func setCallbackRecoveryPage(t *testing.T, f *callbackRecoveryBoundaryFixture, item connectorCallbackRecoveryItem) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"items": []connectorCallbackRecoveryItem{item}})
	if err != nil {
		t.Fatal(err)
	}
	f.page = raw
}

// These tests exercise application dispatch and untrusted response boundaries.
// The fake executor does not authenticate native SQL receipts or prove restart safety.
func TestConnectorCallbackRecoveryApplicationBoundaries(t *testing.T) {
	t.Run("delete exact captured verifier then settle", func(t *testing.T) {
		f, item := callbackRecoveryFixture(t)
		n, err := runConnectorCallbackRecovery(context.Background(), f, f, item.LeaseOwner, 10, 1)
		if err != nil || n != 1 || len(f.deleted) != 1 || f.deleted[0] != item.PKCEReference || len(f.calls) != 3 || f.calls[1] != callbackRecoveryBefore || f.calls[2] != callbackRecoverySettle {
			t.Fatalf("captured cleanup did not settle: count=%d error=%v calls=%v deletes=%v", n, err, f.calls, f.deleted)
		}
	})
	t.Run("failed deletion retains recovery", func(t *testing.T) {
		f, item := callbackRecoveryFixture(t)
		f.deleteErr = errors.New("delete unavailable")
		n, err := runConnectorCallbackRecovery(context.Background(), f, f, item.LeaseOwner, 10, 1)
		if err == nil || n != 0 || len(f.deleted) != 1 || len(f.calls) != 2 {
			t.Fatalf("failed deletion advanced settlement: %d %v %v", n, err, f.calls)
		}
	})
	t.Run("already settled secret skips deletion", func(t *testing.T) {
		f, item := callbackRecoveryFixture(t)
		item.Phase = "secret_settled"
		item.SecretSettled = true
		setCallbackRecoveryPage(t, f, item)
		n, err := runConnectorCallbackRecovery(context.Background(), f, f, item.LeaseOwner, 10, 1)
		if err != nil || n != 1 || len(f.deleted) != 0 || len(f.calls) != 3 {
			t.Fatalf("settled secret was accessed: %d %v %v", n, err, f.deleted)
		}
	})
	t.Run("before denial stops external access", func(t *testing.T) {
		f, item := callbackRecoveryFixture(t)
		f.beforeErr = ErrAuthorizationDenied
		n, err := runConnectorCallbackRecovery(context.Background(), f, f, item.LeaseOwner, 10, 1)
		if err == nil || n != 0 || len(f.deleted) != 0 || len(f.calls) != 2 {
			t.Fatalf("denied compensation advanced: %d %v %v", n, err, f.calls)
		}
	})
	t.Run("cancellation after confirmed deletion permits bounded settlement", func(t *testing.T) {
		f, item := callbackRecoveryFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.cancelOnDelete = cancel
		f.deleteHook = func(ctx context.Context) {
			d, ok := ctx.Deadline()
			if !ok || d.After(item.LeaseExpiresAt.Add(-2*time.Second)) {
				t.Error("delete consumed settlement reserve")
			}
		}
		f.settleHook = func(ctx context.Context) {
			d, ok := ctx.Deadline()
			if ctx.Err() != nil || !ok || d.After(item.LeaseExpiresAt.Add(-100*time.Millisecond)) {
				t.Error("settlement context lost lease fence")
			}
		}
		n, err := runConnectorCallbackRecovery(ctx, f, f, item.LeaseOwner, 10, 1)
		if err != nil || n != 1 {
			t.Fatalf("confirmed cleanup lost settlement: %d %v", n, err)
		}
	})
	t.Run("cancelled before claim refuses", func(t *testing.T) {
		f, item := callbackRecoveryFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		n, err := runConnectorCallbackRecovery(ctx, f, f, item.LeaseOwner, 10, 1)
		if err == nil || n != 0 || len(f.calls) != 0 {
			t.Fatal("cancelled request claimed work")
		}
	})
	for _, mutation := range []struct {
		name   string
		change func(*connectorCallbackRecoveryItem)
	}{
		{"invalid scope", func(i *connectorCallbackRecoveryItem) { i.OrganizationID = "invalid" }},
		{"provider phase", func(i *connectorCallbackRecoveryItem) { i.Phase = "provider" }},
		{"mismatched secret phase", func(i *connectorCallbackRecoveryItem) { i.SecretSettled = true }},
		{"expired lease", func(i *connectorCallbackRecoveryItem) { i.LeaseExpiresAt = time.Now().Add(-time.Second) }},
		{"insufficient settlement reserve", func(i *connectorCallbackRecoveryItem) { i.LeaseExpiresAt = time.Now().Add(time.Second) }},
		{"wrong owner", func(i *connectorCallbackRecoveryItem) { i.LeaseOwner = "different-owner" }},
		{"same effects", func(i *connectorCallbackRecoveryItem) { i.CleanupEffectID = i.AuthorizeEffectID }},
		{"invalid proof", func(i *connectorCallbackRecoveryItem) {
			i.CapturedProof = json.RawMessage(`{"body":"x","version":"v","mac":"invalid"}`)
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			f, item := callbackRecoveryFixture(t)
			mutation.change(&item)
			setCallbackRecoveryPage(t, f, item)
			n, err := runConnectorCallbackRecovery(context.Background(), f, f, "callback-worker", 10, 1)
			if err == nil || n != 0 || len(f.calls) != 1 || len(f.deleted) != 0 {
				t.Fatalf("malformed recovery accessed external resource: %d %v %v", n, err, f.calls)
			}
		})
	}
	t.Run("unknown field invalidates entire page before side effects", func(t *testing.T) {
		f, item := callbackRecoveryFixture(t)
		var page map[string]any
		_ = json.Unmarshal(f.page, &page)
		page["grant_forward"] = true
		f.page, _ = json.Marshal(page)
		n, err := runConnectorCallbackRecovery(context.Background(), f, f, item.LeaseOwner, 10, 1)
		if err == nil || n != 0 || len(f.calls) != 1 || len(f.deleted) != 0 {
			t.Fatal("unknown response field admitted")
		}
	})
	t.Run("duplicate or invalid later item refuses entire page", func(t *testing.T) {
		for _, duplicate := range []bool{true, false} {
			f, item := callbackRecoveryFixture(t)
			second := item
			if !duplicate {
				second.AttemptID = "pid_70000005-0000-4000-8000-000000000005"
				second.Phase = "provider"
			}
			f.page, _ = json.Marshal(map[string]any{"items": []connectorCallbackRecoveryItem{item, second}})
			n, err := runConnectorCallbackRecovery(context.Background(), f, f, item.LeaseOwner, 10, 2)
			if err == nil || n != 0 || len(f.calls) != 1 || len(f.deleted) != 0 {
				t.Fatalf("bad later item partially admitted: %d %v %v", n, err, f.calls)
			}
		}
	})
	t.Run("settlement failure preserves completed count", func(t *testing.T) {
		f, item := callbackRecoveryFixture(t)
		f.settleErr = errors.New("commit outcome unknown")
		n, err := runConnectorCallbackRecovery(context.Background(), f, f, item.LeaseOwner, 10, 1)
		if err == nil || n != 0 || len(f.deleted) != 1 || len(f.calls) != 3 {
			t.Fatalf("ambiguous settlement fabricated success: %d %v", n, err)
		}
	})

	t.Run("all admitted preprovider phases finish only exact compensation", func(t *testing.T) {
		for _, phase := range []string{"consumed", "secret", "rejection_secret", "secret_settled", "rejection_secret_settled"} {
			f, item := callbackRecoveryFixture(t)
			item.Phase = phase
			item.SecretSettled = strings.HasSuffix(phase, "_settled")
			setCallbackRecoveryPage(t, f, item)
			n, err := runConnectorCallbackRecovery(context.Background(), f, f, item.LeaseOwner, 10, 1)
			expectedDeletes := 1
			if item.SecretSettled {
				expectedDeletes = 0
			}
			if err != nil || n != 1 || len(f.deleted) != expectedDeletes || len(f.calls) != 3 {
				t.Fatalf("phase %s failed: %d %v", phase, n, err)
			}
		}
	})
	t.Run("closed wire rejects aliases missing null duplicate and extra proof keys", func(t *testing.T) {
		for _, kind := range []string{"alias", "missing", "null", "duplicate", "proof_extra", "wrong_reference", "uppercase_token"} {
			f, item := callbackRecoveryFixture(t)
			switch kind {
			case "alias":
				f.page = json.RawMessage(strings.Replace(string(f.page), `"organization_id":`, `"Organization_ID":`, 1))
			case "missing":
				var p map[string][]map[string]any
				_ = json.Unmarshal(f.page, &p)
				delete(p["items"][0], "secret_settled")
				f.page, _ = json.Marshal(p)
			case "null":
				f.page = json.RawMessage(strings.Replace(string(f.page), `"secret_settled":false`, `"secret_settled":null`, 1))
			case "duplicate":
				f.page = json.RawMessage(strings.Replace(string(f.page), `"secret_settled":false`, `"secret_settled":true,"secret_settled":false`, 1))
			case "proof_extra":
				item.CapturedProof = json.RawMessage(strings.TrimSuffix(string(item.CapturedProof), "}") + `,"grant_forward":true}`)
				setCallbackRecoveryPage(t, f, item)
			case "wrong_reference":
				item.PKCEReference = "ref:other/captured-secret"
				setCallbackRecoveryPage(t, f, item)
			case "uppercase_token":
				item.LeaseToken = strings.ToUpper(item.LeaseToken)
				setCallbackRecoveryPage(t, f, item)
			}
			n, err := runConnectorCallbackRecovery(context.Background(), f, f, item.LeaseOwner, 10, 1)
			if err == nil || n != 0 || len(f.calls) != 1 || len(f.deleted) != 0 {
				t.Fatalf("%s admitted malformed authority", kind)
			}
		}
	})

}
