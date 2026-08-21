package identity

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestWebhookVerifierRejectsInvalidSignatureAndMarksReplay(t *testing.T) {
	secret := webhookFixtureSecret()
	verifier, err := NewWebhookVerifier("project-live-platform", secret, func() time.Time { return fixtureNow }, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	body := webhookFixtureBody()
	headers := signWebhookFixture(body, secret, "msg_fixture", fixtureNow)
	event, replay, err := verifier.Verify(body, headers)
	if err != nil || replay || event.EventID != "webhook-event-live-018f85a0-2c17-7ba3-91d1-7f0382dd7c31" || event.Kind() != "scim.member.delete" || event.Details.OrganizationReference != "organization-live-a" {
		t.Fatalf("Verify() = %#v, %v, %v", event, replay, err)
	}
	if _, replay, err := verifier.Verify(body, headers); err != nil || !replay {
		t.Fatalf("replay Verify() = %v, %v", replay, err)
	}
	headers.Signature = "v1," + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, sha256.Size))
	if _, _, err := verifier.Verify(body, headers); err != ErrWebhookVerification {
		t.Fatalf("invalid signature error = %v", err)
	}
}

func TestWebhookVerifierContainsClockPanics(t *testing.T) {
	panics := false
	verifier, err := NewWebhookVerifier("project-live-platform", webhookFixtureSecret(), func() time.Time {
		if panics {
			panic("clock unavailable")
		}
		return fixtureNow
	}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	panics = true
	body := webhookFixtureBody()
	headers := signWebhookFixture(body, webhookFixtureSecret(), "msg_fixture", fixtureNow)
	if _, _, err := verifier.Verify(body, headers); err != ErrWebhookVerification {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestWebhookVerifierRejectsNoncanonicalProviderEnvelopeAuthority(t *testing.T) {
	secret := webhookFixtureSecret()
	verifier, err := NewWebhookVerifier("project-live-platform", secret, func() time.Time { return fixtureNow }, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for index, body := range [][]byte{
		[]byte(`{"action":"DELETE","event_id":"webhook-event-live-018f85a0-2c17-7ba3-91d1-7f0382dd7c31","id":"member-live-a","object_type":"member","organization_id":"organization-live-a","project_id":"project-live-platform","source":"SCIM","timestamp":"2026-08-18T13:00:00Z","vertical":"B2B","workspace_id":"workspace-live-platform"}`),
		[]byte(`{"action":"DELETE","details":{"organization_id":"organization-live-a"},"event_id":"018f85a0-2c17-7ba3-91d1-7f0382dd7c31","id":"member-live-a","object_type":"member","project_id":"project-live-platform","source":"SCIM","timestamp":"2026-08-18T13:00:00Z","vertical":"B2B","workspace_id":"workspace-live-platform"}`),
	} {
		headers := signWebhookFixture(body, secret, "msg_hostile_"+strconv.Itoa(index), fixtureNow)
		if _, _, err := verifier.Verify(body, headers); err != ErrWebhookVerification {
			t.Fatalf("Verify(hostile %d) error = %v", index, err)
		}
	}
}

func TestDeprovisionReconcilerRevokesPrincipalAndGrantsAndAuditsOnce(t *testing.T) {
	store := newFixtureStore(t)
	organization, principal, workspace, environments := seedHTTPIdentity(t, store)
	grant, err := NewWorkspaceGrant(fixtureID(t, 700), organization.ID(), principal.ID(), workspace.ID(), environments[0].ID(), RoleSecurityEngineer)
	if err != nil || store.CreateGrant(context.Background(), organization.ID(), grant) != nil {
		t.Fatal(err)
	}
	auditor := &recordingDeprovisionAuditor{}
	verifier, _ := NewWebhookVerifier("project-live-platform", webhookFixtureSecret(), func() time.Time { return fixtureNow }, 5*time.Minute)
	reconciler, err := NewDeprovisionReconciler(store, verifier, auditor)
	if err != nil {
		t.Fatal(err)
	}
	body := webhookFixtureBody()
	headers := signWebhookFixture(body, webhookFixtureSecret(), "msg_fixture", fixtureNow)
	processed, err := reconciler.Handle(context.Background(), body, headers)
	if err != nil || !processed {
		t.Fatalf("Handle() = %v, %v", processed, err)
	}
	if grants, err := store.ListGrants(context.Background(), organization.ID(), principal.ID()); err != nil || len(grants) != 0 {
		t.Fatalf("grants after deprovision = %#v, %v", grants, err)
	}
	principals, err := store.ListPrincipals(context.Background(), organization.ID())
	if err != nil || len(principals) != 1 || principals[0].Active() {
		t.Fatalf("principals after deprovision = %#v, %v", principals, err)
	}
	if len(auditor.events) != 1 || auditor.events[0].PrincipalID != principal.ID() || len(auditor.events[0].GrantIDs) != 1 {
		t.Fatalf("audit events = %#v", auditor.events)
	}
	if processed, err := reconciler.Handle(context.Background(), body, headers); err != nil || processed || len(auditor.events) != 1 {
		t.Fatalf("replay Handle() = %v, %v events=%d", processed, err, len(auditor.events))
	}
}

func TestDeprovisionAuditRunsOutsideTheStoreLock(t *testing.T) {
	store := newFixtureStore(t)
	organization, _, _, _ := seedHTTPIdentity(t, store)
	verifier, _ := NewWebhookVerifier("project-live-platform", webhookFixtureSecret(), func() time.Time { return fixtureNow }, 5*time.Minute)
	auditor := reentrantDeprovisionAuditor{store: store, organizationID: organization.ID()}
	reconciler, _ := NewDeprovisionReconciler(store, verifier, auditor)
	result := make(chan error, 1)
	go func() {
		body := webhookFixtureBody()
		_, err := reconciler.Handle(context.Background(), body,
			signWebhookFixture(body, webhookFixtureSecret(), "msg_fixture", fixtureNow))
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("deprovision audit deadlocked under the store lock")
	}
}

func TestWebhookHTTPHandlerExposesTheExactSignedInternalEndpoint(t *testing.T) {
	store := newFixtureStore(t)
	seedHTTPIdentity(t, store)
	auditor := &recordingDeprovisionAuditor{}
	verifier, _ := NewWebhookVerifier("project-live-platform", webhookFixtureSecret(), func() time.Time { return fixtureNow }, 5*time.Minute)
	reconciler, _ := NewDeprovisionReconciler(store, verifier, auditor)
	handler, err := NewWebhookHTTPHandler(reconciler)
	if err != nil {
		t.Fatal(err)
	}
	body := webhookFixtureBody()
	headers := signWebhookFixture(body, webhookFixtureSecret(), "msg_fixture", fixtureNow)
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/stytch/webhooks", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Svix-Id", headers.MessageID)
	request.Header.Set("Svix-Timestamp", headers.Timestamp)
	request.Header.Set("Svix-Signature", headers.Signature)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || recorder.Body.String() != "{\"processed\":true}\n" {
		t.Fatalf("webhook response = %d %q", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/internal/v1/stytch/webhooks", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Svix-Id", headers.MessageID)
	request.Header.Set("Svix-Timestamp", headers.Timestamp)
	request.Header.Set("Svix-Signature", headers.Signature)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || recorder.Body.String() != "{\"processed\":false}\n" {
		t.Fatalf("webhook replay response = %d %q", recorder.Code, recorder.Body.String())
	}
}

type recordingDeprovisionAuditor struct {
	events []DeprovisionAuditEvent
}

func (auditor *recordingDeprovisionAuditor) Record(_ context.Context, event DeprovisionAuditEvent) error {
	auditor.events = append(auditor.events, event)
	return nil
}

type reentrantDeprovisionAuditor struct {
	store          *MemoryStore
	organizationID domain.ProductID
}

func (auditor reentrantDeprovisionAuditor) Record(ctx context.Context, _ DeprovisionAuditEvent) error {
	_, err := auditor.store.ListPrincipals(ctx, auditor.organizationID)
	return err
}

func webhookFixtureSecret() string {
	return "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, sha256.Size))
}

func webhookFixtureBody() []byte {
	return []byte(`{"action":"DELETE","details":{"organization_id":"organization-live-a"},"event_id":"webhook-event-live-018f85a0-2c17-7ba3-91d1-7f0382dd7c31","id":"member-live-a","object_type":"member","project_id":"project-live-platform","source":"SCIM","timestamp":"2026-08-18T13:00:00Z","vertical":"B2B","workspace_id":"workspace-live-platform"}`)
}

func signWebhookFixture(body []byte, secret, messageID string, timestamp time.Time) WebhookHeaders {
	seconds := strconv.FormatInt(timestamp.Unix(), 10)
	key, _ := base64.StdEncoding.DecodeString(secret[len("whsec_"):])
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "%s.%s.", messageID, seconds)
	_, _ = mac.Write(body)
	return WebhookHeaders{MessageID: messageID, Timestamp: seconds, Signature: "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))}
}
