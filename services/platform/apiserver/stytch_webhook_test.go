package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
)

type stytchWebhookRepositoryStub struct {
	calls     int
	event     platformidentity.WebhookEvent
	digest    []byte
	auditID   string
	processed bool
	err       error
}

func (repository *stytchWebhookRepositoryStub) ReconcileStytchWebhook(_ context.Context, event platformidentity.WebhookEvent, digest []byte, auditID string) (bool, error) {
	repository.calls++
	repository.event = event
	repository.digest = append([]byte(nil), digest...)
	repository.auditID = auditID
	return repository.processed, repository.err
}

func TestProductionStytchWebhookVerifiesTenantAndReplaysDurably(t *testing.T) {
	now := time.Date(2026, 8, 21, 16, 0, 0, 0, time.UTC)
	secret := "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, sha256.Size))
	repository := &stytchWebhookRepositoryStub{processed: true}
	handler, err := newProductionStytchWebhookHandler(repository, "project-live-platform", secret, func() time.Time { return now }, func() (string, error) { return "pid_79000030-0000-4000-8000-000000000030", nil })
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"action":"DELETE","details":{"organization_id":"organization-tenant-a"},"event_id":"webhook-event-live-018f85a0-2c17-7ba3-91d1-7f0382dd7c31","id":"member-live-a","object_type":"member","project_id":"project-live-platform","source":"SCIM","timestamp":"2026-08-21T16:00:00Z","vertical":"B2B","workspace_id":"workspace-live-platform"}`)
	request := signedStytchWebhookRequest(body, secret, now)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	wantDigest := sha256.Sum256(body)
	if response.Code != http.StatusAccepted || response.Body.String() != "{\"processed\":true}\n" || repository.calls != 1 || repository.event.ObjectID != "member-live-a" || !hmac.Equal(repository.digest, wantDigest[:]) || repository.auditID != "pid_79000030-0000-4000-8000-000000000030" {
		t.Fatalf("webhook response=%d/%q repository=%#v", response.Code, response.Body.String(), repository)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, signedStytchWebhookRequest(body, secret, now))
	if response.Code != http.StatusAccepted || response.Body.String() != "{\"processed\":false}\n" || repository.calls != 1 {
		t.Fatalf("replay response=%d/%q calls=%d", response.Code, response.Body.String(), repository.calls)
	}
	unsupported := []byte(`{"action":"UPDATE","details":{"organization_id":"organization-tenant-a"},"event_id":"webhook-event-live-018f85a0-2c17-7ba3-91d1-7f0382dd7c33","id":"member-live-a","member":{"member_id":"member-live-a","organization_id":"organization-tenant-a","status":"active"},"object_type":"member","project_id":"project-live-platform","source":"SCIM","timestamp":"2026-08-21T16:00:00Z","vertical":"B2B","workspace_id":"workspace-live-platform"}`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, signedStytchWebhookRequest(unsupported, secret, now))
	if response.Code != http.StatusAccepted || response.Body.String() != "{\"processed\":false}\n" || repository.calls != 1 {
		t.Fatalf("unsupported response=%d/%q calls=%d", response.Code, response.Body.String(), repository.calls)
	}
}

func TestProductionStytchWebhookReleasesMemoryReplayAfterDatabaseFailure(t *testing.T) {
	now := time.Date(2026, 8, 21, 16, 0, 0, 0, time.UTC)
	secret := "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, sha256.Size))
	repository := &stytchWebhookRepositoryStub{err: errors.New("database unavailable")}
	handler, err := newProductionStytchWebhookHandler(repository, "project-live-platform", secret, func() time.Time { return now }, func() (string, error) { return "pid_79000031-0000-4000-8000-000000000031", nil })
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"action":"DELETE","details":{"organization_id":"organization-tenant-a"},"event_id":"webhook-event-live-018f85a0-2c17-7ba3-91d1-7f0382dd7c32","id":"member-live-a","object_type":"member","project_id":"project-live-platform","source":"SCIM","timestamp":"2026-08-21T16:00:00Z","vertical":"B2B","workspace_id":"workspace-live-platform"}`)
	for attempt := 0; attempt < 2; attempt++ {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, signedStytchWebhookRequest(body, secret, now))
		if response.Code != http.StatusServiceUnavailable || response.Body.String() != "{\"code\":\"webhook_unavailable\"}\n" || response.Header().Get("Retry-After") != "5" {
			t.Fatalf("attempt %d response=%d/%q", attempt, response.Code, response.Body.String())
		}
	}
	if repository.calls != 2 {
		t.Fatalf("database retries=%d", repository.calls)
	}
}

func signedStytchWebhookRequest(body []byte, secret string, now time.Time) *http.Request {
	messageID := "msg_production_fixture"
	timestamp := strconv.FormatInt(now.Unix(), 10)
	key, _ := base64.StdEncoding.DecodeString(secret[len("whsec_"):])
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(messageID + "." + timestamp + "."))
	_, _ = mac.Write(body)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/stytch", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Svix-Id", messageID)
	request.Header.Set("Svix-Timestamp", timestamp)
	request.Header.Set("Svix-Signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return request
}
