package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const workflowIntegrationID = "pid_42000001-0000-4000-8000-000000000001"
const workflowAuditID = "pid_42000002-0000-4000-8000-000000000002"

type integrationWebhookRepositoryStub struct {
	reservation IntegrationWebhookTestReservation
	status      IntegrationWebhookTestStatus
	reserveErr  error
	completeErr error
	reserves    int
	completes   int
	command     IntegrationWebhookTestCommand
	deliveryID  string
	leaseToken  string
	digest      string
	succeeded   bool
}

func (repository *integrationWebhookRepositoryStub) ReserveIntegrationWebhookTest(_ context.Context, command IntegrationWebhookTestCommand, deliveryID, leaseToken string, _ int) (IntegrationWebhookTestReservation, error) {
	repository.reserves++
	repository.command, repository.deliveryID, repository.leaseToken = command, deliveryID, leaseToken
	return repository.reservation, repository.reserveErr
}

func (repository *integrationWebhookRepositoryStub) CompleteIntegrationWebhookTest(_ context.Context, _ domain.Scope, deliveryID, leaseToken, digest string, succeeded bool) (IntegrationWebhookTestStatus, error) {
	repository.completes++
	repository.deliveryID, repository.leaseToken, repository.digest, repository.succeeded = deliveryID, leaseToken, digest, succeeded
	return repository.status, repository.completeErr
}

func (repository *integrationWebhookRepositoryStub) GetIntegrationWebhookTestStatus(context.Context, domain.Scope, string) (IntegrationWebhookTestStatus, error) {
	return repository.status, nil
}

type integrationWebhookSecretStub struct {
	material  []byte
	calls     int
	reference string
}

func (resolver *integrationWebhookSecretStub) ResolveFindingTicketSecret(_ context.Context, reference string) ([]byte, error) {
	resolver.calls++
	resolver.reference = reference
	return resolver.material, nil
}

type integrationWebhookDeliveryStub struct {
	err          error
	calls        int
	destination  string
	payload      string
	digest       string
	deliveryID   string
	secretAtCall []byte
}

type integrationWebhookTesterStub struct {
	status  IntegrationWebhookTestStatus
	err     error
	tests   int
	reads   int
	command IntegrationWebhookTestCommand
	scope   domain.Scope
	id      string
}

func (tester *integrationWebhookTesterStub) TestIntegrationWebhook(_ context.Context, command IntegrationWebhookTestCommand) (IntegrationWebhookTestStatus, error) {
	tester.tests++
	tester.command = command
	result := tester.status
	result.AuditID = command.AuditID
	return result, tester.err
}

func (tester *integrationWebhookTesterStub) GetIntegrationWebhookTestStatus(_ context.Context, scope domain.Scope, id string) (IntegrationWebhookTestStatus, error) {
	tester.reads++
	tester.scope, tester.id = scope, id
	return tester.status, tester.err
}

func (webhook *integrationWebhookDeliveryStub) DeliverIntegrationWebhookTest(_ context.Context, destination, payload, digest, deliveryID string, secret []byte) error {
	webhook.calls++
	webhook.destination, webhook.payload, webhook.digest, webhook.deliveryID = destination, payload, digest, deliveryID
	webhook.secretAtCall = append([]byte(nil), secret...)
	return webhook.err
}

func TestIntegrationWebhookServiceDeliversOnceCompletesAndClearsSecret(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	deliveryID := "pid_41000001-0000-4000-8000-000000000001"
	leaseToken := strings.Repeat("a", 64)
	payload, digest := integrationWebhookPayloadFixture(t, deliveryID)
	completedAt := time.Now().UTC().Truncate(time.Second)
	secret := []byte("0123456789abcdef0123456789abcdef")
	status := IntegrationWebhookTestStatus{IntegrationID: workflowIntegrationID, DeliveryID: deliveryID, DeliveryStatus: "succeeded", SignatureStatus: "signed", AttemptedAt: completedAt.Add(-time.Second), CompletedAt: &completedAt, AuditID: workflowAuditID}
	repository := &integrationWebhookRepositoryStub{reservation: IntegrationWebhookTestReservation{State: "dispatch", DeliveryID: deliveryID, Payload: payload, PayloadDigest: digest, DestinationURL: "https://hooks.example.test/zasp", SecretReference: "secret_ref_webhook_prod", LeaseExpiresAt: time.Now().Add(15 * time.Second)}, status: status}
	secrets := &integrationWebhookSecretStub{material: secret}
	webhook := &integrationWebhookDeliveryStub{}
	service, err := NewIntegrationWebhookTestService(IntegrationWebhookTestServiceConfig{Repository: repository, Secrets: secrets, Webhook: webhook, LeaseSeconds: 15, NewDeliveryID: func(domain.Scope, string) (string, error) { return deliveryID, nil }, NewLeaseToken: func() (string, error) { return leaseToken, nil }})
	if err != nil {
		t.Fatal(err)
	}
	command := IntegrationWebhookTestCommand{Identity: identity, IntegrationID: workflowIntegrationID, ExpectedVersion: 3, IdempotencyKey: "integration-webhook-test-0001", AuditID: workflowAuditID, CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}

	result, err := service.TestIntegrationWebhook(context.Background(), command)
	if err != nil || !reflect.DeepEqual(result, status) {
		t.Fatalf("test delivery = (%#v, %v)", result, err)
	}
	if repository.reserves != 1 || repository.completes != 1 || secrets.calls != 1 || webhook.calls != 1 || !reflect.DeepEqual(repository.command, command) || repository.digest != digest || !repository.succeeded || secrets.reference != "secret_ref_webhook_prod" || webhook.destination != repository.reservation.DestinationURL || webhook.payload != repository.reservation.Payload || webhook.deliveryID != deliveryID || string(webhook.secretAtCall) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("authority drift repository=%#v secret=%q webhook=%#v", repository, secrets.reference, webhook)
	}
	for index, value := range secret {
		if value != 0 {
			t.Fatalf("secret byte %d was not cleared", index)
		}
	}
}

func TestIntegrationWebhookServiceReplaysTerminalStatusWithoutProviderIO(t *testing.T) {
	completedAt := time.Now().UTC().Truncate(time.Second)
	deliveryID := "pid_41000001-0000-4000-8000-000000000001"
	status := IntegrationWebhookTestStatus{IntegrationID: workflowIntegrationID, DeliveryID: deliveryID, DeliveryStatus: "failed", SignatureStatus: "unconfirmed", AttemptedAt: completedAt.Add(-time.Second), CompletedAt: &completedAt, ErrorCode: "delivery_failed", AuditID: workflowAuditID}
	repository := &integrationWebhookRepositoryStub{reservation: IntegrationWebhookTestReservation{State: "failed", DeliveryID: deliveryID, Status: status}, status: status}
	secrets := &integrationWebhookSecretStub{material: []byte(strings.Repeat("s", 32))}
	webhook := &integrationWebhookDeliveryStub{}
	service, err := NewIntegrationWebhookTestService(IntegrationWebhookTestServiceConfig{Repository: repository, Secrets: secrets, Webhook: webhook, LeaseSeconds: 15, NewDeliveryID: func(domain.Scope, string) (string, error) { return "pid_41000002-0000-4000-8000-000000000002", nil }, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 64), nil }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.TestIntegrationWebhook(context.Background(), IntegrationWebhookTestCommand{Identity: fixtureRequestIdentity(t), IntegrationID: workflowIntegrationID, ExpectedVersion: 3, IdempotencyKey: "integration-webhook-test-0001", AuditID: workflowAuditID, CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"})
	if err != nil || !reflect.DeepEqual(result, status) || repository.completes != 0 || secrets.calls != 0 || webhook.calls != 0 {
		t.Fatalf("replay=(%#v,%v) calls=%d/%d/%d", result, err, repository.completes, secrets.calls, webhook.calls)
	}
}

func TestIntegrationWebhookServicePersistsRedactedFailure(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	deliveryID := "pid_41000001-0000-4000-8000-000000000001"
	failed := IntegrationWebhookTestStatus{IntegrationID: workflowIntegrationID, DeliveryID: deliveryID, DeliveryStatus: "failed", SignatureStatus: "unconfirmed", AttemptedAt: now.Add(-time.Second), CompletedAt: &now, ErrorCode: "delivery_failed", AuditID: workflowAuditID}
	payload, digest := integrationWebhookPayloadFixture(t, deliveryID)
	repository := &integrationWebhookRepositoryStub{reservation: IntegrationWebhookTestReservation{State: "dispatch", DeliveryID: deliveryID, Payload: payload, PayloadDigest: digest, DestinationURL: "https://hooks.example.test/zasp", SecretReference: "secret_ref_webhook_prod", LeaseExpiresAt: time.Now().Add(15 * time.Second)}, status: failed}
	webhook := &integrationWebhookDeliveryStub{err: errors.New("provider secret response")}
	service, err := NewIntegrationWebhookTestService(IntegrationWebhookTestServiceConfig{Repository: repository, Secrets: &integrationWebhookSecretStub{material: []byte(strings.Repeat("s", 32))}, Webhook: webhook, LeaseSeconds: 15, NewDeliveryID: func(domain.Scope, string) (string, error) { return deliveryID, nil }, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 64), nil }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.TestIntegrationWebhook(context.Background(), IntegrationWebhookTestCommand{Identity: fixtureRequestIdentity(t), IntegrationID: workflowIntegrationID, ExpectedVersion: 3, IdempotencyKey: "integration-webhook-test-0001", AuditID: workflowAuditID, CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"})
	if err != nil || !reflect.DeepEqual(result, failed) || repository.completes != 1 || repository.succeeded || strings.Contains(result.ErrorCode, "provider") {
		t.Fatalf("failure=(%#v,%v) complete=%d", result, err, repository.completes)
	}
}

func TestFindingTicketWebhookSignsExactIntegrationTestAndAcceptsOnlyEmptyNoContent(t *testing.T) {
	deliveryID := "pid_41000001-0000-4000-8000-000000000001"
	payload := `{"delivery_id":"` + deliveryID + `","event":"integration.webhook.test","version":1}`
	payloadHash := sha256.Sum256([]byte(payload))
	digest := "sha256:" + hex.EncodeToString(payloadHash[:])
	secret := []byte("0123456789abcdef0123456789abcdef")
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(body)
		if request.Method != http.MethodPost || request.URL.Path != "/zasp" || request.Header.Get("User-Agent") != "zasp-integration-webhook/1" || request.Header.Get("X-Zasp-Event") != "integration.webhook.test" || request.Header.Get("X-Zasp-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) || request.Header.Get("X-Zasp-Delivery-ID") != deliveryID || request.Header.Get("X-Zasp-Payload-Digest") != digest || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || string(body) != payload {
			t.Errorf("request=%s %s headers=%#v body=%s", request.Method, request.URL.String(), request.Header, body)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	webhook, err := newFindingTicketWebhook(server.Client(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := webhook.DeliverIntegrationWebhookTest(context.Background(), server.URL+"/zasp", payload, digest, deliveryID, secret); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowHandlerTestsOnlyStoredWebhookDestinationAndReadsRedactedStatus(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	completedAt := time.Now().UTC().Truncate(time.Second)
	deliveryID := "pid_41000001-0000-4000-8000-000000000001"
	status := IntegrationWebhookTestStatus{IntegrationID: workflowIntegrationID, DeliveryID: deliveryID, DeliveryStatus: "succeeded", SignatureStatus: "signed", AttemptedAt: completedAt.Add(-time.Second), CompletedAt: &completedAt, AuditID: workflowAuditID}
	tester := &integrationWebhookTesterStub{status: status}
	handler, err := newWorkflowHTTPHandler(&workflowRepositoryStub{}, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	handler.webhookTests = tester

	request := workflowRequest(t, identity, testCorrelationID, "testIntegrationWebhook", map[string]string{"id": workflowIntegrationID}, http.MethodPost, "/api/v1/integrations/"+workflowIntegrationID+"/test-delivery", `{}`)
	request.Header.Set("Idempotency-Key", "integration-webhook-test-0001")
	request.Header.Set("If-Match", `"3"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || tester.tests != 1 || tester.command.Identity.Scope != identity.Scope || tester.command.IntegrationID != workflowIntegrationID || tester.command.ExpectedVersion != 3 || tester.command.IdempotencyKey != "integration-webhook-test-0001" || tester.command.CorrelationID != testCorrelationID || !validProductID(tester.command.AuditID) || response.Header().Get("X-Audit-ID") != tester.command.AuditID || response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), "destination") || strings.Contains(response.Body.String(), "secret_ref") {
		t.Fatalf("POST=%d headers=%v command=%#v body=%s", response.Code, response.Header(), tester.command, response.Body.String())
	}

	request = workflowRequest(t, identity, testCorrelationID, "getIntegrationWebhookStatus", map[string]string{"id": workflowIntegrationID}, http.MethodGet, "/api/v1/integrations/"+workflowIntegrationID+"/delivery-status", "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || tester.reads != 1 || tester.scope != identity.Scope || tester.id != workflowIntegrationID || response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), "destination") || strings.Contains(response.Body.String(), "secret_ref") {
		t.Fatalf("GET=%d headers=%v scope=%#v id=%s body=%s", response.Code, response.Header(), tester.scope, tester.id, response.Body.String())
	}
}

func TestWorkflowHandlerRejectsActionTimeWebhookDestinationBeforeSideEffect(t *testing.T) {
	tester := &integrationWebhookTesterStub{}
	handler, err := newWorkflowHTTPHandler(&workflowRepositoryStub{}, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	handler.webhookTests = tester
	for _, body := range []string{`{"destination_url":"https://attacker.example/hook"}`, `{"payload":{"secret":"value"}}`, ``, ``} {
		request := workflowRequest(t, fixtureRequestIdentity(t), testCorrelationID, "testIntegrationWebhook", map[string]string{"id": workflowIntegrationID}, http.MethodPost, "/api/v1/integrations/"+workflowIntegrationID+"/test-delivery", body)
		request.Header.Set("Idempotency-Key", "integration-webhook-test-0001")
		request.Header.Set("If-Match", `"3"`)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || tester.tests != 0 {
			t.Fatalf("body=%q status=%d calls=%d response=%s", body, response.Code, tester.tests, response.Body.String())
		}
	}
}

func TestIntegrationWebhookStatusDoesNotClaimUnsignedOrPendingDeliverySucceeded(t *testing.T) {
	now := time.Now().UTC()
	base := IntegrationWebhookTestStatus{IntegrationID: workflowIntegrationID, DeliveryID: "pid_41000001-0000-4000-8000-000000000001", AuditID: workflowAuditID, AttemptedAt: now, SignatureStatus: "unconfirmed", DeliveryStatus: "pending"}
	for _, test := range []struct {
		name   string
		status IntegrationWebhookTestStatus
		valid  bool
	}{
		{"pending", base, true},
		{"pending claims signed", func() IntegrationWebhookTestStatus { s := base; s.SignatureStatus = "signed"; return s }(), false},
		{"pending claims completed", func() IntegrationWebhookTestStatus { s := base; s.CompletedAt = &now; return s }(), false},
		{"failed", func() IntegrationWebhookTestStatus {
			s := base
			s.DeliveryStatus = "failed"
			s.CompletedAt = &now
			s.ErrorCode = "delivery_failed"
			return s
		}(), true},
		{"success unsigned", func() IntegrationWebhookTestStatus {
			s := base
			s.DeliveryStatus = "succeeded"
			s.CompletedAt = &now
			return s
		}(), false},
		{"unknown", func() IntegrationWebhookTestStatus { s := base; s.DeliveryStatus = "unknown"; return s }(), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validIntegrationWebhookTestStatus(test.status, workflowIntegrationID); got != test.valid {
				t.Fatalf("valid=%v want=%v status=%+v", got, test.valid, test.status)
			}
		})
	}
}

func integrationWebhookPayloadFixture(t *testing.T, deliveryID string) (string, string) {
	t.Helper()
	scope := fixtureRequestIdentity(t).Scope
	value, err := json.Marshal(map[string]any{"delivery_id": deliveryID, "event": "integration.webhook.test", "version": 1, "integration": map[string]any{"id": workflowIntegrationID, "version": 3}, "scope": map[string]string{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String()}, "sent_at": time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(value)
	return string(value), "sha256:" + hex.EncodeToString(digest[:])
}

func TestIntegrationWebhookServiceRejectsPayloadDriftBeforeSecretResolution(t *testing.T) {
	id := "pid_41000001-0000-4000-8000-000000000001"
	payload, digest := integrationWebhookPayloadFixture(t, id)
	for _, bad := range []string{`{"version":1}`, strings.ReplaceAll(payload, workflowIntegrationID, id), payload + " "} {
		repository := &integrationWebhookRepositoryStub{reservation: IntegrationWebhookTestReservation{State: "dispatch", DeliveryID: id, Payload: bad, PayloadDigest: digest, DestinationURL: "https://hooks.example.test/zasp", SecretReference: "secret_ref_webhook_prod", LeaseExpiresAt: time.Now().Add(15 * time.Second)}}
		secrets := &integrationWebhookSecretStub{material: []byte(strings.Repeat("s", 32))}
		webhook := &integrationWebhookDeliveryStub{}
		service, err := NewIntegrationWebhookTestService(IntegrationWebhookTestServiceConfig{Repository: repository, Secrets: secrets, Webhook: webhook, LeaseSeconds: 15, NewDeliveryID: func(domain.Scope, string) (string, error) { return id, nil }, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 64), nil }})
		if err != nil {
			t.Fatal(err)
		}
		_, err = service.TestIntegrationWebhook(context.Background(), IntegrationWebhookTestCommand{Identity: fixtureRequestIdentity(t), IntegrationID: workflowIntegrationID, ExpectedVersion: 3, IdempotencyKey: "webhook-hostile-payload-01", AuditID: workflowAuditID, CorrelationID: testCorrelationID})
		if !errors.Is(err, ErrRepositoryUnavailable) || secrets.calls != 0 || webhook.calls != 0 || repository.completes != 0 {
			t.Fatalf("err=%v calls=%d/%d/%d", err, secrets.calls, webhook.calls, repository.completes)
		}
	}
}

func TestIntegrationWebhookDestinationAcceptsRootAndDefaultHTTPSPort(t *testing.T) {
	for _, destination := range []string{"https://hooks.example.test", "https://hooks.example.test/", "https://hooks.example.test:443/zasp"} {
		if !validIntegrationWebhookDestination(destination) {
			t.Fatalf("valid destination rejected: %s", destination)
		}
	}
	for _, destination := range []string{"https://hooks.example.test:8443/zasp", "http://hooks.example.test/", "https://127.0.0.1/", "https://hooks.example.test/?token=secret", "https://hooks.example.test/../private"} {
		if validIntegrationWebhookDestination(destination) {
			t.Fatalf("unsafe destination accepted: %s", destination)
		}
	}
}
