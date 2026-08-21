package apiserver

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type findingTicketRepositoryStub struct {
	reservation FindingTicketReservation
	reserveErr  error
	completeErr error
	releaseErr  error
	reserves    int
	completes   int
	releases    int
	command     FindingTicketCommand
	deliveryID  string
	leaseToken  string
	digest      string
	ticketID    string
}

func (repository *findingTicketRepositoryStub) ReserveFindingTicket(_ context.Context, command FindingTicketCommand, deliveryID, leaseToken string, _ int) (FindingTicketReservation, error) {
	repository.reserves++
	repository.command, repository.deliveryID, repository.leaseToken = command, deliveryID, leaseToken
	return repository.reservation, repository.reserveErr
}

func (repository *findingTicketRepositoryStub) CompleteFindingTicket(_ context.Context, _ domain.Scope, deliveryID, leaseToken, digest, ticketID string) (FindingTicket, error) {
	repository.completes++
	repository.deliveryID, repository.leaseToken, repository.digest, repository.ticketID = deliveryID, leaseToken, digest, ticketID
	return FindingTicket{TicketID: ticketID}, repository.completeErr
}

func (repository *findingTicketRepositoryStub) ReleaseFindingTicket(_ context.Context, _ domain.Scope, deliveryID, leaseToken, digest string) error {
	repository.releases++
	repository.deliveryID, repository.leaseToken, repository.digest = deliveryID, leaseToken, digest
	return repository.releaseErr
}

type findingTicketSecretResolverStub struct {
	material  []byte
	err       error
	calls     int
	reference string
}

func (resolver *findingTicketSecretResolverStub) ResolveFindingTicketSecret(_ context.Context, reference string) ([]byte, error) {
	resolver.calls++
	resolver.reference = reference
	return resolver.material, resolver.err
}

type findingTicketWebhookStub struct {
	ticketID     string
	err          error
	panicValue   any
	calls        int
	destination  string
	payload      string
	digest       string
	deliveryID   string
	secretAtCall []byte
}

func (webhook *findingTicketWebhookStub) DeliverFindingTicket(_ context.Context, destination, payload, digest, deliveryID string, secret []byte) (string, error) {
	webhook.calls++
	webhook.destination, webhook.payload, webhook.digest, webhook.deliveryID = destination, payload, digest, deliveryID
	webhook.secretAtCall = append([]byte(nil), secret...)
	if webhook.panicValue != nil {
		panic(webhook.panicValue)
	}
	return webhook.ticketID, webhook.err
}

func TestFindingTicketServiceDispatchesOnceCompletesAndClearsSecret(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	deliveryID := "pid_41000001-0000-4000-8000-000000000001"
	leaseToken := strings.Repeat("a", 64)
	digest := "sha256:" + strings.Repeat("b", 64)
	secretBytes := []byte("0123456789abcdef0123456789abcdef")
	repository := &findingTicketRepositoryStub{reservation: FindingTicketReservation{State: "dispatch", DeliveryID: deliveryID, Payload: `{"version":1}`, PayloadDigest: digest, DestinationURL: "https://tickets.example.test/zasp", SecretReference: "secret_ref_ticket_prod", LeaseExpiresAt: time.Now().Add(15 * time.Second)}}
	secrets := &findingTicketSecretResolverStub{material: secretBytes}
	webhook := &findingTicketWebhookStub{ticketID: "SEC-1234"}
	service, err := NewFindingTicketService(FindingTicketServiceConfig{Repository: repository, Secrets: secrets, Webhook: webhook, LeaseSeconds: 15, NewDeliveryID: func(domain.Scope, string) (string, error) { return deliveryID, nil }, NewLeaseToken: func() (string, error) { return leaseToken, nil }})
	if err != nil {
		t.Fatal(err)
	}
	command := FindingTicketCommand{Identity: identity, FindingID: riskFindingID, ExpectedVersion: 2, IdempotencyKey: "finding-ticket-0001", CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}

	ticket, err := service.CreateFindingTicket(context.Background(), command)
	if err != nil || ticket.TicketID != "SEC-1234" {
		t.Fatalf("ticket = (%#v, %v)", ticket, err)
	}
	if repository.reserves != 1 || repository.completes != 1 || repository.releases != 0 || secrets.calls != 1 || webhook.calls != 1 {
		t.Fatalf("calls reserve/complete/release/secret/webhook = %d/%d/%d/%d/%d", repository.reserves, repository.completes, repository.releases, secrets.calls, webhook.calls)
	}
	if !reflect.DeepEqual(repository.command, command) || repository.deliveryID != deliveryID || repository.leaseToken != leaseToken || repository.digest != digest || repository.ticketID != "SEC-1234" || secrets.reference != "secret_ref_ticket_prod" || webhook.destination != repository.reservation.DestinationURL || webhook.payload != repository.reservation.Payload || webhook.digest != digest || webhook.deliveryID != deliveryID || string(webhook.secretAtCall) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("dispatch authority drift: repository=%#v secret=%q webhook=%#v", repository, secrets.reference, webhook)
	}
	for index, value := range secretBytes {
		if value != 0 {
			t.Fatalf("secret byte %d was not cleared", index)
		}
	}
}

func TestFindingTicketServiceReplaysCompletedWithoutSecretOrWebhook(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	deliveryID := "pid_41000001-0000-4000-8000-000000000001"
	newCandidateID := "pid_41000002-0000-4000-8000-000000000002"
	repository := &findingTicketRepositoryStub{reservation: FindingTicketReservation{State: "completed", DeliveryID: deliveryID, TicketID: "SEC-1234"}}
	secrets := &findingTicketSecretResolverStub{material: []byte(strings.Repeat("s", 32))}
	webhook := &findingTicketWebhookStub{ticketID: "should-not-run"}
	service, err := NewFindingTicketService(FindingTicketServiceConfig{Repository: repository, Secrets: secrets, Webhook: webhook, LeaseSeconds: 15, NewDeliveryID: func(domain.Scope, string) (string, error) { return newCandidateID, nil }, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 64), nil }})
	if err != nil {
		t.Fatal(err)
	}

	ticket, err := service.CreateFindingTicket(context.Background(), FindingTicketCommand{Identity: identity, FindingID: riskFindingID, ExpectedVersion: 2, IdempotencyKey: "finding-ticket-0001", CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"})
	if err != nil || ticket.TicketID != "SEC-1234" || repository.deliveryID != newCandidateID || repository.completes != 0 || repository.releases != 0 || secrets.calls != 0 || webhook.calls != 0 {
		t.Fatalf("replay = (%#v, %v) calls=%d/%d/%d/%d", ticket, err, repository.completes, repository.releases, secrets.calls, webhook.calls)
	}
}

func TestFindingTicketServiceReleasesOnlyFailedOrPanickedDelivery(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	deliveryID := "pid_41000001-0000-4000-8000-000000000001"
	command := FindingTicketCommand{Identity: identity, FindingID: riskFindingID, ExpectedVersion: 2, IdempotencyKey: "finding-ticket-0001", CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}
	for _, test := range []struct {
		name       string
		webhookErr error
		panicValue any
	}{
		{name: "error", webhookErr: errors.New("provider token leak")},
		{name: "panic", panicValue: "provider secret panic"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &findingTicketRepositoryStub{reservation: FindingTicketReservation{State: "dispatch", DeliveryID: deliveryID, Payload: `{"version":1}`, PayloadDigest: "sha256:" + strings.Repeat("b", 64), DestinationURL: "https://tickets.example.test/zasp", SecretReference: "secret_ref_ticket_prod", LeaseExpiresAt: time.Now().Add(15 * time.Second)}}
			secrets := &findingTicketSecretResolverStub{material: []byte(strings.Repeat("s", 32))}
			webhook := &findingTicketWebhookStub{err: test.webhookErr, panicValue: test.panicValue}
			service, err := NewFindingTicketService(FindingTicketServiceConfig{Repository: repository, Secrets: secrets, Webhook: webhook, LeaseSeconds: 15, NewDeliveryID: func(domain.Scope, string) (string, error) { return deliveryID, nil }, NewLeaseToken: func() (string, error) { return strings.Repeat("a", 64), nil }})
			if err != nil {
				t.Fatal(err)
			}

			if ticket, err := service.CreateFindingTicket(context.Background(), command); !errors.Is(err, ErrRepositoryUnavailable) || !reflect.DeepEqual(ticket, FindingTicket{}) || repository.releases != 1 || repository.completes != 0 {
				t.Fatalf("failed delivery = (%#v, %v), release/complete=%d/%d", ticket, err, repository.releases, repository.completes)
			}
		})
	}
}
