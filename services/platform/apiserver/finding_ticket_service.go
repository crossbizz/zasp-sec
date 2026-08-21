package apiserver

import (
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type findingTicketRepository interface {
	ReserveFindingTicket(context.Context, FindingTicketCommand, string, string, int) (FindingTicketReservation, error)
	CompleteFindingTicket(context.Context, domain.Scope, string, string, string, string) (FindingTicket, error)
	ReleaseFindingTicket(context.Context, domain.Scope, string, string, string) error
}

type FindingTicketSecretResolver interface {
	ResolveFindingTicketSecret(context.Context, string) ([]byte, error)
}

type FindingTicketWebhook interface {
	DeliverFindingTicket(context.Context, string, string, string, string, []byte) (string, error)
}

type FindingTicketServiceConfig struct {
	Repository    findingTicketRepository
	Secrets       FindingTicketSecretResolver
	Webhook       FindingTicketWebhook
	LeaseSeconds  int
	NewDeliveryID func(domain.Scope, string) (string, error)
	NewLeaseToken func() (string, error)
}

type findingTicketService struct {
	repository    findingTicketRepository
	secrets       FindingTicketSecretResolver
	webhook       FindingTicketWebhook
	leaseSeconds  int
	newDeliveryID func(domain.Scope, string) (string, error)
	newLeaseToken func() (string, error)
}

func NewFindingTicketService(config FindingTicketServiceConfig) (FindingTicketCreator, error) {
	if nilInterface(config.Repository) || nilInterface(config.Secrets) || nilInterface(config.Webhook) || config.LeaseSeconds < 5 || config.LeaseSeconds > 30 || config.NewDeliveryID == nil || config.NewLeaseToken == nil {
		return nil, ErrRepositoryConfiguration
	}
	return &findingTicketService{repository: config.Repository, secrets: config.Secrets, webhook: config.Webhook, leaseSeconds: config.LeaseSeconds, newDeliveryID: config.NewDeliveryID, newLeaseToken: config.NewLeaseToken}, nil
}

func (service *findingTicketService) CreateFindingTicket(ctx context.Context, command FindingTicketCommand) (FindingTicket, error) {
	if service == nil || ctx == nil || ctx.Err() != nil || !validFindingTicketCommand(command) {
		return FindingTicket{}, ErrRepositoryOperation
	}
	deliveryID, deliveryErr := service.newDeliveryID(command.Identity.Scope, command.FindingID)
	leaseToken, leaseErr := service.newLeaseToken()
	if deliveryErr != nil || leaseErr != nil || !validProductID(deliveryID) || !findingTicketLeaseTokenPattern.MatchString(leaseToken) {
		return FindingTicket{}, ErrRepositoryUnavailable
	}
	reservation, err := service.repository.ReserveFindingTicket(ctx, command, deliveryID, leaseToken, service.leaseSeconds)
	if err != nil {
		return FindingTicket{}, err
	}
	if !validProductID(reservation.DeliveryID) {
		return FindingTicket{}, ErrRepositoryUnavailable
	}
	switch reservation.State {
	case "completed":
		if !findingTicketProviderIDPattern.MatchString(reservation.TicketID) {
			return FindingTicket{}, ErrRepositoryUnavailable
		}
		return FindingTicket{TicketID: reservation.TicketID}, nil
	case "busy":
		return FindingTicket{}, ErrRepositoryConflict
	case "dispatch":
	default:
		return FindingTicket{}, ErrRepositoryUnavailable
	}

	finalizationDeadline := reservation.LeaseExpiresAt.Add(-100 * time.Millisecond)
	if reservation.LeaseExpiresAt.IsZero() || !finalizationDeadline.After(time.Now()) {
		return FindingTicket{}, ErrRepositoryUnavailable
	}
	providerDeadline := finalizationDeadline.Add(-2 * time.Second)
	if !providerDeadline.After(time.Now()) {
		providerDeadline = time.Now().Add(finalizationDeadline.Sub(time.Now()) / 2)
	}
	providerContext, cancelProvider := context.WithDeadline(ctx, providerDeadline)
	defer cancelProvider()
	finalizationContext, cancelFinalization := context.WithDeadline(context.WithoutCancel(ctx), finalizationDeadline)
	defer cancelFinalization()

	secret, err := service.secrets.ResolveFindingTicketSecret(providerContext, reservation.SecretReference)
	if err != nil || len(secret) < 32 || len(secret) > 4096 {
		clear(secret)
		return FindingTicket{}, service.releaseFailedDelivery(finalizationContext, command.Identity.Scope, reservation, leaseToken)
	}
	defer clear(secret)
	ticketID, err := deliverFindingTicketSafely(service.webhook, providerContext, reservation, secret)
	if err != nil || !findingTicketProviderIDPattern.MatchString(ticketID) {
		return FindingTicket{}, service.releaseFailedDelivery(finalizationContext, command.Identity.Scope, reservation, leaseToken)
	}
	ticket, err := service.repository.CompleteFindingTicket(finalizationContext, command.Identity.Scope, reservation.DeliveryID, leaseToken, reservation.PayloadDigest, ticketID)
	if err != nil || ticket.TicketID != ticketID {
		return FindingTicket{}, ErrRepositoryUnavailable
	}
	return ticket, nil
}

func (service *findingTicketService) releaseFailedDelivery(ctx context.Context, scope domain.Scope, reservation FindingTicketReservation, leaseToken string) error {
	if err := service.repository.ReleaseFindingTicket(ctx, scope, reservation.DeliveryID, leaseToken, reservation.PayloadDigest); err != nil {
		return ErrRepositoryUnavailable
	}
	return ErrRepositoryUnavailable
}

func deliverFindingTicketSafely(webhook FindingTicketWebhook, ctx context.Context, reservation FindingTicketReservation, secret []byte) (ticketID string, err error) {
	defer func() {
		if recover() != nil {
			ticketID = ""
			err = ErrRepositoryUnavailable
		}
	}()
	return webhook.DeliverFindingTicket(ctx, reservation.DestinationURL, reservation.Payload, reservation.PayloadDigest, reservation.DeliveryID, secret)
}
