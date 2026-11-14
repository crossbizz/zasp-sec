package apiserver

import (
	"context"
	"errors"
	"regexp"
	"time"
)

// Deleting the Nango connection a sign-in created.
//
// A sign-in to a SaaS platform (saas_sign_in.go) makes Nango create a
// connection and keep the provider's token for it. When the integration is
// deleted, or is given another connection, PostgreSQL lists that connection
// in zasp_saas_connection_releases in the same transaction (completion.sql
// section ws10_saas_connection_release). The worker below, which runs in the
// API server next to the connector reconciler, deletes listed connections at
// Nango:
//
//   - it claims rows under a lease, so a worker that stops between the claim
//     and the deletion loses nothing: the row is claimed again when the lease
//     expires, and deleting a connection that is already gone succeeds;
//   - a failed deletion is recorded with a stable code and tried again later;
//   - only connections that a completed sign-in of the integration created
//     are ever listed. A reference a person pasted names a connection that
//     was made outside the product, and is left alone.
//
// The statements are system maintenance, like connector reconciliation: they
// run without a request, bound to the lease the worker claimed
// (connector_maintenance_authorization.go).
const (
	postgresSaaSConnectionReleaseReadySQL  = `SELECT to_jsonb(to_regprocedure('public.zasp_saas_connection_release_finish(text,text,text,text,text,text,boolean,text)') IS NOT NULL)`
	postgresSaaSConnectionReleaseClaimSQL  = `SELECT zasp_saas_connection_release_claim($1,$2,$3)`
	postgresSaaSConnectionReleaseFinishSQL = `SELECT zasp_saas_connection_release_finish($1,$2,$3,$4,$5,$6,$7,$8)`
)

var saasConnectionReleaseCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)

// SaaSConnectionRelease is one Nango connection to delete, claimed under a
// lease.
type SaaSConnectionRelease struct {
	OrganizationID      string    `json:"organization_id"`
	WorkspaceID         string    `json:"workspace_id"`
	EnvironmentID       string    `json:"environment_id"`
	ConnectionReference string    `json:"connection_reference"`
	IntegrationID       string    `json:"integration_id"`
	Platform            string    `json:"platform"`
	Reason              string    `json:"reason"`
	Attempt             int       `json:"attempt"`
	LeaseOwner          string    `json:"lease_owner"`
	LeaseToken          string    `json:"lease_token"`
	LeaseExpiresAt      time.Time `json:"lease_expires_at"`
}

// SaaSConnectionReleaseOutcome is what PostgreSQL recorded for a claimed
// release: released, pending (to be tried again at AvailableAt) or failed
// (the last attempt).
type SaaSConnectionReleaseOutcome struct {
	Status      string    `json:"status"`
	Attempt     int       `json:"attempt"`
	AvailableAt time.Time `json:"available_at"`
}

type SaaSConnectionReleaseRepository struct{ database JSONDatabase }

// NewSaaSConnectionReleaseRepository returns the repository, or
// ErrRepositoryNotFound when the database does not have the release section.
// It is called at startup, before requests exist.
func NewSaaSConnectionReleaseRepository(ctx context.Context, database JSONDatabase) (*SaaSConnectionReleaseRepository, error) {
	if nilInterface(database) || ctx == nil {
		return nil, ErrRepositoryConfiguration
	}
	payload, err := database.QueryJSON(ctx, postgresSaaSConnectionReleaseReadySQL)
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil {
		return nil, ErrRepositoryUnavailable
	}
	if !ready {
		return nil, ErrRepositoryNotFound
	}
	return &SaaSConnectionReleaseRepository{database: database}, nil
}

func validSaaSConnectionRelease(release SaaSConnectionRelease) bool {
	return validProductID(release.OrganizationID) && validProductID(release.WorkspaceID) && validProductID(release.EnvironmentID) && validProductID(release.IntegrationID) &&
		saasConnectionReferencePattern.MatchString(release.ConnectionReference) && saasPlatformPattern.MatchString(release.Platform) && stringIn(release.Reason, "integration_deleted", "reference_replaced") &&
		release.Attempt >= 1 && release.Attempt <= 50 && len(release.LeaseOwner) >= 3 && len(release.LeaseOwner) <= 128 && len(release.LeaseToken) == 64 && !release.LeaseExpiresAt.IsZero()
}

// Claim takes up to limit connections whose turn has come.
func (repository *SaaSConnectionReleaseRepository) Claim(ctx context.Context, owner string, leaseSeconds, limit int) ([]SaaSConnectionRelease, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || len(owner) < 3 || len(owner) > 128 || leaseSeconds < 5 || leaseSeconds > 300 || limit < 1 || limit > 100 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSaaSConnectionReleaseClaimSQL, owner, leaseSeconds, limit)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var page struct {
		Items []SaaSConnectionRelease `json:"items"`
	}
	if decodeStrictDiscovery(payload, &page) != nil || page.Items == nil || len(page.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	now := time.Now()
	for index := range page.Items {
		item := &page.Items[index]
		if !validSaaSConnectionRelease(*item) || item.LeaseOwner != owner || !item.LeaseExpiresAt.After(now) || item.LeaseExpiresAt.After(now.Add(time.Duration(leaseSeconds)*time.Second+time.Second)) {
			return nil, ErrRepositoryUnavailable
		}
		item.LeaseExpiresAt = item.LeaseExpiresAt.UTC()
	}
	return page.Items, nil
}

// Finish records the outcome of a claimed release. errorCode is empty for a
// released connection and a stable code otherwise.
func (repository *SaaSConnectionReleaseRepository) Finish(ctx context.Context, release SaaSConnectionRelease, released bool, errorCode string) (SaaSConnectionReleaseOutcome, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validSaaSConnectionRelease(release) || released != (errorCode == "") || !released && !saasConnectionReleaseCodePattern.MatchString(errorCode) {
		return SaaSConnectionReleaseOutcome{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSaaSConnectionReleaseFinishSQL, release.OrganizationID, release.WorkspaceID, release.EnvironmentID, release.ConnectionReference, release.LeaseOwner, release.LeaseToken, released, errorCode)
	if err != nil {
		return SaaSConnectionReleaseOutcome{}, discoveryProviderError(err)
	}
	var outcome SaaSConnectionReleaseOutcome
	if decodeStrictDiscovery(payload, &outcome) != nil || outcome.Attempt != release.Attempt || released != (outcome.Status == "released") || !stringIn(outcome.Status, "released", "pending", "failed") {
		return SaaSConnectionReleaseOutcome{}, ErrRepositoryUnavailable
	}
	outcome.AvailableAt = outcome.AvailableAt.UTC()
	return outcome, nil
}

// SaaSConnectionRemover deletes one connection at Nango. Deleting a
// connection that no longer exists succeeds. ErrRepositoryConfiguration
// means this deployment does not serve the release's platform.
type SaaSConnectionRemover interface {
	RemoveConnection(ctx context.Context, release SaaSConnectionRelease) error
}

type saasConnectionReleaseStore interface {
	Claim(ctx context.Context, owner string, leaseSeconds, limit int) ([]SaaSConnectionRelease, error)
	Finish(ctx context.Context, release SaaSConnectionRelease, released bool, errorCode string) (SaaSConnectionReleaseOutcome, error)
}

type SaaSConnectionReleaserConfig struct {
	Repository   saasConnectionReleaseStore
	Remover      SaaSConnectionRemover
	Owner        string
	LeaseSeconds int
	Limit        int
	Interval     time.Duration
}

// SaaSConnectionReleaser is the release worker.
type SaaSConnectionReleaser struct {
	repository   saasConnectionReleaseStore
	remover      SaaSConnectionRemover
	owner        string
	leaseSeconds int
	limit        int
	interval     time.Duration
}

func NewSaaSConnectionReleaser(config SaaSConnectionReleaserConfig) (*SaaSConnectionReleaser, error) {
	if nilInterface(config.Repository) || nilInterface(config.Remover) || len(config.Owner) < 3 || len(config.Owner) > 128 || config.LeaseSeconds < 5 || config.LeaseSeconds > 300 || config.Limit < 1 || config.Limit > 100 || config.Interval < 10*time.Millisecond || config.Interval > 10*time.Minute {
		return nil, ErrRepositoryConfiguration
	}
	return &SaaSConnectionReleaser{repository: config.Repository, remover: config.Remover, owner: config.Owner, leaseSeconds: config.LeaseSeconds, limit: config.Limit, interval: config.Interval}, nil
}

// Run releases connections until ctx ends. A failure of one pass (the
// database or Nango is unavailable) is retried at the next interval; it
// never ends the worker, and never changes the readiness of the API.
func (releaser *SaaSConnectionReleaser) Run(ctx context.Context) error {
	if releaser == nil || ctx == nil {
		return ErrRepositoryConfiguration
	}
	for ctx.Err() == nil {
		claimed, _ := releaser.releaseOnce(ctx)
		if claimed == releaser.limit {
			// A full batch: more may be due.
			continue
		}
		timer := time.NewTimer(releaser.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

// releaseOnce claims one batch and deletes its connections. It returns the
// number of connections claimed.
func (releaser *SaaSConnectionReleaser) releaseOnce(ctx context.Context) (int, error) {
	if releaser == nil || ctx == nil || ctx.Err() != nil {
		return 0, ErrRepositoryOperation
	}
	ctx = withConnectorMaintenance(ctx)
	releases, err := releaser.repository.Claim(ctx, releaser.owner, releaser.leaseSeconds, releaser.limit)
	if err != nil {
		return 0, err
	}
	var result error
	for _, release := range releases {
		// The deletion must end before the lease does, with time left to
		// record its outcome.
		deadline := release.LeaseExpiresAt.Add(-2 * time.Second)
		if !deadline.After(time.Now()) {
			continue
		}
		removal, cancel := context.WithDeadline(ctx, deadline)
		removeErr := releaser.remover.RemoveConnection(removal, release)
		cancel()
		code := ""
		switch {
		case removeErr == nil:
		case errors.Is(removeErr, ErrRepositoryConfiguration):
			code = "platform_unavailable"
		default:
			code = "nango_unavailable"
		}
		if _, err := releaser.repository.Finish(ctx, release, removeErr == nil, code); err != nil {
			result = errors.Join(result, err)
		}
	}
	return len(releases), result
}
