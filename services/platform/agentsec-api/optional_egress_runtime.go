package main

import (
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/optionalegress"
)

func validOptionalEgressRuntimeConfig(c RuntimeConfig) bool {
	if !c.OptionalEgressEnabled {
		return c.OptionalEgressProfileChecksum == "" && c.OptionalEgressSettlementDSN == ""
	}
	if !c.RuntimeServices.Enabled || !migrations.IsOptionalEgressProfileChecksum(c.OptionalEgressProfileChecksum) {
		return false
	}
	core, coreOK := parseRuntimePostgresDSN(c.PostgresDSN)
	forward, forwardOK := parseRuntimePostgresDSN(c.SecurityAgentPostgresDSN)
	settlement, settlementOK := parseRuntimePostgresDSN(c.OptionalEgressSettlementDSN)
	return coreOK && forwardOK && settlementOK && settlement.User.Username() != core.User.Username() && settlement.User.Username() != forward.User.Username() && settlement.Scheme == forward.Scheme && settlement.Host == forward.Host && settlement.Path == forward.Path && settlement.RawQuery == forward.RawQuery
}

type optionalEgressCredentialResolver struct {
	driver  *connectorSecretsDriver
	root    string
	timeout time.Duration
}

var optionalCredentialSuffix = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`)

func optionalCredentialPath(binding optionalegress.Binding, profile optionalegress.Profile) (string, bool) {
	for _, value := range []string{binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID} {
		id, err := domain.ParseProductID(value)
		if err != nil || id.String() != value {
			return "", false
		}
	}
	scope := binding.OrganizationID + "/" + binding.WorkspaceID + "/" + binding.EnvironmentID + "/"
	prefix := "secret_ref_ai/" + scope
	if !strings.HasPrefix(profile.CredentialReference, prefix) {
		return "", false
	}
	suffix := strings.TrimPrefix(profile.CredentialReference, prefix)
	if !optionalCredentialSuffix.MatchString(suffix) || strings.Contains(suffix, "..") {
		return "", false
	}
	return scope + suffix, true
}

func (r *optionalEgressCredentialResolver) ResolveOptionalCredential(ctx context.Context, binding optionalegress.Binding, profile optionalegress.Profile) ([]byte, error) {
	if r == nil || r.driver == nil || ctx == nil || ctx.Err() != nil || binding.ProfileDigest != profile.ProfileDigest || binding.CredentialDigest != profile.CredentialDigest || profile.Provider != "openrouter" || strings.Contains(profile.CredentialReference, "..") || strings.Contains(profile.CredentialReference, "//") {
		return nil, optionalegress.ErrUnavailable
	}
	path, valid := optionalCredentialPath(binding, profile)
	if !valid {
		return nil, optionalegress.ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	// AI credentials have a distinct server-owned namespace. A profile cannot
	// redirect this lookup into webhook, identity or arbitrary secret paths.
	material, err := r.driver.Read(bounded, r.root+"/"+path)
	if err != nil || len(material) < 16 || len(material) > 4096 {
		clear(material)
		return nil, optionalegress.ErrUnavailable
	}
	return material, nil
}

type optionalEgressRuntimeCloser struct {
	database *apiserver.PostgresJSONDatabase
	sender   *optionalegress.OpenRouterSender
}

func (c *optionalEgressRuntimeCloser) Close() error {
	if c == nil {
		return nil
	}
	var failures []error
	if c.sender != nil {
		failures = append(failures, c.sender.Close())
	}
	if c.database != nil {
		failures = append(failures, c.database.Close())
	}
	return errors.Join(failures...)
}

func newRuntimeOptionalEgress(ctx context.Context, c RuntimeConfig, forward apiserver.JSONDatabase, authorizer apiserver.RequestAuthorizer, secrets *connectorSecretsDriver) (*apiserver.OptionalEgressHTTPConfig, io.Closer, error) {
	if !c.OptionalEgressEnabled {
		return nil, nil, nil
	}
	if !validOptionalEgressRuntimeConfig(c) || ctx == nil || ctx.Err() != nil || authorizer == nil || secrets == nil || secrets.client == nil {
		return nil, nil, errRuntimeUnavailable
	}
	forwardDatabase, ok := forward.(*apiserver.PostgresJSONDatabase)
	if !ok || !forwardDatabase.CurrentAuthorizationRequired() {
		return nil, nil, errRuntimeUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, c.ProviderTimeout)
	defer cancel()
	settlement, _, err := openRuntimePostgres(bounded, c.OptionalEgressSettlementDSN, c.ProviderTimeout)
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	closer := &optionalEgressRuntimeCloser{database: settlement}
	keep := false
	defer func() {
		if !keep {
			_ = closer.Close()
		}
	}()
	repository, err := apiserver.NewOptionalEgressRepositoryForProfile(forwardDatabase, settlement, c.OptionalEgressProfileChecksum)
	if err != nil || repository.Ready(bounded) != nil {
		return nil, nil, errRuntimeUnavailable
	}
	if !connectorPrefixPattern.MatchString(c.ConnectorSecretPrefix) || !strings.HasSuffix(c.ConnectorSecretPrefix, "/oauth") {
		return nil, nil, errRuntimeUnavailable
	}
	sender, err := optionalegress.NewOpenRouterSender(optionalegress.SenderConfig{Resolver: &optionalEgressCredentialResolver{driver: secrets, root: strings.TrimSuffix(c.ConnectorSecretPrefix, "/oauth") + "/ai/openrouter", timeout: c.ProviderTimeout}, Now: time.Now})
	if err != nil {
		return nil, nil, errRuntimeUnavailable
	}
	closer.sender = sender
	keep = true
	return &apiserver.OptionalEgressHTTPConfig{Repository: repository, Authorizer: authorizer, Sender: sender, Clock: time.Now}, closer, nil
}
