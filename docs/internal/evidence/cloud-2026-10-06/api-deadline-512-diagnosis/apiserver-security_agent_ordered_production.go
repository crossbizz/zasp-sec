package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// SecurityAgentOrderedHTTPReleaseVerifier checks the exact deployment release,
// not tenant access. Every request still uses the facade's authorization checks.
type SecurityAgentOrderedHTTPReleaseVerifier interface {
	VerifySecurityAgentOrderedHTTPRelease(context.Context) error
}

const orderedCurrentDeploymentReadySQL = `SELECT zasp_authorization80.ready($1), zasp_ordered_public62.api($2,$3,'{"operation":"deployment_ready"}'::jsonb)`

func (database *PostgresJSONDatabase) VerifySecurityAgentOrderedHTTPRelease(ctx context.Context) error {
	if database == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var raw []byte
	var err error
	database.mu.RLock()
	if database.currentAuthorization {
		defer database.mu.RUnlock()
		if database.closed || nilInterface(database.driver) {
			return ErrRepositoryUnavailable
		}
		// Installed capability is not an actor grant. Keep the public62 API's
		// principal checks and locks, plus independent current catalog readiness.
		var currentReady bool
		start := time.Now()
		deadline, _ := bounded.Deadline()
		authorization := migrations.ProductionAuthorizationEnforcement().Checksum()
		fmt.Printf("PRIVATE_DIAGNOSTIC production-authorization-pin elapsed=%s remaining=%s expired=%t\n", time.Since(start), time.Until(deadline), bounded.Err() != nil)
		start = time.Now()
		public := migrations.ProductionSecurityAgentPublic().Checksum()
		fmt.Printf("PRIVATE_DIAGNOSTIC production-public-pin elapsed=%s remaining=%s expired=%t\n", time.Since(start), time.Until(deadline), bounded.Err() != nil)
		fingerprint := migrations.SecurityAgentPublicFingerprint()
		err = database.driver.QueryRow(bounded, orderedCurrentDeploymentReadySQL, authorization, public, fingerprint).Scan(&currentReady, &raw)
		if err != nil || !currentReady {
			return ErrRepositoryUnavailable
		}
	} else {
		database.mu.RUnlock()
		raw, err = database.QueryJSON(bounded, securityAgentPublicSQL, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint(), json.RawMessage(`{"operation":"deployment_ready"}`))
	}
	var result struct {
		ContractVersion int  `json:"contract_version"`
		Ready           bool `json:"ready"`
	}
	if err != nil || bounded.Err() != nil || len(raw) > 128 || public62Decode(raw, &result) != nil || result.ContractVersion != 62 || !result.Ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

func newSecurityAgentProductionHTTPHandler(ctx context.Context, repository *PostgresRepository, definitions http.Handler, config SecurityAgentPublicHandlerConfig, enabled bool) (http.Handler, error) {
	if repository == nil || nilInterface(repository.database) {
		return nil, ErrRepositoryConfiguration
	}
	config.SigningKey = append([]byte(nil), config.SigningKey...)
	legacy, err := NewSecurityAgentPublicHTTPHandler(repository, definitions, config)
	if err != nil || !enabled {
		return legacy, err
	}
	verifier, ok := repository.database.(SecurityAgentOrderedHTTPReleaseVerifier)
	if !ok || nilInterface(verifier) {
		return nil, ErrRepositoryConfiguration
	}
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := verifier.VerifySecurityAgentOrderedHTTPRelease(bounded); err != nil || bounded.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	authority, err := NewSecurityAgentOrderedResourceAuthority(repository.database)
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	ordered, err := newSecurityAgentOrderedHTTPHandler(authority, repository, func() (http.Handler, error) { return legacy, nil }, config.SigningKey)
	if err != nil {
		return nil, err
	}
	db, _ := repository.database.(temporalHumanFamilyResolver)
	return &securityAgentHumanHTTPHandler{database: db, findingDatabase: repository.database, next: ordered, legacy: legacy}, nil
}
