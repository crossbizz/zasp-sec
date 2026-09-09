package redteamadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	postgresTargetAdapterReadinessSQL = `SELECT to_jsonb(zasp_red_team_invocation_readiness($1,$2))`
	postgresResolveTargetSQL          = `SELECT zasp_red_team_resolve_invocation($1,$2,$3,$4,$5,$6,$7,$8)`
)

var releaseDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type JSONDatabase interface {
	QueryJSON(context.Context, string, ...any) (json.RawMessage, error)
}

type PostgresResolver struct {
	database    JSONDatabase
	checksum    string
	fingerprint string
}

func NewPostgresResolver(database JSONDatabase, checksum, fingerprint string) (*PostgresResolver, error) {
	if database == nil || !releaseDigestPattern.MatchString(checksum) || !releaseDigestPattern.MatchString(fingerprint) {
		return nil, ErrAdapter
	}
	return &PostgresResolver{database: database, checksum: checksum, fingerprint: fingerprint}, nil
}

func (resolver *PostgresResolver) Ready(ctx context.Context) error {
	if resolver == nil || resolver.database == nil || ctx == nil || ctx.Err() != nil {
		return ErrAdapter
	}
	payload, err := resolver.database.QueryJSON(ctx, postgresTargetAdapterReadinessSQL, resolver.checksum, resolver.fingerprint)
	if err != nil || string(payload) != "true" {
		return ErrAdapter
	}
	return nil
}

func (resolver *PostgresResolver) ResolveTarget(ctx context.Context, request TargetResolution) (TargetBinding, error) {
	_, runErr := domain.ParseProductID(request.RunID)
	if resolver == nil || resolver.database == nil || ctx == nil || ctx.Err() != nil || request.Scope.Validate() != nil || runErr != nil || request.RunID == request.TargetID || !runLeaseRE.MatchString(request.LeaseToken) || !validRequestBody(requestBody{TargetID: request.TargetID, TargetKind: request.TargetKind, Category: request.Category, Input: curatedInputs[request.Category]}) {
		return TargetBinding{}, ErrAdapter
	}
	payload, err := resolver.database.QueryJSON(ctx, postgresResolveTargetSQL, request.Scope.OrganizationID().String(), request.Scope.WorkspaceID().String(), request.Scope.EnvironmentID().String(), request.TargetID, request.TargetKind, request.RunID, request.LeaseToken, request.Category)
	if err != nil || len(payload) < 2 || len(payload) > 16*1024 {
		return TargetBinding{}, ErrAdapter
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var binding TargetBinding
	if decoder.Decode(&binding) != nil {
		return TargetBinding{}, ErrAdapter
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || !validBinding(binding) || binding.TargetID != request.TargetID || binding.TargetKind != request.TargetKind {
		return TargetBinding{}, ErrAdapter
	}
	return binding, nil
}

var _ TargetResolver = (*PostgresResolver)(nil)
