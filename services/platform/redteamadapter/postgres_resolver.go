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
	postgresTargetAdapterReadinessSQL = `SELECT to_jsonb(zasp_red_team_target_adapter_readiness($1,$2))`
	postgresResolveTargetSQL          = `SELECT zasp_red_team_resolve_target($1,$2,$3,$4,$5)`
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

func (resolver *PostgresResolver) ResolveTarget(ctx context.Context, scope domain.Scope, targetID, targetKind string) (TargetBinding, error) {
	if resolver == nil || resolver.database == nil || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !validRequestBody(requestBody{TargetID: targetID, TargetKind: targetKind, Category: "prompt_injection", Input: curatedInputs["prompt_injection"]}) {
		return TargetBinding{}, ErrAdapter
	}
	payload, err := resolver.database.QueryJSON(ctx, postgresResolveTargetSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), targetID, targetKind)
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
	if decoder.Decode(&trailing) != io.EOF || !validBinding(binding) || binding.TargetID != targetID || binding.TargetKind != targetKind {
		return TargetBinding{}, ErrAdapter
	}
	return binding, nil
}

var _ TargetResolver = (*PostgresResolver)(nil)
