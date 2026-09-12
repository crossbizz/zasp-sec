package runtimeevent

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

const productionLookupAcceptanceSQL = `SELECT zasp_runtime_lookup_acceptance($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`

type IngestAcceptanceRequest struct {
	IngestReserveRequest
	EnrollmentBinding string
	JobID             domain.ProductID
	OutboxID          domain.ProductID
}

type IngestAcceptance struct {
	Found      bool
	BatchID    domain.ProductID
	Generation int64
	State      string
}

type ProductionAcceptanceRepository interface {
	LookupAcceptance(context.Context, *sensor.TokenCredential, IngestAcceptanceRequest) (IngestAcceptance, error)
}

func (repository *PostgresProductionIngestRepository) LookupAcceptance(ctx context.Context, credential *sensor.TokenCredential, request IngestAcceptanceRequest) (IngestAcceptance, error) {
	if !validProductionRepository(repository, ctx) || credential == nil || !repository.acceptsReserveSchema(request.IngestReserveRequest) || !productionEnrollmentPattern.MatchString(request.EnrollmentBinding) || request.JobID.IsZero() || request.OutboxID.IsZero() {
		return IngestAcceptance{}, ErrProductionIngestUnavailable
	}
	if repository.precision {
		if err := repository.ReadyPrecision(ctx); err != nil {
			return IngestAcceptance{}, err
		}
	}
	locator, secret, err := credential.Parts()
	if err != nil {
		return IngestAcceptance{}, ErrProductionIngestDenied
	}
	defer clear(locator)
	defer clear(secret)
	payload, err := safeProductionQuery(repository.database, ctx, productionLookupAcceptanceSQL, locator, secret, request.EnrollmentBinding, request.BatchID.String(), request.IdempotencyKey, request.ContentDigest[:], request.Source, request.MediaType, request.SchemaVersion, request.PayloadSize, request.EventCount, request.JobID.String(), request.OutboxID.String(), migrations.ProductionRuntimeAcceptance().Checksum(), migrations.ProductionRuntimeAcceptanceSemanticFingerprint())
	var wire struct {
		Found      *bool  `json:"found"`
		BatchID    string `json:"batch_id,omitempty"`
		Generation int64  `json:"generation,omitempty"`
		State      string `json:"state,omitempty"`
	}
	if err != nil || ctx.Err() != nil || len(payload) > 16<<10 || !uniqueProductionJSON(payload) || strictProductionJSON(payload, &wire) != nil || wire.Found == nil {
		return IngestAcceptance{}, ErrProductionIngestUnavailable
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload, &fields) != nil || fields["found"] == nil {
		return IngestAcceptance{}, ErrProductionIngestUnavailable
	}
	if !*wire.Found && len(fields) != 1 || *wire.Found && (len(fields) != 4 || fields["batch_id"] == nil || fields["generation"] == nil || fields["state"] == nil) {
		return IngestAcceptance{}, ErrProductionIngestUnavailable
	}
	result := IngestAcceptance{Found: *wire.Found, Generation: wire.Generation, State: wire.State}
	if wire.BatchID != "" {
		result.BatchID, err = domain.ParseProductID(wire.BatchID)
		if err != nil {
			return IngestAcceptance{}, ErrProductionIngestUnavailable
		}
	}
	if !validIngestAcceptance(result, request.BatchID) {
		return IngestAcceptance{}, ErrProductionIngestUnavailable
	}
	return result, nil
}

func validIngestAcceptance(value IngestAcceptance, batchID domain.ProductID) bool {
	if !value.Found {
		return value == (IngestAcceptance{})
	}
	return value.BatchID == batchID && !batchID.IsZero() && value.Generation > 0 && validAcceptedIngestState(value.State, true)
}

func safeProductionLookupAcceptance(ctx context.Context, repository ProductionAcceptanceRepository, credential *sensor.TokenCredential, request IngestAcceptanceRequest) (value IngestAcceptance, err error) {
	defer func() {
		if recover() != nil {
			value = IngestAcceptance{}
			err = ErrProductionIngestUnavailable
		}
	}()
	value, err = repository.LookupAcceptance(ctx, credential, request)
	if ctx.Err() != nil || err != nil || !validIngestAcceptance(value, request.BatchID) {
		return IngestAcceptance{}, ErrProductionIngestUnavailable
	}
	return value, nil
}
