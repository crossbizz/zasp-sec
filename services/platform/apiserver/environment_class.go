package apiserver

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"net/http"
)

type environmentClassificationInput struct {
	WorkspaceID, Name, Class string
	ClassPresent             bool
}

// Decode exact canonical keys before decoding values: encoding/json's
// case-insensitive struct matching must not turn an invalid class into omission.
func decodeEnvironmentClassification(request *http.Request, create bool) (environmentClassificationInput, error) {
	var input environmentClassificationInput
	var raw json.RawMessage
	if decodeProductionJSON(request, &raw) != nil {
		return input, ErrRepositoryOperation
	}
	fields, ok := budgetJSONObject(raw)
	if !ok {
		return input, ErrRepositoryOperation
	}
	for key, value := range fields {
		switch key {
		case "name":
			if json.Unmarshal(value, &input.Name) != nil {
				return input, ErrRepositoryOperation
			}
		case "workspace_id":
			if !create || json.Unmarshal(value, &input.WorkspaceID) != nil {
				return input, ErrRepositoryOperation
			}
		case "environment_class":
			input.ClassPresent = true
			if json.Unmarshal(value, &input.Class) != nil || !validEnvironmentClass(input.Class) {
				return input, ErrRepositoryOperation
			}
		default:
			return input, ErrRepositoryOperation
		}
	}
	if !validAdministrationName(input.Name) || create && !validAdministrationProductID(input.WorkspaceID) {
		return input, ErrRepositoryOperation
	}
	return input, nil
}

const postgresClassifiedEnvironmentCreateSQL = `SELECT zasp_environment_class_v1.create_environment($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)`
const postgresClassifiedEnvironmentUpdateSQL = `SELECT zasp_environment_class_v1.update_environment($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`

func (r *PostgresRepository) RequireEnvironmentClassProfile(pin string) error {
	if r == nil || !r.currentAuthorization || !migrations.IsEnvironmentClassProfileChecksum(pin) {
		return ErrRepositoryConfiguration
	}
	r.environmentClassProfileChecksum = pin
	return nil
}

// A fixed read capability, separate from caller-controlled SQL admission.
func (d *PostgresJSONDatabase) EnvironmentClassProfileReady(ctx context.Context, pin string) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || !migrations.IsEnvironmentClassProfileChecksum(pin) {
		return false, ErrRepositoryConfiguration
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || !d.currentAuthorization || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var ready bool
	if err := d.driver.QueryRow(ctx, `SELECT zasp_environment_class_v1.caller_ready($1)`, pin).Scan(&ready); err != nil {
		return false, classifyPostgresError(err)
	}
	return ready, nil
}
