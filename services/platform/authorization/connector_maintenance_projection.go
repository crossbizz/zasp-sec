package authorization

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ConnectorMaintenanceProjectionRepository retains the original organization
// session lock, inventory, Stage and Ack. Only the complete registered snapshot
// changes. Registry selection is not evidence of external writer withdrawal.
type ConnectorMaintenanceProjectionRepository struct {
	*PostgresProjectionRepository
	approvalPin, connectorPin string
}

// NewCurrentMaintenanceProjectionRepository refuses an omitted active connector
// family. Connector selection also requires the exact approval profile so one
// writer cannot erase another supplementary family's desired tuples.
func NewCurrentMaintenanceProjectionRepository(ctx context.Context, pool *pgxpool.Pool, approvalPin, connectorPin string) (CurrentProjectionRepository, error) {
	if ctx == nil || ctx.Err() != nil || pool == nil {
		return nil, ErrInvalid
	}
	var installed bool
	if err := pool.QueryRow(ctx, `SELECT to_regnamespace('zasp_connector_maintenance') IS NOT NULL`).Scan(&installed); err != nil {
		return nil, projectionDatabaseError(err)
	}
	if !installed {
		if connectorPin != "" {
			return nil, ErrInvalid
		}
		return NewCurrentProjectionRepository(ctx, pool, approvalPin)
	}
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT zasp_connector_maintenance.projection_profile_state()`).Scan(&raw); err != nil {
		return nil, projectionDatabaseError(err)
	}
	state, err := decodeApprovalMaintenanceProfileState(raw)
	if err != nil || !state.CatalogReady {
		return nil, ErrUnavailable
	}
	if connectorPin == "" {
		if state.Active {
			return nil, ErrUnavailable
		}
		return NewCurrentProjectionRepository(ctx, pool, approvalPin)
	}
	if connectorPin != state.Checksum || approvalPin == "" || !state.Active {
		return nil, ErrInvalid
	}
	// Original approval selector performs its closed catalog/pin admission too.
	if _, err := NewCurrentProjectionRepository(ctx, pool, approvalPin); err != nil {
		return nil, err
	}
	base, err := NewPostgresProjectionRepository(pool)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return &ConnectorMaintenanceProjectionRepository{base, approvalPin, connectorPin}, nil
}

func (r *ConnectorMaintenanceProjectionRepository) WithOrganization(ctx context.Context, org string, fn func(ProjectionSession) error) error {
	if r == nil || r.PostgresProjectionRepository == nil || fn == nil {
		return ErrInvalid
	}
	return r.PostgresProjectionRepository.WithOrganization(ctx, org, func(s ProjectionSession) error {
		original, ok := s.(*postgresProjectionSession)
		if !ok || original == nil {
			return ErrInvalid
		}
		return fn(&connectorMaintenanceProjectionSession{original, r.approvalPin, r.connectorPin})
	})
}

type connectorMaintenanceProjectionSession struct {
	*postgresProjectionSession
	approvalPin, connectorPin string
}

func (s *connectorMaintenanceProjectionSession) Snapshot(ctx context.Context) (ProjectionSnapshot, error) {
	var result ProjectionSnapshot
	if s == nil || s.postgresProjectionSession == nil || ctx == nil || ctx.Err() != nil {
		return result, ErrInvalid
	}
	var raw []byte
	if err := s.conn.QueryRow(ctx, `SELECT zasp_connector_maintenance.snapshot($1,$2,$3)`, s.organizationID, s.approvalPin, s.connectorPin).Scan(&raw); err != nil {
		return result, projectionDatabaseError(err)
	}
	if json.Unmarshal(raw, &result) != nil || ctx.Err() != nil {
		return result, ErrInvalid
	}
	return result, nil
}
