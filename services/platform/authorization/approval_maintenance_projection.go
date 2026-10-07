package authorization

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ApprovalMaintenanceProjectionRepository composes the registered delivery
// grants into the original projection session. It does not activate a module,
// withdraw an old writer, or establish permission to use a different profile.
// Deployment must withdraw the old external projector and its FGA credential
// before activation; the shared SQL login remains available to other consumers.
type ApprovalMaintenanceProjectionRepository struct {
	*PostgresProjectionRepository
	sourceChecksum string
}

type CurrentProjectionRepository interface {
	ProjectionRepository
	Revision(context.Context, string) (Revision, error)
	Pending(context.Context, int) ([]PendingProjection, error)
}

// NewCurrentProjectionRepository makes profile selection explicit. An active
// supplementary profile cannot silently fall back to the old-only snapshot.
// A supplied checksum is accepted only against the live registered catalog.
func NewCurrentProjectionRepository(ctx context.Context, pool *pgxpool.Pool, sourceChecksum string) (CurrentProjectionRepository, error) {
	if ctx == nil || ctx.Err() != nil || pool == nil {
		return nil, ErrInvalid
	}
	var installed bool
	if err := pool.QueryRow(ctx, `SELECT to_regnamespace('zasp_approval_maintenance') IS NOT NULL`).Scan(&installed); err != nil {
		return nil, projectionDatabaseError(err)
	}
	if !installed {
		if sourceChecksum != "" {
			return nil, ErrInvalid
		}
		return NewPostgresProjectionRepository(pool)
	}
	var data []byte
	if err := pool.QueryRow(ctx, `SELECT zasp_approval_maintenance.projection_profile_state()`).Scan(&data); err != nil {
		return nil, projectionDatabaseError(err)
	}
	state, err := decodeApprovalMaintenanceProfileState(data)
	if err != nil || !state.CatalogReady {
		return nil, ErrUnavailable
	}
	if sourceChecksum == "" {
		if state.Active {
			return nil, ErrUnavailable
		}
		return NewPostgresProjectionRepository(pool)
	}
	if sourceChecksum != state.Checksum {
		return nil, ErrInvalid
	}
	return NewApprovalMaintenanceProjectionRepository(pool, sourceChecksum)
}

func NewApprovalMaintenanceProjectionRepository(pool *pgxpool.Pool, sourceChecksum string) (*ApprovalMaintenanceProjectionRepository, error) {
	decoded, err := hex.DecodeString(sourceChecksum)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != sourceChecksum {
		return nil, ErrInvalid
	}
	base, err := NewPostgresProjectionRepository(pool)
	if err != nil {
		return nil, err
	}
	return &ApprovalMaintenanceProjectionRepository{base, sourceChecksum}, nil
}

// WithOrganization retains the original advisory lock, cleanup, Stage,
// Acknowledge, CAS and known-tuple inventory. Only Snapshot changes, and its
// single SQL statement reads both grant families with the same revision.
func (r *ApprovalMaintenanceProjectionRepository) WithOrganization(ctx context.Context, organizationID string, fn func(ProjectionSession) error) error {
	if r == nil || r.PostgresProjectionRepository == nil || fn == nil {
		return ErrInvalid
	}
	return r.PostgresProjectionRepository.WithOrganization(ctx, organizationID, func(session ProjectionSession) error {
		original, ok := session.(*postgresProjectionSession)
		if !ok || original == nil {
			return ErrInvalid
		}
		return fn(&approvalMaintenanceProjectionSession{original, r.sourceChecksum})
	})
}

type approvalMaintenanceProjectionSession struct {
	*postgresProjectionSession
	sourceChecksum string
}

func (s *approvalMaintenanceProjectionSession) Snapshot(ctx context.Context) (ProjectionSnapshot, error) {
	var result ProjectionSnapshot
	if s == nil || s.postgresProjectionSession == nil || ctx == nil {
		return result, ErrInvalid
	}
	var data []byte
	if err := s.conn.QueryRow(ctx, `SELECT zasp_approval_maintenance.snapshot($1,$2)`, s.organizationID, s.sourceChecksum).Scan(&data); err != nil {
		return result, projectionDatabaseError(err)
	}
	if json.Unmarshal(data, &result) != nil {
		return result, ErrInvalid
	}
	return result, nil
}

// Fixed native metadata has an exact nonnullable grammar. Case aliases,
// duplicate fields and null flags must not silently select the legacy profile.
type approvalMaintenanceProfileState struct {
	Active       bool
	Checksum     string
	CatalogReady bool
}

func decodeApprovalMaintenanceProfileState(raw []byte) (approvalMaintenanceProfileState, error) {
	var s approvalMaintenanceProfileState
	if len(raw) == 0 || len(raw) > 512 {
		return s, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return s, ErrInvalid
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return s, ErrInvalid
		}
		seen[key] = true
		value, err := d.Token()
		if err != nil {
			return s, ErrInvalid
		}
		switch key {
		case "active":
			v, ok := value.(bool)
			if !ok {
				return s, ErrInvalid
			}
			s.Active = v
		case "catalog_ready":
			v, ok := value.(bool)
			if !ok {
				return s, ErrInvalid
			}
			s.CatalogReady = v
		case "checksum":
			v, ok := value.(string)
			decoded, e := hex.DecodeString(v)
			if !ok || e != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != v {
				return s, ErrInvalid
			}
			s.Checksum = v
		default:
			return s, ErrInvalid
		}
	}
	t, err = d.Token()
	if err != nil || t != json.Delim('}') || len(seen) != 3 {
		return s, ErrInvalid
	}
	if _, err = d.Token(); err != io.EOF {
		return s, ErrInvalid
	}
	return s, nil
}
