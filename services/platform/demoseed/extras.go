package demoseed

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/zasp-ai/zasp-sec/services/platform/demodata"
)

const (
	registryEntrySQL = `SELECT status, note, version FROM public.zasp_mcp_registry WHERE (organization_id, workspace_id, environment_id, identity) = ($1, $2, $3, $4)`
	// The function the registry's API operation ends in. It records who
	// decided and writes the registry's audit row.
	registryPutSQL = `SELECT zasp_mcp_registry_put($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
)

// seedRegistry records the dataset's approved-servers decisions, made by
// the person the demo is for. A decision that is already recorded as stated
// is left alone, so a second seeding writes nothing.
func seedRegistry(ctx context.Context, tx pgx.Tx, resolved target) (int, error) {
	decisions, err := demodata.RegistryDecisions()
	if err != nil {
		return 0, err
	}
	o, w, e := resolved.scope.OrganizationID().String(), resolved.scope.WorkspaceID().String(), resolved.scope.EnvironmentID().String()
	written := 0
	for _, decision := range decisions {
		var status, note string
		var version int64
		switch err := tx.QueryRow(ctx, registryEntrySQL, o, w, e, decision.Identity).Scan(&status, &note, &version); {
		case errors.Is(err, pgx.ErrNoRows):
			version = 0
		case err != nil:
			return 0, err
		case status == decision.Status && note == decision.Note:
			continue
		}
		audit, err := newID()
		if err != nil {
			return 0, err
		}
		correlation, err := newID()
		if err != nil {
			return 0, err
		}
		var result []byte
		if err := tx.QueryRow(ctx, registryPutSQL, o, w, e, resolved.principal, decision.Identity, decision.Status, decision.Note, version, audit, correlation).Scan(&result); err != nil {
			return 0, fmt.Errorf("record the registry decision for %s: %w", decision.Identity, err)
		}
		written++
	}
	return written, nil
}

// seedExtras writes what is not discovery and does not feed the findings.
// It returns one line per thing it wrote.
func (seeder *Seeder) seedExtras(ctx context.Context, resolved target) ([]string, error) {
	return nil, nil
}
