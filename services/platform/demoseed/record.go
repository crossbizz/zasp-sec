package demoseed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zasp-ai/zasp-sec/services/platform/demodata"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// An integration is two records with one ID: the product record the
// Integrations page lists (a workflow record: name, connector,
// configuration, status) and the discovery record the pipeline collects
// into. The product record is written with the function the product's own
// integration writes end in, which also keeps the idempotency record and
// the audit row of a creation.
//
// A demo integration is created in status "active": it never goes through
// an authorization, because there is nothing to authorize. It has no
// credential, no connection and no schedule, so no worker ever collects it.
const (
	setupValidSQL     = `SELECT zasp_authorization80.integration_setup_valid($1, $2::jsonb)`
	productRecordSQL  = `SELECT body FROM public.zasp_workflow_records WHERE (organization_id, workspace_id, environment_id, kind, id) = ($1, $2, $3, 'integration', $4) AND deleted_at IS NULL`
	workflowCreateSQL = `SELECT zasp_workflow_mutate_v3('create', 'integration', $4, $1, $2, $3, $5, 'createIntegration', $6, 0, $7::jsonb, $8::jsonb, $9, $10)`
)

// ensureProductRecord creates the product record of a demo integration, or
// finds the one an earlier seeding created.
func ensureProductRecord(ctx context.Context, tx pgx.Tx, scope domain.Scope, id domain.ProductID, principal string, integration demodata.Integration, now time.Time) error {
	o, w, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	setup, err := json.Marshal(integration.Configuration)
	if err != nil {
		return err
	}
	// The product's own rule for the configuration of this connector.
	var valid bool
	if err := tx.QueryRow(ctx, setupValidSQL, integration.Provider, string(setup)).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("%w: the configuration of %s is not one the product accepts for connector %q", demodata.ErrDataset, integration.Key, integration.Provider)
	}
	var stored []byte
	switch err := tx.QueryRow(ctx, productRecordSQL, o, w, e, id.String()).Scan(&stored); {
	case err == nil:
		var existing struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(stored, &existing) != nil || len(existing.Name) < len(demodata.NamePrefix) || existing.Name[:len(demodata.NamePrefix)] != demodata.NamePrefix {
			return fmt.Errorf("%w: integration %s exists and is not a demo integration", ErrNotDemo, id)
		}
		return nil
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	at := now.UTC().Format(time.RFC3339)
	body, err := json.Marshal(map[string]any{"id": id.String(), "connector_key": integration.Provider, "name": integration.Name, "configuration": integration.Configuration, "status": "active", "created_at": at, "updated_at": at})
	if err != nil {
		return err
	}
	intent, err := json.Marshal(map[string]any{"resource_id": id.String(), "connector_key": integration.Provider, "name": integration.Name})
	if err != nil {
		return err
	}
	audit, err := newID()
	if err != nil {
		return err
	}
	correlation, err := newID()
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte("zasp-demo-create\x1f" + id.String()))
	var result []byte
	if err := tx.QueryRow(ctx, workflowCreateSQL, o, w, e, id.String(), principal, "demo-seed-"+hex.EncodeToString(digest[:12]), string(intent), string(body), audit, correlation).Scan(&result); err != nil {
		return fmt.Errorf("create the integration record of %s: %w", integration.Key, err)
	}
	return nil
}
