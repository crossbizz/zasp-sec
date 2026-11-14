package demoseed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/zasp-ai/zasp-sec/services/platform/demodata"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// The statements of the discovery pipeline the seeder runs. They are the
// functions the discovery worker's own statements end in: the integration
// record, the snapshot application, the finding projection and the posture
// refresh. The seeder calls them as the migration operator, who is a member
// of the authority role that owns them (zasp_discovery_authority).
//
// What the seeder does not use is the job machinery around them (the sync
// request's outbox event, the leased job, the workflow run): a queued job
// would make the deployment's discovery worker try to collect the demo
// integration from a real provider. The sync row is therefore written
// directly, already claimed, and closed by the snapshot application.
const (
	createIntegrationSQL     = `SELECT zasp_discovery_create_integration($1,$2,$3,$4,$5,$6,$7,$8::jsonb,NULL)`
	transitionIntegrationSQL = `SELECT zasp_discovery_transition_integration($1,$2,$3,$4,$5,$6)`
	integrationStateSQL      = `SELECT state,version,configuration FROM public.zasp_integrations WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`
	insertSyncSQL            = `INSERT INTO public.zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,state,attempt,parser_version,tool_version,started_at) VALUES($1,$2,$3,$4,$5,$6,$7,'manual',$8,'running',1,$9,$10,transaction_timestamp())`
	nextGenerationSQL        = `SELECT COALESCE(max(generation),0)+1 FROM public.zasp_discovery_snapshots WHERE (organization_id,workspace_id,environment_id,integration_id)=($1,$2,$3,$4)`
	applySnapshotSQL         = `SELECT zasp_discovery_apply_snapshot($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15::jsonb,$16::jsonb)`
	cancelProjectionSQL      = `UPDATE public.zasp_projection_work SET state='cancelled',completed_at=transaction_timestamp(),last_error='demo snapshot: projected by the demo seeder' WHERE (organization_id,workspace_id,environment_id,snapshot_id)=($1,$2,$3,$4) AND state='pending' AND attempt=0`
	applyFindingsSQL         = `SELECT zasp_inventory_apply_findings($1,$2,$3,$4::jsonb)`
	refreshPostureSQL        = `SELECT zasp_inventory_refresh_posture_findings($1,$2,$3)`
)

// connectorVersion is the version every demo integration is created with.
const connectorVersion = "1.0.0"

// integrationID is the ID of a dataset integration in a scope. It depends
// only on the scope and the integration's key, which is what makes a second
// seeding refresh the same integration instead of adding one.
func integrationID(scope domain.Scope, key string) domain.ProductID {
	digest := sha256.Sum256([]byte("zasp-demo-integration\x1f" + scope.OrganizationID().String() + "\x1f" + scope.WorkspaceID().String() + "\x1f" + scope.EnvironmentID().String() + "\x1f" + key))
	text := hex.EncodeToString(digest[:])
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%s-%s-4%s-8%s-%s", text[:8], text[8:12], text[13:16], text[17:20], text[20:32]))
	if err != nil {
		panic("demoseed: integration ID: " + err.Error())
	}
	return id
}

func newID() (string, error) {
	id, err := domain.NewProductID()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// configuration is the stored configuration of a demo integration: what the
// fixture says a person would have entered, and the marker.
func configuration(integration demodata.Integration) (string, error) {
	document := map[string]any{demodata.Marker: datasetName}
	for name, value := range integration.Configuration {
		document[name] = value
	}
	encoded, err := json.Marshal(document)
	return string(encoded), err
}

// ensureIntegration creates the integration, or finds the one an earlier
// seeding created, and leaves it active.
func ensureIntegration(ctx context.Context, tx pgx.Tx, scope domain.Scope, integration demodata.Integration) (id domain.ProductID, created bool, err error) {
	id = integrationID(scope, integration.Key)
	stored, err := configuration(integration)
	if err != nil {
		return id, false, err
	}
	o, w, e := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	var state string
	var version int64
	var existing []byte
	switch err := tx.QueryRow(ctx, integrationStateSQL, o, w, e, id.String()).Scan(&state, &version, &existing); {
	case err == pgx.ErrNoRows:
		created = true
		var result []byte
		if err := tx.QueryRow(ctx, createIntegrationSQL, o, w, e, id.String(), integration.Provider, connectorVersion, integration.Name, stored).Scan(&result); err != nil {
			return id, false, fmt.Errorf("create integration %s: %w", integration.Key, err)
		}
		state, version = "pending", 1
	case err != nil:
		return id, false, err
	default:
		var marker map[string]any
		if json.Unmarshal(existing, &marker) != nil || marker[demodata.Marker] != datasetName {
			return id, false, fmt.Errorf("%w: integration %s exists and is not a demo integration", ErrNotDemo, id)
		}
	}
	switch state {
	case "active":
	case "pending", "authorizing", "degraded", "disabled":
		var result []byte
		if err := tx.QueryRow(ctx, transitionIntegrationSQL, o, w, e, id.String(), version, "active").Scan(&result); err != nil {
			return id, false, fmt.Errorf("activate integration %s: %w", integration.Key, err)
		}
	default:
		// A deleted integration keeps its ID. `remove` leaves none behind,
		// so this is an integration a person deleted in the product.
		return id, false, fmt.Errorf("%w: integration %q was deleted in the product; run remove, then seed", ErrConflict, integration.Name)
	}
	return id, created, nil
}

// finding is one discovery finding of a snapshot, in the form the finding
// projection takes.
type finding struct {
	FindingID  string `json:"finding_id"`
	EntityID   string `json:"entity_id"`
	CheckID    string `json:"check_id"`
	EvidenceID string `json:"evidence_id"`
	Source     string `json:"source"`
}
