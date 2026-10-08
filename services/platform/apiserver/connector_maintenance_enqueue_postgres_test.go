package apiserver

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This is original native80/browser/FGA admission, not an active worker fixture.
// It never seeds a task, delegation, service grant or activation record.
func TestConnectorMaintenanceAuthenticatedOAuthEnqueuePostgres(t *testing.T) {
	f := newIntegrationClientFixture(t, true)
	f.freshReferenceSession(t)
	runner, err := migrations.NewRunner(&orderedAdmissionMigrationDatabase{connection: f.owner, t: t})
	if err != nil {
		t.Fatal("original native runner unavailable")
	}
	before := connectorProvenanceNativeState(t, f)
	if err := runner.UpProductionApprovalMaintenanceProfile(f.ctx); err != nil {
		t.Fatal("original approval profile unavailable")
	}
	if err := runner.UpProductionConnectorMaintenance(f.ctx); err != nil {
		t.Fatal("connector profile installation refused")
	}
	if connectorProvenanceNativeState(t, f) != before {
		t.Fatal("supplementary install changed original native state")
	}
	grant, err := f.authorizer.Authorize(f.ctx, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: "authorizeIntegration", PathParameters: map[string]string{"id": integrationClientExisting}})
	if err != nil {
		t.Fatal("original signed browser admission refused")
	}
	rawProof, err := authorizationProofJSON(grant)
	if err != nil {
		t.Fatal("original signed browser proof unavailable")
	}
	var version int64
	var configuration json.RawMessage
	if err := f.owner.QueryRow(f.ctx, `SELECT version,body->'configuration' FROM public.zasp_workflow_records WHERE(organization_id,workspace_id,environment_id,kind,id)=($1,$2,$3,'integration',$4) AND deleted_at IS NULL`, f.browser.Scope.OrganizationID().String(), f.browser.Scope.WorkspaceID().String(), f.browser.Scope.EnvironmentID().String(), integrationClientExisting).Scan(&version, &configuration); err != nil {
		t.Fatal("original committed integration unavailable")
	}
	request := sha256.Sum256([]byte("native authentic OAuth enqueue request"))
	state := sha256.Sum256([]byte("native authentic OAuth enqueue state"))
	attempt := "pid_78218101-0000-4000-8000-000000000001"
	cleanup := connectorDeterministicID(f.browser.Scope, attempt, "pkce-cleanup")
	authorize := connectorDeterministicID(f.browser.Scope, attempt, "oauth-effect")
	expires := time.Now().UTC().Add(5 * time.Minute).Truncate(time.Microsecond)
	args := []any{string(rawProof), f.browser.Scope.OrganizationID().String(), f.browser.Scope.WorkspaceID().String(), f.browser.Scope.EnvironmentID().String(), attempt, integrationClientExisting, "github", f.browser.PrincipalID.String(), grant.Credential.Digest[:], state[:], "ref:oauth/pkce/native-enqueue", request[:], `["read:org"]`, expires, version, configuration, cleanup, authorize}
	const query = `SELECT zasp_connector_maintenance.start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16::jsonb,$17,$18)`
	t.Run("genuine same transaction origin and immutable enrichment", func(t *testing.T) {
		tx, err := f.api.Begin(f.ctx)
		if err != nil {
			t.Fatal("registered API transaction unavailable")
		}
		defer connectorProvenanceRollback(tx)
		var result []byte
		if err := tx.QueryRow(f.ctx, query, args...).Scan(&result); err != nil {
			t.Fatal("genuine authenticated OAuth enqueue refused")
		}
		if !json.Valid(result) {
			t.Fatal("original OAuth response malformed")
		}
		if err := tx.Commit(f.ctx); err != nil {
			t.Fatal("authenticated enqueue commit refused")
		}
		var valid bool
		if err := f.owner.QueryRow(f.ctx, `SELECT
   (SELECT count(*)=2 FROM zasp_connector_maintenance.tasks WHERE effect_id IN($1,$2) AND state='captured_inactive')
   AND EXISTS(SELECT 1 FROM zasp_connector_provenance.origins o JOIN zasp_connector_maintenance.tasks t USING(organization_id,workspace_id,environment_id,effect_id) JOIN zasp_connector_maintenance.oauth_enrichments x USING(organization_id,workspace_id,environment_id,effect_id) WHERE o.effect_id=$1 AND o.committed_effect_digest=t.committed_effect_digest AND x.previous_effect_digest=o.committed_effect_digest AND x.enriched_effect_digest<>x.previous_effect_digest AND x.previous_effect->'oauth_attempt_id'='null'::jsonb AND x.enriched_effect->>'oauth_attempt_id'=$3 AND t.captured_effect=x.previous_effect)
   AND EXISTS(SELECT 1 FROM zasp_connector_maintenance.enqueue_origins o JOIN zasp_connector_maintenance.tasks t USING(organization_id,workspace_id,environment_id,effect_id) WHERE o.effect_id=$2 AND o.operation='authorize' AND o.committed_effect_digest=t.committed_effect_digest AND o.source_proof_digest=t.source_proof_digest)
   AND NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.creation_witness)
   AND NOT EXISTS(SELECT 1 FROM zasp_connector_provenance.creation_witness)
   AND NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.projection_activations)
   AND EXISTS(SELECT 1 FROM zasp_connector_maintenance.registration WHERE singleton AND NOT active)`, cleanup, authorize, attempt).Scan(&valid); err != nil || !valid {
			t.Fatal("genuine origin or append-only inactive task provenance missing")
		}
	})
	t.Run("rollback removes every enqueue and provenance write", func(t *testing.T) {
		before := connectorProvenanceBusinessState(t, f)
		attemptState := func() string {
			var digest string
			if err := f.owner.QueryRow(f.ctx, `SELECT encode(public.digest(convert_to(COALESCE(jsonb_agg(to_jsonb(a) ORDER BY organization_id,workspace_id,environment_id,id)::text,'[]'),'UTF8'),'sha256'),'hex') FROM public.zasp_connector_oauth_attempts a`).Scan(&digest); err != nil {
				t.Fatal("original OAuth attempt state unavailable")
			}
			return digest
		}
		beforeAttempts := attemptState()
		fresh, err := f.authorizer.Authorize(f.ctx, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: "authorizeIntegration", PathParameters: map[string]string{"id": integrationClientExisting}})
		if err != nil {
			t.Fatal("fresh original admission refused")
		}
		freshProof, err := authorizationProofJSON(fresh)
		if err != nil {
			t.Fatal("fresh original proof unavailable")
		}
		tx, err := f.api.Begin(f.ctx)
		if err != nil {
			t.Fatal("registered API transaction unavailable")
		}
		defer connectorProvenanceRollback(tx)
		next := append([]any(nil), args...)
		next[0] = string(freshProof)
		// The unchanged original application denies a competing pending attempt.
		// This is a real native refusal and must leave supplementary rows unchanged.
		next[4] = "pid_78218102-0000-4000-8000-000000000001"
		next[16] = connectorDeterministicID(f.browser.Scope, next[4].(string), "pkce-cleanup")
		next[17] = connectorDeterministicID(f.browser.Scope, next[4].(string), "oauth-effect")
		var result []byte
		var native *pgconn.PgError
		if err := tx.QueryRow(f.ctx, query, next...).Scan(&result); !errors.As(err, &native) || native.Code != "23505" {
			t.Fatal("original competing pending attempt unexpectedly admitted")
		}
		connectorProvenanceRollback(tx)
		var untouched bool
		if err := f.owner.QueryRow(f.ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.tasks WHERE effect_id IN($1,$2)) AND NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.enqueue_origins WHERE effect_id=$2) AND NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.oauth_enrichments WHERE effect_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.creation_witness)`, next[16], next[17]).Scan(&untouched); err != nil || !untouched || connectorProvenanceBusinessState(t, f) != before || attemptState() != beforeAttempts {
			t.Fatal("native refusal left enqueue, task, witness or provenance mutation")
		}
	})
}
