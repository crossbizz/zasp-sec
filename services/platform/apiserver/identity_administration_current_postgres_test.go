package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func TestP7IdentityAdministrationCurrentPostgres(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires retained local OpenFGA; creates an owned store")
	}
	t.Setenv("ZASP_P7_AUDIT_TEST", "1")
	t.Setenv("ZASP_P7_IDENTITY_TEST", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	migrateP7Authorization(t, ctx, owner)
	exec := func(q string, a ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, a...); err != nil {
			t.Fatal(err)
		}
	}
	for _, purpose := range []string{"session", "webhook"} {
		k := sha256.Sum256([]byte("identity-admin-fixture-" + purpose))
		v := sha256.Sum256(k[:])
		exec(`SELECT zasp_authorization80_identity.register_`+purpose+`($1,$2,$3,'project-test-identity80','auth80_api','')`, hex.EncodeToString(v[:]), k[:], strings.Repeat("a", 64))
	}
	i := fixtureRequestIdentity(t)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const target = "pid_99000001-0000-4000-8000-000000000001"
	const investigated = "session-identity-investigated"
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Identity admin','identity-admin.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Identity admin')`, o, w)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Identity admin','production')`, o, w, e)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-identity-admin','member-identity-admin','security_admin',true),($3,$2,'organization-identity-admin','member-identity-target','security_engineer',true)`, p, o, target)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Actor','[]',true),($5,$2,$3,$4,'Target','[]',true)`, p, o, w, e, target)
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('identity-admin-browser-01234567890123456789','sha256'),'session-identity-admin',$1,$2,$3,$4,'[]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour'),(digest('identity-target-browser-01234567890123456789','sha256'),$5,$6,$2,$3,$4,'[]',repeat('y',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, p, o, w, e, investigated, target)
	pc, _ := pgxpool.ParseConfig(dsn)
	pc.ConnConfig.User = "auth80_outbox"
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	projection, _ := authorization.NewPostgresProjectionRepository(pool)
	client, pins := newAuthorizationProjectionFGA(t)
	writer, err := authorization.NewOpenFGATupleWriter(client, pins)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := authorization.NewOpenFGA(client, pins)
	if err != nil {
		t.Fatal(err)
	}
	exec(`SELECT zasp_authorization79.configure($1,$2,$3)`, o, pins.StoreID, pins.ModelID)
	reconcile := func() {
		t.Helper()
		r, err := authorization.Reconcile(ctx, projection, writer, o, pins.StoreID, pins.ModelID)
		if err != nil || !r.Applied {
			t.Fatalf("reconcile=%+v error=%v", r, err)
		}
	}
	reconcile()
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer api.Close(context.Background())
	db, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	if err := db.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repo, err := NewPostgresRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	i, err = repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: "identity-admin-browser-01234567890123456789"})
	if err != nil {
		t.Fatal(err)
	}
	resolver, _ := NewPostgresAuthorizationResolver(db)
	authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: pins.StoreID, ModelID: pins.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	sequence := 100
	id := func() string { sequence++; return fmt.Sprintf("pid_99000000-0000-4000-8000-%012d", sequence) }
	checked := func(m administrationMutation) (json.RawMessage, error) {
		t.Helper()
		reconcile()
		g, err := authorizer.Authorize(ctx, i, i.credentialBinding, RoutedOperation{OperationID: m.Operation, PathParameters: map[string]string{"id": m.ID}})
		if err != nil {
			t.Fatalf("actual FGA %s: %v", m.Operation, err)
		}
		return repo.MutateAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, g), i, m)
	}
	read := func(op, id string) (json.RawMessage, error) {
		t.Helper()
		reconcile()
		g, err := authorizer.Authorize(ctx, i, i.credentialBinding, RoutedOperation{OperationID: op, PathParameters: map[string]string{"id": id}})
		if err != nil {
			t.Fatal(err)
		}
		return repo.ReadAdministration(context.WithValue(ctx, requestAuthorizationContextKey{}, g), i, op, map[string]string{"id": id})
	}
	t.Run("investigated-session", func(t *testing.T) {
		m := administrationMutation{Operation: "revokeSession", ID: investigated, ExpectedVersion: 1, AuditID: id()}
		if _, err := checked(m); err != nil {
			t.Errorf("checked investigated revoke: %v", err)
			return
		}
		var revoked bool
		if err := owner.QueryRow(ctx, `SELECT revoked_at IS NOT NULL AND version=2 FROM zasp_product_sessions WHERE session_id=$1`, investigated).Scan(&revoked); err != nil || !revoked {
			t.Errorf("investigated effect=%v %v", revoked, err)
		}
	})
	t.Run("member-role", func(t *testing.T) {
		m := administrationMutation{Operation: "updateMemberRole", ID: target, Role: "read_only_viewer", ExpectedVersion: 1, AuditID: id()}
		reconcile()
		proof, err := authorizer.Authorize(ctx, i, i.credentialBinding, RoutedOperation{OperationID: m.Operation, PathParameters: map[string]string{"id": target}})
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := authorizationProofJSON(proof)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := api.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT zasp_authorization80.fence($1)`, string(envelope)); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, currentMemberRoleSQL, o, target, m.Role, int64(1), w, e, m.AuditID, target)
		requireIdentityRefusal(t, err)
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		stale := m
		stale.ExpectedVersion = 999
		if _, err := checked(stale); err == nil {
			t.Fatal("stale member version accepted")
		}
		var untouched bool
		if err := owner.QueryRow(ctx, `SELECT role='security_engineer' AND version=1 AND NOT EXISTS(SELECT 1 FROM zasp_admin_audit WHERE id=$2) FROM zasp_identity_memberships WHERE principal_id=$1`, target, stale.AuditID).Scan(&untouched); err != nil || !untouched {
			t.Fatalf("stale member version changed row/audit: %v %v", untouched, err)
		}
		if _, err := checked(m); err != nil {
			t.Errorf("checked member update: %v", err)
			return
		}
		var updated bool
		if err := owner.QueryRow(ctx, `SELECT role='read_only_viewer' AND version=2 FROM zasp_identity_memberships WHERE organization_id=$1 AND principal_id=$2`, o, target).Scan(&updated); err != nil || !updated {
			t.Errorf("role effect=%v %v", updated, err)
		}
	})
	t.Run("PAT-lifecycle", func(t *testing.T) {
		key := []byte("0123456789abcdef0123456789abcdef")
		raw := "zasp_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		m := administrationMutation{Operation: "createAPIToken", ID: id(), Name: "Identity checked", WorkspaceID: w, EnvironmentID: e, Permissions: json.RawMessage(`["view"]`), ExpiresAt: time.Now().UTC().Add(time.Hour), IdempotencyKey: "identity-admin-create-1", GrantID: id(), AuditID: id(), revealKey: key}
		if err := prepareAPITokenReveal(i, &m, m.Operation, raw, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		first, err := checked(m)
		if err != nil {
			t.Errorf("checked PAT create: %v", err)
			return
		}
		if bytes.Contains(first, []byte(raw)) {
			t.Fatal("raw token in mutation output")
		}
		if replay, err := checked(m); err != nil || !bytes.Equal(first, replay) {
			t.Errorf("PAT exact replay differs: %v", err)
		}
		for _, op := range []string{"listAPITokens", "listAPITokenRevealGrants"} {
			if payload, err := read(op, ""); err != nil || !bytes.Contains(payload, []byte(m.ID)) {
				t.Errorf("checked %s missing created token: %v", op, err)
			}
		}
		var envelope apiTokenRevealEnvelope
		if payload, err := read("revealAPIToken", m.GrantID); err != nil || json.Unmarshal(payload, &envelope) != nil {
			t.Errorf("checked encrypted reveal: %v", err)
		} else if revealed, err := decryptAPITokenReveal(key, i, envelope); err != nil || revealed != raw {
			t.Errorf("checked reveal cryptographic binding: %v", err)
		}
		if _, err := repo.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: raw}); err != nil {
			t.Errorf("created PAT authentication: %v", err)
		}
		rotated := "zasp_pat_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		r := administrationMutation{Operation: "rotateAPIToken", ID: m.ID, ReplacementID: id(), ExpectedVersion: 1, IdempotencyKey: "identity-admin-rotate-1", GrantID: id(), AuditID: id(), revealKey: key}
		if err := prepareAPITokenReveal(i, &r, r.Operation, rotated, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if _, err := checked(r); err != nil {
			t.Errorf("checked PAT rotate: %v", err)
			return
		}
		if _, err := repo.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: raw}); err == nil {
			t.Error("old PAT accepted after rotation")
		}
		if _, err := repo.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: rotated}); err != nil {
			t.Errorf("rotated PAT authentication: %v", err)
		}
		ack := administrationMutation{Operation: "acknowledgeAPITokenRevealGrant", ID: r.GrantID, AuditID: id()}
		if _, err := checked(ack); err != nil {
			t.Errorf("checked reveal acknowledgement: %v", err)
		}
		var destroyed bool
		if err := owner.QueryRow(ctx, `SELECT acknowledged_at IS NOT NULL AND ciphertext IS NULL AND nonce IS NULL AND authentication_tag IS NULL FROM zasp_api_token_reveal_grants WHERE grant_id=$1`, r.GrantID).Scan(&destroyed); err != nil || !destroyed {
			t.Errorf("reveal retained after ack: %v %v", destroyed, err)
		}
		revoke := administrationMutation{Operation: "revokeAPIToken", ID: r.ReplacementID, ExpectedVersion: 1, AuditID: id()}
		if _, err := checked(revoke); err != nil {
			t.Errorf("checked PAT revoke: %v", err)
		}
		if _, err := repo.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: rotated}); err == nil {
			t.Error("revoked PAT accepted")
		}
	})
	t.Run("group-mapping-cannot-take-foreign-scope", func(t *testing.T) {
		foreign := id()
		exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Foreign','production')`, o, w, foreign)
		exec(`INSERT INTO zasp_group_mappings(organization_id,group_reference,role,workspace_id,environment_id,version) VALUES($1,'scim-group-test-foreign','read_only_viewer',$2,$3,1)`, o, w, foreign)
		m := administrationMutation{Operation: "updateGroupMappings", ID: "scim-group-test-foreign", Role: "security_admin", WorkspaceID: w, EnvironmentID: e, ExpectedVersion: 1, AuditID: id()}
		if _, err := checked(m); err == nil {
			t.Error("current-scope proof took an existing foreign-scope mapping")
		}
		var unchanged bool
		if err := owner.QueryRow(ctx, `SELECT environment_id=$2 AND role='read_only_viewer' AND version=1 FROM zasp_group_mappings WHERE organization_id=$1 AND group_reference='scim-group-test-foreign'`, o, foreign).Scan(&unchanged); err != nil || !unchanged {
			t.Errorf("foreign mapping changed: %v %v", unchanged, err)
		}
	})
	t.Run("group-mapping-org-revocation", func(t *testing.T) {
		m := administrationMutation{Operation: "updateGroupMappings", ID: "scim-group-test-identity-admin", Role: "read_only_viewer", WorkspaceID: w, EnvironmentID: e, ExpectedVersion: 0, AuditID: id()}
		if _, err := checked(m); err != nil {
			t.Errorf("checked mapping upsert: %v", err)
			return
		}
		var active int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_product_sessions WHERE organization_id=$1 AND revoked_at IS NULL`, o).Scan(&active); err != nil || active != 0 {
			t.Errorf("mapping left active sessions=%d %v", active, err)
		}
	})
}
