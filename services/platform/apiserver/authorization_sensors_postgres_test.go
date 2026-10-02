package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type sensorCheckBarrier struct {
	inner RequestAuthorizer
	after func()
}

func (b *sensorCheckBarrier) Authorize(c context.Context, i RequestIdentity, k CredentialBinding, r RoutedOperation) (RequestAuthorization, error) {
	grant, err := b.inner.Authorize(c, i, k, r)
	if err == nil && b.after != nil {
		b.after()
	}
	return grant, err
}

func TestP7SensorAuthorizationPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	migrateP7Authorization(t, ctx, admin)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := admin.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	identity := fixtureRequestIdentity(t)
	identity.CSRFToken = strings.Repeat("x", 32)
	o, w, e, p := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Sensor authority','sensor-auth.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Sensors')`, o, w)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, o, w, e)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-sensor80','member-sensor80','security_admin',true)`, p, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Production','["view"]',true)`, p, o, w, e)
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('sensor80-credential','sha256'),'session-sensor80',$1,$2,$3,$4,'["view"]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, p, o, w, e)
	ids := []string{"pid_88000001-0000-4000-8000-000000000001", "pid_88000002-0000-4000-8000-000000000002", "pid_88000003-0000-4000-8000-000000000003"}
	for n, id := range ids {
		exec(`INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'Recorded sensor','tetragon','active')`, o, w, e, id)
		token := fmt.Sprintf("pid_88100000-0000-4000-8000-%012d", n+1)
		exec(`SELECT zasp_runtime_issue_sensor_token($1,$2,$3,$4,$5,1,1,digest($5,'sha256'),digest('salt','sha256'),digest($5||'hash','sha256'),clock_timestamp()+interval '1 day')`, o, w, e, id, token)
	}
	foreignEnvironment := "pid_88900001-0000-4000-8000-000000000001"
	foreignSensor := "pid_88900002-0000-4000-8000-000000000002"
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Foreign','production')`, o, w, foreignEnvironment)
	exec(`INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,state) VALUES($1,$2,$3,$4,'Foreign sensor','tetragon','active')`, o, w, foreignEnvironment, foreignSensor)
	config, _ := pgxpool.ParseConfig(dsn)
	config.ConnConfig.User = "auth80_outbox"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	projection, _ := authorization.NewPostgresProjectionRepository(pool)
	store, model := "01K00000000000000000000001", "01K00000000000000000000002"
	exec(`SELECT zasp_authorization79.configure($1,$2,$3)`, o, store, model)
	reconcile := func() {
		t.Helper()
		if _, err := authorization.Reconcile(ctx, projection, &authorizationTestWriter{}, o, store, model); err != nil {
			t.Fatal(err)
		}
	}
	reconcile()
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer api.Close(context.Background())
	database, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	database.currentAuthorization = true
	repository, err := NewSensorPublicRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	resolver, _ := NewPostgresAuthorizationResolver(database)
	checker := authorizationDecisionFixture{allow: map[string]bool{ids[1]: true, ids[2]: true, e: true}, model: model}
	authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: checker, Resolver: resolver, StoreID: store, ModelID: model, AttestationKey: authorizationFixtureAttestor(t)}
	identity.credentialBinding = CredentialBinding{Kind: CredentialBrowserSession, ID: "session-sensor80", Digest: sha256.Sum256([]byte("sensor80-credential"))}
	barrier := &sensorCheckBarrier{inner: authorizer}
	handler, err := NewSensorPublicHTTPHandler(repository, bytes.Repeat([]byte{0x55}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var operations []Operation
	for _, name := range []string{"listSensors", "getSensor", "getSensorCoverage", "createSensorEnrollment", "updateSensor", "deleteSensor", "rotateSensorToken"} {
		policy, err := authorization.LookupOperation(name)
		if err != nil {
			t.Fatal(err)
		}
		operations = append(operations, Operation{Method: policy.Method, Pattern: policy.Path, OperationID: name, Permission: policy.Permission, Security: []CredentialKind{CredentialBrowserSession}, RequireCSRF: policy.Method != "GET", RequireFreshAuth: policy.FreshAuth, Handler: handler})
	}
	router, err := NewRouter(operations)
	if err != nil {
		t.Fatal(err)
	}
	router.(*operationRouter).authorizer = barrier
	call := func(method, path, body, key string, version int) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
		request.Header.Set("Origin", "https://console.example")
		request.Header.Set("X-CSRF-Token", identity.CSRFToken)
		request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		if version > 0 {
			request.Header.Set("If-Match", fmt.Sprintf("%q", fmt.Sprint(version)))
		}
		c := context.WithValue(ctx, identityContextKey{}, identity)
		c = context.WithValue(c, browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://console.example"})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request.WithContext(c))
		return response
	}
	counts := func() (int, int) {
		t.Helper()
		var receipts, audits int
		if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_runtime_sensor_mutations),(SELECT count(*) FROM zasp_admin_audit WHERE action LIKE 'sensor.%')`).Scan(&receipts, &audits); err != nil {
			t.Fatal(err)
		}
		return receipts, audits
	}
	t.Run("denied-first page and exact reads", func(t *testing.T) {
		response := call("GET", "/api/v1/sensors?limit=1", "", "", 0)
		var page struct {
			Items    []ProductSensor
			PageInfo struct {
				Cursor string `json:"next_cursor"`
			} `json:"page_info"`
		}
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].ID != ids[1] {
			t.Fatalf("denied-first list: status=%d items=%v", response.Code, page.Items)
		}
		next := call("GET", "/api/v1/sensors?limit=1&cursor="+page.PageInfo.Cursor, "", "", 0)
		if next.Code != 200 || json.Unmarshal(next.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].ID != ids[2] {
			t.Fatalf("allowed continuation: status=%d items=%v", next.Code, page.Items)
		}
		for _, suffix := range []string{"", "/coverage"} {
			if response := call("GET", "/api/v1/sensors/"+ids[1]+suffix, "", "", 0); response.Code != 200 {
				t.Fatalf("allowed read%s status=%d", suffix, response.Code)
			}
			if response := call("GET", "/api/v1/sensors/"+ids[0]+suffix, "", "", 0); response.Code != 403 {
				t.Fatalf("denied read%s status=%d", suffix, response.Code)
			}
			if response := call("GET", "/api/v1/sensors/"+foreignSensor+suffix, "", "", 0); response.Code != 403 {
				t.Fatalf("foreign read%s status=%d", suffix, response.Code)
			}
		}
		checker.allow[ids[1]], checker.allow[ids[2]] = false, false
		empty := call("GET", "/api/v1/sensors?limit=1", "", "", 0)
		checker.allow[ids[1]], checker.allow[ids[2]] = true, true
		page.PageInfo.Cursor = ""
		if empty.Code != 200 || json.Unmarshal(empty.Body.Bytes(), &page) != nil || len(page.Items) != 0 || page.PageInfo.Cursor != "" {
			t.Fatalf("empty allow set exposed sensors: status=%d items=%d", empty.Code, len(page.Items))
		}
		if _, err := repository.ListSensors(ctx, identity.Scope, "", 1); err == nil {
			t.Fatal("missing current proof accepted")
		}
	})
	t.Run("credential and target changes abort before mutation", func(t *testing.T) {
		receipts, audits := counts()
		barrier.after = func() {
			exec(`UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE session_id='session-sensor80'`)
		}
		response := call("PATCH", "/api/v1/sensors/"+ids[2], `{"name":"Must not commit","mode":"metadata_only"}`, "sensor-stale-credential", 1)
		barrier.after = nil
		exec(`UPDATE zasp_product_sessions SET revoked_at=NULL WHERE session_id='session-sensor80'`)
		if response.Code != 409 {
			t.Fatalf("revoked credential mutation status=%d", response.Code)
		}
		barrier.after = func() {
			exec(`UPDATE zasp_sensors SET version=version+1 WHERE id=$1`, ids[2])
			reconcile()
		}
		response = call("PATCH", "/api/v1/sensors/"+ids[2], `{"name":"Must not commit","mode":"metadata_only"}`, "sensor-stale-target-version", 1)
		barrier.after = nil
		if response.Code != 409 {
			t.Fatalf("changed target mutation status=%d", response.Code)
		}
		if r, a := counts(); r != receipts || a != audits {
			t.Fatal("stale credential/target committed receipt or audit")
		}
		var name string
		if err := admin.QueryRow(ctx, `SELECT name FROM zasp_sensors WHERE id=$1`, ids[2]).Scan(&name); err != nil || name != "Recorded sensor" {
			t.Fatalf("stale effect committed: %q %v", name, err)
		}
	})
	t.Run("fresh checked mutations and audit are atomic", func(t *testing.T) {
		for n, tc := range []struct {
			name, method, path, body string
			version, status          int
		}{
			{"createSensorEnrollment", "POST", "/api/v1/sensors", `{"name":"Paired collector","kind":"otlp","mode":"metadata_only","runtime_sensor_id":"` + ids[0] + `"}`, 0, 201},
			{"updateSensor", "PATCH", "/api/v1/sensors/" + ids[1], `{"name":"Updated sensor","mode":"metadata_only"}`, 1, 200},
			{"rotateSensorToken", "POST", "/api/v1/sensors/" + ids[1] + "/rotate-token", `{}`, 2, 200},
			{"deleteSensor", "DELETE", "/api/v1/sensors/" + ids[1], "", 2, 204},
		} {
			key := fmt.Sprintf("sensor-current-idempotency-%02d", n)
			receipts, audits := counts()
			barrier.after = func() {
				exec(`UPDATE zasp_identity_memberships SET role=CASE role WHEN 'read_only_viewer' THEN 'security_admin' ELSE 'read_only_viewer' END WHERE principal_id=$1 AND organization_id=$2`, p, o)
				reconcile()
			}
			stale := call(tc.method, tc.path, tc.body, key, tc.version)
			barrier.after = nil
			if stale.Code != 409 {
				t.Fatalf("%s stale Check status=%d", tc.name, stale.Code)
			}
			if r, a := counts(); r != receipts || a != audits {
				t.Fatalf("%s stale effect/receipt/audit committed: %d/%d", tc.name, r, a)
			}
			fresh := call(tc.method, tc.path, tc.body, key, tc.version)
			if fresh.Code != tc.status {
				t.Fatalf("%s fresh Check status=%d", tc.name, fresh.Code)
			}
			if r, a := counts(); r != receipts+1 || a != audits+1 {
				t.Fatalf("%s durable receipt/audit count=%d/%d want%d/%d", tc.name, r, a, receipts+1, audits+1)
			}
			reconcile()
			var matched bool
			if err := admin.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_admin_audit a JOIN zasp_runtime_sensor_mutations m ON(a.organization_id,a.workspace_id,a.environment_id,a.actor_id,a.target_id,a.occurred_at)=(m.organization_id,m.workspace_id,m.environment_id,m.principal_id,m.sensor_id,m.created_at) WHERE m.operation=$1 AND m.idempotency_key=$2 AND a.metadata=jsonb_build_object('sensor_version',(m.result#>>'{body,version}')::bigint)`, tc.name, key).Scan(&matched); err != nil || !matched {
				t.Fatalf("audit receipt binding for%s: %v %v", tc.name, matched, err)
			}
			if tc.name == "createSensorEnrollment" {
				var created ProductSensor
				if json.Unmarshal(fresh.Body.Bytes(), &created) != nil || created.RuntimeSensorID != ids[0] {
					t.Fatal("source45 pairing representation lost")
				}
				replay := call(tc.method, tc.path, tc.body, key, tc.version)
				if replay.Code != 409 || strings.Contains(replay.Body.String(), "zasp_sensor_v1.") {
					t.Fatal("replay re-revealed token")
				}
			} else if tc.name == "updateSensor" {
				if replay := call(tc.method, tc.path, tc.body, key, tc.version); replay.Code != 200 {
					t.Fatalf("update replay status=%d", replay.Code)
				}
			}
			if r, a := counts(); r != receipts+1 || a != audits+1 {
				t.Fatal("replay duplicated receipt or audit")
			}
		}
	})
	// Administration audit uses the immutable receipt's selected environment.
	t.Run("queryable redacted sensor audit", func(t *testing.T) {
		grant, err := authorizer.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: "listAuditEvents", PathParameters: map[string]string{}})
		if err != nil {
			t.Fatal(err)
		}
		c := context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
		hasEnvironment := false
		for _, target := range grant.Allowed {
			hasEnvironment = hasEnvironment || target.Kind == "environment" && target.ID == e
		}
		if !hasEnvironment {
			t.Fatal("current selected environment check absent")
		}
		audit, err := NewAuditPublicPageRepository(ctx, database)
		if err != nil {
			t.Fatal(err)
		}
		page, err := audit.read(c, identity, auditPublicPageRequest{sessionDigest: identity.credentialBinding.Digest[:], limit: 100})
		if err != nil || len(page.items) != 4 {
			t.Fatalf("public sensor audit unavailable: %v items=%d", err, len(page.items))
		}
		actions := map[string]int{}
		for _, item := range page.items {
			var row struct {
				ID       string
				Action   string
				Metadata map[string]string
			}
			if json.Unmarshal(item, &row) != nil {
				t.Fatal("audit decode")
			}
			var recordedParent bool
			if err := api.QueryRow(ctx, `SELECT jsonb_array_length(v)=1 AND v->0->>'kind'='environment' AND v->0->>'id'=$3 FROM(SELECT zasp_authorization80.resolve($1,$2,$3,'audit_event',$4,'administration') v) p`, o, w, e, row.ID).Scan(&recordedParent); err != nil || !recordedParent {
				t.Fatalf("receipt event parent binding=%v err=%v", recordedParent, err)
			}
			if strings.HasPrefix(row.Action, "sensor.") && (len(row.Metadata) != 1 || row.Metadata["sensor_version"] == "") {
				t.Fatal("audit metadata not minimized")
			}
			for _, forbidden := range []string{"zasp_sensor_v1.", `"token"`, `"token_id"`, `"token_hash"`, `"locator_digest"`, `"request_digest"`, `"salt"`, `"enrollment_binding"`} {
				if bytes.Contains(item, []byte(forbidden)) {
					t.Fatalf("public audit contains forbidden field/prefix %q", forbidden)
				}
			}
			actions[row.Action]++
		}
		for _, action := range []string{"sensor.create", "sensor.update", "sensor.token.rotate", "sensor.delete"} {
			if actions[action] != 1 {
				t.Fatalf("public action %s count=%d want1", action, actions[action])
			}
		}
		for _, mode := range []string{"sensor-only", "foreign environment", "revoked environment permission"} {
			checker.allow[e] = false
			checker.allow[foreignEnvironment] = mode == "foreign environment"
			denied, err := authorizer.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: "listAuditEvents", PathParameters: map[string]string{}})
			if err != nil {
				t.Fatalf("%s current collection Check: %v", mode, err)
			}
			restricted := context.WithValue(ctx, requestAuthorizationContextKey{}, denied)
			page, err := audit.read(restricted, identity, auditPublicPageRequest{sessionDigest: identity.credentialBinding.Digest[:], limit: 100})
			if err != nil || len(page.items) != 0 {
				t.Fatalf("%s audit leaked: items=%d err=%v", mode, len(page.items), err)
			}
		}
		checker.allow[e], checker.allow[foreignEnvironment] = true, false
		exec(`UPDATE zasp_identity_memberships SET role=CASE role WHEN 'read_only_viewer' THEN 'security_admin' ELSE 'read_only_viewer' END WHERE principal_id=$1 AND organization_id=$2`, p, o)
		reconcile()
		if _, err := audit.read(c, identity, auditPublicPageRequest{sessionDigest: identity.credentialBinding.Digest[:], limit: 100}); err == nil {
			t.Fatal("stale audit revision disclosed events")
		}
		fresh, err := authorizer.Authorize(ctx, identity, identity.credentialBinding, RoutedOperation{OperationID: "listAuditEvents", PathParameters: map[string]string{}})
		if err != nil {
			t.Fatal(err)
		}
		freshContext := context.WithValue(ctx, requestAuthorizationContextKey{}, fresh)
		exec(`UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE session_id='session-sensor80'`)
		_, revokedErr := audit.read(freshContext, identity, auditPublicPageRequest{sessionDigest: identity.credentialBinding.Digest[:], limit: 100})
		exec(`UPDATE zasp_product_sessions SET revoked_at=NULL WHERE session_id='session-sensor80'`)
		if revokedErr == nil {
			t.Fatal("revoked audit credential disclosed events")
		}
		var pins bool
		if err := admin.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&pins); err != nil || !pins {
			t.Fatalf("canonical61 readiness changed: %v %v", pins, err)
		}
	})
	t.Run("audit collision rolls back native effect and receipt", func(t *testing.T) {
		key := "sensor-audit-collision-01"
		// An owned fault row has the correct derived ID but another target.
		// The production path must refuse it, not silently discard its audit.
		exec(`INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) VALUES($1,$2,$3,zasp_discovery_canonical_id($1,$2,$3,'sensor_mutation_audit',jsonb_build_array($4::text,'updateSensor',$5::text)::text),$4,'sensor.update',$6,'succeeded','{}')`, o, w, e, p, key, ids[0])
		receipts, audits := counts()
		response := call("PATCH", "/api/v1/sensors/"+ids[2], `{"name":"Must roll back","mode":"metadata_only"}`, key, 2)
		if response.Code != 409 {
			t.Fatalf("audit collision status=%d", response.Code)
		}
		if r, a := counts(); r != receipts || a != audits {
			t.Fatal("audit collision committed receipt or duplicate audit")
		}
		var name string
		var version int
		if err := admin.QueryRow(ctx, `SELECT name,version FROM zasp_sensors WHERE id=$1`, ids[2]).Scan(&name, &version); err != nil || name != "Recorded sensor" || version != 2 {
			t.Fatalf("audit rollback effect=%q/%d err=%v", name, version, err)
		}
	})
	t.Run("source45 and current61 readiness reject drift", func(t *testing.T) {
		for _, statement := range []string{
			`UPDATE zasp_schema_versions SET checksum=repeat('0',64) WHERE version=45`,
			`GRANT EXECUTE ON FUNCTION zasp_runtime_public_sensor_detail(text,text,text,text) TO PUBLIC`,
			`UPDATE zasp_schema_versions SET checksum=repeat('0',64) WHERE version=61`,
		} {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, statement); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			var ready bool
			err = tx.QueryRow(ctx, `SELECT zasp_authorization80.sensor_source_ready()`).Scan(&ready)
			rollbackErr := tx.Rollback(ctx)
			if err != nil || rollbackErr != nil || ready {
				t.Fatalf("source drift accepted=%v query=%v rollback=%v", ready, err, rollbackErr)
			}
		}
	})
	t.Log("mounted actual sensor router/handler and installed SQL; preauthenticated local identity, controlled Check responses; no live FGA/provider claim")
}
