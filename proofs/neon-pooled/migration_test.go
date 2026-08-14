package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testAPIKey       = "test-api-key-kept-inside-the-test-process"
	testProjectID    = "silent-dawn-123456"
	testParentBranch = "br-old-dawn-123456"
	testBranchID     = "br-proof-dawn-654321"
	testEndpointID   = "ep-proof-dawn-654321"
	testOperationID  = "a07f8772-1877-4da9-a939-3a3ae62d1d8d"
	testMarker       = "0123456789abcdef"
	testBranchName   = "zasp-m0-05-0123456789abcdef"
	testParentHost   = "ep-cool-darkness-123456.us-east-2.aws.neon.tech"
	testChildHost    = "ep-proof-dawn-654321.us-east-2.aws.neon.tech"
)

func TestExecuteMigrationProofRunsOwnedBranchAndMigrationInOrder(t *testing.T) {
	t.Parallel()

	events := &eventLog{}
	provider := newProviderServer(t, events, providerBehavior{createdBranchState: "init", createdEndpointState: "init"})
	database := &recordingMigrationDB{events: events, fingerprints: []string{"baseline", "baseline"}}
	api, err := newNeonAPIClient(provider.URL, testAPIKey, provider.Client())
	if err != nil {
		t.Fatalf("newNeonAPIClient() error = %v", err)
	}

	summary, err := executeMigrationProof(context.Background(), migrationRunConfig{
		apiKey:      testAPIKey,
		databaseURL: validDirectNeonURL(),
		marker:      testMarker,
		projectID:   testProjectID,
	}, migrationDependencies{
		api: api,
		openDatabase: func(_ context.Context, target validatedConnection) (migrationDatabase, error) {
			events.add("db:open")
			if target.expected.host != testChildHost {
				t.Fatal("database opener received the wrong child host")
			}
			if err := validateEffectivePGXConfig(target.config, target.expected); err != nil {
				t.Fatal("database opener received an unsafe pgx configuration")
			}
			return database, nil
		},
	})

	if err != nil {
		t.Fatalf("executeMigrationProof() error = %v", err)
	}
	if summary != migrationSuccessSummary {
		t.Fatalf("executeMigrationProof() summary = %q, want fixed success summary", summary)
	}
	want := []string{
		"api:list-endpoints",
		"api:list-branches-preflight",
		"api:create-branch",
		"api:wait-operation",
		"api:wait-readiness-branch",
		"api:wait-readiness-endpoints",
		"db:open",
		"db:fingerprint",
		"db:up",
		"db:shape",
		"db:down",
		"db:fingerprint",
		"db:close",
		"api:delete-branch",
		"api:wait-delete-operation",
		"api:list-branches-cleanup",
	}
	if got := events.snapshot(); !equalStrings(got, want) {
		t.Fatalf("event order = %#v, want %#v", got, want)
	}
}

func TestExecuteMigrationProofReconcilesMalformedSuccessfulCreateAndDeletes(t *testing.T) {
	t.Parallel()

	events := &eventLog{}
	provider := newProviderServer(t, events, providerBehavior{
		omitCreatedEndpoint: true,
		recoverCreated:      true,
	})
	api, err := newNeonAPIClient(provider.URL, testAPIKey, provider.Client())
	if err != nil {
		t.Fatalf("newNeonAPIClient() error = %v", err)
	}
	opened := false

	_, err = executeMigrationProof(context.Background(), migrationRunConfig{
		apiKey: testAPIKey, databaseURL: validDirectNeonURL(), marker: testMarker, projectID: testProjectID, pollInterval: time.Millisecond,
	}, migrationDependencies{api: api, openDatabase: func(context.Context, validatedConnection) (migrationDatabase, error) {
		opened = true
		return nil, errors.New("must not open")
	}})

	if !errors.Is(err, errMigrationAPI) {
		t.Fatalf("executeMigrationProof() error = %v, want fixed API failure", err)
	}
	if opened {
		t.Fatal("database opened after a malformed create response")
	}
	want := []string{
		"api:list-endpoints",
		"api:list-branches-preflight",
		"api:create-branch",
		"api:list-branches-recovery",
		"api:list-endpoints-recovery",
		"api:delete-branch",
		"api:wait-delete-operation",
		"api:list-branches-cleanup",
	}
	if got := events.snapshot(); !equalStrings(got, want) {
		t.Fatalf("malformed-create cleanup order = %#v, want %#v", got, want)
	}
}

func TestExecuteMigrationProofCleansUpEveryPostCreateFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		openError  error
		database   *recordingMigrationDB
		wantDBLast string
	}{
		{name: "database open", openError: errors.New("driver detail")},
		{name: "baseline", database: &recordingMigrationDB{fingerprintErrorAt: 1}, wantDBLast: "db:fingerprint"},
		{name: "up", database: &recordingMigrationDB{fingerprints: []string{"baseline"}, upError: errors.New("driver detail")}, wantDBLast: "db:up"},
		{name: "shape", database: &recordingMigrationDB{fingerprints: []string{"baseline"}, shapeError: errors.New("driver detail")}, wantDBLast: "db:shape"},
		{name: "down", database: &recordingMigrationDB{fingerprints: []string{"baseline"}, downError: errors.New("driver detail")}, wantDBLast: "db:down"},
		{name: "baseline mismatch", database: &recordingMigrationDB{fingerprints: []string{"baseline", "changed"}}, wantDBLast: "db:fingerprint"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			events := &eventLog{}
			provider := newProviderServer(t, events, providerBehavior{})
			api, err := newNeonAPIClient(provider.URL, testAPIKey, provider.Client())
			if err != nil {
				t.Fatalf("newNeonAPIClient() error = %v", err)
			}
			if test.database != nil {
				test.database.events = events
			}
			_, err = executeMigrationProof(context.Background(), migrationRunConfig{
				apiKey: testAPIKey, databaseURL: validDirectNeonURL(), marker: testMarker, projectID: testProjectID,
			}, migrationDependencies{
				api: api,
				openDatabase: func(context.Context, validatedConnection) (migrationDatabase, error) {
					events.add("db:open")
					if test.openError != nil {
						return nil, test.openError
					}
					return test.database, nil
				},
			})

			if err == nil {
				t.Fatal("executeMigrationProof() succeeded after an injected failure")
			}
			got := events.snapshot()
			if !containsString(got, "api:delete-branch") || got[len(got)-1] != "api:list-branches-cleanup" {
				t.Fatalf("cleanup events missing after failure: %#v", got)
			}
			if test.wantDBLast != "" && !containsString(got, test.wantDBLast) {
				t.Fatalf("injected database stage %q was not reached: %#v", test.wantDBLast, got)
			}
		})
	}
}

func TestExecuteMigrationProofGivesCleanupFailurePrecedence(t *testing.T) {
	t.Parallel()

	events := &eventLog{}
	provider := newProviderServer(t, events, providerBehavior{deleteStatus: http.StatusInternalServerError})
	api, err := newNeonAPIClient(provider.URL, testAPIKey, provider.Client())
	if err != nil {
		t.Fatalf("newNeonAPIClient() error = %v", err)
	}
	database := &recordingMigrationDB{
		events:       events,
		fingerprints: []string{"baseline"},
		upError:      errors.New("database-secret-must-not-escape"),
	}

	_, err = executeMigrationProof(context.Background(), migrationRunConfig{
		apiKey: testAPIKey, databaseURL: validDirectNeonURL(), marker: testMarker, projectID: testProjectID,
	}, migrationDependencies{
		api: api,
		openDatabase: func(context.Context, validatedConnection) (migrationDatabase, error) {
			return database, nil
		},
	})

	if !errors.Is(err, errMigrationCleanup) {
		t.Fatalf("executeMigrationProof() error = %v, want cleanup failure", err)
	}
	if strings.Contains(err.Error(), "database-secret") {
		t.Fatal("cleanup-precedence error disclosed database detail")
	}
}

func TestExecuteMigrationProofRequiresOneExactParentEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		behavior  providerBehavior
		projectID string
	}{
		{name: "wrong project response", behavior: providerBehavior{parentProjectID: "other-project-123"}, projectID: testProjectID},
		{name: "missing host", behavior: providerBehavior{parentHost: "ep-other-dawn-123456.us-east-2.aws.neon.tech"}, projectID: testProjectID},
		{name: "duplicate host", behavior: providerBehavior{duplicateParent: true}, projectID: testProjectID},
		{name: "invalid requested project", projectID: "../project"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			events := &eventLog{}
			provider := newProviderServer(t, events, test.behavior)
			api, err := newNeonAPIClient(provider.URL, testAPIKey, provider.Client())
			if err != nil {
				t.Fatalf("newNeonAPIClient() error = %v", err)
			}
			_, err = executeMigrationProof(context.Background(), migrationRunConfig{
				apiKey: testAPIKey, databaseURL: validDirectNeonURL(), marker: testMarker, projectID: test.projectID,
			}, migrationDependencies{api: api, openDatabase: func(context.Context, validatedConnection) (migrationDatabase, error) {
				t.Fatal("database opened without exact parent endpoint ownership")
				return nil, nil
			}})

			if !errors.Is(err, errMigrationConfiguration) && !errors.Is(err, errMigrationAPI) {
				t.Fatalf("executeMigrationProof() error = %v, want fixed configuration/API failure", err)
			}
			if containsString(events.snapshot(), "api:create-branch") {
				t.Fatal("branch was created without one exact parent endpoint")
			}
		})
	}
}

func TestExecuteMigrationProofRefusesUnprovenCleanupTarget(t *testing.T) {
	t.Parallel()

	events := &eventLog{}
	provider := newProviderServer(t, events, providerBehavior{createdBranchName: "unowned-branch"})
	api, err := newNeonAPIClient(provider.URL, testAPIKey, provider.Client())
	if err != nil {
		t.Fatalf("newNeonAPIClient() error = %v", err)
	}

	_, err = executeMigrationProof(context.Background(), migrationRunConfig{
		apiKey: testAPIKey, cleanupTimeout: 20 * time.Millisecond, databaseURL: validDirectNeonURL(), marker: testMarker, projectID: testProjectID,
	}, migrationDependencies{api: api, openDatabase: func(context.Context, validatedConnection) (migrationDatabase, error) {
		t.Fatal("database opened for an unowned branch response")
		return nil, nil
	}})

	if !errors.Is(err, errMigrationCleanup) {
		t.Fatalf("executeMigrationProof() error = %v, want cleanup failure", err)
	}
	if containsString(events.snapshot(), "api:delete-branch") {
		t.Fatal("cleanup attempted a branch whose run ownership was not proven")
	}
}

func TestExecuteMigrationProofRecoversAndDeletesBranchAfterAmbiguousCreateFailure(t *testing.T) {
	t.Parallel()

	events := &eventLog{}
	provider := newProviderServer(t, events, providerBehavior{
		createStatus:         http.StatusInternalServerError,
		recoverCreated:       true,
		recoveryVisibleAfter: 2,
	})
	api, err := newNeonAPIClient(provider.URL, testAPIKey, provider.Client())
	if err != nil {
		t.Fatalf("newNeonAPIClient() error = %v", err)
	}

	_, err = executeMigrationProof(context.Background(), migrationRunConfig{
		apiKey: testAPIKey, databaseURL: validDirectNeonURL(), marker: testMarker, projectID: testProjectID, pollInterval: time.Millisecond,
	}, migrationDependencies{api: api, openDatabase: func(context.Context, validatedConnection) (migrationDatabase, error) {
		t.Fatal("database opened after an ambiguous create failure")
		return nil, nil
	}})

	if !errors.Is(err, errMigrationAPI) {
		t.Fatalf("executeMigrationProof() error = %v, want the fixed original API failure", err)
	}
	want := []string{
		"api:list-endpoints",
		"api:list-branches-preflight",
		"api:create-branch",
		"api:list-branches-recovery",
		"api:list-branches-recovery",
		"api:list-endpoints-recovery",
		"api:delete-branch",
		"api:wait-delete-operation",
		"api:list-branches-cleanup",
	}
	if got := events.snapshot(); !equalStrings(got, want) {
		t.Fatalf("ambiguous-create cleanup order = %#v, want %#v", got, want)
	}
}

func TestExecuteMigrationProofRejectsFinishedOperationWithFailuresAndCleansUp(t *testing.T) {
	t.Parallel()

	events := &eventLog{}
	provider := newProviderServer(t, events, providerBehavior{
		createOperationStatus: "finished",
		operationFailures:     1,
	})
	api, err := newNeonAPIClient(provider.URL, testAPIKey, provider.Client())
	if err != nil {
		t.Fatalf("newNeonAPIClient() error = %v", err)
	}
	opened := false

	_, err = executeMigrationProof(context.Background(), migrationRunConfig{
		apiKey: testAPIKey, databaseURL: validDirectNeonURL(), marker: testMarker, projectID: testProjectID,
	}, migrationDependencies{api: api, openDatabase: func(context.Context, validatedConnection) (migrationDatabase, error) {
		opened = true
		return nil, errors.New("must not open")
	}})

	if !errors.Is(err, errMigrationAPI) {
		t.Fatalf("executeMigrationProof() error = %v, want fixed API failure", err)
	}
	if opened {
		t.Fatal("database opened after an operation reported failures")
	}
	if !containsString(events.snapshot(), "api:delete-branch") {
		t.Fatal("owned branch was not deleted after operation validation failed")
	}
}

func TestNeonAPIClientRejectsRedirectOversizedBodyAndDeadlineWithoutDisclosure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		timeout time.Duration
	}{
		{name: "redirect", handler: func(response http.ResponseWriter, request *http.Request) {
			http.Redirect(response, request, "/provider-secret", http.StatusFound)
		}},
		{name: "oversized body", handler: func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"endpoints":[{"host":"` + strings.Repeat("x", neonAPIResponseLimit) + `"}]}`))
		}},
		{name: "deadline", timeout: 25 * time.Millisecond, handler: func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(http.StatusOK)
			if flusher, ok := response.(http.Flusher); ok {
				flusher.Flush()
			}
			time.Sleep(100 * time.Millisecond)
			_, _ = response.Write([]byte(`{"provider-secret":"must-not-escape"}`))
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(test.handler)
			defer server.Close()
			api, err := newNeonAPIClient(server.URL, testAPIKey, server.Client())
			if err != nil {
				t.Fatalf("newNeonAPIClient() error = %v", err)
			}
			ctx := context.Background()
			if test.timeout != 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, test.timeout)
				defer cancel()
			}
			_, err = api.listEndpoints(ctx, testProjectID)
			if !errors.Is(err, errMigrationAPI) {
				t.Fatalf("listEndpoints() error = %v, want fixed API failure", err)
			}
			if strings.Contains(err.Error(), "provider-secret") || strings.Contains(err.Error(), server.URL) || strings.Contains(err.Error(), testAPIKey) {
				t.Fatal("API failure disclosed request or provider detail")
			}
		})
	}
}

func TestDirectChildConnectionPreservesIdentityAndStrengthensTLS(t *testing.T) {
	clearPGEnvironment(t)

	target, err := validatedDirectPGXConnection(validDirectNeonURL(), testChildHost)
	if err != nil {
		t.Fatalf("validatedDirectPGXConnection() error = %v", err)
	}
	if target.expected.host != testChildHost || target.config.Host != testChildHost {
		t.Fatal("child connection did not use the exact returned direct host")
	}
	if target.expected.user != "proof-user" || target.expected.password != "proof-pass" || target.expected.database != "proof" {
		t.Fatal("child connection changed database identity fields")
	}
	if target.config.TLSConfig == nil || target.config.TLSConfig.ServerName != testChildHost || target.config.TLSConfig.InsecureSkipVerify {
		t.Fatal("child connection did not force hostname-verifying TLS")
	}
	if _, err := validatedDirectPGXConnection(validDirectNeonURL(), testChildHost+"-pooler"); err == nil {
		t.Fatal("validatedDirectPGXConnection() accepted a pooled or malformed returned host")
	}
}

func TestMigrationParentCanonicalizesOnlyAValidatedDirectOrPoolerHost(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "direct", raw: validDirectNeonURL(), want: testParentHost},
		{name: "pooler", raw: validPoolerNeonURL(), want: testParentHost},
		{
			name: "pooler substring is an exact direct label",
			raw:  "postgresql://proof-user:proof-pass@ep-cool-darkness-123456-pooler-extra.us-east-2.aws.neon.tech/proof?sslmode=require",
			want: "ep-cool-darkness-123456-pooler-extra.us-east-2.aws.neon.tech",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			host, err := directHostFromURL(test.raw)
			if err != nil {
				t.Fatalf("directHostFromURL() error = %v", err)
			}
			if host != test.want {
				t.Fatal("directHostFromURL() did not return the exact canonical direct host")
			}
		})
	}
}

func TestDirectChildConnectionAcceptsValidatedPoolerParentIdentity(t *testing.T) {
	clearPGEnvironment(t)

	target, err := validatedDirectPGXConnection(validPoolerNeonURL(), testChildHost)
	if err != nil {
		t.Fatalf("validatedDirectPGXConnection() error = %v", err)
	}
	if target.config.Host != testChildHost || strings.Contains(target.config.Host, "-pooler") {
		t.Fatal("validated pooler parent did not produce the exact child direct destination")
	}
	if target.config.User != "proof-user" || target.config.Password != "proof-pass" || target.config.Database != "proof" {
		t.Fatal("child connection changed the validated parent identity")
	}
}

func TestDirectDatabaseOpenerRejectsPGEnvironmentChangedAfterValidation(t *testing.T) {
	clearPGEnvironment(t)
	target, err := validatedDirectPGXConnection(validDirectNeonURL(), testChildHost)
	if err != nil {
		t.Fatalf("validatedDirectPGXConnection() error = %v", err)
	}
	t.Setenv("PGHOST", "conflicting-host.example.com")

	_, err = openPGXMigrationDatabase(context.Background(), target)

	if !errors.Is(err, errMigrationConfiguration) {
		t.Fatalf("openPGXMigrationDatabase() error = %v, want configuration rejection", err)
	}
}

func TestMigrationAssetsRenderOnlyAQuotedSafeIdentifier(t *testing.T) {
	t.Parallel()

	assets, err := renderMigrationAssets("zasp_m005_0123456789abcdef")
	if err != nil {
		t.Fatalf("renderMigrationAssets() error = %v", err)
	}
	if !strings.Contains(assets.up, `CREATE SCHEMA "zasp_m005_0123456789abcdef"`) ||
		!strings.Contains(assets.up, `"zasp_m005_0123456789abcdef"."migration_probe"`) ||
		assets.down != `DROP SCHEMA "zasp_m005_0123456789abcdef" CASCADE;` {
		t.Fatal("migration assets did not render the fixed up/down pair")
	}
	for _, unsafe := range []string{"unsafe;drop", "UPPER", "has space", "", strings.Repeat("a", 64)} {
		if _, err := renderMigrationAssets(unsafe); err == nil {
			t.Fatalf("renderMigrationAssets() accepted unsafe identifier %q", unsafe)
		}
	}
}

type providerBehavior struct {
	createOperationStatus string
	createdBranchName     string
	createdBranchState    string
	createdEndpointState  string
	createStatus          int
	deleteStatus          int
	duplicateParent       bool
	omitCreatedEndpoint   bool
	operationFailures     int
	parentHost            string
	parentProjectID       string
	recoverCreated        bool
	recoveryVisibleAfter  int
}

func newProviderServer(t *testing.T, events *eventLog, behavior providerBehavior) *httptest.Server {
	t.Helper()
	if behavior.createdBranchName == "" {
		behavior.createdBranchName = testBranchName
	}
	if behavior.createdBranchState == "" {
		behavior.createdBranchState = "ready"
	}
	if behavior.createdEndpointState == "" {
		behavior.createdEndpointState = "active"
	}
	if behavior.createOperationStatus == "" {
		behavior.createOperationStatus = "running"
	}
	if behavior.deleteStatus == 0 {
		behavior.deleteStatus = http.StatusOK
	}
	if behavior.createStatus == 0 {
		behavior.createStatus = http.StatusCreated
	}
	if behavior.parentHost == "" {
		behavior.parentHost = testParentHost
	}
	if behavior.parentProjectID == "" {
		behavior.parentProjectID = testProjectID
	}

	return httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+testAPIKey || request.Header.Get("Accept") != "application/json" {
			t.Error("provider request omitted its bearer or accept header")
		}
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/projects/"+testProjectID+"/endpoints":
			afterCreate := containsString(events.snapshot(), "api:create-branch")
			recovering := behavior.recoverCreated && afterCreate &&
				!containsString(events.snapshot(), "api:wait-operation")
			if recovering {
				events.add("api:list-endpoints-recovery")
			} else if afterCreate {
				events.add("api:wait-readiness-endpoints")
			} else {
				events.add("api:list-endpoints")
			}
			duplicate := ""
			if behavior.duplicateParent {
				duplicate = fmt.Sprintf(`,{"host":%q,"id":"ep-duplicate-123456","project_id":%q,"branch_id":%q,"region_id":"aws-us-east-2","autoscaling_limit_min_cu":0.25,"autoscaling_limit_max_cu":1,"type":"read_write","current_state":"idle","settings":{"pg_settings":{}},"pooler_enabled":false,"pooler_mode":"transaction","disabled":false,"passwordless_access":false,"creation_source":"console","created_at":"2026-08-13T00:00:00Z","updated_at":"2026-08-13T00:00:00Z","proxy_host":"us-east-2.aws.neon.tech","suspend_timeout_seconds":0,"provisioner":"k8s-neonvm"}`, behavior.parentHost, behavior.parentProjectID, testParentBranch)
			}
			recoveredEndpoint := ""
			if recovering || afterCreate {
				recoveredEndpoint = fmt.Sprintf(`,{"host":%q,"id":%q,"project_id":%q,"branch_id":%q,"region_id":"aws-us-east-2","autoscaling_limit_min_cu":0.25,"autoscaling_limit_max_cu":1,"type":"read_write","current_state":"active","settings":{"pg_settings":{}},"pooler_enabled":false,"pooler_mode":"transaction","disabled":false,"passwordless_access":false,"creation_source":"api","created_at":"2026-08-13T00:00:00Z","updated_at":"2026-08-13T00:00:00Z","proxy_host":"us-east-2.aws.neon.tech","suspend_timeout_seconds":0,"provisioner":"k8s-neonvm"}`, testChildHost, testEndpointID, testProjectID, testBranchID)
			}
			fmt.Fprintf(response, `{"endpoints":[{"host":%q,"id":"ep-cool-darkness-123456","project_id":%q,"branch_id":%q,"region_id":"aws-us-east-2","autoscaling_limit_min_cu":0.25,"autoscaling_limit_max_cu":1,"type":"read_write","current_state":"idle","settings":{"pg_settings":{}},"pooler_enabled":false,"pooler_mode":"transaction","disabled":false,"passwordless_access":false,"creation_source":"console","created_at":"2026-08-13T00:00:00Z","updated_at":"2026-08-13T00:00:00Z","proxy_host":"us-east-2.aws.neon.tech","suspend_timeout_seconds":0,"provisioner":"k8s-neonvm"}%s%s]}`, behavior.parentHost, behavior.parentProjectID, testParentBranch, duplicate, recoveredEndpoint)
		case request.Method == http.MethodGet && request.URL.Path == "/projects/"+testProjectID+"/branches" && request.URL.Query().Get("search") == testBranchName:
			if containsString(events.snapshot(), "api:delete-branch") {
				events.add("api:list-branches-cleanup")
				_, _ = response.Write([]byte(`{"branches":[],"annotations":{},"pagination":{}}`))
			} else if behavior.recoverCreated && containsString(events.snapshot(), "api:create-branch") {
				events.add("api:list-branches-recovery")
				if countString(events.snapshot(), "api:list-branches-recovery") < behavior.recoveryVisibleAfter {
					_, _ = response.Write([]byte(`{"branches":[],"annotations":{},"pagination":{}}`))
				} else {
					fmt.Fprintf(response, `{"branches":[{"id":%q,"project_id":%q,"parent_id":%q,"name":%q,"current_state":"ready","state_changed_at":"2026-08-13T00:00:00Z","creation_source":"api","created_at":"2026-08-13T00:00:00Z","updated_at":"2026-08-13T00:00:00Z","default":false,"protected":false,"cpu_used_sec":0,"active_time_seconds":0,"compute_time_seconds":0,"written_data_bytes":0,"data_transfer_bytes":0}],"annotations":{%q:{"value":{"zasp-proof-marker":%q}}},"pagination":{}}`, testBranchID, testProjectID, testParentBranch, testBranchName, testBranchID, testMarker)
				}
			} else if containsString(events.snapshot(), "api:create-branch") {
				events.add("api:wait-readiness-branch")
				fmt.Fprintf(response, `{"branches":[{"id":%q,"project_id":%q,"parent_id":%q,"name":%q,"current_state":"ready","state_changed_at":"2026-08-13T00:00:00Z","creation_source":"api","created_at":"2026-08-13T00:00:00Z","updated_at":"2026-08-13T00:00:00Z","default":false,"protected":false,"cpu_used_sec":0,"active_time_seconds":0,"compute_time_seconds":0,"written_data_bytes":0,"data_transfer_bytes":0}],"annotations":{},"pagination":{}}`, testBranchID, testProjectID, testParentBranch, testBranchName)
			} else {
				events.add("api:list-branches-preflight")
				_, _ = response.Write([]byte(`{"branches":[],"annotations":{},"pagination":{}}`))
			}
		case request.Method == http.MethodPost && request.URL.Path == "/projects/"+testProjectID+"/branches":
			events.add("api:create-branch")
			response.WriteHeader(behavior.createStatus)
			if behavior.createStatus != http.StatusCreated {
				_, _ = response.Write([]byte(`{"provider-secret":"must-not-escape"}`))
				return
			}
			endpointJSON := fmt.Sprintf(`{"host":%q,"id":%q,"project_id":%q,"branch_id":%q,"region_id":"aws-us-east-2","autoscaling_limit_min_cu":0.25,"autoscaling_limit_max_cu":1,"type":"read_write","current_state":%q,"settings":{"pg_settings":{}},"pooler_enabled":false,"pooler_mode":"transaction","disabled":false,"passwordless_access":false,"creation_source":"api","created_at":"2026-08-13T00:00:00Z","updated_at":"2026-08-13T00:00:00Z","proxy_host":"us-east-2.aws.neon.tech","suspend_timeout_seconds":0,"provisioner":"k8s-neonvm"}`, testChildHost, testEndpointID, testProjectID, testBranchID, behavior.createdEndpointState)
			if behavior.omitCreatedEndpoint {
				endpointJSON = ""
			} else {
				endpointJSON = "," + endpointJSON
			}
			fmt.Fprintf(response, `{"branch":{"id":%q,"project_id":%q,"parent_id":%q,"name":%q,"current_state":%q,"state_changed_at":"2026-08-13T00:00:00Z","creation_source":"api","created_at":"2026-08-13T00:00:00Z","updated_at":"2026-08-13T00:00:00Z","default":false,"protected":false,"cpu_used_sec":0,"active_time_seconds":0,"compute_time_seconds":0,"written_data_bytes":0,"data_transfer_bytes":0},"endpoints":[%s],"operations":[{"id":%q,"project_id":%q,"branch_id":%q,"endpoint_id":%q,"action":"start_compute","status":%q,"failures_count":%d,"created_at":"2026-08-13T00:00:00Z","updated_at":"2026-08-13T00:00:00Z","total_duration_ms":0}],"roles":[],"databases":[]}`, testBranchID, testProjectID, testParentBranch, behavior.createdBranchName, behavior.createdBranchState, strings.TrimPrefix(endpointJSON, ","), testOperationID, testProjectID, testBranchID, testEndpointID, behavior.createOperationStatus, behavior.operationFailures)
		case request.Method == http.MethodGet && request.URL.Path == "/projects/"+testProjectID+"/operations/"+testOperationID:
			if containsString(events.snapshot(), "api:delete-branch") {
				events.add("api:wait-delete-operation")
			} else {
				events.add("api:wait-operation")
			}
			fmt.Fprintf(response, `{"operation":{"id":%q,"project_id":%q,"branch_id":%q,"endpoint_id":%q,"action":"start_compute","status":"finished","failures_count":0,"created_at":"2026-08-13T00:00:00Z","updated_at":"2026-08-13T00:00:00Z","total_duration_ms":1}}`, testOperationID, testProjectID, testBranchID, testEndpointID)
		case request.Method == http.MethodDelete && request.URL.Path == "/projects/"+testProjectID+"/branches/"+testBranchID:
			events.add("api:delete-branch")
			response.WriteHeader(behavior.deleteStatus)
			if behavior.deleteStatus == http.StatusOK {
				fmt.Fprintf(response, `{"branch":{"id":%q,"project_id":%q,"parent_id":%q,"name":%q,"current_state":"ready","state_changed_at":"2026-08-13T00:00:00Z","creation_source":"api","created_at":"2026-08-13T00:00:00Z","updated_at":"2026-08-13T00:00:00Z","default":false,"protected":false,"cpu_used_sec":0,"active_time_seconds":0,"compute_time_seconds":0,"written_data_bytes":0,"data_transfer_bytes":0},"operations":[{"id":%q,"project_id":%q,"branch_id":%q,"endpoint_id":%q,"action":"delete_timeline","status":"running","failures_count":0,"created_at":"2026-08-13T00:00:00Z","updated_at":"2026-08-13T00:00:00Z","total_duration_ms":0}]}`, testBranchID, testProjectID, testParentBranch, behavior.createdBranchName, testOperationID, testProjectID, testBranchID, testEndpointID)
			} else {
				_, _ = response.Write([]byte(`{"provider-secret":"must-not-escape"}`))
			}
		default:
			t.Errorf("unexpected provider request: %s %s", request.Method, request.URL.RequestURI())
			response.WriteHeader(http.StatusNotFound)
		}
	}))
}

type recordingMigrationDB struct {
	events             *eventLog
	fingerprintCalls   int
	fingerprintErrorAt int
	fingerprints       []string
	upError            error
	shapeError         error
	downError          error
}

func (database *recordingMigrationDB) Fingerprint(context.Context, string) (string, error) {
	database.events.add("db:fingerprint")
	database.fingerprintCalls++
	if database.fingerprintErrorAt == database.fingerprintCalls {
		return "", errors.New("driver detail")
	}
	if database.fingerprintCalls > len(database.fingerprints) {
		return "baseline", nil
	}
	return database.fingerprints[database.fingerprintCalls-1], nil
}

func (database *recordingMigrationDB) Up(context.Context, migrationAssets) error {
	database.events.add("db:up")
	return database.upError
}

func (database *recordingMigrationDB) VerifyShape(context.Context, string) error {
	database.events.add("db:shape")
	return database.shapeError
}

func (database *recordingMigrationDB) Down(context.Context, migrationAssets) error {
	database.events.add("db:down")
	return database.downError
}

func (database *recordingMigrationDB) Close(context.Context) error {
	database.events.add("db:close")
	return nil
}

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (log *eventLog) add(event string) {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.events = append(log.events, event)
}

func (log *eventLog) snapshot() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]string(nil), log.events...)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func validPoolerNeonURL() string {
	return "postgresql://proof-user:proof-pass@ep-cool-darkness-123456-pooler.us-east-2.aws.neon.tech/proof?sslmode=require"
}

func countString(values []string, target string) int {
	count := 0
	for _, value := range values {
		if value == target {
			count++
		}
	}
	return count
}
