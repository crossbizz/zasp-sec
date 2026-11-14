package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/evidencepack/evidencepacktest"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// The API gate admits the three compliance export statements only for their
// own operation, the request's scope and principal, the session of the
// request, the compiled release identity and the export of the path.
func TestComplianceExportStatementsAreAdmittedForTheirOwnRequest(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	o, w, e, p := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	digest := sha256.Sum256([]byte("session"))
	export := "pid_6c000001-0000-4000-8000-000000000001"
	checksum, fingerprint := migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()
	grant := func(operation string, mutate ...func(*RequestAuthorization)) RequestAuthorization {
		g := RequestAuthorization{OperationID: operation, Identity: identity, Credential: CredentialBinding{Kind: CredentialBrowserSession, Digest: digest}, Allowed: []AuthorizationTarget{{Scope: identity.Scope, Kind: "environment", ID: e}}}
		if operation != "createComplianceExport" {
			g.PathParameters = map[string]string{"id": export}
		}
		for _, change := range mutate {
			change(&g)
		}
		return g
	}
	create := []any{o, w, e, p, digest[:], "key-1", json.RawMessage(`{"agent_id":"` + evidencepacktest.Agent + `"}`), checksum, fingerprint}
	get := []any{o, w, e, p, digest[:], export, checksum, fingerprint}
	issue := []any{o, w, e, p, digest[:], export, strings.Repeat("a", 64), "json", "issue", checksum, fingerprint}
	read := []any{o, w, e, p, digest[:], export, strings.Repeat("a", 64), "json", "read", checksum, fingerprint}
	for name, item := range map[string]struct {
		grant RequestAuthorization
		query string
		args  []any
	}{
		"create": {grant("createComplianceExport"), postgresComplianceExportCreateSQL, create},
		"status": {grant("getComplianceExport"), postgresComplianceExportGetSQL, get},
		"grant":  {grant("createComplianceDownloadGrant"), postgresComplianceExportGrantSQL, issue},
		"read":   {grant("downloadComplianceExport"), postgresComplianceExportGrantSQL, read},
	} {
		if !authorizationStatementAllowed(item.grant, item.query, item.args) {
			t.Errorf("%s was refused", name)
		}
	}
	replace := func(args []any, index int, value any) []any {
		changed := append([]any{}, args...)
		changed[index] = value
		return changed
	}
	other := sha256.Sum256([]byte("another session"))
	for name, item := range map[string]struct {
		grant RequestAuthorization
		query string
		args  []any
	}{
		"create under another operation":   {grant("getComplianceExport"), postgresComplianceExportCreateSQL, create},
		"create without fresh auth":        {grant("createComplianceExport", func(g *RequestAuthorization) { g.Identity.FreshAuthenticated = false }), postgresComplianceExportCreateSQL, create},
		"create with an API token":         {grant("createComplianceExport", func(g *RequestAuthorization) { g.Identity.CredentialKind = CredentialBearerToken }), postgresComplianceExportCreateSQL, create},
		"create for another principal":     {grant("createComplianceExport"), postgresComplianceExportCreateSQL, replace(create, 3, export)},
		"create in another environment":    {grant("createComplianceExport"), postgresComplianceExportCreateSQL, replace(create, 2, export)},
		"create with another session":      {grant("createComplianceExport"), postgresComplianceExportCreateSQL, replace(create, 4, other[:])},
		"create with another release":      {grant("createComplianceExport"), postgresComplianceExportCreateSQL, replace(create, 7, strings.Repeat("0", 64))},
		"create without the environment":   {grant("createComplianceExport", func(g *RequestAuthorization) { g.Allowed = nil }), postgresComplianceExportCreateSQL, create},
		"status of another export":         {grant("getComplianceExport"), postgresComplianceExportGetSQL, replace(get, 5, evidencepacktest.Agent)},
		"status under the create":          {grant("createComplianceExport"), postgresComplianceExportGetSQL, get},
		"issue under the download":         {grant("downloadComplianceExport"), postgresComplianceExportGrantSQL, issue},
		"read under the grant":             {grant("createComplianceDownloadGrant"), postgresComplianceExportGrantSQL, read},
		"an unknown grant action":          {grant("downloadComplianceExport"), postgresComplianceExportGrantSQL, replace(read, 8, "extend")},
		"a grant of another export":        {grant("downloadComplianceExport"), postgresComplianceExportGrantSQL, replace(read, 5, evidencepacktest.Agent)},
		"a statement with a missing value": {grant("getComplianceExport"), postgresComplianceExportGetSQL, get[:7]},
	} {
		if authorizationStatementAllowed(item.grant, item.query, item.args) {
			t.Errorf("%s was admitted", name)
		}
	}
}

// An export request names a framework and control, or one agent alone.
func TestComplianceExportRequestNamesOneAgent(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"view", "view_audit", "view_compliance"}
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	job := `{"export_id":"pid_6c000001-0000-4000-8000-000000000001","organization_id":"` + identity.Scope.OrganizationID().String() + `","workspace_id":"` + identity.Scope.WorkspaceID().String() + `","environment_id":"` + identity.Scope.EnvironmentID().String() + `","state":"pending","phase":"queued","failure_code":null,"created_at":"2026-11-14T09:00:00Z","retrieval_expires_at":"2026-11-15T09:00:00Z","mapping_revision":"product-evidence-v1"}`
	database := &discoveryCallDatabase{schema: ProductionRecoverySchemaVersion, responses: map[string]json.RawMessage{postgresComplianceReadySQL: json.RawMessage(`true`), postgresComplianceExportCreateSQL: json.RawMessage(job)}}
	repository, err := NewComplianceExportsRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("session"))
	if _, err := repository.Create(context.Background(), identity, digest[:], "pack-1", ComplianceExportRequest{AgentID: evidencepacktest.Agent}); err != nil {
		t.Fatalf("agent export: %v", err)
	}
	last := database.arguments[len(database.arguments)-1]
	if request, ok := last[6].(json.RawMessage); !ok || string(request) != `{"agent_id":"`+evidencepacktest.Agent+`"}` {
		t.Fatalf("request = %#v", last[6])
	}
	for name, request := range map[string]ComplianceExportRequest{
		"an agent with a framework": {AgentID: evidencepacktest.Agent, Framework: "hipaa"},
		"an agent with a control":   {AgentID: evidencepacktest.Agent, ControlID: "ASI03"},
		"a malformed agent":         {AgentID: "agent"},
	} {
		if _, err := repository.Create(context.Background(), identity, digest[:], "pack-2", request); !errors.Is(err, ErrRepositoryOperation) {
			t.Errorf("%s was accepted: %v", name, err)
		}
	}
}

// A stored export of one agent is validated as the pack it is before the API
// hands it out.
func TestCompliancePersistedEvidenceAcceptsAnAgentPack(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	pack := evidencepacktest.Pack()
	if !validCompliancePersistedEvidence(pack, identity) {
		t.Fatal("a captured pack was refused")
	}
	for name, changed := range map[string]string{
		"another schema":     strings.Replace(string(pack), "agent-evidence-pack-v1", "agent-evidence-pack-v9", 1),
		"an unknown member":  strings.Replace(string(pack), `{"schema_version"`, `{"raw_prompt":"x","schema_version"`, 1),
		"an empty object":    `{}`,
		"controls in a pack": `{"control":{}}`,
	} {
		if validCompliancePersistedEvidence(json.RawMessage(changed), identity) {
			t.Errorf("%s was accepted", name)
		}
	}
}
