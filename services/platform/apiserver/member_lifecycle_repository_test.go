package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// Every call crosses the same two production boundaries as an HTTP invitation:
// a fenced PostgreSQL statement and the provider's scoped directory endpoints.
type memberInvitationDatabase struct {
	JSONDatabase
	t                 *testing.T
	existing          bool
	completionFailure bool
	attemptedNew      bool
	alreadyActive     bool
	steps             []string
}

func (d *memberInvitationDatabase) QueryJSON(_ context.Context, statement string, args ...any) (json.RawMessage, error) {
	d.t.Helper()
	if statement != memberLifecycleWriteSQL || len(args) != 8 || args[4] != "inviteMember" {
		d.t.Fatalf("unexpected query %s: %#v", statement, args)
	}
	var body memberInvitationWrite
	if err := json.Unmarshal(args[6].([]byte), &body); err != nil {
		d.t.Fatal(err)
	}
	d.steps = append(d.steps, body.Phase)
	if body.Email != "jordan@example.com" || body.Role != "read_only_viewer" || body.DisplayName != "Jordan" || body.Key != "member-invitation-test-key" {
		d.t.Fatalf("wrong intent: %#v", body)
	}
	switch body.Phase {
	case "reserve":
		if !d.existing {
			return json.Marshal(map[string]any{"_deliver_to": "organization-test-acme", "_resume": d.attemptedNew})
		}
	case "send_new":
		d.attemptedNew = true
		return json.RawMessage(`{}`), nil
	case "check":
		if d.alreadyActive {
			return json.RawMessage(`{"_mutation_state":"conflict"}`), nil
		}
		return json.RawMessage(`{}`), nil
	case "complete":
		if body.MemberReference != "member-test-invited" {
			d.t.Fatalf("unbound member: %#v", body)
		}
		if d.completionFailure {
			d.completionFailure = false
			return nil, ErrRepositoryUnavailable
		}
		d.existing = true
	case "release":
		return json.RawMessage(`{}`), nil
	default:
		d.t.Fatalf("unknown stage: %s", body.Phase)
	}
	return json.RawMessage(`{"id":"pid_a0000000-0000-4000-8000-000000000001","status":"pending"}`), nil
}

func TestMemberInvitationRecoveryAndOrganizationBinding(t *testing.T) {
	for _, test := range []struct {
		name                              string
		failCompletion, wrongOrganization bool
		steps, providerCalls              []string
	}{
		{"safe replay", false, false, []string{"reserve", "send_new", "complete", "reserve"}, []string{"/v1/b2b/organizations/members/search", "/v1/b2b/magic_links/email/invite"}},
		{"recover acknowledgement", true, false, []string{"reserve", "send_new", "complete", "reserve", "check", "complete"}, []string{"/v1/b2b/organizations/members/search", "/v1/b2b/magic_links/email/invite", "/v1/b2b/organizations/members/search"}},
		{"mismatched directory result", false, true, []string{"reserve", "release"}, []string{"/v1/b2b/organizations/members/search"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			fake := &fakeStytchDirectory{}
			if test.wrongOrganization {
				fake.members = []DirectoryMember{{Reference: "member-test-invited", OrganizationReference: "organization-test-other", Email: "jordan@example.com", Status: "active"}}
			}
			driver := directoryFor(t, newTestStytchDirectory(t, fake))
			auth := &StytchOAuthAuthenticator{baseURL: driver.baseURL, client: driver.client, project: driver.project, secret: driver.secret}
			db := &memberInvitationDatabase{t: t, completionFailure: test.failCompletion}
			repo := &PostgresRepository{database: db, memberDirectory: &RepositoryIdentityProvider{authenticator: auth, redirectURI: driver.inviteRedirectURL}}
			m := administrationMutation{Operation: "inviteMember", ID: "pid_a0000000-0000-4000-8000-000000000001", AuditID: "pid_a0000000-0000-4000-8000-000000000002", Name: "Jordan", Email: "jordan@example.com", Role: "read_only_viewer", IdempotencyKey: "member-invitation-test-key"}
			admin := fixtureRequestIdentity(t)
			_, err := repo.MutateAdministration(ctx, admin, m)
			if test.wrongOrganization || test.failCompletion {
				if !errors.Is(err, ErrRepositoryUnavailable) {
					t.Fatalf("first attempt: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !test.wrongOrganization {
				m.ID = "pid_a0000000-0000-4000-8000-000000000003"
				result, err := repo.MutateAdministration(ctx, admin, m)
				if err != nil || !json.Valid(result) || !db.existing {
					t.Fatalf("replay: %s, %v", result, err)
				}
			}
			if !reflect.DeepEqual(db.steps, test.steps) || !reflect.DeepEqual(fake.paths(), test.providerCalls) {
				t.Fatalf("calls: %#v, %#v", db.steps, fake.paths())
			}
		})
	}
}

func TestMemberDirectoryFillsHistoricalProfilesOnlyFromMatchingProviderRecords(t *testing.T) {
	const local = `{"items":[{"organization_id":"customer","organization_reference":"organization-test-acme","member_reference":"member-test-alice","display_name":"Locally edited","version":9007199254740993},{"organization_id":"customer","organization_reference":"organization-test-acme","member_reference":"member-test-bob"},{"organization_id":"customer","organization_reference":"organization-test-acme","member_reference":"member-test-chris","display_name":"Chris","email":"chris@example.com"}],"cursor":"untouched"}`
	alice := DirectoryMember{Name: "Provider Alice", Reference: "member-test-alice", OrganizationReference: "organization-test-acme", Email: "alice@example.com", Status: "active"}
	bob := DirectoryMember{Name: "Bob Example", Reference: "member-test-bob", OrganizationReference: "organization-test-acme", Email: "bob@example.com", Status: "active"}
	for _, tc := range []struct {
		name    string
		members []DirectoryMember
		success bool
	}{
		{"legacy and local names", []DirectoryMember{alice, bob}, true},
		{"wrong organization", []DirectoryMember{alice, {Reference: bob.Reference, OrganizationReference: "organization-test-other", Email: bob.Email}}, false},
		{"unrequested member", []DirectoryMember{{Reference: "member-test-other", OrganizationReference: bob.OrganizationReference, Email: bob.Email}}, false},
		{"duplicate", []DirectoryMember{bob, bob}, false},
		{"missing provider profiles", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeStytchDirectory{members: tc.members}
			driver := directoryFor(t, newTestStytchDirectory(t, fake))
			repo := PostgresRepository{memberDirectory: &RepositoryIdentityProvider{authenticator: &StytchOAuthAuthenticator{baseURL: driver.baseURL, client: driver.client, project: driver.project, secret: driver.secret}, redirectURI: driver.inviteRedirectURL}}
			result := repo.enrichMemberPage(context.Background(), "customer", json.RawMessage(local))
			if !reflect.DeepEqual(fake.paths(), []string{"/v1/b2b/organizations/members/search"}) {
				t.Fatalf("unexpected calls: %v", fake.paths())
			}
			query := fake.requests[0].Body
			if !reflect.DeepEqual(query["organization_ids"], []any{"organization-test-acme"}) || !reflect.DeepEqual(query["query"], map[string]any{
				"operator": "AND", "operands": []any{map[string]any{"filter_name": "member_ids", "filter_value": []any{"member-test-alice", "member-test-bob"}}},
			}) {
				t.Fatalf("query escaped the member page: %#v", query)
			}
			if !tc.success {
				if string(result) != local {
					t.Fatalf("unexpected profile data: %s", result)
				}
				return
			}
			var page struct {
				Items []struct {
					Name    string `json:"display_name"`
					Email   string `json:"email"`
					Version int64  `json:"version"`
				} `json:"items"`
				Cursor string `json:"cursor"`
			}
			if err := json.Unmarshal(result, &page); err != nil || page.Cursor != "untouched" || len(page.Items) != 3 ||
				page.Items[0].Name != "Locally edited" || page.Items[0].Email != alice.Email || page.Items[0].Version != 9007199254740993 ||
				page.Items[1].Name != bob.Name || page.Items[1].Email != bob.Email || page.Items[2].Name != "Chris" || page.Items[2].Email != "chris@example.com" {
				t.Fatalf("wrong hydrated member page: %s (%v)", result, err)
			}
		})
	}
}

func TestMemberInvitationToExistingProviderAccount(t *testing.T) {
	for _, active := range []bool{false, true} {
		fake := &fakeStytchDirectory{members: []DirectoryMember{{Reference: "member-test-invited", OrganizationReference: "organization-test-acme", Email: "jordan@example.com", Status: "active"}}}
		driver := directoryFor(t, newTestStytchDirectory(t, fake))
		auth := &StytchOAuthAuthenticator{baseURL: driver.baseURL, client: driver.client, project: driver.project, secret: driver.secret}
		db := &memberInvitationDatabase{t: t, alreadyActive: active}
		repo := &PostgresRepository{database: db, memberDirectory: &RepositoryIdentityProvider{authenticator: auth, redirectURI: driver.inviteRedirectURL}}
		m := administrationMutation{Operation: "inviteMember", ID: "pid_a0000000-0000-4000-8000-000000000001", AuditID: "pid_a0000000-0000-4000-8000-000000000002", Name: "Jordan", Email: "jordan@example.com", Role: "read_only_viewer", IdempotencyKey: "member-invitation-test-key"}
		_, err := repo.MutateAdministration(context.Background(), fixtureRequestIdentity(t), m)
		if active {
			if !errors.Is(err, ErrRepositoryConflict) || len(fake.paths()) != 1 {
				t.Fatalf("already-active member was emailed: %v, %v", err, fake.paths())
			}
		} else {
			if err != nil || !reflect.DeepEqual(fake.paths(), []string{"/v1/b2b/organizations/members/search", "/v1/b2b/magic_links/email/login_or_signup"}) {
				t.Fatalf("returning member: %v %v", err, fake.paths())
			}
			link := fake.requests[1].Body
			if link["organization_id"] != "organization-test-acme" || link["email_address"] != m.Email || link["login_redirect_url"] != driver.inviteRedirectURL {
				t.Fatalf("unbound link: %v", link)
			}
		}
	}
}
