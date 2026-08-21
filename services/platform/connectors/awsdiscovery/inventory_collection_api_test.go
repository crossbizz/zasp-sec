package awsdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type recordingAWSInventoryCaller struct {
	snapshot CollectionInventory
	calls    int
}

func (caller *recordingAWSInventoryCaller) GetCollectionInventory(context.Context, []byte) (CollectionInventory, error) {
	caller.calls++
	return caller.snapshot, nil
}

func (caller *recordingAWSInventoryCaller) CheckCollectionReadiness(context.Context) error {
	return nil
}

type recordingSecurityAnalyzer struct {
	calls             []SecurityMode
	credential        [][]byte
	expiresAt         []time.Time
	remainingEntities []int
}

func (*recordingSecurityAnalyzer) CheckCollectionReadiness(context.Context) error { return nil }

func (analyzer *recordingSecurityAnalyzer) Collect(_ context.Context, request CollectionSecurityRequest, credential []byte) (CollectionSecurityResult, error) {
	analyzer.calls = append(analyzer.calls, request.Mode)
	analyzer.credential = append(analyzer.credential, bytes.Clone(credential))
	analyzer.expiresAt = append(analyzer.expiresAt, request.CredentialExpiresAt)
	analyzer.remainingEntities = append(analyzer.remainingEntities, request.RemainingEntities)
	result := json.RawMessage(`{"findings":[{"check_id":"iam_role_administratoraccess_policy","resource_arn":"arn:aws:iam::123456789012:role/read","resource_id":"read","region":"global","severity":"high","status":"FAIL"}],"version":"5.39.1"}`)
	if request.Mode == SecurityModeCartographyAWS {
		result = json.RawMessage(`{"policies":[{"arn":"arn:aws:iam::123456789012:policy/read","name":"read","principal_arns":["arn:aws:iam::123456789012:role/read"]}],"roles":[{"arn":"arn:aws:iam::123456789012:role/read","name":"read","trusted_role_arns":[]}],"version":"0.139.1"}`)
	}
	return CollectionSecurityResult{Mode: request.Mode, SourceDigest: request.SourceDigest, Result: result}, nil
}

func TestInventoryCollectionAPIRequiresAllFourPhasesBeforeComplete(t *testing.T) {
	t.Parallel()
	authority := awsInventoryAuthority(t, "pid_51000001-0000-4000-8000-000000000001")
	caller := &recordingAWSInventoryCaller{snapshot: awsInventoryFixture()}
	analyzer := &recordingSecurityAnalyzer{}
	api, err := NewInventoryCollectionAPI(caller, analyzer, authority, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte(`{"access_key_id":"ASIAABCDEFGHIJKLMNOP","expires_at":"2026-08-20T12:15:00Z","secret_access_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","session_token":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)
	request := CollectionPageRequest{Provider: collection.ProviderAWS, Subject: collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, Page: 1, RemainingItems: 100, RemainingRelationships: 200, RemainingFindings: 7, RemainingBytes: 1 << 20}

	account, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil || account.Complete || len(account.Entities) != 1 || len(account.Relationships) != 0 || len(account.Findings) != 0 {
		t.Fatalf("account page = %#v, %v", account, err)
	}
	request.Cursor, request.Page = account.Cursor, 2
	iam, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil || iam.Complete || len(iam.Entities) != 2 || len(iam.Relationships) != 3 || len(iam.Findings) != 0 {
		t.Fatalf("IAM page = %#v, %v", iam, err)
	}
	request.Cursor, request.Page = iam.Cursor, 3
	resources, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil || resources.Complete || len(resources.Entities) != 2 || len(resources.Relationships) != 4 || len(resources.Findings) != 0 {
		t.Fatalf("resource page = %#v, %v", resources, err)
	}
	request.Cursor, request.Page = resources.Cursor, 4
	posture, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil || !posture.Complete || len(posture.Entities) != 0 || len(posture.Relationships) != 0 || len(posture.Findings) != 1 {
		t.Fatalf("posture page = %#v, %v", posture, err)
	}
	if caller.calls != 4 || len(analyzer.calls) != 2 || analyzer.calls[0] != SecurityModeCartographyAWS || analyzer.calls[1] != SecurityModeProwlerAWS {
		t.Fatalf("caller/analyzer calls = %d / %v", caller.calls, analyzer.calls)
	}
	if len(analyzer.expiresAt) != 2 || analyzer.expiresAt[0] != caller.snapshot.CredentialExpiresAt || analyzer.expiresAt[1] != caller.snapshot.CredentialExpiresAt {
		t.Fatalf("security credential expiry = %v, want %v", analyzer.expiresAt, caller.snapshot.CredentialExpiresAt)
	}
	if len(analyzer.credential) != 2 || !bytes.Equal(analyzer.credential[0], credential) || !bytes.Equal(analyzer.credential[1], credential) {
		t.Fatalf("security credential propagation = %q", analyzer.credential)
	}
	if len(analyzer.remainingEntities) != 2 || analyzer.remainingEntities[0] != request.RemainingItems || analyzer.remainingEntities[1] != request.RemainingFindings {
		t.Fatalf("security item budgets = %v", analyzer.remainingEntities)
	}
}

func TestInventoryCollectionAPIScopesIdenticalAWSARNsToDifferentOrganizations(t *testing.T) {
	t.Parallel()
	credential := []byte("temporary-aws-credential-value")
	request := CollectionPageRequest{Provider: collection.ProviderAWS, Subject: collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}, Page: 1, RemainingItems: 100, RemainingRelationships: 200, RemainingFindings: 100, RemainingBytes: 1 << 20}
	first, err := NewInventoryCollectionAPI(&recordingAWSInventoryCaller{snapshot: awsInventoryFixture()}, &recordingSecurityAnalyzer{}, awsInventoryAuthority(t, "pid_51000001-0000-4000-8000-000000000001"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewInventoryCollectionAPI(&recordingAWSInventoryCaller{snapshot: awsInventoryFixture()}, &recordingSecurityAnalyzer{}, awsInventoryAuthority(t, "pid_52000001-0000-4000-8000-000000000001"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	firstPage, firstErr := first.FetchCollectionPage(context.Background(), credential, request)
	secondPage, secondErr := second.FetchCollectionPage(context.Background(), credential, request)
	var firstEntity, secondEntity struct {
		ID string `json:"id"`
	}
	if firstErr != nil || secondErr != nil || json.Unmarshal(firstPage.Entities[0], &firstEntity) != nil || json.Unmarshal(secondPage.Entities[0], &secondEntity) != nil || firstEntity.ID == secondEntity.ID {
		t.Fatalf("tenant-scoped identity = %q / %q, errors %v / %v", firstEntity.ID, secondEntity.ID, firstErr, secondErr)
	}
}

func awsInventoryFixture() CollectionInventory {
	cartography := json.RawMessage(`{"account_id":"123456789012","managed_policies":{"arn:aws:iam::123456789012:role/read":{"arn:aws:iam::123456789012:policy/read":[]}},"roles":[{"Arn":"arn:aws:iam::123456789012:role/read","AssumeRolePolicyDocument":{},"CreateDate":"2026-08-20T00:00:00Z","Path":"/","RoleId":"AROAABCDEFGHIJKLMNOP","RoleName":"read"}]}`)
	prowler := json.RawMessage(`{"account_id":"123456789012","instances":[{"Arn":"arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0","HttpEndpoint":"enabled","HttpTokens":"required","InstanceId":"i-0123456789abcdef0","Region":"us-east-1","State":"running"}],"roles":[{"Arn":"arn:aws:iam::123456789012:role/read","AssumeRolePolicyDocument":{},"AttachedPolicies":[{"PolicyName":"read"}],"IsServiceRole":false,"RoleId":"AROAABCDEFGHIJKLMNOP","RoleName":"read"}]}`)
	return CollectionInventory{Identity: Identity{AccountID: "123456789012", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/discovery/session"}, CredentialExpiresAt: time.Date(2026, 8, 20, 12, 20, 0, 0, time.UTC), CartographySource: cartography, CartographyDigest: sha256.Sum256(cartography), ProwlerSource: prowler, ProwlerDigest: sha256.Sum256(prowler)}
}

func awsInventoryAuthority(t *testing.T, organization string) CollectionInventoryAuthority {
	t.Helper()
	parse := func(value string) domain.ProductID {
		id, err := domain.ParseProductID(value)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	scope, err := domain.NewScope(parse(organization), parse("pid_51000002-0000-4000-8000-000000000002"), parse("pid_51000003-0000-4000-8000-000000000003"))
	if err != nil {
		t.Fatal(err)
	}
	return CollectionInventoryAuthority{Scope: scope, IntegrationID: parse("pid_51000004-0000-4000-8000-000000000004"), ConnectionID: parse("pid_51000005-0000-4000-8000-000000000005"), JobID: parse("pid_51000006-0000-4000-8000-000000000006"), Attempt: 1, ObservedAt: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
}
