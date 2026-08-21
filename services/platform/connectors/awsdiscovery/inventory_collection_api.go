package awsdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var inventoryCursorPattern = regexp.MustCompile(`^aws:(iam|resources|posture|complete):([0-9a-f]{16}):([0-9a-f]{32})$`)

type CollectionInventoryCaller interface {
	GetCollectionInventory(context.Context, []byte) (CollectionInventory, error)
	CheckCollectionReadiness(context.Context) error
}

type CollectionSecurityAnalyzer interface {
	Collect(context.Context, CollectionSecurityRequest, []byte) (CollectionSecurityResult, error)
	CheckCollectionReadiness(context.Context) error
}

type CollectionInventory struct {
	Identity            Identity
	CredentialExpiresAt time.Time
	CartographySource   json.RawMessage
	CartographyDigest   [sha256.Size]byte
	ProwlerSource       json.RawMessage
	ProwlerDigest       [sha256.Size]byte
}

type CollectionInventoryAuthority struct {
	Scope                              domain.Scope
	IntegrationID, ConnectionID, JobID domain.ProductID
	Attempt                            int
	ObservedAt, CredentialExpiresAt    time.Time
}

type InventoryCollectionAPI struct {
	caller    CollectionInventoryCaller
	analyzer  CollectionSecurityAnalyzer
	authority CollectionInventoryAuthority
	timeout   time.Duration
}

type prowlerInventorySource struct {
	AccountID string                     `json:"account_id"`
	Instances []prowlerInventoryInstance `json:"instances"`
	Roles     []json.RawMessage          `json:"roles"`
}

type prowlerInventoryInstance struct {
	ARN          string `json:"Arn"`
	HTTPEndpoint string `json:"HttpEndpoint"`
	HTTPTokens   string `json:"HttpTokens"`
	InstanceID   string `json:"InstanceId"`
	Region       string `json:"Region"`
	State        string `json:"State"`
}

func NewInventoryCollectionAPI(caller CollectionInventoryCaller, analyzer CollectionSecurityAnalyzer, authority CollectionInventoryAuthority, timeout time.Duration) (*InventoryCollectionAPI, error) {
	if nilInventoryDependency(caller) || nilInventoryDependency(analyzer) || !validCollectionInventoryAuthority(authority) || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, ErrInvalid
	}
	return &InventoryCollectionAPI{caller: caller, analyzer: analyzer, authority: authority, timeout: timeout}, nil
}

func (api *InventoryCollectionAPI) FetchCollectionPage(ctx context.Context, credential []byte, request CollectionPageRequest) (CollectionPage, error) {
	if ctx != nil && ctx.Err() != nil {
		return CollectionPage{}, providercollection.ClassifyProviderError(ctx, ctx.Err())
	}
	if api == nil || nilInventoryDependency(api.caller) || nilInventoryDependency(api.analyzer) || ctx == nil || len(credential) < 16 || len(credential) > 65_536 || !validInventoryPageRequest(request) {
		return CollectionPage{}, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	borrowed := bytes.Clone(credential)
	inventory, err := callCollectionInventory(api.caller, bounded, borrowed)
	clear(borrowed)
	if err != nil || bounded.Err() != nil {
		return CollectionPage{}, providercollection.ClassifyProviderError(bounded, err)
	}
	if !validCollectionInventory(inventory, request.Subject, api.authority.ObservedAt) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	digest := collectionInventoryDigest(inventory)
	phase, cursorDigest, ok := inventoryRequestPhase(request)
	if !ok || request.Page > 1 && cursorDigest != digest {
		return CollectionPage{}, ErrInvalid
	}
	var page CollectionPage
	switch phase {
	case "account":
		page, err = api.accountPage(request, inventory, digest)
	case "iam":
		page, err = api.iamPage(bounded, request, inventory, credential, digest)
	case "resources":
		page, err = api.resourcePage(request, inventory, digest)
	case "posture":
		page, err = api.posturePage(bounded, request, inventory, credential, digest)
	default:
		err = ErrInvalid
	}
	if err != nil {
		return CollectionPage{}, err
	}
	if len(page.Raw) > int(request.RemainingBytes) || len(page.Entities) > request.RemainingItems || len(page.Relationships) > request.RemainingRelationships || len(page.Findings) > request.RemainingFindings {
		return CollectionPage{}, providercollection.ErrPageCapacity
	}
	return page, nil
}

func (api *InventoryCollectionAPI) CheckCollectionReadiness(ctx context.Context) error {
	if api == nil || nilInventoryDependency(api.caller) || nilInventoryDependency(api.analyzer) || ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	if err := callInventoryReadiness(api.caller, bounded); err != nil || bounded.Err() != nil {
		return ErrDenied
	}
	if err := callSecurityReadiness(api.analyzer, bounded); err != nil || bounded.Err() != nil {
		return ErrDenied
	}
	return nil
}

func (api *InventoryCollectionAPI) accountPage(request CollectionPageRequest, inventory CollectionInventory, digest [16]byte) (CollectionPage, error) {
	accountID := deterministicAWSInventoryID(api.authority.Scope, request.Subject, "aws_account", inventory.Identity.AccountID)
	entity := marshalInventoryEntity(accountID, "aws_account", inventory.Identity.AccountID, "AWS account "+inventory.Identity.AccountID, map[string]any{"account_id": inventory.Identity.AccountID}, map[string]any{})
	return NewCollectionPage(request.Subject, inventoryCursor("iam", request.Subject, digest), false, []json.RawMessage{entity}, nil)
}

func (api *InventoryCollectionAPI) iamPage(ctx context.Context, request CollectionPageRequest, inventory CollectionInventory, credential []byte, digest [16]byte) (CollectionPage, error) {
	securityRequest := api.securityRequest(request, SecurityModeCartographyAWS, inventory.CredentialExpiresAt, inventory.CartographySource, inventory.CartographyDigest)
	result, err := callSecurityAnalyzer(api.analyzer, ctx, securityRequest, credential)
	if err != nil || result.Mode != SecurityModeCartographyAWS || result.SourceDigest != inventory.CartographyDigest || !validSecurityResult(securityRequest, result.Result) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	var graph cartographySecurityResult
	if !decodeExactSecurityResult(result.Result, &graph) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	accountID := deterministicAWSInventoryID(api.authority.Scope, request.Subject, "aws_account", request.Subject.ID)
	entities := make([]json.RawMessage, 0, len(graph.Roles)+len(graph.Policies))
	relationships := make([]json.RawMessage, 0, len(graph.Roles)*2+len(graph.Policies)*2)
	roleIDs := make(map[string]string, len(graph.Roles))
	for _, role := range graph.Roles {
		roleID := deterministicAWSInventoryID(api.authority.Scope, request.Subject, "aws_role", role.ARN)
		roleIDs[role.ARN] = roleID
		entities = append(entities, marshalInventoryEntity(roleID, "aws_role", role.ARN, role.Name, map[string]any{"account_id": request.Subject.ID, "arn": role.ARN, "name": role.Name}, map[string]any{}))
		relationships = append(relationships, marshalInventoryRelationship(api.authority.Scope, request.Subject, "contains", request.Subject.ID+"|contains|"+role.ARN, accountID, roleID))
	}
	for _, policy := range graph.Policies {
		policyID := deterministicAWSInventoryID(api.authority.Scope, request.Subject, "aws_policy", policy.ARN)
		entities = append(entities, marshalInventoryEntity(policyID, "aws_policy", policy.ARN, policy.Name, map[string]any{"account_id": request.Subject.ID, "arn": policy.ARN, "name": policy.Name, "policy_type": "managed"}, map[string]any{}))
		relationships = append(relationships, marshalInventoryRelationship(api.authority.Scope, request.Subject, "contains", request.Subject.ID+"|contains|"+policy.ARN, accountID, policyID))
		for _, principal := range policy.PrincipalARNs {
			roleID, exists := roleIDs[principal]
			if !exists {
				return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
			}
			relationships = append(relationships, marshalInventoryRelationship(api.authority.Scope, request.Subject, "uses_policy", principal+"|uses_policy|"+policy.ARN, roleID, policyID))
		}
	}
	for _, role := range graph.Roles {
		for _, trusted := range role.TrustedRoleARNs {
			trustedID, exists := roleIDs[trusted]
			if !exists {
				return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
			}
			relationships = append(relationships, marshalInventoryRelationship(api.authority.Scope, request.Subject, "trusts", role.ARN+"|trusts|"+trusted, roleIDs[role.ARN], trustedID))
		}
	}
	sortRawInventory(entities)
	sortRawInventory(relationships)
	return NewCollectionPage(request.Subject, inventoryCursor("resources", request.Subject, digest), false, entities, relationships)
}

func (api *InventoryCollectionAPI) resourcePage(request CollectionPageRequest, inventory CollectionInventory, digest [16]byte) (CollectionPage, error) {
	var source prowlerInventorySource
	if !decodeExactSecurityResult(inventory.ProwlerSource, &source) || source.AccountID != request.Subject.ID || source.Instances == nil || source.Roles == nil {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	accountID := deterministicAWSInventoryID(api.authority.Scope, request.Subject, "aws_account", request.Subject.ID)
	serviceNative := "aws:ec2"
	serviceID := deterministicAWSInventoryID(api.authority.Scope, request.Subject, "aws_service", serviceNative)
	entities := []json.RawMessage{marshalInventoryEntity(serviceID, "aws_service", serviceNative, "EC2", map[string]any{"account_id": request.Subject.ID, "name": "EC2", "service": "ec2"}, map[string]any{})}
	relationships := []json.RawMessage{marshalInventoryRelationship(api.authority.Scope, request.Subject, "contains", request.Subject.ID+"|contains|"+serviceNative, accountID, serviceID)}
	for _, instance := range source.Instances {
		if !validInventoryInstance(request.Subject.ID, instance) {
			return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		resourceID := deterministicAWSInventoryID(api.authority.Scope, request.Subject, "aws_resource", instance.ARN)
		entities = append(entities, marshalInventoryEntity(resourceID, "aws_resource", instance.ARN, instance.InstanceID, map[string]any{"account_id": request.Subject.ID, "arn": instance.ARN, "name": instance.InstanceID, "region": instance.Region, "resource_type": "instance"}, map[string]any{"state": instance.State}))
		relationships = append(relationships,
			marshalInventoryRelationship(api.authority.Scope, request.Subject, "contains", request.Subject.ID+"|contains|"+instance.ARN, accountID, resourceID),
			marshalInventoryRelationship(api.authority.Scope, request.Subject, "belongs_to", instance.ARN+"|belongs_to|"+request.Subject.ID, resourceID, accountID),
			marshalInventoryRelationship(api.authority.Scope, request.Subject, "belongs_to", instance.ARN+"|belongs_to|"+serviceNative, resourceID, serviceID),
		)
	}
	sortRawInventory(entities)
	sortRawInventory(relationships)
	return NewCollectionPage(request.Subject, inventoryCursor("posture", request.Subject, digest), false, entities, relationships)
}

func (api *InventoryCollectionAPI) posturePage(ctx context.Context, request CollectionPageRequest, inventory CollectionInventory, credential []byte, digest [16]byte) (CollectionPage, error) {
	securityRequest := api.securityRequest(request, SecurityModeProwlerAWS, inventory.CredentialExpiresAt, inventory.ProwlerSource, inventory.ProwlerDigest)
	result, err := callSecurityAnalyzer(api.analyzer, ctx, securityRequest, credential)
	if err != nil || result.Mode != SecurityModeProwlerAWS || result.SourceDigest != inventory.ProwlerDigest || !validSecurityResult(securityRequest, result.Result) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	var posture prowlerSecurityResult
	if !decodeExactSecurityResult(result.Result, &posture) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	findings := make([]json.RawMessage, 0, len(posture.Findings))
	for _, finding := range posture.Findings {
		kind := "aws_resource"
		if strings.HasPrefix(finding.ResourceARN, "arn:aws:iam::") {
			kind = "aws_role"
		}
		entityID := deterministicAWSInventoryID(api.authority.Scope, request.Subject, kind, finding.ResourceARN)
		findingID := deterministicAWSInventoryID(api.authority.Scope, request.Subject, "prowler_finding", finding.CheckID+"\x1f"+finding.ResourceARN)
		findings = append(findings, marshalInventoryFinding(findingID, entityID, finding, api.authority.ObservedAt))
	}
	sortRawInventory(findings)
	return NewCollectionPageWithFindings(request.Subject, inventoryCursor("complete", request.Subject, digest), true, nil, nil, findings)
}

func (api *InventoryCollectionAPI) securityRequest(page CollectionPageRequest, mode SecurityMode, credentialExpiresAt time.Time, source json.RawMessage, digest [sha256.Size]byte) CollectionSecurityRequest {
	phase := "iam"
	remainingEntities := page.RemainingItems
	if mode == SecurityModeProwlerAWS {
		phase = "posture"
		remainingEntities = page.RemainingFindings
	}
	return CollectionSecurityRequest{Mode: mode, Scope: api.authority.Scope, IntegrationID: api.authority.IntegrationID, ConnectionID: api.authority.ConnectionID, JobID: api.authority.JobID, Attempt: api.authority.Attempt, CursorLineage: page.Page, Subject: page.Subject, Phase: phase, ObservedAt: api.authority.ObservedAt, CredentialExpiresAt: credentialExpiresAt, RemainingBytes: page.RemainingBytes, RemainingEntities: remainingEntities, RemainingRelationships: page.RemainingRelationships, SourceDigest: digest, Source: bytes.Clone(source)}
}

func validCollectionInventoryAuthority(authority CollectionInventoryAuthority) bool {
	return authority.Scope.Validate() == nil && !authority.IntegrationID.IsZero() && !authority.ConnectionID.IsZero() && !authority.JobID.IsZero() && authority.Attempt >= 1 && authority.Attempt <= 100 && exactUTCSecurityTime(authority.ObservedAt)
}

func validInventoryPageRequest(request CollectionPageRequest) bool {
	if request.Provider != collection.ProviderAWS || request.Subject.Kind != "aws_account" || !awsAccountIDPattern.MatchString(request.Subject.ID) || request.Page < 1 || request.Page > 4 || request.RemainingItems < 0 || request.RemainingRelationships < 0 || request.RemainingFindings < 0 || request.RemainingBytes < 1 {
		return false
	}
	_, _, ok := inventoryRequestPhase(request)
	return ok
}

func inventoryRequestPhase(request CollectionPageRequest) (string, [16]byte, bool) {
	if request.Page == 1 && (request.Cursor == (collection.Cursor{}) || request.Cursor == (collection.Cursor{Provider: collection.ProviderAWS, Version: "cursor_v1", Value: "initial"})) {
		return "account", [16]byte{}, true
	}
	if request.Cursor.Provider != collection.ProviderAWS || request.Cursor.Version != "cursor_v1" {
		return "", [16]byte{}, false
	}
	match := inventoryCursorPattern.FindStringSubmatch(request.Cursor.Value)
	if len(match) != 4 || match[2] != providercollection.CompleteCursorBinding(collection.ProviderAWS, request.Subject) || map[int]string{2: "iam", 3: "resources", 4: "posture"}[request.Page] != match[1] {
		return "", [16]byte{}, false
	}
	decoded, err := hex.DecodeString(match[3])
	var digest [16]byte
	copy(digest[:], decoded)
	return match[1], digest, err == nil && len(decoded) == len(digest)
}

func validCollectionInventory(inventory CollectionInventory, subject collection.SubjectBinding, observedAt time.Time) bool {
	return inventory.Identity.AccountID == subject.ID && validCollectionIdentity(inventory.Identity) && exactUTCSecurityTime(inventory.CredentialExpiresAt) && inventory.CredentialExpiresAt.After(observedAt) && canonicalSecurityObject(inventory.CartographySource) && canonicalSecurityObject(inventory.ProwlerSource) && sha256.Sum256(inventory.CartographySource) == inventory.CartographyDigest && sha256.Sum256(inventory.ProwlerSource) == inventory.ProwlerDigest
}

func collectionInventoryDigest(inventory CollectionInventory) [16]byte {
	combined := sha256.Sum256(append(append(make([]byte, 0, sha256.Size*2), inventory.CartographyDigest[:]...), inventory.ProwlerDigest[:]...))
	var digest [16]byte
	copy(digest[:], combined[:len(digest)])
	return digest
}

func inventoryCursor(phase string, subject collection.SubjectBinding, digest [16]byte) collection.Cursor {
	return collection.Cursor{Provider: collection.ProviderAWS, Version: "cursor_v1", Value: fmt.Sprintf("aws:%s:%s:%x", phase, providercollection.CompleteCursorBinding(collection.ProviderAWS, subject), digest)}
}

func deterministicAWSInventoryID(scope domain.Scope, subject collection.SubjectBinding, kind, nativeID string) string {
	seed := scope.OrganizationID().String() + "\x1f" + scope.WorkspaceID().String() + "\x1f" + scope.EnvironmentID().String() + "\x1f" + subject.Kind + "\x1f" + subject.ID + "\x1f" + kind + "\x1f" + nativeID
	digest := sha256.Sum256([]byte(seed))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	return fmt.Sprintf("pid_%x-%x-%x-%x-%x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func marshalInventoryEntity(id, kind, nativeID, display string, stable, attributes map[string]any) json.RawMessage {
	encoded, _ := json.Marshal(struct {
		ID             string         `json:"id"`
		Kind           string         `json:"kind"`
		SourceNativeID string         `json:"source_native_id"`
		DisplayName    string         `json:"display_name"`
		StableFields   map[string]any `json:"stable_fields"`
		Attributes     map[string]any `json:"attributes"`
	}{id, kind, nativeID, display, stable, attributes})
	return encoded
}

func marshalInventoryRelationship(scope domain.Scope, subject collection.SubjectBinding, kind, nativeID, from, to string) json.RawMessage {
	id := deterministicAWSInventoryID(scope, subject, "relationship", kind+"\x1f"+nativeID+"\x1f"+from+"\x1f"+to)
	encoded, _ := json.Marshal(struct {
		ID             string         `json:"id"`
		Kind           string         `json:"kind"`
		SourceNativeID string         `json:"source_native_id"`
		FromEntityID   string         `json:"from_entity_id"`
		ToEntityID     string         `json:"to_entity_id"`
		Attributes     map[string]any `json:"attributes"`
	}{ID: id, Kind: kind, SourceNativeID: nativeID, FromEntityID: from, ToEntityID: to, Attributes: map[string]any{}})
	return encoded
}

func marshalInventoryFinding(id, entityID string, finding prowlerSecurityFinding, observedAt time.Time) json.RawMessage {
	encoded, _ := json.Marshal(struct {
		ID         string `json:"id"`
		EntityID   string `json:"entity_id"`
		CheckID    string `json:"check_id"`
		Severity   string `json:"severity"`
		Status     string `json:"status"`
		ObservedAt string `json:"observed_at"`
	}{ID: id, EntityID: entityID, CheckID: finding.CheckID, Severity: finding.Severity, Status: finding.Status, ObservedAt: observedAt.Format(time.RFC3339)})
	return encoded
}

func validInventoryInstance(accountID string, instance prowlerInventoryInstance) bool {
	match := securityInstanceARNPattern.FindStringSubmatch(instance.ARN)
	return len(match) == 4 && match[2] == accountID && match[1] == instance.Region && match[3] == instance.InstanceID && (instance.HTTPEndpoint == "enabled" || instance.HTTPEndpoint == "disabled") && (instance.HTTPTokens == "optional" || instance.HTTPTokens == "required") && map[string]bool{"pending": true, "running": true, "shutting-down": true, "terminated": true, "stopping": true, "stopped": true}[instance.State]
}

func sortRawInventory(values []json.RawMessage) {
	sort.Slice(values, func(left, right int) bool {
		return identityForAWSInventorySort(values[left]) < identityForAWSInventorySort(values[right])
	})
}

func identityForAWSInventorySort(raw json.RawMessage) string {
	var value struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(raw, &value)
	return value.ID
}

func callCollectionInventory(caller CollectionInventoryCaller, ctx context.Context, credential []byte) (inventory CollectionInventory, resultErr error) {
	defer func() {
		if recover() != nil {
			inventory = CollectionInventory{}
			resultErr = ErrDenied
		}
	}()
	return caller.GetCollectionInventory(ctx, credential)
}

func callInventoryReadiness(caller CollectionInventoryCaller, ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrDenied
		}
	}()
	return caller.CheckCollectionReadiness(ctx)
}

func callSecurityAnalyzer(analyzer CollectionSecurityAnalyzer, ctx context.Context, request CollectionSecurityRequest, credential []byte) (result CollectionSecurityResult, resultErr error) {
	borrowed := bytes.Clone(credential)
	defer clear(borrowed)
	defer func() {
		if recover() != nil {
			result = CollectionSecurityResult{}
			resultErr = ErrDenied
		}
	}()
	return analyzer.Collect(ctx, request, borrowed)
}

func callSecurityReadiness(analyzer CollectionSecurityAnalyzer, ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrDenied
		}
	}()
	return analyzer.CheckCollectionReadiness(ctx)
}

func nilInventoryDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}

var _ CollectionAPI = (*InventoryCollectionAPI)(nil)
