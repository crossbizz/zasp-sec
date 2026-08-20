package inventorysearch

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	absoluteMaximumDocuments     = 10_000
	absoluteMaximumDocumentBytes = 65_536
	absoluteMaximumBatchBytes    = 8 << 20
	absoluteMaximumResults       = 100
	contentDigestDomain          = "zasp.inventory-search.complete-snapshot.v1"
)

var (
	ErrConfiguration  = errors.New("inventory search configuration rejected")
	ErrInput          = errors.New("inventory search input rejected")
	ErrCanceled       = errors.New("inventory search operation canceled")
	ErrRetryable      = errors.New("inventory search operation retryable")
	ErrUnknownOutcome = errors.New("inventory search operation outcome unknown")
	ErrDenied         = errors.New("inventory search authority denied")
	ErrRejected       = errors.New("inventory search operation rejected")
	ErrStale          = errors.New("inventory search snapshot generation stale")
	ErrDrift          = errors.New("inventory search immutable document drift")
	ErrUnavailable    = errors.New("inventory search unavailable")
	kindPattern       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	documentIDPattern = regexp.MustCompile(`^inv_[0-9a-f]{64}$`)
	secretNamePattern = regexp.MustCompile(`(^|_)(access_token|api_key|credential|password|private_key|refresh_token|secret|token)($|_)`)
)

// allowedAttributesByKind is deliberately closed. Projection inputs must add a
// reviewed, non-secret field here before that field can become searchable.
var allowedAttributesByKind = map[string]map[string]struct{}{
	"account":                    attributeSet("account_id", "organization_id", "partition"),
	"application":                attributeSet("application_id", "label", "sign_on_mode", "status"),
	"aws_account":                attributeSet("account_id", "organization_id", "partition"),
	"aws_instance":               attributeSet("account_id", "arn", "availability_zone", "instance_type", "region", "state", "subnet_id", "vpc_id"),
	"aws_policy":                 attributeSet("account_id", "arn", "path", "policy_id", "scope"),
	"aws_role":                   attributeSet("account_id", "arn", "path", "role_id"),
	"cluster":                    attributeSet("cluster_name", "provider", "region", "version"),
	"database":                   attributeSet("engine", "region", "version"),
	"github_app":                 attributeSet("app_id", "slug"),
	"github_organization":        attributeSet("login", "organization_id"),
	"github_permission":          attributeSet("permission", "repository", "subject"),
	"github_repository":          attributeSet("archived", "default_branch", "full_name", "owner", "repository_id", "visibility"),
	"github_workflow":            attributeSet("path", "repository", "state"),
	"group":                      attributeSet("group_id", "group_type", "name"),
	"identity":                   attributeSet("login", "status", "user_type"),
	"kubernetes_cluster":         attributeSet("cluster_name", "provider", "region", "version"),
	"kubernetes_namespace":       attributeSet("cluster_name", "namespace"),
	"kubernetes_service_account": attributeSet("cluster_name", "namespace", "service_account"),
	"kubernetes_workload":        attributeSet("cluster_name", "namespace", "workload_kind", "workload_name"),
	"namespace":                  attributeSet("cluster_name", "namespace"),
	"okta_application":           attributeSet("application_id", "label", "sign_on_mode", "status"),
	"okta_group":                 attributeSet("group_id", "group_type", "name"),
	"okta_service_principal":     attributeSet("application_id", "status"),
	"okta_user":                  attributeSet("login", "status", "user_type"),
	"permission":                 attributeSet("permission", "repository", "subject"),
	"repository":                 attributeSet("archived", "default_branch", "full_name", "owner", "repository_id", "visibility"),
	"service_account":            attributeSet("cluster_name", "namespace", "service_account"),
	"service_principal":          attributeSet("application_id", "status"),
	"workflow":                   attributeSet("path", "repository", "state"),
	"workload":                   attributeSet("cluster_name", "namespace", "workload_kind", "workload_name"),
}

type Config struct {
	MaximumDocuments     int
	MaximumDocumentBytes int
	MaximumBatchBytes    int
	MaximumResults       int
}

type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Document struct {
	EntityID    domain.ProductID
	Kind        string
	DisplayName string
	Attributes  []Attribute
}

type Snapshot struct {
	Scope         domain.Scope
	IntegrationID domain.ProductID
	SnapshotID    domain.ProductID
	Generation    int64
	InputDigest   [sha256.Size]byte
	Documents     []Document
}

type ApplyResult struct {
	SnapshotID    domain.ProductID
	Generation    int64
	InputDigest   [sha256.Size]byte
	ContentDigest [sha256.Size]byte
	DocumentIDs   []string
	Replayed      bool
	Removed       int
}

type Query struct {
	IntegrationID domain.ProductID
	SnapshotID    domain.ProductID
	Generation    int64
	InputDigest   [sha256.Size]byte
	ContentDigest [sha256.Size]byte
	Text          string
	Kinds         []string
	AfterEntityID domain.ProductID
	Limit         int
}

type Hit struct {
	EntityID    domain.ProductID
	Kind        string
	DisplayName string
	Attributes  []Attribute
}

type Page struct {
	Hits         []Hit
	NextEntityID domain.ProductID
}

// DriverSnapshot is the immutable authority fence shared by every driver
// phase. Implementations must compare the entire value on replay.
type DriverSnapshot struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	IntegrationID  string
	SnapshotID     string
	Generation     int64
	InputDigest    [sha256.Size]byte
	ContentDigest  [sha256.Size]byte
}

type DriverDocument struct {
	Snapshot    DriverSnapshot
	DocumentID  string
	EntityID    string
	Kind        string
	DisplayName string
	Attributes  []Attribute
}

// DriverStage immutably creates or reconciles every document in one complete
// snapshot. It must not change the active generation.
type DriverStage struct {
	Snapshot  DriverSnapshot
	Documents []DriverDocument
}

type DriverStaged struct {
	Snapshot    DriverSnapshot
	DocumentIDs []string
	Replayed    bool
}

// DriverActivation generation-fences the current snapshot. A driver must
// return ErrStale when a newer generation is already active and ErrDrift when
// the same generation has a different immutable binding or document set.
type DriverActivation struct {
	Snapshot    DriverSnapshot
	DocumentIDs []string
}

type DriverActivated struct {
	ActiveSnapshot    DriverSnapshot
	ActiveDocumentIDs []string
	Replayed          bool
}

// DriverDiscard removes only the rejected candidate's immutable document IDs.
// Implementations must first prove ExpectedActiveSnapshot and its document IDs
// are still current, and must never delete an ID in ExpectedActiveDocumentIDs.
type DriverDiscard struct {
	CandidateSnapshot         DriverSnapshot
	CandidateDocumentIDs      []string
	ExpectedActiveSnapshot    DriverSnapshot
	ExpectedActiveDocumentIDs []string
}

type DriverDiscarded struct {
	CandidateSnapshot DriverSnapshot
	ActiveSnapshot    DriverSnapshot
	ActiveDocumentIDs []string
	Removed           int
	Replayed          bool
}

// DriverCleanup removes only generations older than ActiveSnapshot. It must
// re-check the complete active fence so a delayed cleanup cannot delete newer
// data.
type DriverCleanup struct {
	ActiveSnapshot DriverSnapshot
}

type DriverCleaned struct {
	ActiveSnapshot DriverSnapshot
	Removed        int
	Replayed       bool
}

type DriverQuery struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	IntegrationID  string
	SnapshotID     string
	Generation     int64
	InputDigest    [sha256.Size]byte
	ContentDigest  [sha256.Size]byte
	Text           string
	Kinds          []string
	AfterEntityID  string
	Limit          int
	Sort           []string
}

type DriverSearchResult struct {
	Hits         []DriverDocument
	NextEntityID string
}

type Driver interface {
	Stage(context.Context, DriverStage) (DriverStaged, error)
	Activate(context.Context, DriverActivation) (DriverActivated, error)
	DiscardStage(context.Context, DriverDiscard) (DriverDiscarded, error)
	RemoveStale(context.Context, DriverCleanup) (DriverCleaned, error)
	Search(context.Context, DriverQuery) (DriverSearchResult, error)
}

type Store struct {
	driver Driver
	config Config
}

func New(driver Driver, config Config) (*Store, error) {
	if nilInterface(driver) || config.MaximumDocuments < 1 || config.MaximumDocuments > absoluteMaximumDocuments || config.MaximumDocumentBytes < 1 || config.MaximumDocumentBytes > absoluteMaximumDocumentBytes || config.MaximumBatchBytes < config.MaximumDocumentBytes || config.MaximumBatchBytes > absoluteMaximumBatchBytes || config.MaximumResults < 1 || config.MaximumResults > absoluteMaximumResults {
		return nil, ErrConfiguration
	}
	return &Store{driver: driver, config: config}, nil
}

func (store *Store) ApplySnapshot(ctx context.Context, snapshot Snapshot) (ApplyResult, error) {
	if !store.usable() || ctx == nil {
		return ApplyResult{}, ErrInput
	}
	if ctx.Err() != nil {
		return ApplyResult{}, ErrCanceled
	}
	stage, expectedIDs, ok := store.driverStage(snapshot)
	if !ok {
		return ApplyResult{}, ErrInput
	}
	staged, err := callStage(store.driver, ctx, stage)
	if err != nil {
		return ApplyResult{}, sanitizeDriverError(err)
	}
	if !sameDriverSnapshot(staged.Snapshot, stage.Snapshot) || !equalDocumentIDs(staged.DocumentIDs, expectedIDs) {
		return ApplyResult{}, ErrDrift
	}
	activation := DriverActivation{Snapshot: stage.Snapshot, DocumentIDs: append([]string(nil), expectedIDs...)}
	activated, err := callActivate(store.driver, ctx, activation)
	if err != nil {
		stable := sanitizeDriverError(err)
		if !errors.Is(stable, ErrStale) && !errors.Is(stable, ErrDrift) {
			return ApplyResult{}, stable
		}
		if !validRejectedActivation(stage.Snapshot, expectedIDs, activated, stable) {
			return ApplyResult{}, ErrUnknownOutcome
		}
		discard := DriverDiscard{
			CandidateSnapshot: stage.Snapshot, CandidateDocumentIDs: append([]string(nil), expectedIDs...),
			ExpectedActiveSnapshot: activated.ActiveSnapshot, ExpectedActiveDocumentIDs: append([]string(nil), activated.ActiveDocumentIDs...),
		}
		discarded, discardErr := callDiscardStage(store.driver, ctx, discard)
		if discardErr != nil {
			return ApplyResult{}, sanitizeDriverError(discardErr)
		}
		if discarded.CandidateSnapshot != discard.CandidateSnapshot || discarded.ActiveSnapshot != discard.ExpectedActiveSnapshot || !equalDocumentIDs(discarded.ActiveDocumentIDs, discard.ExpectedActiveDocumentIDs) || discarded.Removed < 0 {
			return ApplyResult{}, ErrUnknownOutcome
		}
		return ApplyResult{}, stable
	}
	if !sameDriverSnapshot(activated.ActiveSnapshot, stage.Snapshot) || !equalDocumentIDs(activated.ActiveDocumentIDs, expectedIDs) {
		return ApplyResult{}, ErrDrift
	}
	cleanup := DriverCleanup{ActiveSnapshot: stage.Snapshot}
	cleaned, err := callRemoveStale(store.driver, ctx, cleanup)
	if err != nil {
		return ApplyResult{}, sanitizeDriverError(err)
	}
	if !sameDriverSnapshot(cleaned.ActiveSnapshot, stage.Snapshot) || cleaned.Removed < 0 {
		return ApplyResult{}, ErrDrift
	}
	return ApplyResult{
		SnapshotID: snapshot.SnapshotID, Generation: snapshot.Generation, InputDigest: snapshot.InputDigest,
		ContentDigest: stage.Snapshot.ContentDigest, DocumentIDs: append([]string(nil), expectedIDs...),
		Replayed: activated.Replayed, Removed: cleaned.Removed,
	}, nil
}

func (store *Store) Search(ctx context.Context, scope domain.Scope, query Query) (Page, error) {
	if !store.usable() || ctx == nil {
		return Page{}, ErrInput
	}
	if ctx.Err() != nil {
		return Page{}, ErrCanceled
	}
	driverQuery, ok := store.driverQuery(scope, query)
	if !ok {
		return Page{}, ErrInput
	}
	result, err := callSearch(store.driver, ctx, driverQuery)
	if err != nil {
		return Page{}, sanitizeDriverError(err)
	}
	return store.productPage(scope, query, result)
}

func (store *Store) driverStage(snapshot Snapshot) (DriverStage, []string, bool) {
	if snapshot.Scope.Validate() != nil || !validProductID(snapshot.IntegrationID) || !validProductID(snapshot.SnapshotID) || snapshot.Generation < 1 || !validDigest(snapshot.InputDigest) || len(snapshot.Documents) > store.config.MaximumDocuments {
		return DriverStage{}, nil, false
	}
	documents := append([]Document(nil), snapshot.Documents...)
	sort.Slice(documents, func(left, right int) bool {
		return documents[left].EntityID.String() < documents[right].EntityID.String()
	})
	driverDocuments := make([]DriverDocument, len(documents))
	expectedIDs := make([]string, len(documents))
	seen := make(map[domain.ProductID]struct{}, len(documents))
	totalBytes := 0
	for index, document := range documents {
		attributes, documentBytes, valid := normalizedAttributes(document.Kind, document.Attributes, store.config.MaximumDocumentBytes)
		if !validProductID(document.EntityID) || !kindPattern.MatchString(document.Kind) || !validText(document.DisplayName, 256, false) || !valid || documentBytes+len(document.DisplayName)+len(document.Kind)+512 > store.config.MaximumDocumentBytes {
			return DriverStage{}, nil, false
		}
		if _, duplicate := seen[document.EntityID]; duplicate {
			return DriverStage{}, nil, false
		}
		seen[document.EntityID] = struct{}{}
		totalBytes += documentBytes + len(document.DisplayName) + len(document.Kind) + 512
		if totalBytes > store.config.MaximumBatchBytes {
			return DriverStage{}, nil, false
		}
		driverDocuments[index] = DriverDocument{EntityID: document.EntityID.String(), Kind: document.Kind, DisplayName: document.DisplayName, Attributes: attributes}
	}
	binding := DriverSnapshot{
		OrganizationID: snapshot.Scope.OrganizationID().String(), WorkspaceID: snapshot.Scope.WorkspaceID().String(), EnvironmentID: snapshot.Scope.EnvironmentID().String(),
		IntegrationID: snapshot.IntegrationID.String(), SnapshotID: snapshot.SnapshotID.String(), Generation: snapshot.Generation, InputDigest: snapshot.InputDigest,
	}
	binding.ContentDigest = canonicalContentDigest(binding, driverDocuments)
	for index := range driverDocuments {
		driverDocuments[index].Snapshot = binding
		id := documentID(snapshot.Scope, snapshot.IntegrationID, snapshot.SnapshotID, snapshot.Generation, snapshot.InputDigest, binding.ContentDigest, documents[index].EntityID)
		driverDocuments[index].DocumentID = id
		expectedIDs[index] = id
	}
	return DriverStage{Snapshot: binding, Documents: driverDocuments}, expectedIDs, true
}

func (store *Store) driverQuery(scope domain.Scope, query Query) (DriverQuery, bool) {
	if scope.Validate() != nil || !validProductID(query.IntegrationID) || !validProductID(query.SnapshotID) || query.Generation < 1 || !validDigest(query.InputDigest) || !validDigest(query.ContentDigest) || !validOptionalText(query.Text, 256) || query.Limit < 1 || query.Limit > store.config.MaximumResults || len(query.Kinds) > 32 || !query.AfterEntityID.IsZero() && !validProductID(query.AfterEntityID) {
		return DriverQuery{}, false
	}
	kinds := append([]string(nil), query.Kinds...)
	sort.Strings(kinds)
	for index, kind := range kinds {
		if !kindPattern.MatchString(kind) || allowedAttributesByKind[kind] == nil || index > 0 && kind == kinds[index-1] {
			return DriverQuery{}, false
		}
	}
	after := ""
	if !query.AfterEntityID.IsZero() {
		after = query.AfterEntityID.String()
	}
	return DriverQuery{
		OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(),
		IntegrationID: query.IntegrationID.String(), SnapshotID: query.SnapshotID.String(), Generation: query.Generation, InputDigest: query.InputDigest, ContentDigest: query.ContentDigest,
		Text: query.Text, Kinds: kinds, AfterEntityID: after, Limit: query.Limit, Sort: []string{"entity_id"},
	}, true
}

func (store *Store) productPage(scope domain.Scope, query Query, result DriverSearchResult) (Page, error) {
	if len(result.Hits) > query.Limit {
		return Page{}, ErrUnavailable
	}
	wantedKinds := make(map[string]struct{}, len(query.Kinds))
	for _, kind := range query.Kinds {
		wantedKinds[kind] = struct{}{}
	}
	hits := make([]Hit, len(result.Hits))
	seen := make(map[domain.ProductID]struct{}, len(result.Hits))
	previous := query.AfterEntityID.String()
	wantBinding := DriverSnapshot{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), IntegrationID: query.IntegrationID.String(), SnapshotID: query.SnapshotID.String(), Generation: query.Generation, InputDigest: query.InputDigest, ContentDigest: query.ContentDigest}
	for index, document := range result.Hits {
		entityID, err := domain.ParseProductID(document.EntityID)
		if err != nil || !sameDriverSnapshot(document.Snapshot, wantBinding) || document.DocumentID != documentID(scope, query.IntegrationID, query.SnapshotID, query.Generation, query.InputDigest, query.ContentDigest, entityID) || !validDriverDocument(document, store.config.MaximumDocumentBytes) || document.EntityID <= previous {
			return Page{}, ErrDrift
		}
		if len(wantedKinds) > 0 {
			if _, requested := wantedKinds[document.Kind]; !requested {
				return Page{}, ErrDrift
			}
		}
		if _, duplicate := seen[entityID]; duplicate {
			return Page{}, ErrDrift
		}
		seen[entityID] = struct{}{}
		previous = document.EntityID
		hits[index] = Hit{EntityID: entityID, Kind: document.Kind, DisplayName: document.DisplayName, Attributes: cloneAttributes(document.Attributes)}
	}
	var next domain.ProductID
	if result.NextEntityID != "" {
		parsed, err := domain.ParseProductID(result.NextEntityID)
		if err != nil || len(result.Hits) != query.Limit || len(result.Hits) == 0 || result.NextEntityID != result.Hits[len(result.Hits)-1].EntityID {
			return Page{}, ErrDrift
		}
		next = parsed
	} else if len(result.Hits) == query.Limit {
		return Page{}, ErrDrift
	}
	return Page{Hits: hits, NextEntityID: next}, nil
}

func validDriverDocument(document DriverDocument, maximumBytes int) bool {
	organizationID, organizationErr := domain.ParseProductID(document.Snapshot.OrganizationID)
	workspaceID, workspaceErr := domain.ParseProductID(document.Snapshot.WorkspaceID)
	environmentID, environmentErr := domain.ParseProductID(document.Snapshot.EnvironmentID)
	_, integrationErr := domain.ParseProductID(document.Snapshot.IntegrationID)
	_, snapshotErr := domain.ParseProductID(document.Snapshot.SnapshotID)
	entityID, entityErr := domain.ParseProductID(document.EntityID)
	_, scopeErr := domain.NewScope(organizationID, workspaceID, environmentID)
	attributes, attributeBytes, valid := normalizedAttributes(document.Kind, document.Attributes, maximumBytes)
	return organizationErr == nil && workspaceErr == nil && environmentErr == nil && integrationErr == nil && snapshotErr == nil && entityErr == nil && scopeErr == nil && document.Snapshot.Generation >= 1 && validDigest(document.Snapshot.InputDigest) && validDigest(document.Snapshot.ContentDigest) && documentIDPattern.MatchString(document.DocumentID) && kindPattern.MatchString(document.Kind) && validText(document.DisplayName, 256, false) && valid && attributeBytes+len(document.DisplayName)+len(document.Kind)+512 <= maximumBytes && reflect.DeepEqual(attributes, document.Attributes) && validProductID(entityID)
}

func normalizedAttributes(kind string, input []Attribute, maximumBytes int) ([]Attribute, int, bool) {
	allowlist := allowedAttributesByKind[kind]
	if allowlist == nil {
		return nil, 0, false
	}
	attributes := cloneAttributes(input)
	sort.Slice(attributes, func(left, right int) bool { return attributes[left].Name < attributes[right].Name })
	totalBytes := 2
	for index, attribute := range attributes {
		trimmed := strings.TrimSpace(attribute.Value)
		nested := len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid([]byte(trimmed))
		_, allowed := allowlist[attribute.Name]
		if !kindPattern.MatchString(attribute.Name) || secretNamePattern.MatchString(attribute.Name) || !allowed || !validText(attribute.Value, 2_048, false) || nested || index > 0 && attribute.Name == attributes[index-1].Name {
			return nil, 0, false
		}
		totalBytes += len(attribute.Name) + len(attribute.Value) + 8
		if totalBytes > maximumBytes {
			return nil, 0, false
		}
	}
	return attributes, totalBytes, true
}

func canonicalContentDigest(snapshot DriverSnapshot, documents []DriverDocument) [sha256.Size]byte {
	hasher := sha256.New()
	writeDigestString(hasher, contentDigestDomain)
	writeDigestString(hasher, snapshot.OrganizationID)
	writeDigestString(hasher, snapshot.WorkspaceID)
	writeDigestString(hasher, snapshot.EnvironmentID)
	writeDigestString(hasher, snapshot.IntegrationID)
	writeDigestString(hasher, snapshot.SnapshotID)
	writeDigestInt64(hasher, snapshot.Generation)
	writeDigestBytes(hasher, snapshot.InputDigest[:])
	writeDigestInt64(hasher, int64(len(documents)))
	for _, document := range documents {
		writeDigestString(hasher, document.EntityID)
		writeDigestString(hasher, document.Kind)
		writeDigestString(hasher, document.DisplayName)
		writeDigestInt64(hasher, int64(len(document.Attributes)))
		for _, attribute := range document.Attributes {
			writeDigestString(hasher, attribute.Name)
			writeDigestString(hasher, attribute.Value)
		}
	}
	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

func writeDigestString(hasher hash.Hash, value string) { writeDigestBytes(hasher, []byte(value)) }

func writeDigestBytes(hasher hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = hasher.Write(size[:])
	_, _ = hasher.Write(value)
}

func writeDigestInt64(hasher hash.Hash, value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	_, _ = hasher.Write(encoded[:])
}

func validOptionalText(value string, maximum int) bool {
	return value == "" || validText(value, maximum, true)
}

func validText(value string, maximum int, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validProductID(id domain.ProductID) bool {
	if id.IsZero() {
		return false
	}
	parsed, err := domain.ParseProductID(id.String())
	return err == nil && parsed == id
}

func validDigest(value [sha256.Size]byte) bool { return value != [sha256.Size]byte{} }

func documentID(scope domain.Scope, integrationID, snapshotID domain.ProductID, generation int64, inputDigest, contentDigest [sha256.Size]byte, entityID domain.ProductID) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), integrationID.String(), snapshotID.String(), fmt.Sprintf("%d", generation), hex.EncodeToString(inputDigest[:]), hex.EncodeToString(contentDigest[:]), entityID.String()}, "\x1f")))
	return "inv_" + hex.EncodeToString(digest[:])
}

func sanitizeDriverError(err error) error {
	for _, stable := range []error{ErrCanceled, ErrRetryable, ErrUnknownOutcome, ErrDenied, ErrRejected, ErrStale, ErrDrift, ErrUnavailable} {
		if errors.Is(err, stable) {
			return stable
		}
	}
	return ErrUnavailable
}

func callStage(driver Driver, ctx context.Context, input DriverStage) (result DriverStaged, resultErr error) {
	defer func() {
		if recover() != nil {
			result = DriverStaged{}
			resultErr = ErrUnavailable
		}
	}()
	return driver.Stage(ctx, cloneDriverStage(input))
}

func callActivate(driver Driver, ctx context.Context, input DriverActivation) (result DriverActivated, resultErr error) {
	defer func() {
		if recover() != nil {
			result = DriverActivated{}
			resultErr = ErrUnavailable
		}
	}()
	input.DocumentIDs = append([]string(nil), input.DocumentIDs...)
	return driver.Activate(ctx, input)
}

func callDiscardStage(driver Driver, ctx context.Context, input DriverDiscard) (result DriverDiscarded, resultErr error) {
	defer func() {
		if recover() != nil {
			result = DriverDiscarded{}
			resultErr = ErrUnavailable
		}
	}()
	input.CandidateDocumentIDs = append([]string(nil), input.CandidateDocumentIDs...)
	input.ExpectedActiveDocumentIDs = append([]string(nil), input.ExpectedActiveDocumentIDs...)
	return driver.DiscardStage(ctx, input)
}

func callRemoveStale(driver Driver, ctx context.Context, input DriverCleanup) (result DriverCleaned, resultErr error) {
	defer func() {
		if recover() != nil {
			result = DriverCleaned{}
			resultErr = ErrUnavailable
		}
	}()
	return driver.RemoveStale(ctx, input)
}

func callSearch(driver Driver, ctx context.Context, input DriverQuery) (result DriverSearchResult, resultErr error) {
	defer func() {
		if recover() != nil {
			result = DriverSearchResult{}
			resultErr = ErrUnavailable
		}
	}()
	return driver.Search(ctx, cloneDriverQuery(input))
}

func cloneDriverStage(input DriverStage) DriverStage {
	input.Documents = append([]DriverDocument(nil), input.Documents...)
	for index := range input.Documents {
		input.Documents[index].Attributes = cloneAttributes(input.Documents[index].Attributes)
	}
	return input
}

func cloneDriverQuery(input DriverQuery) DriverQuery {
	input.Kinds = append([]string(nil), input.Kinds...)
	input.Sort = append([]string(nil), input.Sort...)
	return input
}

func cloneAttributes(input []Attribute) []Attribute { return append([]Attribute(nil), input...) }

func sameDriverSnapshot(left, right DriverSnapshot) bool { return left == right }

func validRejectedActivation(candidate DriverSnapshot, candidateIDs []string, activated DriverActivated, reason error) bool {
	active := activated.ActiveSnapshot
	if active.OrganizationID != candidate.OrganizationID || active.WorkspaceID != candidate.WorkspaceID || active.EnvironmentID != candidate.EnvironmentID || active.IntegrationID != candidate.IntegrationID || !validDriverSnapshot(active) || !validDocumentIDs(activated.ActiveDocumentIDs) || !validDocumentIDs(candidateIDs) {
		return false
	}
	if errors.Is(reason, ErrStale) {
		return active.Generation > candidate.Generation
	}
	return errors.Is(reason, ErrDrift) && active.Generation == candidate.Generation && active != candidate
}

func validDriverSnapshot(snapshot DriverSnapshot) bool {
	organizationID, organizationErr := domain.ParseProductID(snapshot.OrganizationID)
	workspaceID, workspaceErr := domain.ParseProductID(snapshot.WorkspaceID)
	environmentID, environmentErr := domain.ParseProductID(snapshot.EnvironmentID)
	_, integrationErr := domain.ParseProductID(snapshot.IntegrationID)
	_, snapshotErr := domain.ParseProductID(snapshot.SnapshotID)
	_, scopeErr := domain.NewScope(organizationID, workspaceID, environmentID)
	return organizationErr == nil && workspaceErr == nil && environmentErr == nil && integrationErr == nil && snapshotErr == nil && scopeErr == nil && snapshot.Generation >= 1 && validDigest(snapshot.InputDigest) && validDigest(snapshot.ContentDigest)
}

func validDocumentIDs(ids []string) bool {
	if len(ids) > absoluteMaximumDocuments {
		return false
	}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if !documentIDPattern.MatchString(id) {
			return false
		}
		if _, duplicate := seen[id]; duplicate {
			return false
		}
		seen[id] = struct{}{}
	}
	return true
}

func equalDocumentIDs(left, right []string) bool {
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

func attributeSet(names ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(names))
	for _, name := range names {
		result[name] = struct{}{}
	}
	return result
}

func (store *Store) usable() bool { return store != nil && !nilInterface(store.driver) }

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
