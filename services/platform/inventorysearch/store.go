package inventorysearch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
)

var (
	ErrConfiguration  = errors.New("inventory search configuration rejected")
	ErrInput          = errors.New("inventory search input rejected")
	ErrCanceled       = errors.New("inventory search operation canceled")
	ErrRetryable      = errors.New("inventory search operation retryable")
	ErrUnknownOutcome = errors.New("inventory search operation outcome unknown")
	ErrDenied         = errors.New("inventory search authority denied")
	ErrRejected       = errors.New("inventory search operation rejected")
	ErrDrift          = errors.New("inventory search immutable document drift")
	ErrUnavailable    = errors.New("inventory search unavailable")
	kindPattern       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	documentIDPattern = regexp.MustCompile(`^inv_[0-9a-f]{64}$`)
)

type Config struct {
	MaximumDocuments     int
	MaximumDocumentBytes int
	MaximumBatchBytes    int
	MaximumResults       int
}

type Document struct {
	EntityID     domain.ProductID
	Kind         string
	DisplayName  string
	StableFields json.RawMessage
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
	SnapshotID  domain.ProductID
	Generation  int64
	InputDigest [sha256.Size]byte
	DocumentIDs []string
	Replayed    bool
}

type Query struct {
	IntegrationID domain.ProductID
	SnapshotID    domain.ProductID
	Generation    int64
	InputDigest   [sha256.Size]byte
	Text          string
	Kinds         []string
	AfterEntityID domain.ProductID
	Limit         int
}

type Hit struct {
	EntityID     domain.ProductID
	Kind         string
	DisplayName  string
	StableFields json.RawMessage
}

type Page struct {
	Hits         []Hit
	NextEntityID domain.ProductID
}

type DriverDocument struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	IntegrationID  string
	SnapshotID     string
	Generation     int64
	InputDigest    [sha256.Size]byte
	DocumentID     string
	EntityID       string
	Kind           string
	DisplayName    string
	StableFields   json.RawMessage
}

type DriverApply struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	IntegrationID  string
	SnapshotID     string
	Generation     int64
	InputDigest    [sha256.Size]byte
	Documents      []DriverDocument
}

type DriverApplied struct {
	SnapshotID  string
	Generation  int64
	InputDigest [sha256.Size]byte
	DocumentIDs []string
	Replayed    bool
}

type DriverQuery struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	IntegrationID  string
	SnapshotID     string
	Generation     int64
	InputDigest    [sha256.Size]byte
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
	Apply(context.Context, DriverApply) (DriverApplied, error)
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
	input, expectedIDs, ok := store.driverApply(snapshot)
	if !ok {
		return ApplyResult{}, ErrInput
	}
	applied, err := callApply(store.driver, ctx, input)
	if err != nil {
		return ApplyResult{}, sanitizeDriverError(err)
	}
	if applied.SnapshotID != input.SnapshotID || applied.Generation != input.Generation || applied.InputDigest != input.InputDigest || !reflect.DeepEqual(applied.DocumentIDs, expectedIDs) {
		return ApplyResult{}, ErrUnavailable
	}
	return ApplyResult{SnapshotID: snapshot.SnapshotID, Generation: snapshot.Generation, InputDigest: snapshot.InputDigest, DocumentIDs: append([]string(nil), applied.DocumentIDs...), Replayed: applied.Replayed}, nil
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

func (store *Store) driverApply(snapshot Snapshot) (DriverApply, []string, bool) {
	if snapshot.Scope.Validate() != nil || !validProductID(snapshot.IntegrationID) || !validProductID(snapshot.SnapshotID) || snapshot.Generation < 1 || !validDigest(snapshot.InputDigest) || len(snapshot.Documents) < 1 || len(snapshot.Documents) > store.config.MaximumDocuments {
		return DriverApply{}, nil, false
	}
	documents := append([]Document(nil), snapshot.Documents...)
	sort.Slice(documents, func(left, right int) bool {
		return documents[left].EntityID.String() < documents[right].EntityID.String()
	})
	input := DriverApply{
		OrganizationID: snapshot.Scope.OrganizationID().String(),
		WorkspaceID:    snapshot.Scope.WorkspaceID().String(),
		EnvironmentID:  snapshot.Scope.EnvironmentID().String(),
		IntegrationID:  snapshot.IntegrationID.String(),
		SnapshotID:     snapshot.SnapshotID.String(),
		Generation:     snapshot.Generation,
		InputDigest:    snapshot.InputDigest,
		Documents:      make([]DriverDocument, len(documents)),
	}
	expectedIDs := make([]string, len(documents))
	seen := make(map[domain.ProductID]struct{}, len(documents))
	totalBytes := 0
	for index, document := range documents {
		if !validDocument(document, store.config.MaximumDocumentBytes) {
			return DriverApply{}, nil, false
		}
		if _, duplicate := seen[document.EntityID]; duplicate {
			return DriverApply{}, nil, false
		}
		seen[document.EntityID] = struct{}{}
		totalBytes += len(document.StableFields) + len(document.DisplayName) + len(document.Kind) + 512
		if totalBytes > store.config.MaximumBatchBytes {
			return DriverApply{}, nil, false
		}
		id := documentID(snapshot.Scope, snapshot.IntegrationID, snapshot.SnapshotID, document.EntityID)
		expectedIDs[index] = id
		input.Documents[index] = DriverDocument{
			OrganizationID: input.OrganizationID, WorkspaceID: input.WorkspaceID, EnvironmentID: input.EnvironmentID,
			IntegrationID: input.IntegrationID, SnapshotID: input.SnapshotID, Generation: input.Generation,
			InputDigest: input.InputDigest, DocumentID: id, EntityID: document.EntityID.String(), Kind: document.Kind,
			DisplayName: document.DisplayName, StableFields: append(json.RawMessage(nil), document.StableFields...),
		}
	}
	return input, expectedIDs, true
}

func (store *Store) driverQuery(scope domain.Scope, query Query) (DriverQuery, bool) {
	if scope.Validate() != nil || !validProductID(query.IntegrationID) || !validProductID(query.SnapshotID) || query.Generation < 1 || !validDigest(query.InputDigest) || !validOptionalText(query.Text, 256) || query.Limit < 1 || query.Limit > store.config.MaximumResults || len(query.Kinds) > 32 || !query.AfterEntityID.IsZero() && !validProductID(query.AfterEntityID) {
		return DriverQuery{}, false
	}
	kinds := append([]string(nil), query.Kinds...)
	sort.Strings(kinds)
	for index, kind := range kinds {
		if !kindPattern.MatchString(kind) || index > 0 && kind == kinds[index-1] {
			return DriverQuery{}, false
		}
	}
	after := ""
	if !query.AfterEntityID.IsZero() {
		after = query.AfterEntityID.String()
	}
	return DriverQuery{
		OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(),
		IntegrationID: query.IntegrationID.String(), SnapshotID: query.SnapshotID.String(), Generation: query.Generation, InputDigest: query.InputDigest,
		Text: query.Text, Kinds: kinds, AfterEntityID: after, Limit: query.Limit, Sort: []string{"entity_id"},
	}, true
}

func (store *Store) productPage(scope domain.Scope, query Query, result DriverSearchResult) (Page, error) {
	if len(result.Hits) > query.Limit {
		return Page{}, ErrUnavailable
	}
	hits := make([]Hit, len(result.Hits))
	seen := make(map[domain.ProductID]struct{}, len(result.Hits))
	previous := query.AfterEntityID.String()
	for index, document := range result.Hits {
		entityID, err := domain.ParseProductID(document.EntityID)
		if err != nil || document.OrganizationID != scope.OrganizationID().String() || document.WorkspaceID != scope.WorkspaceID().String() || document.EnvironmentID != scope.EnvironmentID().String() || document.IntegrationID != query.IntegrationID.String() || document.SnapshotID != query.SnapshotID.String() || document.Generation != query.Generation || document.InputDigest != query.InputDigest || document.DocumentID != documentID(scope, query.IntegrationID, query.SnapshotID, entityID) || !validDriverDocument(document, store.config.MaximumDocumentBytes) || document.EntityID <= previous {
			return Page{}, ErrUnavailable
		}
		if _, duplicate := seen[entityID]; duplicate {
			return Page{}, ErrUnavailable
		}
		seen[entityID] = struct{}{}
		previous = document.EntityID
		hits[index] = Hit{EntityID: entityID, Kind: document.Kind, DisplayName: document.DisplayName, StableFields: append(json.RawMessage(nil), document.StableFields...)}
	}
	var next domain.ProductID
	if result.NextEntityID != "" {
		parsed, err := domain.ParseProductID(result.NextEntityID)
		if err != nil || len(result.Hits) != query.Limit || len(result.Hits) == 0 || result.NextEntityID != result.Hits[len(result.Hits)-1].EntityID {
			return Page{}, ErrUnavailable
		}
		next = parsed
	} else if len(result.Hits) == query.Limit {
		return Page{}, ErrUnavailable
	}
	return Page{Hits: hits, NextEntityID: next}, nil
}

func validDriverDocument(document DriverDocument, maximumBytes int) bool {
	organizationID, organizationErr := domain.ParseProductID(document.OrganizationID)
	workspaceID, workspaceErr := domain.ParseProductID(document.WorkspaceID)
	environmentID, environmentErr := domain.ParseProductID(document.EnvironmentID)
	_, integrationErr := domain.ParseProductID(document.IntegrationID)
	_, snapshotErr := domain.ParseProductID(document.SnapshotID)
	entityID, entityErr := domain.ParseProductID(document.EntityID)
	_, scopeErr := domain.NewScope(organizationID, workspaceID, environmentID)
	return organizationErr == nil && workspaceErr == nil && environmentErr == nil && integrationErr == nil && snapshotErr == nil && entityErr == nil && scopeErr == nil && document.Generation >= 1 && validDigest(document.InputDigest) && documentIDPattern.MatchString(document.DocumentID) && validDocument(Document{EntityID: entityID, Kind: document.Kind, DisplayName: document.DisplayName, StableFields: document.StableFields}, maximumBytes)
}

func validDocument(document Document, maximumBytes int) bool {
	return validProductID(document.EntityID) && kindPattern.MatchString(document.Kind) && validText(document.DisplayName, 256, false) && len(document.StableFields) >= 2 && len(document.StableFields) <= maximumBytes && document.StableFields[0] == '{' && document.StableFields[len(document.StableFields)-1] == '}' && json.Valid(document.StableFields)
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

func validDigest(value [sha256.Size]byte) bool {
	return value != [sha256.Size]byte{}
}

func documentID(scope domain.Scope, integrationID, snapshotID, entityID domain.ProductID) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), integrationID.String(), snapshotID.String(), entityID.String(),
	}, "\x1f")))
	return "inv_" + hex.EncodeToString(digest[:])
}

func sanitizeDriverError(err error) error {
	for _, stable := range []error{ErrCanceled, ErrRetryable, ErrUnknownOutcome, ErrDenied, ErrRejected, ErrDrift, ErrUnavailable} {
		if errors.Is(err, stable) {
			return stable
		}
	}
	return ErrUnavailable
}

func callApply(driver Driver, ctx context.Context, input DriverApply) (result DriverApplied, resultErr error) {
	defer func() {
		if recover() != nil {
			result = DriverApplied{}
			resultErr = ErrUnavailable
		}
	}()
	return driver.Apply(ctx, cloneDriverApply(input))
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

func cloneDriverApply(input DriverApply) DriverApply {
	input.Documents = append([]DriverDocument(nil), input.Documents...)
	for index := range input.Documents {
		input.Documents[index].StableFields = append(json.RawMessage(nil), input.Documents[index].StableFields...)
	}
	return input
}

func cloneDriverQuery(input DriverQuery) DriverQuery {
	input.Kinds = append([]string(nil), input.Kinds...)
	input.Sort = append([]string(nil), input.Sort...)
	return input
}

func (store *Store) usable() bool {
	return store != nil && !nilInterface(store.driver)
}

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
