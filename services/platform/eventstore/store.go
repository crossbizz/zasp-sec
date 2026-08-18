package eventstore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	maximumOperationTimeout = 30 * time.Second
	maximumResultCount      = 100
	timestampLayout         = "2006-01-02T15:04:05.000Z"
)

var (
	ErrConfiguration = errors.New("event store configuration rejected")
	ErrEvent         = errors.New("event rejected")
	ErrFilter        = errors.New("event filter rejected")
	ErrIndex         = errors.New("event index failed")
	ErrSearch        = errors.New("event search failed")
)

type Config struct {
	OperationTimeout time.Duration
	MaximumResults   int
}

type Event struct {
	Scope         domain.Scope
	EventID       domain.ProductID
	SessionID     domain.ProductID
	AgentID       domain.ProductID
	Source        string
	SourceEventID string
	Class         string
	Action        string
	Decision      string
	EventTime     time.Time
}

type Filter struct {
	SessionID domain.ProductID
	Limit     int
}

type DriverDocument struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	EventID        string
	SessionID      string
	AgentID        string
	Source         string
	SourceEventID  string
	Class          string
	Action         string
	Decision       string
	EventTime      string
}

type DriverQuery struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	SessionID      string
	Limit          int
	Sort           []string
}

type DriverIndexed struct{ EventID string }

type Driver interface {
	Index(context.Context, DriverDocument) (DriverIndexed, error)
	Search(context.Context, DriverQuery) ([]DriverDocument, error)
}

type EventStore interface {
	Index(context.Context, domain.Scope, Event) error
	Search(context.Context, domain.Scope, Filter) ([]Event, error)
}

type Store struct {
	driver Driver
	config Config
}

func New(driver Driver, config Config) (*Store, error) {
	if nilInterface(driver) || config.OperationTimeout <= 0 || config.OperationTimeout > maximumOperationTimeout ||
		config.MaximumResults <= 0 || config.MaximumResults > maximumResultCount {
		return nil, ErrConfiguration
	}
	return &Store{driver: driver, config: config}, nil
}

func (store *Store) Index(ctx context.Context, scope domain.Scope, event Event) error {
	if store == nil || nilInterface(store.driver) || ctx == nil {
		return ErrIndex
	}
	document, err := buildDriverDocument(scope, event)
	if err != nil {
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, store.config.OperationTimeout)
	defer cancel()
	if operationCtx.Err() != nil {
		return ErrIndex
	}
	indexed, err := indexDriver(store.driver, operationCtx, document)
	if err != nil || operationCtx.Err() != nil || indexed.EventID != document.EventID {
		return ErrIndex
	}
	return nil
}

func (store *Store) Search(ctx context.Context, scope domain.Scope, filter Filter) ([]Event, error) {
	if store == nil || nilInterface(store.driver) || ctx == nil {
		return nil, ErrSearch
	}
	query, err := buildDriverQuery(scope, filter, store.config.MaximumResults)
	if err != nil {
		return nil, err
	}
	operationCtx, cancel := context.WithTimeout(ctx, store.config.OperationTimeout)
	defer cancel()
	if operationCtx.Err() != nil {
		return nil, ErrSearch
	}
	documents, err := searchDriver(store.driver, operationCtx, query)
	if err != nil || operationCtx.Err() != nil || len(documents) > filter.Limit {
		return nil, ErrSearch
	}
	result := make([]Event, 0, len(documents))
	seen := make(map[string]struct{}, len(documents))
	previousTime, previousID := "", ""
	for _, document := range documents {
		if document.OrganizationID != query.OrganizationID || document.WorkspaceID != query.WorkspaceID ||
			document.EnvironmentID != query.EnvironmentID || document.SessionID != query.SessionID {
			return nil, ErrSearch
		}
		if _, duplicate := seen[document.EventID]; duplicate {
			return nil, ErrSearch
		}
		event, conversionErr := eventFromDocument(document)
		if conversionErr != nil || !validEvent(scope, event) {
			return nil, ErrSearch
		}
		if previousTime > document.EventTime || (previousTime == document.EventTime && previousID >= document.EventID) {
			return nil, ErrSearch
		}
		seen[document.EventID] = struct{}{}
		previousTime, previousID = document.EventTime, document.EventID
		result = append(result, event)
	}
	return result, nil
}

func buildDriverDocument(scope domain.Scope, event Event) (DriverDocument, error) {
	if !validEvent(scope, event) {
		return DriverDocument{}, ErrEvent
	}
	return DriverDocument{
		OrganizationID: scope.OrganizationID().String(),
		WorkspaceID:    scope.WorkspaceID().String(),
		EnvironmentID:  scope.EnvironmentID().String(),
		EventID:        event.EventID.String(),
		SessionID:      event.SessionID.String(),
		AgentID:        event.AgentID.String(),
		Source:         event.Source,
		SourceEventID:  event.SourceEventID,
		Class:          event.Class,
		Action:         event.Action,
		Decision:       event.Decision,
		EventTime:      event.EventTime.Format(timestampLayout),
	}, nil
}

func buildDriverQuery(scope domain.Scope, filter Filter, maximumResults int) (DriverQuery, error) {
	if scope.Validate() != nil || filter.SessionID.String() == "" || maximumResults <= 0 || maximumResults > maximumResultCount ||
		filter.Limit <= 0 || filter.Limit > maximumResults {
		return DriverQuery{}, ErrFilter
	}
	return DriverQuery{
		OrganizationID: scope.OrganizationID().String(),
		WorkspaceID:    scope.WorkspaceID().String(),
		EnvironmentID:  scope.EnvironmentID().String(),
		SessionID:      filter.SessionID.String(),
		Limit:          filter.Limit,
		Sort:           []string{"event_time", "event_id"},
	}, nil
}

func eventFromDocument(document DriverDocument) (Event, error) {
	organizationID, organizationErr := domain.ParseProductID(document.OrganizationID)
	workspaceID, workspaceErr := domain.ParseProductID(document.WorkspaceID)
	environmentID, environmentErr := domain.ParseProductID(document.EnvironmentID)
	eventID, eventErr := domain.ParseProductID(document.EventID)
	sessionID, sessionErr := domain.ParseProductID(document.SessionID)
	agentID, agentErr := domain.ParseProductID(document.AgentID)
	eventTime, timeErr := time.Parse(timestampLayout, document.EventTime)
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil || eventErr != nil || sessionErr != nil || agentErr != nil || timeErr != nil {
		return Event{}, ErrSearch
	}
	scope, scopeErr := domain.NewScope(organizationID, workspaceID, environmentID)
	if scopeErr != nil {
		return Event{}, ErrSearch
	}
	return Event{
		Scope: scope, EventID: eventID, SessionID: sessionID, AgentID: agentID,
		Source: document.Source, SourceEventID: document.SourceEventID, Class: document.Class,
		Action: document.Action, Decision: document.Decision, EventTime: eventTime,
	}, nil
}

func validEvent(scope domain.Scope, event Event) bool {
	if scope.Validate() != nil || event.Scope.Validate() != nil || scope != event.Scope || event.EventID.String() == "" ||
		event.SessionID.String() == "" || event.AgentID.String() == "" || event.Source != "runtime_gateway" ||
		event.Class != "tool" || event.Action != "invoke" || !validDecision(event.Decision) ||
		!validSourceEventID(event.SourceEventID) || event.EventTime.Location() != time.UTC ||
		event.EventTime.Nanosecond()%int(time.Millisecond) != 0 {
		return false
	}
	formatted := event.EventTime.Format(timestampLayout)
	parsed, err := time.Parse(timestampLayout, formatted)
	return err == nil && parsed.Equal(event.EventTime)
}

func validDecision(decision string) bool {
	return decision == "allowed" || decision == "monitored" || decision == "blocked"
}

func validSourceEventID(value string) bool {
	if len(value) == 0 || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func indexDriver(driver Driver, ctx context.Context, document DriverDocument) (indexed DriverIndexed, resultErr error) {
	defer func() {
		if recover() != nil {
			indexed = DriverIndexed{}
			resultErr = ErrIndex
		}
	}()
	return driver.Index(ctx, document)
}

func searchDriver(driver Driver, ctx context.Context, query DriverQuery) (documents []DriverDocument, resultErr error) {
	defer func() {
		if recover() != nil {
			documents = nil
			resultErr = ErrSearch
		}
	}()
	return driver.Search(ctx, query)
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
