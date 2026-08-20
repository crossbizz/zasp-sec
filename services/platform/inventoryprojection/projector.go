package inventoryprojection

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var ErrProjection = errors.New("inventory projection rejected")

var projectionTokenPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)

type Kind string

const (
	KindAsset    Kind = "asset"
	KindAgent    Kind = "agent"
	KindTool     Kind = "tool"
	KindIdentity Kind = "identity"
	KindRuntime  Kind = "runtime"
)

type IdentityBinding struct {
	Scope          domain.Scope
	IntegrationID  domain.ProductID
	Provider       string
	Source         string
	Kind           Kind
	Namespace      string
	SourceNativeID string
	CanonicalID    domain.ProductID
	RuleVersion    int
	Priority       int
}

type Observation struct {
	Binding                 IdentityBinding
	SnapshotID              domain.ProductID
	Generation              int64
	DisplayName             string
	EvidenceID              domain.ProductID
	ConfidenceBasisPoints   int
	FirstSeen               time.Time
	LastSeen                time.Time
	ObservedAt              time.Time
	FreshUntil              time.Time
	SourceProjectionVersion int
}

type SourceObservation struct {
	IntegrationID           domain.ProductID
	Provider                string
	Source                  string
	Namespace               string
	SourceNativeID          string
	SnapshotID              domain.ProductID
	Generation              int64
	EvidenceID              domain.ProductID
	ConfidenceBasisPoints   int
	FirstSeen               time.Time
	LastSeen                time.Time
	ObservedAt              time.Time
	FreshUntil              time.Time
	IdentityRuleVersion     int
	SourceProjectionVersion int
}

type Annotation struct {
	Scope    domain.Scope
	EntityID domain.ProductID
	Owner    string
	Team     string
	Tags     []string
	Version  int
}

type EntityProjection struct {
	Scope                   domain.Scope
	ID                      domain.ProductID
	Kind                    Kind
	DisplayName             string
	Owner                   string
	Team                    string
	Tags                    []string
	ConfidenceBasisPoints   int
	FirstSeen               time.Time
	LastSeen                time.Time
	ObservedAt              time.Time
	FreshUntil              time.Time
	ProjectionVersion       int
	AnnotationVersion       int
	WinningIntegrationID    domain.ProductID
	WinningProvider         string
	WinningSource           string
	WinningSourceNativeID   string
	WinningIdentityRule     int
	WinningSourceProjection int
	Sources                 []SourceObservation
}

func Project(observations []Observation) ([]EntityProjection, error) {
	return ProjectWithAnnotations(observations, nil)
}

func ProjectWithAnnotations(observations []Observation, annotations []Annotation) ([]EntityProjection, error) {
	if len(observations) > 100_000 || len(annotations) > 100_000 {
		return nil, ErrProjection
	}
	byIdentity := make(map[string]Observation, len(observations))
	byEntity := make(map[string][]Observation, len(observations))
	for _, observation := range observations {
		if !validObservation(observation) {
			return nil, ErrProjection
		}
		identityKey := bindingKey(observation.Binding)
		if current, exists := byIdentity[identityKey]; exists {
			if current != observation {
				return nil, ErrProjection
			}
			continue
		}
		byIdentity[identityKey] = observation
		entityKey := scopedEntityKey(observation.Binding.Scope, observation.Binding.CanonicalID)
		byEntity[entityKey] = append(byEntity[entityKey], observation)
	}

	annotationByEntity := make(map[string]Annotation, len(annotations))
	for _, annotation := range annotations {
		normalized, ok := normalizeAnnotation(annotation)
		if !ok {
			return nil, ErrProjection
		}
		key := scopedEntityKey(normalized.Scope, normalized.EntityID)
		if current, exists := annotationByEntity[key]; exists {
			if !equalAnnotation(current, normalized) {
				return nil, ErrProjection
			}
			continue
		}
		annotationByEntity[key] = normalized
	}

	result := make([]EntityProjection, 0, len(byEntity))
	for key, values := range byEntity {
		projection, err := projectEntity(values)
		if err != nil {
			return nil, err
		}
		if annotation, exists := annotationByEntity[key]; exists {
			projection.Owner = annotation.Owner
			projection.Team = annotation.Team
			projection.Tags = append([]string(nil), annotation.Tags...)
			projection.AnnotationVersion = annotation.Version
			delete(annotationByEntity, key)
		}
		result = append(result, projection)
	}
	if len(annotationByEntity) != 0 {
		return nil, ErrProjection
	}
	sort.Slice(result, func(left, right int) bool {
		leftScope := scopeKey(result[left].Scope)
		rightScope := scopeKey(result[right].Scope)
		if leftScope != rightScope {
			return leftScope < rightScope
		}
		return result[left].ID.String() < result[right].ID.String()
	})
	return result, nil
}

func projectEntity(values []Observation) (EntityProjection, error) {
	if len(values) == 0 {
		return EntityProjection{}, ErrProjection
	}
	sort.Slice(values, func(left, right int) bool { return lessObservation(values[left], values[right]) })
	winner := values[0]
	projection := EntityProjection{
		Scope:                   winner.Binding.Scope,
		ID:                      winner.Binding.CanonicalID,
		Kind:                    winner.Binding.Kind,
		DisplayName:             winner.DisplayName,
		ConfidenceBasisPoints:   winner.ConfidenceBasisPoints,
		FirstSeen:               winner.FirstSeen,
		LastSeen:                winner.LastSeen,
		ObservedAt:              winner.ObservedAt,
		FreshUntil:              winner.FreshUntil,
		ProjectionVersion:       winner.SourceProjectionVersion,
		WinningIntegrationID:    winner.Binding.IntegrationID,
		WinningProvider:         winner.Binding.Provider,
		WinningSource:           winner.Binding.Source,
		WinningSourceNativeID:   winner.Binding.SourceNativeID,
		WinningIdentityRule:     winner.Binding.RuleVersion,
		WinningSourceProjection: winner.SourceProjectionVersion,
		Sources:                 make([]SourceObservation, 0, len(values)),
	}
	for _, value := range values {
		if value.Binding.Scope != projection.Scope || value.Binding.CanonicalID != projection.ID || value.Binding.Kind != projection.Kind {
			return EntityProjection{}, ErrProjection
		}
		if value.FirstSeen.Before(projection.FirstSeen) {
			projection.FirstSeen = value.FirstSeen
		}
		if value.LastSeen.After(projection.LastSeen) {
			projection.LastSeen = value.LastSeen
		}
		if value.ObservedAt.After(projection.ObservedAt) {
			projection.ObservedAt = value.ObservedAt
		}
		if value.FreshUntil.Before(projection.FreshUntil) {
			projection.FreshUntil = value.FreshUntil
		}
		if value.SourceProjectionVersion > projection.ProjectionVersion {
			projection.ProjectionVersion = value.SourceProjectionVersion
		}
		projection.Sources = append(projection.Sources, SourceObservation{
			IntegrationID:           value.Binding.IntegrationID,
			Provider:                value.Binding.Provider,
			Source:                  value.Binding.Source,
			Namespace:               value.Binding.Namespace,
			SourceNativeID:          value.Binding.SourceNativeID,
			SnapshotID:              value.SnapshotID,
			Generation:              value.Generation,
			EvidenceID:              value.EvidenceID,
			ConfidenceBasisPoints:   value.ConfidenceBasisPoints,
			FirstSeen:               value.FirstSeen,
			LastSeen:                value.LastSeen,
			ObservedAt:              value.ObservedAt,
			FreshUntil:              value.FreshUntil,
			IdentityRuleVersion:     value.Binding.RuleVersion,
			SourceProjectionVersion: value.SourceProjectionVersion,
		})
	}
	return projection, nil
}

func validObservation(value Observation) bool {
	return validBinding(value.Binding) && !value.SnapshotID.IsZero() && value.Generation > 0 &&
		boundedText(value.DisplayName, 256) && !value.EvidenceID.IsZero() &&
		value.ConfidenceBasisPoints >= 0 && value.ConfidenceBasisPoints <= 10_000 &&
		canonicalTime(value.FirstSeen) && canonicalTime(value.LastSeen) && canonicalTime(value.ObservedAt) && canonicalTime(value.FreshUntil) &&
		!value.LastSeen.Before(value.FirstSeen) && !value.ObservedAt.Before(value.LastSeen) && value.FreshUntil.After(value.ObservedAt) &&
		value.SourceProjectionVersion > 0 && value.SourceProjectionVersion <= 1_000_000
}

func validBinding(value IdentityBinding) bool {
	return value.Scope.Validate() == nil && !value.IntegrationID.IsZero() && validToken(value.Provider) && validToken(value.Source) &&
		validKind(value.Kind) && validToken(value.Namespace) && boundedText(value.SourceNativeID, 1024) && !value.CanonicalID.IsZero() &&
		value.RuleVersion > 0 && value.RuleVersion <= 1_000_000 && value.Priority >= 0 && value.Priority <= 1_000_000
}

func normalizeAnnotation(value Annotation) (Annotation, bool) {
	if value.Scope.Validate() != nil || value.EntityID.IsZero() || !optionalText(value.Owner, 128) || !optionalText(value.Team, 128) || value.Version <= 0 || value.Version > 1_000_000 || len(value.Tags) > 32 {
		return Annotation{}, false
	}
	value.Tags = append([]string(nil), value.Tags...)
	for _, tag := range value.Tags {
		if !boundedText(tag, 64) {
			return Annotation{}, false
		}
	}
	sort.Strings(value.Tags)
	for index := 1; index < len(value.Tags); index++ {
		if value.Tags[index] == value.Tags[index-1] {
			return Annotation{}, false
		}
	}
	return value, true
}

func equalAnnotation(left, right Annotation) bool {
	if left.Scope != right.Scope || left.EntityID != right.EntityID || left.Owner != right.Owner || left.Team != right.Team || left.Version != right.Version || len(left.Tags) != len(right.Tags) {
		return false
	}
	for index := range left.Tags {
		if left.Tags[index] != right.Tags[index] {
			return false
		}
	}
	return true
}

func lessObservation(left, right Observation) bool {
	if left.Binding.Priority != right.Binding.Priority {
		return left.Binding.Priority < right.Binding.Priority
	}
	leftKey := strings.Join([]string{left.Binding.IntegrationID.String(), left.Binding.Provider, left.Binding.Source, left.Binding.Namespace, left.Binding.SourceNativeID}, "\x1f")
	rightKey := strings.Join([]string{right.Binding.IntegrationID.String(), right.Binding.Provider, right.Binding.Source, right.Binding.Namespace, right.Binding.SourceNativeID}, "\x1f")
	return leftKey < rightKey
}

func bindingKey(value IdentityBinding) string {
	return strings.Join([]string{scopeKey(value.Scope), value.IntegrationID.String(), value.Provider, value.Source, string(value.Kind), value.Namespace, value.SourceNativeID}, "\x1f")
}

func scopedEntityKey(scope domain.Scope, id domain.ProductID) string {
	return scopeKey(scope) + "\x1f" + id.String()
}

func scopeKey(scope domain.Scope) string {
	return strings.Join([]string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}, "\x1f")
}

func validKind(value Kind) bool {
	return value == KindAsset || value == KindAgent || value == KindTool || value == KindIdentity || value == KindRuntime
}

func validToken(value string) bool {
	return projectionTokenPattern.MatchString(value)
}

func boundedText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func optionalText(value string, maximum int) bool {
	return value == "" || boundedText(value, maximum)
}

func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}
