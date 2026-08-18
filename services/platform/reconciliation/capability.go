package reconciliation

import (
	"context"
	"sort"
	"sync"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type CapabilityCategory string

const (
	CapabilityDataRead       CapabilityCategory = "data_read"
	CapabilityDataWrite      CapabilityCategory = "data_write"
	CapabilityActionExecute  CapabilityCategory = "action_execute"
	CapabilityIdentityAssume CapabilityCategory = "identity_assume"
	CapabilityNetworkEgress  CapabilityCategory = "network_egress"
	CapabilityAdministration CapabilityCategory = "administration"
)

type CapabilityState string

const (
	CapabilityReachable CapabilityState = "reachable"
	CapabilityObserved  CapabilityState = "observed"
	CapabilityVerified  CapabilityState = "verified"
	CapabilityBlocked   CapabilityState = "blocked"
)

type TargetKind string

const (
	TargetTool     TargetKind = "tool"
	TargetIdentity TargetKind = "identity"
	TargetResource TargetKind = "resource"
	TargetAction   TargetKind = "action"
)

type CapabilityEvidenceKind string

const (
	EvidenceRuntime                  CapabilityEvidenceKind = "runtime"
	EvidenceProvider                 CapabilityEvidenceKind = "provider"
	EvidenceAttackLab                CapabilityEvidenceKind = "attack_lab"
	EvidenceRuntimePolicy            CapabilityEvidenceKind = "runtime_policy"
	EvidenceVerifiedWithoutAuthority CapabilityEvidenceKind = "verified_without_authority"
)

type CapabilityEdge struct {
	Scope      domain.Scope
	AgentID    domain.ProductID
	TargetID   domain.ProductID
	TargetKind TargetKind
	Category   CapabilityCategory
	Outcome    string
	EvidenceID domain.ProductID
}

type Capability struct {
	AgentID, TargetID domain.ProductID
	TargetKind        TargetKind
	Category          CapabilityCategory
	Outcome           string
	State             CapabilityState
	Reachable         bool
	EvidenceIDs       []domain.ProductID
}

type CapabilityEvidence struct {
	AgentID, TargetID domain.ProductID
	Category          CapabilityCategory
	Kind              CapabilityEvidenceKind
	EvidenceID        domain.ProductID
}

type capabilityRecord struct {
	scope domain.Scope
	value Capability
}

type CapabilityGraph struct {
	mu     sync.RWMutex
	values map[string]capabilityRecord
}

func NewCapabilityGraph(edges []CapabilityEdge) (*CapabilityGraph, error) {
	if len(edges) == 0 || len(edges) > 10_000 {
		return nil, ErrReconciliation
	}
	graph := &CapabilityGraph{values: make(map[string]capabilityRecord, len(edges))}
	for _, edge := range edges {
		if !validCapabilityEdge(edge) {
			return nil, ErrReconciliation
		}
		key := capabilityKey(edge.Scope, edge.AgentID, edge.TargetID, edge.Category)
		if _, exists := graph.values[key]; exists {
			return nil, ErrReconciliation
		}
		graph.values[key] = capabilityRecord{scope: edge.Scope, value: Capability{AgentID: edge.AgentID, TargetID: edge.TargetID, TargetKind: edge.TargetKind, Category: edge.Category, Outcome: edge.Outcome, State: CapabilityReachable, Reachable: true, EvidenceIDs: []domain.ProductID{edge.EvidenceID}}}
	}
	return graph, nil
}

func (graph *CapabilityGraph) Query(ctx context.Context, scope domain.Scope, agentID domain.ProductID) ([]Capability, error) {
	if graph == nil || graph.values == nil || !active(ctx) || scope.Validate() != nil || agentID.IsZero() {
		return nil, ErrReconciliation
	}
	graph.mu.RLock()
	defer graph.mu.RUnlock()
	result := []Capability{}
	for _, record := range graph.values {
		if record.scope == scope && record.value.AgentID == agentID {
			result = append(result, cloneCapability(record.value))
		}
	}
	if len(result) == 0 {
		return nil, ErrReconciliation
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Category != result[right].Category {
			return result[left].Category < result[right].Category
		}
		return result[left].TargetID.String() < result[right].TargetID.String()
	})
	return result, nil
}

func (graph *CapabilityGraph) ApplyEvidence(ctx context.Context, scope domain.Scope, evidence CapabilityEvidence) error {
	if graph == nil || graph.values == nil || !active(ctx) || scope.Validate() != nil || evidence.AgentID.IsZero() || evidence.TargetID.IsZero() || evidence.EvidenceID.IsZero() || !validCapabilityCategory(evidence.Category) {
		return ErrReconciliation
	}
	state := CapabilityState("")
	switch evidence.Kind {
	case EvidenceRuntime, EvidenceProvider:
		state = CapabilityObserved
	case EvidenceAttackLab:
		state = CapabilityVerified
	case EvidenceRuntimePolicy:
		state = CapabilityBlocked
	default:
		return ErrReconciliation
	}
	key := capabilityKey(scope, evidence.AgentID, evidence.TargetID, evidence.Category)
	graph.mu.Lock()
	defer graph.mu.Unlock()
	record, ok := graph.values[key]
	if !ok || record.scope != scope {
		return ErrReconciliation
	}
	for _, retained := range record.value.EvidenceIDs {
		if retained == evidence.EvidenceID {
			return ErrReconciliation
		}
	}
	if capabilityRank(state) < capabilityRank(record.value.State) {
		return ErrReconciliation
	}
	record.value.State = state
	record.value.EvidenceIDs = append(record.value.EvidenceIDs, evidence.EvidenceID)
	graph.values[key] = record
	return nil
}

type PostureRule string

const (
	RuleOwnerlessAgent   PostureRule = "ownerless_agent"
	RuleHumanCredential  PostureRule = "human_credential"
	RuleSharedCredential PostureRule = "shared_credential"
	RuleUntrustedWrite   PostureRule = "untrusted_production_write"
)

type PostureEvidence struct {
	Rule PostureRule
	ID   domain.ProductID
}

type PostureInput struct {
	Scope                 domain.Scope
	AgentID               domain.ProductID
	Owner                 string
	HumanCredential       bool
	CredentialFingerprint string
	CredentialAgentCount  int
	UntrustedInput        bool
	ProductionWrite       bool
	EvidenceIDs           []PostureEvidence
}

type PostureFinding struct {
	ID, AgentID, EvidenceID domain.ProductID
	Scope                   domain.Scope
	Rule                    PostureRule
}

func EvaluatePosture(ctx context.Context, input PostureInput) ([]PostureFinding, error) {
	if !active(ctx) || input.Scope.Validate() != nil || input.AgentID.IsZero() || input.CredentialAgentCount < 0 || input.CredentialAgentCount > 100_000 || len(input.EvidenceIDs) > 16 {
		return nil, ErrReconciliation
	}
	evidence := map[PostureRule]domain.ProductID{}
	for _, item := range input.EvidenceIDs {
		if !validPostureRule(item.Rule) || item.ID.IsZero() || !evidence[item.Rule].IsZero() {
			return nil, ErrReconciliation
		}
		evidence[item.Rule] = item.ID
	}
	conditions := []struct {
		rule    PostureRule
		matched bool
	}{
		{RuleOwnerlessAgent, input.Owner == ""},
		{RuleHumanCredential, input.HumanCredential},
		{RuleSharedCredential, input.CredentialAgentCount > 1 && validFingerprint(input.CredentialFingerprint)},
		{RuleUntrustedWrite, input.UntrustedInput && input.ProductionWrite},
	}
	result := []PostureFinding{}
	for _, condition := range conditions {
		if !condition.matched {
			continue
		}
		evidenceID := evidence[condition.rule]
		if evidenceID.IsZero() {
			return nil, ErrReconciliation
		}
		id, err := deterministicID(scopeIdentity(input.Scope) + "\x00posture\x00" + input.AgentID.String() + "\x00" + string(condition.rule))
		if err != nil {
			return nil, ErrReconciliation
		}
		result = append(result, PostureFinding{ID: id, AgentID: input.AgentID, EvidenceID: evidenceID, Scope: input.Scope, Rule: condition.rule})
	}
	return result, nil
}

func validCapabilityEdge(edge CapabilityEdge) bool {
	return edge.Scope.Validate() == nil && !edge.AgentID.IsZero() && !edge.TargetID.IsZero() && edge.AgentID != edge.TargetID && validTargetKind(edge.TargetKind) && validCapabilityCategory(edge.Category) && capabilityOutcome(edge.Category) == edge.Outcome && !edge.EvidenceID.IsZero()
}
func validCapabilityCategory(value CapabilityCategory) bool {
	return value == CapabilityDataRead || value == CapabilityDataWrite || value == CapabilityActionExecute || value == CapabilityIdentityAssume || value == CapabilityNetworkEgress || value == CapabilityAdministration
}
func validTargetKind(value TargetKind) bool {
	return value == TargetTool || value == TargetIdentity || value == TargetResource || value == TargetAction
}
func capabilityOutcome(value CapabilityCategory) string {
	switch value {
	case CapabilityDataRead:
		return "read"
	case CapabilityDataWrite:
		return "write"
	case CapabilityActionExecute:
		return "execute"
	case CapabilityIdentityAssume:
		return "assume"
	case CapabilityNetworkEgress:
		return "connect"
	case CapabilityAdministration:
		return "administer"
	default:
		return ""
	}
}
func validPostureRule(value PostureRule) bool {
	return value == RuleOwnerlessAgent || value == RuleHumanCredential || value == RuleSharedCredential || value == RuleUntrustedWrite
}
func capabilityKey(scope domain.Scope, agentID, targetID domain.ProductID, category CapabilityCategory) string {
	return scopeIdentity(scope) + "\x00" + agentID.String() + "\x00" + targetID.String() + "\x00" + string(category)
}
func cloneCapability(value Capability) Capability {
	value.EvidenceIDs = append([]domain.ProductID(nil), value.EvidenceIDs...)
	return value
}
func capabilityRank(value CapabilityState) int {
	switch value {
	case CapabilityReachable:
		return 0
	case CapabilityObserved:
		return 1
	case CapabilityVerified:
		return 2
	case CapabilityBlocked:
		return 3
	default:
		return -1
	}
}
