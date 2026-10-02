package apiserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

type orderedDeploymentClaim struct {
	OrganizationID    string          `json:"organization_id"`
	WorkspaceID       string          `json:"workspace_id"`
	EnvironmentID     string          `json:"environment_id"`
	DeviceID          string          `json:"device_id"`
	CredentialID      string          `json:"credential_id"`
	DesiredGeneration int64           `json:"desired_generation"`
	Sequence          int64           `json:"sequence"`
	PolicyVersion     int64           `json:"policy_version"`
	InputDigest       string          `json:"input_digest"`
	LeaseExpiresAt    time.Time       `json:"lease_expires_at"`
	Composition       json.RawMessage `json:"composition"`
}

type orderedDeploymentComposition struct {
	PersistentSources []struct {
		ID      string        `json:"id"`
		Version int64         `json:"version"`
		Policy  policy.Policy `json:"policy"`
	} `json:"persistent_sources"`
	TemporarySources []struct {
		SourceID          string                  `json:"source_id"`
		RunID             string                  `json:"run_id"`
		StepID            string                  `json:"step_id"`
		ActionKey         string                  `json:"action_key"`
		CredentialID      string                  `json:"credential_id"`
		Sequence          int64                   `json:"sequence"`
		PolicyVersion     int64                   `json:"policy_version"`
		DesiredGeneration int64                   `json:"desired_generation"`
		EnvelopeDigest    string                  `json:"envelope_digest"`
		IssuedAt          string                  `json:"issued_at"`
		ExpiresAt         string                  `json:"expires_at"`
		FailureMode       string                  `json:"failure_mode"`
		Policies          []policy.CompiledPolicy `json:"policies"`
	} `json:"temporary_sources"`
	Policies             []policy.CompiledPolicy `json:"policies"`
	ExpiresAt            string                  `json:"expires_at"`
	ReplacementExpiresAt string                  `json:"replacement_expires_at,omitempty"`
}

func orderedDeploymentInputDigest(binding []string, raw json.RawMessage) string {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256([]byte(strings.Join(append(append([]string{}, binding...), string(canonical)), "\x1f")))
	return "sha256:" + hex.EncodeToString(hash[:])
}

func orderedDeploymentCompositionValid(raw json.RawMessage, scope domain.Scope, r, s, d, credential string, sequence, generation int64, sourceDigest string) (orderedDeploymentComposition, bool) {
	return orderedDeploymentCompositionModeValid(raw, scope, r, s, d, credential, sequence, generation, sourceDigest, false)
}

func orderedDeploymentCompositionModeValid(raw json.RawMessage, scope domain.Scope, r, s, d, credential string, sequence, generation int64, sourceDigest string, cleanup bool) (orderedDeploymentComposition, bool) {
	var value orderedDeploymentComposition
	fields := []string{"persistent_sources", "temporary_sources", "policies", "expires_at"}
	if cleanup {
		fields = append(fields, "replacement_expires_at")
	}
	if _, ok := orderedDeploymentClosedObject(raw, orderedDeploymentResponseBytes, fields...); !ok || decodeStrictDiscovery(raw, &value) != nil || value.PersistentSources == nil || len(value.PersistentSources) > 100 || value.TemporarySources == nil || !cleanup && len(value.TemporarySources) < 1 || len(value.TemporarySources) > 100 {
		return value, false
	}
	compiled := make([]policy.CompiledPolicy, 0, 100)
	prior := ""
	for _, source := range value.PersistentSources {
		if source.ID <= prior || source.ID != source.Policy.ID || source.Version < 1 || source.Version > 1000000000 {
			return value, false
		}
		p, active, err := policy.CompileGatewayPolicy(source.Policy)
		if err != nil || source.Policy.Rollout != "monitor" && source.Policy.Rollout != "enforced" {
			return value, false
		}
		if active {
			compiled = append(compiled, p)
		}
		prior = source.ID
	}
	prior = ""
	minimum := time.Time{}
	if cleanup {
		cap, err := time.Parse(time.RFC3339Nano, value.ReplacementExpiresAt)
		if err != nil || value.ReplacementExpiresAt != cap.UTC().Format("2006-01-02T15:04:05.000000Z") || !cap.After(time.Now().Add(time.Minute)) || cap.After(time.Now().Add(24*time.Hour+30*time.Second)) {
			return value, false
		}
		minimum = cap
	}
	found := false
	policyCount := len(value.PersistentSources)
	for _, source := range value.TemporarySources {
		identity := source.RunID + "\x1f" + source.StepID
		_, digestOK := decodeTemporaryPolicyDigest(source.EnvelopeDigest)
		issued, issueErr := time.Parse(time.RFC3339Nano, source.IssuedAt)
		expires, expireErr := time.Parse(time.RFC3339Nano, source.ExpiresAt)
		if identity <= prior || !validProductID(source.RunID) || !validProductID(source.StepID) || !validProductID(source.CredentialID) || !digestOK || source.Sequence < 1 || source.Sequence > 999999999 || source.PolicyVersion != source.Sequence || source.DesiredGeneration < 1 || source.DesiredGeneration > 999999999 || source.ActionKey != "create_temporary_policy" && source.ActionKey != "isolate_session" || source.FailureMode != "open" && source.FailureMode != "closed" || issueErr != nil || expireErr != nil || source.IssuedAt != issued.UTC().Format("2006-01-02T15:04:05.000000Z") || source.ExpiresAt != expires.UTC().Format("2006-01-02T15:04:05.000000Z") || !expires.After(time.Now()) || !expires.After(issued) || len(source.Policies) < 1 || len(source.Policies) > 100 {
			return value, false
		}
		canonical, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_source", strings.Join([]string{source.RunID, source.StepID, d, strconv.FormatInt(source.Sequence, 10), source.EnvelopeDigest}, "\x1f"))
		if source.SourceID != canonical {
			return value, false
		}
		policyPrior := ""
		policyCount += len(source.Policies)
		for _, p := range source.Policies {
			expected, err := policy.Compile(policy.Policy{ID: p.ID, Trigger: p.Trigger, Action: p.Action, Conditions: p.Conditions})
			if err != nil || p.ID <= policyPrior || !reflect.DeepEqual(p, expected) {
				return value, false
			}
			policyPrior = p.ID
			compiled = append(compiled, p)
		}
		if source.RunID == r && source.StepID == s {
			if cleanup || found || source.CredentialID != credential || source.Sequence != sequence || source.DesiredGeneration != generation || source.EnvelopeDigest != sourceDigest || source.FailureMode != "closed" || !orderedContainmentPolicies(source.Policies, true) {
				return value, false
			}
			found = true
		}
		if minimum.IsZero() || expires.Before(minimum) {
			minimum = expires
		}
		prior = identity
	}
	if !cleanup && !found || len(compiled) > 100 || policyCount > 100 || value.ExpiresAt != minimum.UTC().Format("2006-01-02T15:04:05.000000Z") || cleanup && !minimum.After(time.Now().Add(time.Minute)) {
		return value, false
	}
	sort.Slice(compiled, func(i, j int) bool { return compiled[i].ID < compiled[j].ID })
	for i := 1; i < len(compiled); i++ {
		if compiled[i-1].ID == compiled[i].ID {
			return value, false
		}
	}
	return value, reflect.DeepEqual(value.Policies, compiled)
}
