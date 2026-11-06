// Package optionalegress implements the application's finding explanation boundary.
// SQL adapters own current policy, authorization and durable effect admission.
package optionalegress

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrInvalid     = errors.New("optional egress request rejected")
	ErrUnavailable = errors.New("optional egress unavailable")
	ErrUnknown     = errors.New("optional egress outcome unknown")
)

type State string

const (
	Reserved State = "reserved"
	Started  State = "started"
	Complete State = "complete"
	Failed   State = "failed"
	Unknown  State = "unknown"
)

type Phase string

const (
	ReplayPhase   Phase = "replay"
	SourcePhase   Phase = "source"
	ReservePhase  Phase = "reserve"
	DispatchPhase Phase = "dispatch"
)

// Intent contains authenticated server identity. HTTP clients supply only the
// finding ID/version and retained idempotency key; they never supply this scope.
type Intent struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	ActorID        string `json:"actor_id"`
	FindingID      string `json:"finding_id"`
	FindingVersion int64  `json:"finding_version"`
	IdempotencyKey string `json:"idempotency_key"`
	Purpose        string `json:"purpose"`
}

type Summary struct {
	FindingID     string `json:"finding_id"`
	Version       int64  `json:"version"`
	Rule          string `json:"rule"`
	Severity      string `json:"severity"`
	EvidenceCount int64  `json:"evidence_count"`
	SourceDigest  string `json:"source_digest"`
}

// Profile prices and every field named NanoCredits use nano-USD in this NEW
// profile: 1 USD = 1,000,000,000 nano-USD. Prompt/completion rates are nano-USD
// per million tokens. This profile does not reinterpret or reuse the existing
// Security Agent planner's separately versioned budget/account cost units.
const CostUnit = "usd_nano"

type Profile struct {
	ProfileID                            string `json:"profile_id"`
	ProfileVersion                       int64  `json:"profile_version"`
	ProfileDigest                        string `json:"profile_digest"`
	Provider                             string `json:"provider"`
	Purpose                              string `json:"purpose"`
	Model                                string `json:"model"`
	Backend                              string `json:"backend"`
	AccountID                            string `json:"account_id"`
	CredentialReference                  string `json:"credential_reference"`
	CredentialDigest                     string `json:"credential_digest"`
	CapabilityDigest                     string `json:"capability_digest"`
	PricingDigest                        string `json:"pricing_digest"`
	EffectiveAt                          string `json:"effective_at"`
	ExpiresAt                            string `json:"expires_at"`
	InputTokenBound                      int64  `json:"input_token_bound"`
	OutputTokenCap                       int64  `json:"output_token_cap"`
	PromptPriceNanoCreditsPerMillion     int64  `json:"prompt_price_nano_credits_per_million"`
	CompletionPriceNanoCreditsPerMillion int64  `json:"completion_price_nano_credits_per_million"`
	CostCeilingNanoCredits               int64  `json:"cost_ceiling_nano_credits"`
	MaximumOutstandingNanoCredits        int64  `json:"maximum_outstanding_nano_credits"`
	MaximumConcurrency                   int64  `json:"maximum_concurrency"`
	TimeoutMilliseconds                  int64  `json:"timeout_milliseconds"`
	PolicyVersion                        string `json:"policy_version"`
}

type Source struct {
	Summary Summary `json:"summary"`
	Profile Profile `json:"profile"`
}

type Binding struct {
	Intent
	RequestID              string `json:"request_id"`
	SourceDigest           string `json:"source_digest"`
	ProfileID              string `json:"profile_id"`
	ProfileVersion         int64  `json:"profile_version"`
	ProfileDigest          string `json:"profile_digest"`
	BodyDigest             string `json:"body_digest"`
	PricingDigest          string `json:"pricing_digest"`
	CredentialDigest       string `json:"credential_digest"`
	InputTokenBound        int64  `json:"input_token_bound"`
	OutputTokenCap         int64  `json:"output_token_cap"`
	CostCeilingNanoCredits int64  `json:"cost_ceiling_nano_credits"`
	Deadline               string `json:"deadline"`
}

// Usage.CostNanoCredits is ceil(OpenRouter usage.cost USD * 1e9).
type Usage struct {
	InputTokens     int64 `json:"input_tokens"`
	OutputTokens    int64 `json:"output_tokens"`
	CostNanoCredits int64 `json:"cost_nano_credits"`
}

type Receipt struct {
	Binding      Binding `json:"binding"`
	State        State   `json:"state"`
	ResultDigest string  `json:"result_digest"`
	FailureCode  string  `json:"failure_code"`
	Usage        *Usage  `json:"usage"`
}

type ReplayResult struct {
	Found   bool     `json:"found"`
	Receipt *Receipt `json:"receipt"`
}
type Reservation struct {
	Receipt
	NewlyReserved bool `json:"newly_reserved"`
}
type DispatchResult struct {
	Receipt
	NewlyStarted bool   `json:"newly_started"`
	Nonce        string `json:"nonce"`
	StartedAt    string `json:"started_at"`
}

// Claim is returned only by confirmed SQL RESERVED->STARTED admission. It does
// not itself prove admission: the production SQL adapter is the trusted mint.
type Claim struct {
	Binding
	Nonce string `json:"nonce"`
}
type Settlement struct {
	Claim
	State        State  `json:"state"`
	ResultDigest string `json:"result_digest"`
	FailureCode  string `json:"failure_code"`
	Usage        *Usage `json:"usage"`
}

// Proof is opaque current authorization attestation, not a client field or an
// unsigned Allowed flag. Production adapters install the existing transaction80
// proof context and fence the current organization revision on EACH call.
type Proof json.RawMessage

type Authorizer interface {
	Authorize(context.Context, Intent, Phase) (Proof, error)
}
type Store interface {
	Replay(context.Context, Intent, Proof) (ReplayResult, error)
	Source(context.Context, Intent, Proof) (Source, error)
	Reserve(context.Context, Binding, Proof) (Reservation, error)
	Dispatch(context.Context, Binding, Proof) (DispatchResult, error)
	Settle(context.Context, Settlement) (Receipt, error)
}

type TransientExplanation struct {
	Explanation    string `json:"explanation"`
	Recommendation string `json:"recommendation"`
}
type SendOutcome struct {
	State        State
	Result       *TransientExplanation
	ResultDigest string
	FailureCode  string
	Usage        *Usage
}
type Sender interface {
	Send(context.Context, *Prepared, Claim) SendOutcome
}
type Result struct {
	Receipt     Receipt
	Explanation *TransientExplanation
	Replayed    bool
}

type Config struct {
	Store        Store
	Authorizer   Authorizer
	Sender       Sender
	Now          func() time.Time
	NewRequestID func() (string, error)
}
