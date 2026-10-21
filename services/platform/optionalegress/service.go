package optionalegress

import (
	"context"
	"encoding/json"
	"reflect"
	"time"
)

type Service struct {
	store      Store
	authorizer Authorizer
	sender     Sender
	now        func() time.Time
	newID      func() (string, error)
}

func nilValue(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func New(c Config) (*Service, error) {
	if nilValue(c.Store) || nilValue(c.Authorizer) || nilValue(c.Sender) || c.Now == nil || c.NewRequestID == nil {
		return nil, ErrInvalid
	}
	return &Service{store: c.Store, authorizer: c.Authorizer, sender: c.Sender, now: c.Now, newID: c.NewRequestID}, nil
}
func (s *Service) proof(ctx context.Context, i Intent, p Phase) (Proof, error) {
	v, e := s.authorizer.Authorize(ctx, i, p)
	if e != nil || ctx.Err() != nil || len(v) == 0 || len(v) > 65536 || !json.Valid(v) {
		return nil, ErrUnavailable
	}
	return v, nil
}

// Generate never retries a paid provider effect. A replay returns durable
// metadata only; raw model text remains transient and is not passed to Store.
func (s *Service) Generate(ctx context.Context, i Intent) (Result, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !validIntent(i) {
		return Result{}, ErrInvalid
	}
	proof, e := s.proof(ctx, i, ReplayPhase)
	if e != nil {
		return Result{}, e
	}
	old, e := s.store.Replay(ctx, i, proof)
	if e != nil || ctx.Err() != nil {
		return Result{}, ErrUnavailable
	}
	if old.Found {
		if old.Receipt == nil || !validReceipt(*old.Receipt, i) {
			return Result{}, ErrUnavailable
		}
		return Result{Receipt: *old.Receipt, Replayed: true}, nil
	}
	if old.Receipt != nil {
		return Result{}, ErrUnavailable
	}
	proof, e = s.proof(ctx, i, SourcePhase)
	if e != nil {
		return Result{}, e
	}
	source, e := s.store.Source(ctx, i, proof)
	if e != nil || ctx.Err() != nil {
		return Result{}, ErrUnavailable
	}
	id, e := s.newID()
	if e != nil {
		return Result{}, ErrUnavailable
	}
	prepared, e := Prepare(i, source, id, s.now())
	if e != nil {
		return Result{}, e
	}
	proof, e = s.proof(ctx, i, ReservePhase)
	if e != nil {
		return Result{}, e
	}
	reserved, e := s.store.Reserve(ctx, prepared.binding, proof)
	if e != nil || ctx.Err() != nil || !validReceipt(reserved.Receipt, i) {
		return Result{}, ErrUnavailable
	}
	if !reserved.NewlyReserved {
		return Result{Receipt: reserved.Receipt, Replayed: true}, nil
	}
	if reserved.Binding != prepared.binding || reserved.State != Reserved {
		return Result{}, ErrUnavailable
	}
	proof, e = s.proof(ctx, i, DispatchPhase)
	if e != nil {
		return Result{}, e
	}
	admitted, e := s.store.Dispatch(ctx, prepared.binding, proof)
	// A lost commit reply cannot distinguish RESERVED from STARTED. Sending here
	// could duplicate an effect; only a confirmed newly_started response permits it.
	if e != nil || ctx.Err() != nil {
		return Result{}, ErrUnknown
	}
	if !validReceipt(admitted.Receipt, i) || admitted.Binding != prepared.binding {
		return Result{}, ErrUnknown
	}
	if !admitted.NewlyStarted {
		return Result{Receipt: admitted.Receipt, Replayed: true}, nil
	}
	started, ok := canonicalTime(admitted.StartedAt)
	deadline, ok2 := canonicalTime(prepared.binding.Deadline)
	if admitted.State != Started || !noncePattern.MatchString(admitted.Nonce) || !ok || !ok2 || !started.Before(deadline) {
		return Result{}, ErrUnknown
	}
	claim := Claim{Binding: prepared.binding, Nonce: admitted.Nonce}
	outcome := sendSafely(ctx, s.sender, prepared, claim)
	if !validSendOutcome(outcome, prepared.binding) {
		outcome = SendOutcome{State: Unknown, FailureCode: "provider_contract"}
	}
	settlement := Settlement{Claim: claim, State: outcome.State, ResultDigest: outcome.ResultDigest, FailureCode: outcome.FailureCode, Usage: outcome.Usage}
	// Captured settlement is required after cancellation/revocation. It records
	// existing evidence only, with its original claim and no new provider I/O.
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	receipt, e := s.store.Settle(bounded, settlement)
	if e != nil || !validReceipt(receipt, i) || receipt.Binding != prepared.binding || receipt.State != settlement.State || receipt.ResultDigest != settlement.ResultDigest || receipt.FailureCode != settlement.FailureCode || !sameUsage(receipt.Usage, settlement.Usage) {
		return Result{}, ErrUnknown
	}
	result := Result{Receipt: receipt}
	if receipt.State == Complete {
		result.Explanation = outcome.Result
		return result, nil
	}
	return result, ErrUnknown
}
func sendSafely(ctx context.Context, s Sender, p *Prepared, c Claim) (out SendOutcome) {
	out = SendOutcome{State: Unknown, FailureCode: "provider_contract"}
	defer func() {
		if recover() != nil {
			out = SendOutcome{State: Unknown, FailureCode: "provider_contract"}
		}
	}()
	return s.Send(ctx, p, c)
}
func sameUsage(a, b *Usage) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
func validUsage(u *Usage, b Binding) bool {
	return u != nil && u.InputTokens >= 0 && u.InputTokens <= b.InputTokenBound && u.OutputTokens >= 0 && u.OutputTokens <= b.OutputTokenCap && u.CostNanoCredits >= 0 && u.CostNanoCredits <= b.CostCeilingNanoCredits
}
func validBinding(b Binding, i Intent) bool {
	_, ok := canonicalTime(b.Deadline)
	return b.Intent == i && validIntent(i) && validID(b.RequestID) && validID(b.ProfileID) && b.ProfileVersion >= 1 && b.ProfileVersion <= 1000000 && hashPattern.MatchString(b.SourceDigest) && hashPattern.MatchString(b.ProfileDigest) && hashPattern.MatchString(b.BodyDigest) && hashPattern.MatchString(b.PricingDigest) && hashPattern.MatchString(b.CredentialDigest) && b.InputTokenBound >= 1 && b.InputTokenBound <= 1000000 && b.OutputTokenCap >= 1 && b.OutputTokenCap <= 8192 && b.CostCeilingNanoCredits >= 1 && b.CostCeilingNanoCredits <= 1000000000000 && ok
}
func validFailure(s string) bool {
	switch s {
	case "", "provider_transport", "provider_status", "provider_contract", "credential_unavailable", "deadline", "dispatch_uncertain", "expired_no_send":
		return true
	}
	return false
}
func validReceipt(r Receipt, i Intent) bool {
	if !validBinding(r.Binding, i) || !validFailure(r.FailureCode) {
		return false
	}
	switch r.State {
	case Reserved, Started:
		return r.ResultDigest == "" && r.FailureCode == "" && r.Usage == nil
	case Complete:
		return hashPattern.MatchString(r.ResultDigest) && r.FailureCode == "" && validUsage(r.Usage, r.Binding)
	case Failed:
		return r.ResultDigest == "" && r.FailureCode == "expired_no_send" && r.Usage == nil
	case Unknown:
		return (r.ResultDigest == "" || hashPattern.MatchString(r.ResultDigest)) && r.FailureCode != "" && r.Usage == nil
	}
	return false
}
func validSendOutcome(o SendOutcome, b Binding) bool {
	if o.State == Complete {
		return o.Result != nil && validText(o.Result.Explanation) && validText(o.Result.Recommendation) && o.FailureCode == "" && hashPattern.MatchString(o.ResultDigest) && validUsage(o.Usage, b)
	}
	return o.State == Unknown && o.Result == nil && o.FailureCode != "" && validFailure(o.FailureCode) && (o.ResultDigest == "" || hashPattern.MatchString(o.ResultDigest)) && o.Usage == nil
}
