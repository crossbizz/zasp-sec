package sandboxcutover

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

var ErrCASRefused = errors.New("sandbox cutover CAS refused")
var errRejected = errors.New("sandbox cutover rejected")

const evidenceLifetime = 30 * time.Second
const fenceLifetime = 15 * time.Second

func ExecuteSandboxQueryCutover(ctx context.Context, request Request, deps Dependencies) Result {
	result := Result{Outcome: Refused, Rollout: NotStarted}
	if ctx == nil || ctx.Err() != nil || !text(request.ReleaseReference) || deps.Now == nil || deps.NewTransitionID == nil {
		return result
	}
	for _, dependency := range []any{deps.Releases, deps.Database, deps.Artifacts, deps.Search, deps.Observer, deps.Kubernetes} {
		if nilValue(dependency) {
			return result
		}
	}
	ctx, cancel := context.WithTimeout(ctx, evidenceLifetime)
	defer cancel()
	binding, err := deps.Releases.Verify(ctx, request.ReleaseReference)
	if err != nil || !validRelease(binding) || ctx.Err() != nil {
		return result
	}
	initial, err := deps.Observer.ObserveBackfill(ctx, binding)
	if err != nil || !validObservation(initial, binding, deps.Now()) {
		return result
	}
	capture, err := deps.Database.Capture(ctx, binding)
	if err != nil || !validCapture(capture) {
		return result
	}
	if deps.Search.Ready(ctx) != nil {
		return result
	}
	for _, receipt := range capture.Records {
		body, archive, err := deps.Artifacts.Read(ctx, binding, receipt)
		if err != nil {
			return result
		}
		documents, err := sessionsearch.BuildDocuments(receipt.Binding, body, archive)
		if err != nil || len(documents) != len(receipt.DocumentIDs) {
			return result
		}
		for i, document := range documents {
			if document.DocumentID != receipt.DocumentIDs[i] {
				return result
			}
		}
		// One canonical receipt is one scope and at most1000 documents. Never
		// send a global, mixed-tenant set to the provider verification method.
		if deps.Search.VerifyVisibleDocuments(ctx, documents) != nil {
			return result
		}
	}
	if ctx.Err() != nil {
		return result
	}
	fenceCtx, stopFence := context.WithTimeout(ctx, fenceLifetime)
	defer stopFence()
	entered := false
	fenceResult, _ := deps.Database.WithFence(fenceCtx, binding, func(fence Fence) error {
		if entered || nilValue(fence) {
			return errRejected
		}
		entered = true
		if fenceCtx.Err() != nil || fence.Ready(fenceCtx) != nil {
			return errRejected
		}
		current, err := fence.Capture(fenceCtx)
		if err != nil || !validCapture(current) || current.Digest != capture.Digest || !reflect.DeepEqual(current.Records, capture.Records) {
			return errRejected
		}
		observed, err := deps.Observer.RevalidateBackfill(fenceCtx, binding, initial)
		if err != nil || !validObservation(observed, binding, deps.Now()) || observed.IdentityDigest != initial.IdentityDigest || observed.API != initial.API || !fresh(initial.ObservedAt, deps.Now()) {
			return errRejected
		}
		if deps.Search.Ready(fenceCtx) != nil {
			return errRejected
		}
		id := deps.NewTransitionID()
		if !text(id) {
			return errRejected
		}
		cutoff, err := fence.AliveAt(fenceCtx)
		if err != nil || cutoff.IsZero() || !fresh(initial.ObservedAt, deps.Now()) || fenceCtx.Err() != nil {
			return errRejected
		}
		result.Audit = Audit{TransitionID: id, ReleaseDigest: binding.ArtifactDigest, ReceiptSetDigest: capture.Digest, ReceiptCount: len(capture.Records), AuthorizedAt: cutoff.UTC(), DatabaseIdentity: binding.DatabaseIdentity, ProviderIdentity: binding.ProviderIdentity, APIUID: initial.API.UID, SourceResourceVersion: initial.API.ResourceVersion, TargetTemplateDigest: binding.To.APITemplateDigest}
		// Once invoked, an error can hide persistence. Only a definite conditional
		// rejection or exact transition-specific readback settles that ambiguity.
		result.Outcome, result.Rollout = Indeterminate, Pending
		state, dispatchErr := deps.Kubernetes.DispatchQuery(fenceCtx, binding, initial.API, result.Audit)
		if errors.Is(dispatchErr, ErrCASRefused) {
			result.Outcome, result.Rollout = Refused, NotStarted
			return nil
		}
		if dispatchErr == nil && matches(state, result.Audit) {
			result.Outcome, result.ResultResourceVersion = Applied, state.API.ResourceVersion
			return nil
		}
		if fenceCtx.Err() == nil {
			state, readErr := deps.Kubernetes.Reconcile(fenceCtx, binding, result.Audit)
			if readErr == nil && matches(state, result.Audit) {
				result.Outcome, result.ResultResourceVersion = Applied, state.API.ResourceVersion
			}
		}
		return nil
	})
	// Operation/callback errors and release confirmation are independent. Neither
	// can rewrite an already-established applied outcome after dispatch.
	result.CleanupConfirmed = fenceResult.CleanupConfirmed
	return result
}

func matches(state AppliedState, audit Audit) bool {
	return state.Audit == audit && state.API.UID == audit.APIUID && text(state.API.ResourceVersion) && state.API.ResourceVersion != audit.SourceResourceVersion && state.API.TemplateDigest == audit.TargetTemplateDigest
}

func validRelease(b ReleaseBinding) bool {
	return b.From.SchemaVersion == 50 && b.To.SchemaVersion == 50 && b.From.Phase == "backfill" && b.To.Phase == "query" && b.From.APIIndex == "zasp-runtime-sessions-v1" && b.To.APIIndex == "zasp-runtime-sessions-v2" && b.From.OtherResourcesDigest == b.To.OtherResourcesDigest && digest(b.ArtifactDigest) && digest(b.From.OtherResourcesDigest) && digest(b.From.APITemplateDigest) && digest(b.To.APITemplateDigest) && b.From.APITemplateDigest != b.To.APITemplateDigest && strings.HasPrefix(b.KubernetesServer, "https://") && digest(b.KubernetesCADigest) && text(b.Namespace) && text(b.NamespaceUID) && text(b.DatabaseIdentity) && text(b.ProviderIdentity)
}

func validCapture(c Capture) bool {
	return digest(c.Digest) && c.Records != nil && len(c.Records) <= 10000
}

func validObservation(o Observation, b ReleaseBinding, now time.Time) bool {
	return fresh(o.ObservedAt, now) && digest(o.IdentityDigest) && text(o.API.UID) && text(o.API.ResourceVersion) && o.API.TemplateDigest == b.From.APITemplateDigest
}

func fresh(observed, now time.Time) bool {
	return !observed.IsZero() && !now.Before(observed) && now.Sub(observed) < evidenceLifetime
}

func text(value string) bool {
	return len(value) > 0 && len(value) <= 2048 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func digest(value string) bool {
	return len(value) == 64 && strings.IndexFunc(value, func(r rune) bool { return !strings.ContainsRune("0123456789abcdef", r) }) == -1
}

func nilValue(value any) bool {
	if value == nil {
		return true
	}
	r := reflect.ValueOf(value)
	return slices.Contains([]reflect.Kind{reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice}, r.Kind()) && r.IsNil()
}
