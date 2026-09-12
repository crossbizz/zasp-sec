// Package sandboxcutover implements the fixed schema50 query-cutover protocol.
// It has no live CLI, production release verifier, or default provider adapters.
package sandboxcutover

import (
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

type Request struct{ ReleaseReference string }

// Manifest describes an authenticated, validated render. OtherResourcesDigest
// covers everything except the API template. The verifier must establish that
// the template delta is exactly the session-index selection, not merely trust
// these digest fields supplied alongside caller-controlled manifests.
type Manifest struct {
	SchemaVersion                                            int
	Phase, APIIndex, APITemplateDigest, OtherResourcesDigest string
}

// ReleaseBinding is produced by the configured trust boundary, never decoded
// from a request by the executor. All fields are values, with no mutable aliases.
type ReleaseBinding struct {
	ArtifactDigest                                                string
	From, To                                                      Manifest
	KubernetesServer, KubernetesCADigest, Namespace, NamespaceUID string
	DatabaseIdentity, ProviderIdentity                            string
}

type ReleaseVerifier interface {
	Verify(context.Context, string) (ReleaseBinding, error)
}

type ReceiptRecord struct {
	Binding                                                           sessionsearch.ReceiptBinding
	ReceiptReference, ReceiptVersion, ProjectVersion, CompleteVersion string
	EventIDs, DocumentIDs                                             []string
}

// Capture must come from a complete canonical-receipt-led scan with explicit
// rejection of missing LEFT JOIN targets. Digest covers every ordered binding.
type Capture struct {
	Digest  string
	Records []ReceiptRecord
}

type Database interface {
	Capture(context.Context, ReleaseBinding) (Capture, error)
	// WithFence owns rollback/close, including when the callback returns error.
	// It must obey the supplied deadline and never invoke the callback twice.
	// Its error reports operation/callback failure independently of confirmed
	// cleanup. Even a refused callback can have confirmed rollback and close.
	WithFence(context.Context, ReleaseBinding, func(Fence) error) (FenceResult, error)
}

type FenceResult struct {
	// True only when release of all owned transaction/connection resources was
	// confirmed. A nil operation error or canceled context is not confirmation.
	CleanupConfirmed bool
}

type Fence interface {
	Ready(context.Context) error
	Capture(context.Context) (Capture, error)
	AliveAt(context.Context) (time.Time, error)
}

type ArtifactReader interface {
	Read(context.Context, ReleaseBinding, ReceiptRecord) (receipt, archive []byte, err error)
}

type SearchVerifier interface {
	Ready(context.Context) error
	VerifyVisibleDocuments(context.Context, []sessionsearch.Document) error
}

type APIIdentity struct {
	UID, ResourceVersion, TemplateDigest string
}

// IdentityDigest covers the full observer's11-consumer UID/generation/template/
// image/ReplicaSet/pod evidence. The concrete observer must validate that evidence.
type Observation struct {
	ObservedAt     time.Time
	IdentityDigest string
	API            APIIdentity
}

type Observer interface {
	ObserveBackfill(context.Context, ReleaseBinding) (Observation, error)
	RevalidateBackfill(context.Context, ReleaseBinding, Observation) (Observation, error)
}

type Audit struct {
	TransitionID, ReleaseDigest, ReceiptSetDigest       string
	ReceiptCount                                        int
	AuthorizedAt                                        time.Time
	DatabaseIdentity, ProviderIdentity                  string
	APIUID, SourceResourceVersion, TargetTemplateDigest string
}

// AppliedState is evidence read from Kubernetes, not a success Boolean.
type AppliedState struct {
	API   APIIdentity
	Audit Audit
}

type Kubernetes interface {
	// A definite refusal uses ErrCASRefused. Every other error is ambiguous once
	// called; adapters must not retry the request or silently change preconditions.
	DispatchQuery(context.Context, ReleaseBinding, APIIdentity, Audit) (AppliedState, error)
	Reconcile(context.Context, ReleaseBinding, Audit) (AppliedState, error)
}

type Dependencies struct {
	Releases        ReleaseVerifier
	Database        Database
	Artifacts       ArtifactReader
	Search          SearchVerifier
	Observer        Observer
	Kubernetes      Kubernetes
	Now             func() time.Time
	NewTransitionID func() string
}

type Outcome string

const (
	Refused       Outcome = "refused"
	Applied       Outcome = "applied"
	Indeterminate Outcome = "indeterminate"
)

type Rollout string

const (
	NotStarted Rollout = "not_started"
	Pending    Rollout = "pending"
)

type Result struct {
	Outcome               Outcome
	Rollout               Rollout
	Audit                 Audit
	ResultResourceVersion string
	CleanupConfirmed      bool
}
