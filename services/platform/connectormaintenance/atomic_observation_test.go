package connectormaintenance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type atomicObservationFixture struct {
	*pinFreshnessFixture
	observations int
	events       []string
	mutation     string
}

// Legacy calls deliberately fail: an atomic source must never fall back to
// independently observed facts and revisions.
func (f *atomicObservationFixture) Facts(context.Context, Reference) (Facts, error) {
	return Facts{}, ErrUnavailable
}
func (f *atomicObservationFixture) Revision(context.Context, string) (authorization.Revision, error) {
	return authorization.Revision{}, ErrUnavailable
}
func (f *atomicObservationFixture) Observe(ctx context.Context, ref Reference) (Facts, authorization.Revision, error) {
	f.events = append(f.events, "observe")
	f.observations++
	facts, revision := f.facts, f.revision
	if ref != facts.Reference || ctx.Err() != nil {
		return Facts{}, authorization.Revision{}, ErrUnavailable
	}
	if f.mutation == "before pending" {
		revision.Applied++
	}
	if f.observations == 2 {
		switch f.mutation {
		case "after source":
			facts.ContextDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		case "after revision":
			revision.Generation++
		case "after expiry":
			facts.Expires = time.Now().Add(-time.Second)
		case "after error":
			return Facts{}, authorization.Revision{}, ErrUnavailable
		}
	}
	return facts, revision, nil
}
func (f *atomicObservationFixture) Check(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
	f.events = append(f.events, q.PrincipalKind)
	model := f.revision.ModelID
	if f.mutation == "wrong model" {
		model = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
	}
	return authorization.Decision{Allowed: f.mutation != q.PrincipalKind, ModelID: model}, nil
}

func TestAtomicConnectorObservation(t *testing.T) {
	for _, mutation := range []string{"", "before pending", "user", "service", "wrong model", "after source", "after revision", "after expiry", "after error"} {
		t.Run(mutation, func(t *testing.T) {
			f := &atomicObservationFixture{pinFreshnessFixture: newPinFreshnessFixture(migrations.ProductionAuthorizationEnforcement().Checksum()), mutation: mutation}
			f.facts.Expires = f.facts.Expires.UTC()
			a, err := NewAuthority(f, f, f.revision.StoreID, f.revision.ModelID, f.facts.Profile, make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			proof, err := a.Authorize(context.Background(), f.facts.Reference, BeforeSecretFailure)
			expected := []string{"observe", "user", "service", "observe"}
			switch mutation {
			case "before pending":
				expected = expected[:1]
			case "user", "wrong model":
				expected = expected[:2]
			case "service":
				expected = expected[:3]
			}
			if !reflect.DeepEqual(f.events, expected) {
				t.Fatalf("fresh observation and permission boundaries: got %v want %v", f.events, expected)
			}
			if mutation != "" {
				if err == nil || len(proof) != 0 {
					t.Fatal("changed live authority produced proof")
				}
				return
			}
			if err != nil {
				t.Fatalf("atomic authority refused: %v", err)
			}
			var envelope struct {
				Body string `json:"body"`
			}
			if json.Unmarshal(proof, &envelope) != nil {
				t.Fatal("invalid envelope")
			}
			body, err := base64.StdEncoding.DecodeString(envelope.Body)
			if err != nil {
				t.Fatal(err)
			}
			var signed struct {
				Facts    Facts                  `json:"facts"`
				Revision authorization.Revision `json:"revision"`
				Phase    string                 `json:"phase"`
			}
			if json.Unmarshal(body, &signed) != nil || signed.Facts != f.facts || signed.Revision != f.revision || signed.Phase != "before_secret_failure" {
				t.Fatal("signed proof did not preserve actual observed pair")
			}
			if _, err = a.Authorize(context.Background(), f.facts.Reference, BeforeProvider); err != nil || f.observations != 4 {
				t.Fatal("subsequent phase reused observation")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err = a.Authorize(ctx, f.facts.Reference, BeforeProvider); !errors.Is(err, ErrUnavailable) || f.observations != 4 {
				t.Fatal("canceled phase observed or produced proof")
			}
		})
	}
}

// Decode the actual wire object used by Executor.Observe; malformed storage
// results cannot be converted into signed facts through a permissive fallback.
func TestAtomicObservationStoredValues(t *testing.T) {
	sourcePin := migrations.ProductionAuthorizationEnforcement().Checksum()
	f := newPinFreshnessFixture(sourcePin)
	f.facts.Expires = f.facts.Expires.UTC()
	valid := func() map[string]any { return map[string]any{"facts": f.facts, "revision": f.revision} }
	for _, name := range []string{"exact stored pair", "unknown outer field", "internal disposition", "missing revision", "foreign organization", "pending projection", "unknown nested field", "wrong source pin", "null facts"} {
		t.Run(name, func(t *testing.T) {
			object := valid()
			switch name {
			case "unknown outer field":
				object["fallback"] = true
			case "internal disposition":
				object["disposition"] = "ok"
			case "missing revision":
				delete(object, "revision")
			case "foreign organization":
				r := f.revision
				r.OrganizationID = f.facts.Reference.Workspace
				object["revision"] = r
			case "pending projection":
				r := f.revision
				r.Applied++
				object["revision"] = r
			case "unknown nested field":
				b, _ := json.Marshal(f.facts)
				var nested map[string]any
				_ = json.Unmarshal(b, &nested)
				nested["extra"] = true
				object["facts"] = nested
			case "wrong source pin":
				facts := f.facts
				facts.SourceProfile = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
				object["facts"] = facts
			case "null facts":
				object["facts"] = nil
			}
			raw, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			facts, revision, err := decodeObservation(raw, f.facts.Reference, f.facts.Profile, sourcePin)
			if name != "exact stored pair" {
				if err == nil {
					t.Fatal("untrusted stored observation admitted")
				}
				return
			}
			if err != nil || facts != f.facts || revision != f.revision {
				t.Fatal("actual stored pair was not preserved")
			}
		})
	}
}

// These are the actual Executor error mappings used by preparation release:
// a lost lease must remain retryable/unavailable rather than pause-denied.
func TestAtomicObservationDatabaseFailureClasses(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		want       error
	}{
		{"expired or changed lease", "40001", ErrUnavailable},
		{"missing original task", "P0002", ErrUnavailable},
		{"current source or permission denied", "42501", ErrDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := databaseError(&pgconn.PgError{Code: tc.code})
			if !errors.Is(got, tc.want) {
				t.Fatal("database failure changed preparation disposition")
			}
			if tc.want == ErrUnavailable && errors.Is(got, ErrDenied) {
				t.Fatal("lease loss became permission denial")
			}
		})
	}
}
