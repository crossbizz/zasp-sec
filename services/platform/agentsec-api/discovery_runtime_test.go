package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Only the database boundary is controlled. Construction, capability selection,
// readiness, public query routing and decoding are the production repository.
type discoveryRuntimeDatabase struct {
	t       *testing.T
	queries []string
}

func (d *discoveryRuntimeDatabase) SchemaVersion(context.Context) (string, error) {
	return "production-discovery-execution-v1", nil
}
func (d *discoveryRuntimeDatabase) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected write")
}
func (d *discoveryRuntimeDatabase) QueryJSON(_ context.Context, query string, args ...any) (json.RawMessage, error) {
	d.queries = append(d.queries, query)
	switch query {
	case "SELECT to_jsonb(zasp_execution_readiness($1,$2))":
		if len(args) != 2 {
			d.t.Fatal("readiness arguments")
		}
		return json.RawMessage(`true`), nil
	case "SELECT to_jsonb(zasp_discovery_principal_ready($1))":
		if len(args) != 1 || args[0] != apiserver.DiscoveryDatabaseAuthorityAPI {
			d.t.Fatal("principal arguments")
		}
		return json.RawMessage(`true`), nil
	case "SELECT zasp_execution_sync_history($1,$2,$3,$4,$5,$6,$7)", "SELECT zasp_temporal72.sync_history($1,$2,$3,$4,$5,$6,$7)":
		if len(args) != 7 || args[3] != "pid_72000004-0000-4000-8000-000000000004" || args[6] != 10 {
			d.t.Fatal("history arguments")
		}
		return json.RawMessage(`{"items":[],"next_id":null,"next_requested_at":null}`), nil
	default:
		d.t.Fatalf("unexpected database statement: %s", query)
		return nil, errors.New("unexpected statement")
	}
}

type discoveryRuntimeCapability struct {
	*discoveryRuntimeDatabase
	available   bool
	err         error
	contexts    []context.Context
	authorities []string
}

func (d *discoveryRuntimeCapability) TemporalDiscoveryAvailable(ctx context.Context, authority string) (bool, error) {
	d.contexts = append(d.contexts, ctx)
	d.authorities = append(d.authorities, authority)
	return d.available, d.err
}

func TestDiscoveryRuntimeRepositorySelectsInstalledProfile(t *testing.T) {
	for _, mode := range []string{"installed", "absent", "no-interface", "invalid-installed"} {
		t.Run(mode, func(t *testing.T) {
			base := &discoveryRuntimeDatabase{t: t}
			capability := &discoveryRuntimeCapability{discoveryRuntimeDatabase: base, available: mode == "installed"}
			if mode == "invalid-installed" {
				capability.err = apiserver.ErrRepositoryUnavailable
			}
			var next apiserver.JSONDatabase = capability
			if mode == "no-interface" {
				next = base
			}
			traced := &tracedJSONDatabase{next: next, metrics: newOperationalMetrics(), exporter: newStructuredSpanExporter(io.Discard)}
			repo, err := apiserver.NewDiscoveryRepositoryForAuthority(traced, apiserver.DiscoveryDatabaseAuthorityAPI)
			if mode == "invalid-installed" {
				if !errors.Is(err, apiserver.ErrRepositoryConfiguration) || repo != nil || len(base.queries) != 0 {
					t.Fatalf("invalid installed profile fell back: repo=%v err=%v queries=%v", repo != nil, err, base.queries)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = repo.Ready(context.Background()); err != nil {
				t.Fatal(err)
			}
			var ids [3]domain.ProductID
			for i, text := range []string{"pid_72000001-0000-4000-8000-000000000001", "pid_72000002-0000-4000-8000-000000000002", "pid_72000003-0000-4000-8000-000000000003"} {
				ids[i], err = domain.ParseProductID(text)
				if err != nil {
					t.Fatal(err)
				}
			}
			scope, err := domain.NewScope(ids[0], ids[1], ids[2])
			if err != nil {
				t.Fatal(err)
			}
			page, err := repo.ListIntegrationSyncs(context.Background(), scope, "pid_72000004-0000-4000-8000-000000000004", nil, "", 10)
			if err != nil || len(page.Items) != 0 {
				t.Fatalf("public history: %+v %v", page, err)
			}
			want := "SELECT zasp_execution_sync_history($1,$2,$3,$4,$5,$6,$7)"
			if mode == "installed" {
				want = "SELECT zasp_temporal72.sync_history($1,$2,$3,$4,$5,$6,$7)"
			}
			if got := base.queries[len(base.queries)-1]; got != want {
				t.Fatalf("public repository selected %q, want %q", got, want)
			}
			if mode == "installed" {
				if len(base.queries) != 1 || len(capability.contexts) != 2 {
					t.Fatalf("unexpected readiness path queries=%v probes=%d", base.queries, len(capability.contexts))
				}
				capability.err = apiserver.ErrRepositoryUnavailable
				if err := repo.Ready(context.Background()); !errors.Is(err, apiserver.ErrRepositoryUnavailable) {
					t.Fatalf("live drift accepted: %v", err)
				}
			}
		})
	}
}

func TestDiscoveryRuntimeCapabilityForwardsAndRefusesInvalidInputs(t *testing.T) {
	type probe interface {
		TemporalDiscoveryAvailable(context.Context, string) (bool, error)
	}
	base := &discoveryRuntimeDatabase{t: t}
	capability := &discoveryRuntimeCapability{discoveryRuntimeDatabase: base, available: true}
	traced := &tracedJSONDatabase{next: capability}
	p, ok := any(traced).(probe)
	if !ok {
		t.Fatal("traced database dropped discovery capability")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, authority := range []string{apiserver.DiscoveryDatabaseAuthorityAPI, apiserver.DiscoveryDatabaseAuthorityOutbox, "foreign-authority"} {
		got, err := p.TemporalDiscoveryAvailable(ctx, authority)
		if !got || err != nil || capability.contexts[len(capability.contexts)-1] != ctx || capability.authorities[len(capability.authorities)-1] != authority {
			t.Fatal("capability context/authority changed")
		}
	}
	sentinel := errors.New("installed drift")
	capability.available = false
	capability.err = sentinel
	if got, err := p.TemporalDiscoveryAvailable(ctx, "zasp_discovery_api"); got || !errors.Is(err, sentinel) {
		t.Fatal("capability error lost")
	}
	cancel()
	before := len(capability.contexts)
	for _, entry := range []struct {
		name string
		db   *tracedJSONDatabase
		ctx  context.Context
	}{
		{"nil-wrapper", nil, context.Background()}, {"nil-next", &tracedJSONDatabase{}, context.Background()},
		{"typed-nil", &tracedJSONDatabase{next: (*discoveryRuntimeCapability)(nil)}, context.Background()},
		{"nil-context", traced, nil}, {"cancelled", traced, ctx},
	} {
		t.Run(entry.name, func(t *testing.T) {
			p := any(entry.db).(probe)
			if got, err := p.TemporalDiscoveryAvailable(entry.ctx, "zasp_discovery_api"); got || !errors.Is(err, apiserver.ErrRepositoryUnavailable) {
				t.Fatalf("invalid input accepted: %v %v", got, err)
			}
		})
	}
	if len(capability.contexts) != before {
		t.Fatal("invalid input reached underlying authority")
	}
}
