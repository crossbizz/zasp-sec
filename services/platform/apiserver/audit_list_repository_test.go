package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func auditListRepositoryFixture(t *testing.T, payload json.RawMessage) (*AuditPublicPageRepository, *discoveryCallDatabase, RequestIdentity) {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	identity.Permissions = append(identity.Permissions, "view_audit")
	database := &discoveryCallDatabase{schema: ProductionRecoverySchemaVersion, responses: map[string]json.RawMessage{postgresAuditPublicPageReadySQL: json.RawMessage(`true`), postgresAuditPublicPageSQL: payload}, errors: map[string]error{}}
	repository, err := NewAuditPublicPageRepository(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	return repository, database, identity
}

type auditListContextDatabase struct {
	*discoveryCallDatabase
	cancel   context.CancelFunc
	observed time.Duration
	blocking bool
}

func (db *auditListContextDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("missing inherited bound")
	}
	db.observed = time.Until(deadline)
	if db.blocking {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	raw, err := db.discoveryCallDatabase.QueryJSON(ctx, query, args...)
	if query == postgresAuditPublicPageSQL && db.cancel != nil {
		db.cancel()
	}
	return raw, err
}
func TestAuditExportPublicPageRepositoryContextsAndInvalidInput(t *testing.T) {
	r, db, identity := auditListRepositoryFixture(t, json.RawMessage(`{"items":[],"has_more":false}`))
	digest := sha256.Sum256([]byte("session"))
	input := auditPublicPageRequest{sessionDigest: digest[:], limit: 50}
	for _, kind := range []string{"nilctx", "canceled", "expired", "digest", "zero", "limit", "one-sided-id", "one-sided-time", "nanoseconds", "filter", "permission", "bearer", "csrf"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			in := input
			selected := identity
			switch kind {
			case "nilctx":
				ctx = nil
			case "canceled":
				c, stop := context.WithCancel(ctx)
				stop()
				ctx = c
			case "expired":
				c, stop := context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer stop()
				ctx = c
			case "digest":
				in.sessionDigest = digest[:31]
			case "zero":
				in.sessionDigest = make([]byte, 32)
			case "limit":
				in.limit = 0
			case "one-sided-id":
				in.afterID = "pid_72000001-0000-4000-8000-000000000001"
			case "one-sided-time":
				in.afterTime = time.Now()
			case "nanoseconds":
				in.afterID = "pid_72000001-0000-4000-8000-000000000001"
				in.afterTime = time.Date(2026, 1, 1, 0, 0, 0, 1, time.UTC)
			case "filter":
				in.filters.from = "2026-01-01T00:00:00Z"
			case "permission":
				selected.Permissions = []string{"view"}
			case "bearer":
				selected.CredentialKind = CredentialBearerToken
			case "csrf":
				selected.CSRFToken = ""
			}
			before := len(db.queries)
			if _, err := r.read(ctx, selected, in); err == nil || len(db.queries) != before {
				t.Fatal("invalid request reached authority", err)
			}
		})
	}
	ctx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	bounded := &auditListContextDatabase{discoveryCallDatabase: db}
	scoped, err := NewAuditPublicPageRepository(ctx, bounded)
	if err != nil || bounded.observed <= 0 || bounded.observed > 100*time.Millisecond {
		t.Fatal("startup detached parent deadline", err, bounded.observed)
	}
	canceled, doCancel := context.WithCancel(context.Background())
	bounded.cancel = doCancel
	if _, err := scoped.read(canceled, identity, input); !errors.Is(err, context.Canceled) {
		t.Fatal("successful DB bytes beat cancellation", err)
	}
	bounded.cancel = nil
	bounded.blocking = true
	short, end := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer end()
	if _, err := scoped.read(short, identity, input); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked call outlived parent", err)
	}
	for _, raw := range []string{`false`, `null`, `"true"`, `1`, `{"ready":true}`, `true false`, strings.Repeat(" ", 17) + `true`} {
		db.responses[postgresAuditPublicPageReadySQL] = json.RawMessage(raw)
		if _, err := NewAuditPublicPageRepository(context.Background(), db); err == nil {
			t.Errorf("startup accepted %q", raw)
		}
	}
	if _, err := NewAuditPublicPageRepository(nil, db); err == nil {
		t.Fatal("nil parent accepted")
	}
	if _, err := NewAuditPublicPageRepository(context.Background(), nil); err == nil {
		t.Fatal("nil DB accepted")
	}
	if _, _, err := newProductionHandlers(nil, nil, nil, nil, CookiePolicy{AuditPublicPages: &AuditPublicPageRepository{}}); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatal("malformed optional capability accepted")
	}
}

func TestAuditExportPublicPageDecoderListSemantics(t *testing.T) {
	base := auditListItemFixture(t)
	for _, tc := range []struct {
		name, metadata, target string
		valid                  bool
	}{
		{"empty", `{"":""}`, "target", true}, {"opaque-case", `{"Key":"","key":""}`, "target", true}, {"escaped-pair", `{"\ud83d\ude00":"\ud83d\ude00"}`, "target", true}, {"literal-escape", `{"\\ud800":"\\udfff"}`, "target", true},
		{"large-key", `{"` + strings.Repeat("k", 800000) + `":""}`, "target", true},
		{"value512", `{"v":"` + strings.Repeat("😀", 256) + `"}`, "target", true}, {"value513", `{"v":"` + strings.Repeat("😀", 256) + `x"}`, "target", false},
		{"target128", `{}`, strings.Repeat("😀", 64), true}, {"target129", `{}`, strings.Repeat("😀", 64) + "x", false},
		{"numeric-unprojected", `{"n":1}`, "target", false}, {"bool-unprojected", `{"n":true}`, "target", false}, {"nested-unprojected", `{"n":{}}`, "target", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			quoted, _ := json.Marshal(tc.target)
			item := strings.Replace(string(base), `"target_id":"policy-fixture"`, `"target_id":`+string(quoted), 1)
			item = strings.Replace(item, `"metadata":{}`, `"metadata":`+tc.metadata, 1)
			raw := json.RawMessage(`{"items":[` + item + `],"has_more":false}`)
			page, err := decodeAuditPublicPage(raw, auditPublicPageRequest{limit: 50})
			if (err == nil) != tc.valid {
				t.Fatal("list UTF16/opaque projection boundary", err)
			}
			if tc.valid && !bytes.Equal(page.items[0], []byte(item)) {
				t.Fatal("decoder rewrote original item bytes")
			}
		})
	}
	for _, kind := range []string{"actor", "action", "outcome", "from", "to", "order", "keyset", "count", "properties33", "field-alias", "field-duplicate"} {
		t.Run(kind, func(t *testing.T) {
			in := auditPublicPageRequest{limit: 1}
			item := string(base)
			raw := `{"items":[` + item + `],"has_more":false}`
			switch kind {
			case "actor":
				in.filters.actorID = "pid_10000004-0000-4000-8000-000000000009"
			case "action":
				in.filters.action = "policy.delete"
			case "outcome":
				in.filters.outcome = "denied"
			case "from":
				in.filters.from = "2027-01-01T00:00:00.000000Z"
			case "to":
				in.filters.to = "2026-09-12T00:00:00.123456Z"
			case "keyset":
				in.afterID = "pid_72000001-0000-4000-8000-000000000001"
				in.afterTime = time.Date(2026, 9, 12, 0, 0, 0, 123456000, time.UTC)
			case "count", "order":
				if kind == "order" {
					in.limit = 2
				}
				raw = `{"items":[` + strings.Replace(item, "72000001", "71000001", 1) + `,` + item + `],"has_more":false}`
			case "properties33":
				metadata := map[string]string{}
				for i := 0; i < 33; i++ {
					metadata[string(rune('a'+i))] = ""
				}
				body, _ := json.Marshal(metadata)
				raw = strings.Replace(raw, `"metadata":{}`, `"metadata":`+string(body), 1)
			case "field-alias":
				raw = strings.Replace(raw, `"id":`, `"ID":`, 1)
			case "field-duplicate":
				raw = strings.Replace(raw, `"id":`, `"id":"pid_72000001-0000-4000-8000-000000000001","id":`, 1)
			}
			if _, err := decodeAuditPublicPage([]byte(raw), in); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatal("invalid stored page accepted", err)
			}
		})
	}
}
func TestAuditExportPublicPageRepositoryWireAndFailures(t *testing.T) {
	payload := json.RawMessage(`{"items":[` + string(auditListItemFixture(t)) + `],"has_more":true}`)
	r, db, identity := auditListRepositoryFixture(t, payload)
	identity.FreshAuthenticated = false
	digest := sha256.Sum256([]byte("owned-page-session"))
	in := auditPublicPageRequest{sessionDigest: digest[:], limit: 50}
	page, err := r.read(context.Background(), identity, in)
	if err != nil || len(page.items) != 1 || !page.hasMore {
		t.Fatal("explicit page lost", err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), digest[:], identity.CSRFToken, []byte(`{}`), nil, nil, 50, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()}
	if db.query != `SELECT zasp_audit_export_public_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)` || !reflect.DeepEqual(db.args, want) {
		t.Fatalf("wrong12 argument authority: %s %#v", db.query, db.args)
	}
	if postgresAuditPublicPageReadySQL != `SELECT to_jsonb(zasp_audit_export_public_page_readiness($1,$2))` {
		t.Fatal("readiness cannot add export/storage authority or return native boolean")
	}
	for code, want := range map[string]error{"22023": ErrRepositoryOperation, "28000": ErrRepositoryAuthentication, "42501": ErrAuditExportForbidden, "55000": ErrRepositoryUnavailable, "XX000": ErrRepositoryUnavailable, "23505": ErrRepositoryUnavailable, "P0002": ErrRepositoryUnavailable} {
		db.errors[postgresAuditPublicPageSQL] = &pgconn.PgError{Code: code, Message: "private-audit-source"}
		if _, err := r.read(context.Background(), identity, in); !errors.Is(err, want) || strings.Contains(err.Error(), "private-audit-source") {
			t.Errorf("SQL%s: %v", code, err)
		}
	}
	delete(db.errors, postgresAuditPublicPageSQL)
	db.responses[postgresAuditPublicPageReadySQL] = json.RawMessage(`false`)
	if _, err := r.read(context.Background(), identity, in); !errors.Is(err, ErrRepositoryUnavailable) || db.query != postgresAuditPublicPageReadySQL {
		t.Fatal("warmed readiness bypass", err)
	}
}
func TestAuditExportPublicPageDecoderRefusesMalformed(t *testing.T) {
	item := string(auditListItemFixture(t))
	valid := `{"items":[` + item + `],"has_more":false}`
	cases := map[string]string{"null": `null`, "array": `[]`, "extra": strings.Replace(valid, `"has_more":false`, `"has_more":false,"extra":1`, 1), "alias": strings.Replace(valid, `"has_more"`, `"Has_More"`, 1), "duplicate": strings.Replace(valid, `"has_more":false`, `"has_more":false,"has_more":false`, 1), "nullItems": `{"items":null,"has_more":false}`, "nullMore": `{"items":[],"has_more":null}`, "emptyMore": `{"items":[],"has_more":true}`, "trailing": valid + `{}`, "itemExtra": strings.Replace(valid, `"action":`, `"extra":1,"action":`, 1), "itemNull": strings.Replace(valid, `"target_id":"policy-fixture"`, `"target_id":null`, 1), "metadataNull": strings.Replace(valid, `"metadata":{}`, `"metadata":{"k":null}`, 1), "metadataDuplicate": strings.Replace(valid, `"metadata":{}`, `"metadata":{"k":"","k":""}`, 1), "surrogate": strings.Replace(valid, `"metadata":{}`, `"metadata":{"\ud800":""}`, 1), "controlScalar": strings.Replace(valid, `"metadata":{}`, `"metadata":{"k":"\udfff"}`, 1), "invalidUTF8": strings.Replace(valid, "policy-fixture", string([]byte{255}), 1), "oversize": strings.Repeat(" ", (1<<20)+4097), "duplicateID": `{"items":[` + item + `,` + item + `],"has_more":false}`}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			r, _, identity := auditListRepositoryFixture(t, json.RawMessage(payload))
			digest := sha256.Sum256([]byte("session"))
			if _, err := r.read(context.Background(), identity, auditPublicPageRequest{sessionDigest: digest[:], limit: 50}); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("malformed private page accepted: %v", err)
			}
		})
	}
}
