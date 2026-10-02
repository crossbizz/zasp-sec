package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const publicPageRuntimeReady = `SELECT to_jsonb(zasp_audit_export_public_page_readiness($1,$2))`
const publicPageRuntimeRead = `SELECT zasp_audit_export_public_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`

type publicPageCallerKey struct{}
type publicPageRuntimeDB struct {
	auditExportRuntimeDatabase
	ordinary                               bool
	pageGate                               json.RawMessage
	pageCalls, pageReadyCalls, legacyCalls int
	pageArgs                               []any
	badContext                             bool
	callerRequired                         bool
	cancelPage                             context.CancelFunc
}

func (db *publicPageRuntimeDB) SchemaVersion(context.Context) (string, error) {
	if db.ordinary {
		return apiserver.ReferenceSchemaVersion, nil
	}
	return apiserver.ProductionRecoverySchemaVersion, nil
}

func (db *publicPageRuntimeDB) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	if query == publicPageRuntimeReady {
		db.pageReadyCalls++
		deadline, bounded := ctx.Deadline()
		if !bounded || time.Until(deadline) > 5*time.Second || ctx.Err() != nil {
			db.badContext = true
		}
		if db.callerRequired && db.pageReadyCalls == 1 && (ctx.Value(publicPageCallerKey{}) != "owned-caller" || time.Until(deadline) > 2*time.Second) {
			db.badContext = true
		}
		if db.cancelPage != nil {
			db.cancelPage()
		}
		return db.pageGate, nil
	}
	if query == publicPageRuntimeRead {
		db.pageCalls++
		db.pageArgs = args
		return json.RawMessage(`{"items":[],"has_more":false}`), nil
	}
	if strings.Contains(query, "AS item FROM zasp_admin_audit WHERE") {
		db.legacyCalls++
		return json.RawMessage(`{"items":[]}`), nil
	}
	if strings.Contains(query, "FROM zasp_product_sessions AS session JOIN") {
		query = strings.Replace(query, "FROM zasp_product_sessions AS session JOIN", "FROM zasp_product_sessions session JOIN", 1)
	}
	return db.auditExportRuntimeDatabase.QueryJSON(ctx, query, args...)
}

func publicPageRuntimeRequest(config RuntimeConfig, path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, config.PublicOrigin+path, nil)
	req.RemoteAddr = "10.20.0.10:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("X-Forwarded-Host", req.Host)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Port", "443")
	req.Header.Set("X-Zasp-Expected-Scope", "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003")
	req.AddCookie(&http.Cookie{Name: "__Host-zasp_session", Value: "owned-runtime-session"})
	return req
}

func TestAuditPublicPageCompositionSelectedAndLegacy(t *testing.T) {
	t.Setenv("HOSTNAME", "audit-page-runtime-test")
	for _, security := range []bool{false, true} {
		for _, selected := range []bool{false, true} {
			name := "ordinary"
			if security {
				name = "security-agent"
			}
			if selected {
				name += "/selected"
			} else {
				name += "/legacy"
			}
			t.Run(name, func(t *testing.T) {
				config := fixtureAuditExportRuntimeConfig(t)
				if !selected {
					config.AuditExports = nil
				}
				db := &publicPageRuntimeDB{auditExportRuntimeDatabase: auditExportRuntimeDatabase{gate: json.RawMessage(`true`)}, pageGate: json.RawMessage(`true`)}
				db.ordinary = !security
				db.callerRequired = true
				caller, stop := context.WithTimeout(context.WithValue(context.Background(), publicPageCallerKey{}, "owned-caller"), 2*time.Second)
				defer stop()
				var securityDB apiserver.JSONDatabase
				if security {
					securityDB = db
				}
				deps, err := composeRuntimeDependenciesWithContext(caller, config, db, securityDB, apiserver.CallbackProviderFunc(func(context.Context, string, string) (apiserver.SessionGrant, error) {
					return apiserver.SessionGrant{}, errors.New("unused callback")
				}))
				// Export startup requires production-recovery-v1, which itself
				// requires the separate security-agent repository. Preserve refusal.
				if !security && selected {
					for _, c := range deps.Closers {
						_ = c.Close()
					}
					if err != errRuntimeUnavailable || deps.ProductHandler != nil || db.legacyCalls != 0 {
						t.Fatal("unsupported ordinary export profile fell back")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					for _, c := range deps.Closers {
						_ = c.Close()
					}
				})
				path := "/api/v1/audit-events"
				if selected {
					path += "?action=policy.update&limit=7"
				}
				response := httptest.NewRecorder()
				deps.ProductHandler.ServeHTTP(response, publicPageRuntimeRequest(config, path))
				if response.Code != 200 {
					t.Fatalf("outer selected=%t status=%d body=%s", selected, response.Code, response.Body.String())
				}
				if selected {
					if db.pageCalls != 1 || db.pageReadyCalls < 2 || db.legacyCalls != 0 || db.badContext {
						t.Fatalf("selected page bypassed registered authority: page=%d ready=%d legacy=%d badContext=%t", db.pageCalls, db.pageReadyCalls, db.legacyCalls, db.badContext)
					}
					args := db.pageArgs
					if len(args) != 12 {
						t.Fatalf("page arguments=%d", len(args))
					}
					digest := sha256.Sum256([]byte("owned-runtime-session"))
					if args[0] != "pid_10000001-0000-4000-8000-000000000001" || args[3] != "pid_10000004-0000-4000-8000-000000000004" || !bytes.Equal(args[4].([]byte), digest[:]) || args[5] != strings.Repeat("c", 32) || string(args[6].([]byte)) != `{"action":"policy.update"}` || args[7] != nil || args[8] != nil || args[9] != 7 || args[10] != migrations.ProductionAuditExports().Checksum() || args[11] != migrations.ProductionAuditExportsSemanticFingerprint() {
						t.Fatal("outer middleware lost exact scoped twelve-argument authority")
					}
					db.pageGate = json.RawMessage(`false`)
					late := httptest.NewRecorder()
					deps.ProductHandler.ServeHTTP(late, publicPageRuntimeRequest(config, path))
					if late.Code != 503 || db.pageCalls != 1 || db.legacyCalls != 0 {
						t.Fatal("late readiness refusal fell back or read data", late.Code)
					}
				} else if db.legacyCalls != 1 || db.pageCalls != 0 || db.pageReadyCalls != 0 {
					t.Fatal("nil profile changed legacy authority")
				}
			})
		}
	}
}

func TestAuditPublicPageCompositionSelectedStartupRefusal(t *testing.T) {
	t.Setenv("HOSTNAME", "audit-page-runtime-test")
	for _, gate := range []string{`false`, `null`, `{"ready":true}`, `true`} {
		t.Run(gate, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			db := &publicPageRuntimeDB{auditExportRuntimeDatabase: auditExportRuntimeDatabase{gate: json.RawMessage(`true`)}, pageGate: json.RawMessage(gate)}
			if gate == `true` {
				db.cancelPage = cancel
			}
			deps, err := composeRuntimeDependenciesWithContext(ctx, fixtureAuditExportRuntimeConfig(t), db, db, apiserver.CallbackProviderFunc(func(context.Context, string, string) (apiserver.SessionGrant, error) {
				return apiserver.SessionGrant{}, errors.New("unused callback")
			}))
			for _, c := range deps.Closers {
				_ = c.Close()
			}
			if err != errRuntimeUnavailable || deps.ProductHandler != nil || len(deps.Closers) != 0 || db.pageReadyCalls != 1 {
				t.Fatal("selected startup did not refuse page authority", err, db.pageReadyCalls)
			}
		})
	}
}
